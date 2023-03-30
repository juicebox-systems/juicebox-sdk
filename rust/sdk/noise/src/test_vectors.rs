use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;
use x25519_dalek as x25519;

use super::{client, server};

/// See <https://github.com/noiseprotocol/noise_wiki/wiki/Test-vectors>.
#[derive(Debug, Deserialize)]
#[allow(unused)]
struct TestVector {
    name: Option<String>,
    protocol_name: Option<String>,
    // unsupported: hybrid
    #[serde(default)]
    fail: bool,
    #[serde(default)]
    fallback: bool,
    fallback_pattern: Option<String>,
    init_prologue: String,
    // unsupported: init_psks
    init_static: Option<String>,
    init_ephemeral: String,
    init_remote_static: Option<String>,
    resp_prologue: String,
    // unsupported: resp_psks
    resp_static: Option<String>,
    resp_ephemeral: Option<String>,
    resp_remote_static: Option<String>,
    handshake_hash: Option<String>,
    messages: Vec<TestMessage>,
}

#[derive(Debug, Deserialize)]
struct TestMessage {
    payload: String,
    ciphertext: String,
}

#[derive(Deserialize)]
struct VectorFile {
    vectors: Vec<TestVector>,
}

fn open(filename: &str) -> fs::File {
    let path = Path::new("src/noise/vectors").join(filename);
    fs::File::open(&path).unwrap_or_else(|e| {
        panic!(
            "failed to open {path:?} from {cwd:?}: {e}",
            cwd = std::env::current_dir().unwrap()
        )
    })
}

fn load_json(filename: &str) -> Vec<TestVector> {
    let file = open(filename);
    let contents: VectorFile = serde_json::from_reader(file).unwrap();
    contents.vectors
}

fn load_flynn(filename: &str) -> Vec<TestVector> {
    fn extract_keys(keys: HashMap<String, String>) -> TestVector {
        TestVector {
            name: None,
            protocol_name: keys.get("handshake").cloned(),
            fail: false,
            fallback: false,
            fallback_pattern: None,
            init_prologue: keys.get("prologue").cloned().unwrap_or_default(),
            init_static: keys.get("init_static").cloned(),
            init_ephemeral: keys.get("gen_init_ephemeral").cloned().unwrap(),
            init_remote_static: None,
            resp_prologue: keys.get("prologue").cloned().unwrap_or_default(),
            resp_static: keys.get("resp_static").cloned(),
            resp_ephemeral: keys.get("gen_resp_ephemeral").cloned(),
            resp_remote_static: None,
            handshake_hash: None,
            messages: (0..)
                .map_while(|i| {
                    keys.get(&format!("msg_{i}_payload"))
                        .cloned()
                        .map(|payload| {
                            let ciphertext =
                                keys.get(&format!("msg_{i}_ciphertext")).cloned().unwrap();
                            TestMessage {
                                payload,
                                ciphertext,
                            }
                        })
                })
                .collect(),
        }
    }

    let file = BufReader::new(open(filename));
    let mut vectors = Vec::new();
    let mut keys = HashMap::new();
    for (i, line) in file.lines().enumerate() {
        let line = line.unwrap();
        if line.is_empty() {
            vectors.push(extract_keys(std::mem::take(&mut keys)));
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            keys.insert(key.to_owned(), value.to_owned());
            continue;
        }
        panic!("failed to parse line {} of {filename:?}", i + 1);
    }
    if !keys.is_empty() {
        vectors.push(extract_keys(keys));
    }
    vectors
}

#[derive(Debug, Eq, PartialEq)]
struct NumPassed(usize);

fn test_vectors(vectors: &[TestVector]) -> NumPassed {
    let mut overall_fail = false;
    let mut num_passed = NumPassed(0);
    for vector in vectors {
        let name = (vector.name.as_ref())
            .or(vector.protocol_name.as_ref())
            .unwrap();
        match std::panic::catch_unwind(|| test_vector(vector)) {
            Ok(true) => {
                num_passed.0 += 1;
                println!("{name}: OK");
            }
            Ok(false) => {}
            Err(cause) => {
                overall_fail = true;
                println!("{name}: FAIL: {cause:?}");
            }
        }
    }
    if overall_fail {
        panic!();
    }
    num_passed
}

/// Returns true if the test runs successfully, false if the test was
/// skipped, and panics on failure.
fn test_vector(vector: &TestVector) -> bool {
    let protocol = (vector.protocol_name.as_ref())
        .or(vector.name.as_ref())
        .unwrap();
    if protocol != "Noise_NK_25519_ChaChaPoly_BLAKE2s" {
        return false;
    }

    let handshake_request = &vector.messages[0];
    let handshake_response = &vector.messages[1];

    let (client, request_fields) = client::Handshake::start_with_secret(
        x25519::StaticSecret::from(hex_decode32(&vector.init_ephemeral)),
        &match &vector.init_remote_static {
            Some(key) => x25519::PublicKey::from(hex_decode32(key)),
            None => x25519::PublicKey::from(&x25519::StaticSecret::from(hex_decode32(
                vector.resp_static.as_ref().unwrap(),
            ))),
        },
        &hex_decode(&vector.init_prologue),
        &hex_decode(&handshake_request.payload),
    )
    .expect("client start handshake");

    assert_eq!(
        hex::encode(concat(
            &request_fields.client_ephemeral_public,
            &request_fields.payload_ciphertext
        )),
        handshake_request.ciphertext,
        "client send handshake request"
    );

    let (server, payload_plaintext) = server::Handshake::start_with_secret(
        x25519::StaticSecret::from(hex_decode32(vector.resp_ephemeral.as_ref().unwrap())),
        (
            &x25519::StaticSecret::from(hex_decode32(vector.resp_static.as_ref().unwrap())),
            &x25519::PublicKey::from(&x25519::StaticSecret::from(hex_decode32(
                vector.resp_static.as_ref().unwrap(),
            ))),
        ),
        &hex_decode(&vector.resp_prologue),
        &request_fields,
    )
    .expect("server start handshake");

    assert_eq!(
        hex::encode(&payload_plaintext),
        handshake_request.payload,
        "server receive handshake request"
    );

    let (mut server, response_fields) = server
        .finish(&hex_decode(&handshake_response.payload))
        .expect("server finish handshake");
    assert_eq!(
        hex::encode(concat(
            &response_fields.server_ephemeral_public,
            &response_fields.payload_ciphertext
        )),
        handshake_response.ciphertext,
        "server send handshake response"
    );

    let (mut client, response_plaintext) = client
        .finish(&response_fields)
        .expect("client finish handshake");
    assert_eq!(
        hex::encode(response_plaintext),
        handshake_response.payload,
        "client receive handshake response"
    );

    let mut messages = vector.messages.iter().skip(2);
    loop {
        let Some(request) = messages.next() else { break };
        let ciphertext = client
            .encrypt(&hex_decode(&request.payload))
            .expect("client encrypt transport request");
        assert_eq!(
            hex::encode(&ciphertext),
            request.ciphertext,
            "client send transport request"
        );

        let plaintext = server
            .decrypt(&ciphertext)
            .expect("server receive transport request");
        assert_eq!(
            hex::encode(&plaintext),
            request.payload,
            "server receive transport request"
        );

        let Some(response) = messages.next() else { break };
        let ciphertext = server
            .encrypt(&hex_decode(&response.payload))
            .expect("server encrypt transport response");
        assert_eq!(
            hex::encode(&ciphertext),
            response.ciphertext,
            "server send transport response"
        );

        let plaintext = client
            .decrypt(&ciphertext)
            .expect("client receive transport response");
        assert_eq!(
            hex::encode(&plaintext),
            response.payload,
            "client receive transport response"
        );
    }

    true
}

fn concat(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().chain(b).cloned().collect()
}

fn hex_decode(input: &str) -> Vec<u8> {
    hex::decode(input).unwrap()
}

fn hex_decode32(input: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    hex::decode_to_slice(input, &mut out).unwrap();
    out
}

#[test]
fn test_cacophony() {
    assert_eq!(test_vectors(&load_json("cacophony.txt")), NumPassed(1));
}

#[test]
fn test_noise_c() {
    assert_eq!(test_vectors(&load_json("noise-c-basic.txt")), NumPassed(1));
}

#[test]
fn test_snow() {
    assert_eq!(test_vectors(&load_json("snow.txt")), NumPassed(1));
}

#[test]
fn test_flynn() {
    assert_eq!(test_vectors(&load_flynn("flynn.txt")), NumPassed(4));
}
