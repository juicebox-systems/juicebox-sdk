//! An implementation of the Noise NK protocol for encrypted communication.
//!
//! [Noise](https://noiseprotocol.org/) is a framework that defines a bunch of
//! related protocols for secure communication. This module implements the
//! Noise NK protocol only. Noise NK has a simple message pattern that allows
//! the handshake to complete after a single request and response. This code
//! has very few branches by focusing on just Noise NK, compared to a
//! general-purpose implementation of all the Noise protocols.
//!
//! This module is currently limited to `Noise_NK_25519_ChaChaPoly_BLAKE2s`
//! specifically, which is probably what you'd want to use when doing
//! cryptography in software in 32-bit mode.
//!
//! This module takes some minor liberties compared to the Noise spec:
//!
//! - Noise uses the terminology 'initiator' and 'responder', whereas this
//!   module names the roles 'client' and 'server'.
//! - Noise simply concatenates binary fields to form messages, whereas this
//!   module it up to the caller to either concatenate them or encode them some
//!   other way.
//! - Noise limits messages to 65535 bytes, whereas this module does not.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use blake2::Blake2s256;
use chacha20poly1305::aead::{Aead, KeyInit};
pub use chacha20poly1305::aead::{Error as EncryptionError, Payload};
use chacha20poly1305::ChaCha20Poly1305;
use core::fmt;
use digest::Digest;
use juicebox_sdk_marshalling::bytes;
use serde::{Deserialize, Serialize};
use x25519_dalek as x25519;

pub mod client;
pub mod server;

#[cfg(test)]
mod test_vectors;

const PROTOCOL_NAME: &str = "Noise_NK_25519_ChaChaPoly_BLAKE2s";
const HASH_LEN: usize = 32;

/// Sent from the client to the server during a handshake.
#[derive(Clone, Deserialize, Serialize)]
pub struct HandshakeRequest {
    /// A plaintext ephemeral public key for the client.
    #[serde(with = "bytes")]
    pub client_ephemeral_public: Vec<u8>,

    /// An encrypted request payload. Note that this payload does not have
    /// forward secrecy.
    #[serde(with = "bytes")]
    pub payload_ciphertext: Vec<u8>,
}

impl fmt::Debug for HandshakeRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HandshakeRequest").finish_non_exhaustive()
    }
}

/// Sent from the server to the client during a handshake.
#[derive(Clone, Deserialize, Serialize)]
pub struct HandshakeResponse {
    /// A plaintext ephemeral public key for the server.
    #[serde(with = "bytes")]
    pub server_ephemeral_public: Vec<u8>,

    /// An encrypted response payload.
    #[serde(with = "bytes")]
    pub payload_ciphertext: Vec<u8>,
}

impl fmt::Debug for HandshakeResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HandshakeResponse").finish_non_exhaustive()
    }
}

/// Clients and servers use this to communicate after the handshake.
pub struct Transport {
    inbound: CipherState,
    outbound: CipherState,
}

impl fmt::Debug for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Transport").finish_non_exhaustive()
    }
}

impl Transport {
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        self.inbound.decrypt_with_ad(Payload {
            msg: ciphertext,
            aad: &[],
        })
    }
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        self.outbound.encrypt_with_ad(Payload {
            msg: plaintext,
            aad: &[],
        })
    }
}

/// This corresponds to a Noise protocol "CipherState" object for
/// ChaCha20Poly1305.
///
/// # Security Note
///
/// The docs for the `chacha20poly1305` crate warn about PowerPC and older
/// CPUs:
///
/// > It is not suitable for use on processors with a variable-time
/// > multiplication operation (e.g. short circuit on multiply-by-zero /
/// > multiply-by-one, such as certain 32-bit PowerPC CPUs and some non-ARM
/// > microcontrollers)."
struct CipherState {
    cipher: ChaCha20Poly1305,
    nonce: u64,
}

impl CipherState {
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(&key.into()),
            nonce: 0,
        }
    }

    pub fn encrypt_with_ad(&mut self, payload: Payload) -> Result<Vec<u8>, EncryptionError> {
        let nonce = self.next_nonce();
        self.cipher.encrypt(&nonce, payload)
    }

    pub fn decrypt_with_ad(&mut self, payload: Payload) -> Result<Vec<u8>, EncryptionError> {
        let nonce = self.next_nonce();
        self.cipher.decrypt(&nonce, payload)
    }

    fn next_nonce(&mut self) -> chacha20poly1305::Nonce {
        let mut padded = [0u8; 12];
        padded[4..].copy_from_slice(&self.nonce.to_le_bytes());

        self.nonce = self.nonce.checked_add(1).unwrap();
        // It'd take hundreds of years to increment a nonce this far. This
        // check is just here to be compliant with the Noise spec.
        assert_ne!(
            self.nonce,
            u64::MAX,
            "Noise reserves the nonce value 2^64 - 1"
        );

        chacha20poly1305::Nonce::from(padded)
    }
}

/// This corresponds to `h` in the Noise spec.
struct HandshakeHash([u8; HASH_LEN]);

impl HandshakeHash {
    fn new() -> (Self, ChainingKey) {
        let h = if PROTOCOL_NAME.len() >= HASH_LEN {
            Blake2s256::digest(PROTOCOL_NAME).into()
        } else {
            // Noise processes shorter names differently
            unimplemented!()
        };
        (Self(h), ChainingKey(h))
    }

    fn mix_hash(&mut self, data: &[u8]) {
        self.0 = Blake2s256::new()
            .chain_update(self.0)
            .chain_update(data)
            .finalize()
            .into();
    }
}

/// This corresponds to `ck` in the Noise spec.
struct ChainingKey([u8; HASH_LEN]);

impl ChainingKey {
    fn mix_key(&mut self, dh: &x25519::SharedSecret) -> CipherState {
        let (ck, k) = hkdf_pair(&self.0, dh.as_bytes());
        self.0 = ck;
        CipherState::new(k)
    }

    fn split(self, role: Role) -> Transport {
        let (k1, k2) = hkdf_pair(&self.0, &[]);
        match role {
            Role::Server => Transport {
                inbound: CipherState::new(k1),
                outbound: CipherState::new(k2),
            },
            Role::Client => Transport {
                inbound: CipherState::new(k2),
                outbound: CipherState::new(k1),
            },
        }
    }
}

/// Used in [`ChainingKey::split`].
enum Role {
    Client,
    Server,
}

fn hkdf_pair(salt: &[u8], ikm: &[u8]) -> ([u8; HASH_LEN], [u8; HASH_LEN]) {
    // This uses `SimpleHmac` with Blake2 because of eager vs lazy block
    // consumption, as explained in `hmac` crate docs.
    let kdf = hkdf::Hkdf::<Blake2s256, hmac::SimpleHmac<Blake2s256>>::new(Some(salt), ikm);
    if HASH_LEN != 32 {
        unimplemented!("Noise treats HDKF output differently for 64-byte hash len");
    }
    let mut okm = [0u8; HASH_LEN * 2];
    kdf.expand(&[], &mut okm).unwrap();
    let mut first = [0u8; HASH_LEN];
    first.copy_from_slice(&okm[..HASH_LEN]);
    let mut second = [0u8; HASH_LEN];
    second.copy_from_slice(&okm[HASH_LEN..]);
    (first, second)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chacha_nonce() {
        let mut cipher = CipherState::new([0u8; 32]);
        assert_eq!(
            <[u8; 12]>::from(cipher.next_nonce()),
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            <[u8; 12]>::from(cipher.next_nonce()),
            [0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            <[u8; 12]>::from(cipher.next_nonce()),
            [0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0]
        );
        cipher.nonce = 256;
        assert_eq!(
            <[u8; 12]>::from(cipher.next_nonce()),
            [0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]
        );
    }
}
