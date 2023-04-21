use async_trait::async_trait;
use js_sys::{try_iter, Array, Object, Promise, Uint8Array};
use loam_sdk as sdk;
use loam_sdk_bridge::{DeleteError, PinHashingMode, RecoverError, RegisterError};
use serde::{Deserialize, Serialize};
use serde_wasm_bindgen::from_value;
use std::str::FromStr;
use url::Url;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Blob, Request, RequestInit, RequestMode, Response};

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(extends = Object, typescript_type = "Realm[]")]
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub type RealmArray;

    #[wasm_bindgen(js_name = fetch)]
    pub fn fetch_with_request(input: &Request) -> Promise;
}

#[wasm_bindgen(getter_with_clone)]
#[derive(Serialize, Deserialize)]
pub struct Realm {
    pub address: String,
    pub public_key: Vec<u8>,
    pub id: Vec<u8>,
}

#[wasm_bindgen]
impl Realm {
    #[wasm_bindgen(constructor)]
    pub fn new(address: String, public_key: Vec<u8>, id: Vec<u8>) -> Self {
        console_error_panic_hook::set_once();
        Self {
            address,
            public_key,
            id,
        }
    }
}

impl From<Realm> for sdk::Realm {
    fn from(value: Realm) -> Self {
        sdk::Realm {
            address: Url::from_str(&value.address).unwrap(),
            public_key: value.public_key,
            id: sdk::RealmId(value.id.try_into().unwrap()),
        }
    }
}

#[wasm_bindgen(getter_with_clone)]
pub struct Configuration {
    pub realms: RealmArray,
    pub register_threshold: u8,
    pub recover_threshold: u8,
    pub pin_hashing_mode: PinHashingMode,
}

#[wasm_bindgen]
impl Configuration {
    #[wasm_bindgen(constructor)]
    pub fn new(
        realms: RealmArray,
        register_threshold: u8,
        recover_threshold: u8,
        pin_hashing_mode: PinHashingMode,
    ) -> Self {
        console_error_panic_hook::set_once();
        Self {
            realms,
            register_threshold,
            recover_threshold,
            pin_hashing_mode,
        }
    }
}

impl From<Configuration> for sdk::Configuration {
    fn from(value: Configuration) -> Self {
        sdk::Configuration {
            realms: Array::from(&value.realms)
                .iter()
                .map(|value| sdk::Realm::from(from_value::<Realm>(value).unwrap()))
                .collect(),
            register_threshold: value.register_threshold,
            recover_threshold: value.recover_threshold,
            pin_hashing_mode: sdk::PinHashingMode::from(value.pin_hashing_mode as u8),
        }
    }
}

#[wasm_bindgen]
pub struct Client(sdk::Client<HttpClient>);

#[wasm_bindgen]
impl Client {
    /// Constructs a new `Client`.
    ///
    /// The configuration provided must include at least one realm.
    ///
    /// The `auth_token` represents the authority to act as a particular user
    /// and should be valid for the lifetime of the `Client`.
    #[wasm_bindgen(constructor)]
    pub fn new(configuration: Configuration, auth_token: String) -> Self {
        console_error_panic_hook::set_once();
        let sdk = sdk::Client::new(
            sdk::Configuration::from(configuration),
            sdk::AuthToken::from(auth_token),
            HttpClient(),
        );
        Self(sdk)
    }

    /// Stores a new PIN-protected secret.
    ///
    /// If it's successful, this also deletes any prior secrets for this user.
    ///
    /// Upon failure, a `Register` will be provided.
    ///
    /// # Warning
    ///
    /// If the secrets vary in length (such as passwords), the caller should
    /// add padding to obscure the secrets' length.
    pub async fn register(
        &self,
        pin: Vec<u8>,
        secret: Vec<u8>,
        num_guesses: u16,
    ) -> Result<(), RegisterError> {
        self.0
            .register(
                &sdk::Pin(pin),
                &sdk::UserSecret(secret),
                sdk::Policy { num_guesses },
            )
            .await
            .map_err(RegisterError::from)
    }

    /// Retrieves a PIN-protected secret.
    ///
    /// If it's successful, this also deletes any earlier secrets for this
    /// user.
    ///
    /// Upon failure, a `RecoverError` will be provided.
    pub async fn recover(&self, pin: Vec<u8>) -> Result<Uint8Array, RecoverError> {
        match self.0.recover(&sdk::Pin(pin)).await {
            Ok(secret) => Ok(Uint8Array::from(secret.0.as_slice())),
            Err(err) => Err(RecoverError::from(err)),
        }
    }

    /// Deletes all secrets for this user.
    ///
    /// Upon failure, a `DeleteError` will be provided.
    pub async fn delete_all(&self) -> Result<(), DeleteError> {
        self.0.delete_all().await.map_err(DeleteError::from)
    }
}

struct HttpClient();

#[async_trait(?Send)]
impl sdk::http::Client for HttpClient {
    async fn send(&self, request: sdk::http::Request) -> Option<sdk::http::Response> {
        let mut opts = RequestInit::new();
        opts.method(request.method.as_str());
        opts.mode(RequestMode::Cors);

        if let Some(body) = &request.body {
            opts.body(Some(&Uint8Array::from(body.as_slice())));
        }

        let js_request = Request::new_with_str_and_init(request.url.as_str(), &opts)
            .expect("Failed to initialze request");

        request.headers.iter().for_each(|(name, value)| {
            js_request.headers().set(name, value).unwrap();
        });

        match JsFuture::from(fetch_with_request(&js_request)).await {
            Ok(value) => {
                let response: Response = value.dyn_into().unwrap();

                let headers = try_iter(&response.headers())
                    .unwrap()
                    .unwrap()
                    .map(|entry| Array::from(&entry.unwrap()))
                    .map(|entry| {
                        (
                            entry.get(0).as_string().unwrap(),
                            entry.get(1).as_string().unwrap(),
                        )
                    })
                    .collect();

                let body = match JsFuture::from(response.blob().unwrap()).await {
                    Ok(value) => {
                        let blob: Blob = value.into();
                        let array_buffer = JsFuture::from(blob.array_buffer()).await.unwrap();
                        Uint8Array::new(&array_buffer).to_vec()
                    }
                    Err(_) => vec![],
                };

                Some(sdk::http::Response {
                    status_code: response.status(),
                    headers,
                    body,
                })
            }
            Err(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{Client, Configuration, Realm, RealmArray};
    use loam_sdk_bridge::{DeleteError, PinHashingMode, RecoverError, RegisterError};
    use serde_wasm_bindgen::to_value;
    use wasm_bindgen_test::*;

    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    async fn test_register() {
        let client = client("https://httpbin.org/anything/");
        let result = client
            .register(Vec::from("1234"), Vec::from("apollo"), 2)
            .await;
        assert!(
            matches!(result, Err(RegisterError::Protocol)),
            "got {result:?}"
        );
    }

    #[wasm_bindgen_test]
    async fn test_recover() {
        let client = client("https://httpbin.org/anything/");
        let result = client.recover(Vec::from("1234")).await;
        assert!(
            matches!(result, Err(RecoverError::Protocol)),
            "got {result:?}"
        );
    }

    #[wasm_bindgen_test]
    async fn test_delete() {
        let client = client("https://httpbin.org/anything/");
        let result = client.delete_all().await;
        assert!(
            matches!(result, Err(DeleteError::Protocol)),
            "got {result:?}"
        );
    }

    fn client(url: &str) -> Client {
        Client::new(
            Configuration {
                realms: RealmArray {
                    obj: to_value(&vec![Realm {
                        address: url.to_string(),
                        public_key: vec![0; 32],
                        id: vec![0; 16],
                    }])
                    .unwrap()
                    .into(),
                },
                register_threshold: 1,
                recover_threshold: 1,
                pin_hashing_mode: PinHashingMode::None,
            },
            "token".to_string(),
        )
    }
}
