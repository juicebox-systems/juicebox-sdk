use async_trait::async_trait;
use futures_channel::oneshot;
use js_sys::{try_iter, Array, Object, Promise, Uint8Array};
use juicebox_sdk as sdk;
use juicebox_sdk_bridge::{DeleteError, RecoverErrorReason, RegisterError};
use sdk::Sleeper;
use serde_wasm_bindgen::from_value;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::{spawn_local, JsFuture};
use web_sys::{Blob, Request, RequestInit, RequestMode, Response};

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(extends = Object, typescript_type = "Configuration[]")]
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub type ConfigurationArray;

    #[wasm_bindgen(js_name = fetch)]
    pub fn fetch_with_request(input: &Request) -> Promise;
}

#[wasm_bindgen]
pub struct Configuration(sdk::Configuration);

#[derive(Debug)]
#[repr(C)]
#[wasm_bindgen]
pub struct RecoverError {
    /// The reason recovery failed.
    pub reason: RecoverErrorReason,
    /// Guesses remaining is only valid if `reason` is `Unsuccessful`
    pub guesses_remaining: Option<u16>,
}

impl From<sdk::RecoverError> for RecoverError {
    fn from(value: sdk::RecoverError) -> Self {
        match value {
            sdk::RecoverError::InvalidAuth => Self {
                reason: RecoverErrorReason::InvalidAuth,
                guesses_remaining: None,
            },
            sdk::RecoverError::InvalidPin { guesses_remaining } => Self {
                reason: RecoverErrorReason::InvalidPin,
                guesses_remaining: Some(guesses_remaining),
            },
            sdk::RecoverError::NotRegistered => Self {
                reason: RecoverErrorReason::NotRegistered,
                guesses_remaining: None,
            },
            sdk::RecoverError::Transient => Self {
                reason: RecoverErrorReason::Transient,
                guesses_remaining: None,
            },
            sdk::RecoverError::Assertion => Self {
                reason: RecoverErrorReason::Assertion,
                guesses_remaining: None,
            },
        }
    }
}

#[wasm_bindgen]
impl Configuration {
    #[wasm_bindgen(constructor)]
    pub fn new(value: JsValue) -> Self {
        console_error_panic_hook::set_once();

        let json_string = match value.as_string() {
            Some(s) => s,
            None => js_sys::JSON::stringify(&value)
                .unwrap()
                .as_string()
                .unwrap(),
        };

        Self(sdk::Configuration::from_json(&json_string).expect("invalid configuration json"))
    }
}

impl From<Configuration> for sdk::Configuration {
    fn from(value: Configuration) -> Self {
        value.0
    }
}

#[wasm_bindgen]
pub struct Client(sdk::Client<WasmSleeper, HttpClient, WasmAuthTokenManager>);

#[wasm_bindgen]
impl Client {
    /// Constructs a new `Client`.
    ///
    /// # Arguments
    ///
    /// * `configuration` – Represents the current configuration. The configuration
    /// provided must include at least one `Realm`.
    /// * `previous_configurations` – Represents any other configurations you have
    /// previously registered with that you may not yet have migrated the data from.
    /// During `Client.recover`, they will be tried if the current user has not yet
    /// registered on the current configuration. These should be ordered from most recently
    /// to least recently used.
    /// * `auth_token` – Represents the authority to act as a particular user
    /// and should be valid for the lifetime of the `Client`.
    #[wasm_bindgen(constructor)]
    pub fn new(configuration: Configuration, previous_configurations: ConfigurationArray) -> Self {
        console_error_panic_hook::set_once();
        let sdk = sdk::Client::new(
            sdk::Configuration::from(configuration),
            Array::from(&previous_configurations)
                .iter()
                .map(|value| from_value::<sdk::Configuration>(value).unwrap())
                .collect(),
            WasmAuthTokenManager,
            HttpClient(),
            WasmSleeper,
        );
        Self(sdk)
    }

    /// Stores a new PIN-protected secret on the configured realms.
    ///
    /// # Note
    ///
    /// The provided secret must have a maximum length of 128-bytes.
    ///
    /// Upon failure, a `RegisterError` will be provided.
    pub async fn register(
        &self,
        pin: Vec<u8>,
        secret: Vec<u8>,
        info: Vec<u8>,
        num_guesses: u16,
    ) -> Result<(), RegisterError> {
        self.0
            .register(
                &sdk::Pin::from(pin),
                &sdk::UserSecret::from(secret),
                &sdk::UserInfo::from(info),
                sdk::Policy { num_guesses },
            )
            .await
            .map_err(RegisterError::from)
    }

    /// Retrieves a PIN-protected secret from the configured realms, or falls
    /// back to the previous realms if the current realms do not have a secret
    /// registered.
    ///
    /// Upon failure, a `RecoverError` will be provided.
    pub async fn recover(&self, pin: Vec<u8>, info: Vec<u8>) -> Result<Uint8Array, RecoverError> {
        match self
            .0
            .recover(&sdk::Pin::from(pin), &sdk::UserInfo::from(info))
            .await
        {
            Ok(secret) => Ok(Uint8Array::from(secret.expose_secret())),
            Err(err) => Err(RecoverError::from(err)),
        }
    }

    /// Deletes the registered secret for this user, if any.
    ///
    /// Upon failure, a `DeleteError` will be provided.
    pub async fn delete(&self) -> Result<(), DeleteError> {
        self.0.delete().await.map_err(DeleteError::from)
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

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = "setTimeout", catch)]
    fn set_timeout(handler: &js_sys::Function, timeout: i32) -> Result<JsValue, JsValue>;
}

struct WasmSleeper;

#[async_trait]
impl Sleeper for WasmSleeper {
    async fn sleep(&self, duration: Duration) {
        let (send, recv) = oneshot::channel();
        let ok = {
            // This dance lets us cleanup the closure when we're done with it
            // without explicitly holding it across the recv.await boundary which
            // we can't because its not Send.
            let cb_holder = Arc::new(Mutex::new(None));
            let cb_holder2 = cb_holder.clone();
            let cb = Closure::once(move || {
                let _ref = cb_holder2.clone(); // force a ref to be moved into here.
                _ = send.send(()); // Nothing we can do if this errors at this point.
            });
            let ok = set_timeout(
                cb.as_ref().unchecked_ref(),
                duration.as_millis().try_into().unwrap(),
            )
            .is_ok();
            *cb_holder.lock().unwrap() = Some(cb);
            ok
        };
        if ok {
            _ = recv.await;
        }
    }
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = "JuiceboxGetAuthToken", catch)]
    async fn get_auth_token(realm_id: Uint8Array) -> Result<JsValue, JsValue>;
}

struct WasmAuthTokenManager;

#[async_trait]
impl sdk::AuthTokenManager for WasmAuthTokenManager {
    async fn get(&self, realm: &sdk::RealmId) -> Option<sdk::AuthToken> {
        let (tx, rx) = oneshot::channel();

        {
            let future = get_auth_token(Uint8Array::from(realm.0.as_ref()));

            spawn_local(async move {
                match future.await {
                    Ok(value) => {
                        _ = tx.send(value.as_string().map(sdk::AuthToken::from));
                    }
                    Err(_) => {
                        _ = tx.send(None);
                    }
                }
            });
        }

        rx.await.unwrap()
    }
}

#[cfg(test)]
mod tests {
    use crate::{Client, Configuration, RecoverError, WasmSleeper};
    use instant::Instant;
    use js_sys::{Function, Reflect};
    use juicebox_sdk as sdk;
    use juicebox_sdk_bridge::{DeleteError, RecoverErrorReason, RegisterError};
    use sdk::Sleeper;
    use serde_wasm_bindgen::to_value;
    use wasm_bindgen::JsValue;
    use wasm_bindgen_test::*;

    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    async fn test_register() {
        let client = client("https://httpbin.org/anything/");
        let result = client
            .register(
                Vec::from("1234"),
                Vec::from("apollo"),
                Vec::from("artemis"),
                2,
            )
            .await;
        assert!(
            matches!(result, Err(RegisterError::Assertion)),
            "got {result:?}"
        );
    }

    #[wasm_bindgen_test]
    async fn test_recover() {
        let client = client("https://httpbin.org/anything/");
        let result = client
            .recover(Vec::from("1234"), Vec::from("artemis"))
            .await;
        assert!(
            matches!(
                result,
                Err(RecoverError {
                    reason: RecoverErrorReason::Assertion,
                    guesses_remaining: None
                })
            ),
            "got {result:?}"
        );
    }

    #[wasm_bindgen_test]
    async fn test_sleep() {
        let start = Instant::now();
        WasmSleeper
            .sleep(std::time::Duration::from_millis(100))
            .await;
        let dur = start.elapsed();
        assert!(
            dur >= instant::Duration::from_millis(100),
            "sleep only lasted {dur:?} should of been at least 100ms"
        );
    }

    #[wasm_bindgen_test]
    async fn test_delete() {
        let client = client("https://httpbin.org/anything/");
        let result = client.delete().await;
        assert!(
            matches!(result, Err(DeleteError::Assertion)),
            "got {result:?}"
        );
    }

    fn client(url: &str) -> Client {
        let mock_get_auth_function = Function::new_with_args(
            "realmId",
            "return new Promise(function(resolve, reject) { resolve('abc.123'); });",
        );

        Reflect::set(
            &web_sys::window().unwrap(),
            &JsValue::from("JuiceboxGetAuthToken"),
            &mock_get_auth_function,
        )
        .expect("setting JuiceboxGetAuthToken function failed");

        Client::new(
            Configuration(sdk::Configuration {
                realms: vec![sdk::Realm {
                    id: sdk::RealmId([0; 16]),
                    address: url.parse().unwrap(),
                    public_key: None,
                }],
                register_threshold: 1,
                recover_threshold: 1,
                pin_hashing_mode: sdk::PinHashingMode::FastInsecure,
            }),
            to_value::<Vec<sdk::Configuration>>(&vec![]).unwrap().into(),
        )
    }
}
