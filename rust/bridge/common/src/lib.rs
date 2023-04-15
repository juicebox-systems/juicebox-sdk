use loam_sdk as sdk;

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::{wasm_bindgen, JsValue};

#[cfg(feature = "tokio")]
use tokio::runtime::Runtime;

#[cfg(feature = "tokio")]
pub struct Client<HttpClient: sdk::http::Client> {
    pub sdk: sdk::Client<HttpClient>,
    pub runtime: Runtime,
}

#[cfg(feature = "tokio")]
impl<HttpClient: sdk::http::Client> Client<HttpClient> {
    pub fn new(sdk: sdk::Client<HttpClient>) -> Self {
        Self {
            sdk,
            runtime: Runtime::new().unwrap(),
        }
    }
}

#[repr(C)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub enum RegisterError {
    InvalidAuth = 0,
    Network = 1,
    Protocol = 2,
    Unavailable = 3,
}

impl From<sdk::RegisterError> for RegisterError {
    fn from(value: sdk::RegisterError) -> Self {
        match value {
            sdk::RegisterError::InvalidAuth => Self::InvalidAuth,
            sdk::RegisterError::NetworkError => Self::Network,
            sdk::RegisterError::ProtocolError => Self::Protocol,
        }
    }
}

#[cfg(feature = "wasm")]
impl From<RegisterError> for JsValue {
    fn from(value: RegisterError) -> Self {
        JsValue::from(value as u8)
    }
}

#[repr(C)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub enum RecoverError {
    InvalidAuth = 0,
    Network = 1,
    Unsuccessful = 2,
    Protocol = 3,
}

impl From<sdk::RecoverError> for RecoverError {
    fn from(value: sdk::RecoverError) -> Self {
        match value {
            sdk::RecoverError::InvalidAuth => RecoverError::InvalidAuth,
            sdk::RecoverError::NetworkError => RecoverError::Network,
            sdk::RecoverError::Unsuccessful(_) => RecoverError::Unsuccessful,
            sdk::RecoverError::ProtocolError => RecoverError::Protocol,
        }
    }
}

#[cfg(feature = "wasm")]
impl From<RecoverError> for JsValue {
    fn from(value: RecoverError) -> Self {
        JsValue::from(value as u8)
    }
}

#[repr(C)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub enum DeleteError {
    InvalidAuth = 0,
    Network = 1,
    Protocol = 2,
}

impl From<sdk::DeleteError> for DeleteError {
    fn from(value: sdk::DeleteError) -> Self {
        match value {
            sdk::DeleteError::InvalidAuth => DeleteError::InvalidAuth,
            sdk::DeleteError::NetworkError => DeleteError::Network,
            sdk::DeleteError::ProtocolError => DeleteError::Protocol,
        }
    }
}

#[cfg(feature = "wasm")]
impl From<DeleteError> for JsValue {
    fn from(value: DeleteError) -> Self {
        JsValue::from(value as u8)
    }
}
