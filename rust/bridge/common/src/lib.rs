use loam_sdk as sdk;
use tokio::runtime::Runtime;

pub struct Client<HttpClient: sdk::http::Client> {
    pub sdk: sdk::Client<HttpClient>,
    pub runtime: Runtime,
}

impl<HttpClient: sdk::http::Client> Client<HttpClient> {
    pub fn new(sdk: sdk::Client<HttpClient>) -> Self {
        Self {
            sdk,
            runtime: Runtime::new().unwrap(),
        }
    }
}

#[repr(C)]
pub enum RegisterError {
    InvalidAuth = 0,
    Network,
    Protocol,
    Unavailable,
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

#[repr(C)]
pub enum RecoverError {
    InvalidAuth = 0,
    Network,
    Unsuccessful,
    Protocol,
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

#[repr(C)]
pub enum DeleteError {
    InvalidAuth = 0,
    Network,
    Protocol,
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
