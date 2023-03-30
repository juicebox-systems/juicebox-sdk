use crate::http;
use crate::rpc::{Rpc, Service};
use loam_sdk_core::marshalling;
use loam_sdk_core::requests::{SecretsRequest, SecretsResponse};
use loam_sdk_core::types::{AuthToken, RealmId};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug)]
pub struct LoadBalancerService();
impl Service for LoadBalancerService {}

impl Rpc<LoadBalancerService> for ClientRequest {
    const PATH: &'static str = "req";
    type Response = ClientResponse;
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClientRequest {
    pub realm: RealmId,
    pub auth_token: AuthToken,
    pub request: SecretsRequest,
}

#[derive(Debug, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum ClientResponse {
    Ok(SecretsResponse),
    Unavailable,
    InvalidAuth,
}

#[derive(Debug)]
pub enum ClientError {
    Network,
    HttpStatus(http::ResponseStatus),
    Serialization(marshalling::SerializationError),
    Deserialization(marshalling::DeserializationError),
    HsmRpcError,
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ClientError::*;
        match self {
            Network => {
                write!(f, "network error")
            }
            HttpStatus(e) => {
                write!(f, "non-OK HTTP status: {e}")
            }
            Serialization(e) => {
                write!(f, "serialization error: {e:?}")
            }
            Deserialization(e) => {
                write!(f, "deserialization error: {e:?}")
            }
            HsmRpcError => {
                write!(f, "HSM RPC error")
            }
        }
    }
}

impl From<marshalling::SerializationError> for ClientError {
    fn from(value: marshalling::SerializationError) -> Self {
        ClientError::Serialization(value)
    }
}

impl From<marshalling::DeserializationError> for ClientError {
    fn from(value: marshalling::DeserializationError) -> Self {
        ClientError::Deserialization(value)
    }
}
