use serde::{Deserialize, Serialize};

use crate::marshalling;
use crate::rpc::{Rpc, Service};
use crate::types::{
    AuthToken, GenerationNumber, MaskedTgkShare, OprfBlindedInput, OprfBlindedResult, Policy,
    RealmId, UnlockTag, UserSecretShare,
};

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
    InvalidUrl,
    Network,
    HttpStatus(HttpResponseStatus),
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
            InvalidUrl => {
                write!(f, "invalid url")
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

#[derive(Copy, Clone, Debug)]
pub struct HttpResponseStatus {
    pub status: u16,
}

impl std::fmt::Display for HttpResponseStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "(code: {})", self.status)
    }
}

impl From<u16> for HttpResponseStatus {
    fn from(status: u16) -> Self {
        Self { status }
    }
}

impl HttpResponseStatus {
    pub fn response_type(self) -> HttpResponseStatusType {
        HttpResponseStatusType::from_status(self.status)
    }

    pub fn is_success(self) -> bool {
        self.response_type().is_success()
    }

    pub fn is_error(self) -> bool {
        self.response_type().is_error()
    }
}

#[derive(Copy, Clone, Debug)]
pub enum HttpResponseStatusType {
    Unknown = 0,
    Informational = 100,
    Success = 200,
    Redirection = 300,
    ClientError = 400,
    ServerError = 500,
}

impl HttpResponseStatusType {
    pub fn from_status(status: u16) -> Self {
        match status {
            100..=199 => Self::Informational,
            200..=299 => Self::Success,
            300..=399 => Self::Redirection,
            400..=499 => Self::ClientError,
            500..=599 => Self::ServerError,
            _ => Self::Unknown,
        }
    }

    pub fn is_success(self) -> bool {
        matches!(self, Self::Success)
    }

    pub fn is_error(self) -> bool {
        matches!(self, Self::ClientError | Self::ServerError)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum SecretsRequest {
    Register1(Register1Request),
    Register2(Register2Request),
    Recover1(Recover1Request),
    Recover2(Recover2Request),
    Delete(DeleteRequest),
}

#[derive(Debug, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum SecretsResponse {
    Register1(Register1Response),
    Register2(Register2Response),
    Recover1(Recover1Response),
    Recover2(Recover2Response),
    Delete(DeleteResponse),
}

/// Request message for the first phase of registration.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Register1Request {
    pub generation: GenerationNumber,
    pub blinded_pin: OprfBlindedInput,
}

/// Response message for the first phase of registration.
#[derive(Debug, Deserialize, Serialize)]
pub enum Register1Response {
    Ok { blinded_oprf_pin: OprfBlindedResult },
    BadGeneration { first_available: GenerationNumber },
}

/// Request message for the second phase of registration.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Register2Request {
    pub generation: GenerationNumber,
    pub masked_tgk_share: MaskedTgkShare,
    pub tag: UnlockTag,
    pub secret_share: UserSecretShare,
    pub policy: Policy,
}

/// Response message for the second phase of registration.
#[derive(Debug, Deserialize, Serialize)]
pub enum Register2Response {
    Ok { found_earlier_generations: bool },
    NotRegistering,
    AlreadyRegistered,
}

/// Request message for the first phase of recovery.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Recover1Request {
    /// Which generation to recover. If the generation number is not provided, the
    /// server will start recovery with the latest generation.
    pub generation: Option<GenerationNumber>,
    pub blinded_pin: OprfBlindedInput,
}

/// Response message for the first phase of recovery.
#[derive(Debug, Deserialize, Serialize)]
pub enum Recover1Response {
    Ok {
        generation: GenerationNumber,
        blinded_oprf_pin: OprfBlindedResult,
        masked_tgk_share: MaskedTgkShare,
        /// The largest-numbered generation record on the server that's older
        /// than `generation`, if any. This allows the client to discover older
        /// generations to clean up or try recovering.
        previous_generation: Option<GenerationNumber>,
    },
    NotRegistered {
        generation: Option<GenerationNumber>,
        previous_generation: Option<GenerationNumber>,
    },
    PartiallyRegistered {
        generation: GenerationNumber,
        previous_generation: Option<GenerationNumber>,
    },
    NoGuesses {
        generation: GenerationNumber,
        previous_generation: Option<GenerationNumber>,
    },
}

/// Request message for the second phase of recovery.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Recover2Request {
    pub generation: GenerationNumber,
    pub tag: UnlockTag,
}

/// Response message for the second phase of recovery.
#[derive(Debug, Deserialize, Serialize)]
pub enum Recover2Response {
    Ok(UserSecretShare),
    NotRegistered,
    BadUnlockTag,
}

/// Request message to delete registered secrets.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeleteRequest {
    /// If `Some`, the server deletes generations from 0 up to and excluding
    /// this number. If `None`, the server deletes all generations.
    pub up_to: Option<GenerationNumber>,
}

/// Response message to delete registered secrets.
#[derive(Debug, Deserialize, Serialize)]
pub enum DeleteResponse {
    Ok,
}
