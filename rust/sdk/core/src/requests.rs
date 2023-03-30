use serde::{Deserialize, Serialize};

use crate::types::{
    AuthToken, GenerationNumber, MaskedTgkShare, OprfBlindedInput, OprfBlindedResult, Policy,
    RealmId, UnlockTag, UserSecretShare,
};

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
