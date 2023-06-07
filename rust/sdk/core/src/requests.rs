extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;
use core::time::Duration;
use serde::{Deserialize, Serialize};

use crate::types::{
    AuthToken, MaskedTgkShare, OprfBlindedInput, OprfBlindedResult, OprfSeed, Policy, RealmId,
    RegistrationVersion, SaltShare, SessionId, UnlockTag, UserSecretShare,
};
use juicebox_sdk_noise as noise;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClientRequest {
    pub realm: RealmId,
    pub auth_token: AuthToken,
    pub session_id: SessionId,
    pub kind: ClientRequestKind,
    pub encrypted: NoiseRequest,
}

/// Used in [`ClientRequest`].
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ClientRequestKind {
    /// The [`ClientRequest`] contains just a Noise handshake request, without
    /// a [`SecretsRequest`]. The server does not need to access the user's
    /// record to process this.
    HandshakeOnly,
    /// The [`ClientRequest`] contains a Noise handshake or transport request
    /// with an encrypted [`SecretsRequest`]. The server will need to access
    /// the user's record to process this.
    SecretsRequest,
}

#[derive(Debug, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum ClientResponse {
    Ok(NoiseResponse),
    /// The appropriate server to handle the request is not currently
    /// available.
    Unavailable,
    /// The request's auth token is not acceptable.
    InvalidAuth,
    /// The server could not find the Noise session state referenced by the
    /// request's session ID. This can occur in normal circumstances when a
    /// server restarts or has expired the session. The client should open a
    /// new session.
    MissingSession,
    /// The server could not decrypt the encapsulated Noise request.
    SessionError,
    // The server could not deserialize the [`ClientRequest`] or the
    // encapsulated [`SecretsRequest`].
    DecodingError,
    /// The payload sent to the server was too large to be processed.
    PayloadTooLarge,
}

/// A Noise protocol handshake or transport message.
#[derive(Clone, Deserialize, Serialize)]
pub enum NoiseRequest {
    Handshake { handshake: noise::HandshakeRequest },
    Transport { ciphertext: Vec<u8> },
}

impl fmt::Debug for NoiseRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Handshake { .. } => f
                .debug_struct("NoiseRequest::Handshake")
                .finish_non_exhaustive(),
            Self::Transport { .. } => f
                .debug_struct("NoiseRequest::Transport")
                .finish_non_exhaustive(),
        }
    }
}

#[derive(Deserialize, Serialize)]
pub enum NoiseResponse {
    Handshake {
        handshake: noise::HandshakeResponse,
        /// Once the session becomes inactive for this long, the client should
        /// discard the session.
        session_lifetime: Duration,
    },
    Transport {
        ciphertext: Vec<u8>,
    },
}

impl fmt::Debug for NoiseResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Handshake {
                session_lifetime, ..
            } => f
                .debug_struct("NoiseResponse::Handshake")
                .field("session_lifetime", &session_lifetime)
                .finish_non_exhaustive(),
            Self::Transport { .. } => f
                .debug_struct("NoiseResponse::Transport")
                .finish_non_exhaustive(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum SecretsRequest {
    Register1,
    Register2(Box<Register2Request>),
    Recover1,
    Recover2(Recover2Request),
    Recover3(Recover3Request),
    Delete,
}

impl SecretsRequest {
    /// Returns whether the request type requires forward secrecy.
    ///
    /// This controls whether the request may be sent as part of a Noise NK
    /// handshake request, which does not provide forward secrecy.
    ///
    /// For more sensitive request types, this returns true, requiring an
    /// established Noise session before the request can be sent. Decrypting
    /// these requests would require both the server/realm's static secret key
    /// and the ephemeral key used only for this session.
    ///
    /// For less sensitive request types, this returns false, indicating that
    /// they can be piggy-backed with the Noise NK handshake request.
    /// Decrypting these requests would be possible with just the
    /// server/realm's static secret key (even any time in the future).
    pub fn needs_forward_secrecy(&self) -> bool {
        match self {
            Self::Register1 => false,
            Self::Register2(_) => true,
            Self::Recover1 => false,
            Self::Recover2(_) => true,
            Self::Recover3(_) => true,
            Self::Delete => false,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum SecretsResponse {
    Register1(Register1Response),
    Register2(Register2Response),
    Recover1(Recover1Response),
    Recover2(Recover2Response),
    Recover3(Recover3Response),
    Delete(DeleteResponse),
}

/// Response message for the first phase of registration.
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Register1Response {
    Ok,
}

/// Request message for the second phase of registration.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Register2Request {
    pub version: RegistrationVersion,
    pub salt_share: SaltShare,
    pub oprf_seed: OprfSeed,
    pub tag: UnlockTag,
    pub masked_tgk_share: MaskedTgkShare,
    pub secret_share: UserSecretShare,
    pub policy: Policy,
}

/// Response message for the second phase of registration.
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Register2Response {
    Ok,
}

/// Response message for the first phase of recovery.
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Recover1Response {
    Ok {
        version: RegistrationVersion,
        salt_share: SaltShare,
    },
    NotRegistered,
    NoGuesses,
}

/// Request message for the second phase of recovery.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Recover2Request {
    pub version: RegistrationVersion,
    pub blinded_oprf_input: OprfBlindedInput,
}

/// Response message for the second phase of recovery.
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Recover2Response {
    Ok {
        blinded_oprf_result: OprfBlindedResult,
        masked_tgk_share: MaskedTgkShare,
    },
    VersionMismatch,
    NotRegistered,
    NoGuesses,
}

/// Request message for the third phase of recovery.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Recover3Request {
    pub version: RegistrationVersion,
    pub tag: UnlockTag,
}

/// Response message for the third phase of recovery.
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Recover3Response {
    Ok { secret_share: UserSecretShare },
    VersionMismatch,
    NotRegistered,
    BadUnlockTag { guesses_remaining: u16 },
    NoGuesses,
}

/// Response message to delete registered secrets.
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum DeleteResponse {
    Ok,
}

/// The maximum expected request size from the SDK
pub const BODY_SIZE_LIMIT: usize = 2048;

#[cfg(test)]
mod tests {
    use crate::{
        marshalling,
        requests::{Register2Request, SecretsRequest, BODY_SIZE_LIMIT},
        types::{
            MaskedTgkShare, OprfSeed, Policy, RegistrationVersion, SaltShare, UnlockTag,
            UserSecretShare,
        },
    };

    #[test]
    fn test_request_body_size_limit() {
        let secrets_request = SecretsRequest::Register2(Box::new(Register2Request {
            version: RegistrationVersion::from([0xff; 16]),
            salt_share: SaltShare::from([0xff; 17]),
            oprf_seed: OprfSeed::from([0xff; 32]),
            tag: UnlockTag::from([0xff; 32]),
            masked_tgk_share: MaskedTgkShare::try_from(vec![0xff; 33]).unwrap(),
            secret_share: UserSecretShare::try_from(vec![0xff; 146]).unwrap(),
            policy: Policy {
                num_guesses: u16::MAX,
            },
        }));
        let serialized = marshalling::to_vec(&secrets_request).unwrap();
        assert!(serialized.len() < BODY_SIZE_LIMIT);
    }
}
