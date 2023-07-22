extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;
use core::time::Duration;
use serde::{Deserialize, Serialize};

use crate::oprf::{OprfBlindedInput, OprfBlindedResult, OprfKey};
use crate::types::{
    AuthToken, EncryptedUserSecret, EncryptedUserSecretCommitment, Policy, RealmId,
    RegistrationVersion, SessionId, UnlockKeyCommitment, UnlockKeyTag,
    UserSecretEncryptionKeyScalarShare,
};
use juicebox_sdk_marshalling::bytes;
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
    Handshake {
        handshake: noise::HandshakeRequest,
    },
    Transport {
        #[serde(with = "bytes")]
        ciphertext: Vec<u8>,
    },
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
        #[serde(with = "bytes")]
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
    pub oprf_key: OprfKey,
    pub unlock_key_commitment: UnlockKeyCommitment,
    pub unlock_key_tag: UnlockKeyTag,
    pub user_secret_encryption_key_scalar_share: UserSecretEncryptionKeyScalarShare,
    pub encrypted_user_secret: EncryptedUserSecret,
    pub encrypted_user_secret_commitment: EncryptedUserSecretCommitment,
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
    Ok { version: RegistrationVersion },
    NotRegistered,
    NoGuesses,
}

/// Request message for the second phase of recovery.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Recover2Request {
    pub version: RegistrationVersion,
    pub oprf_blinded_input: OprfBlindedInput,
}

/// Response message for the second phase of recovery.
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Recover2Response {
    Ok {
        oprf_blinded_result: OprfBlindedResult,
        unlock_key_commitment: UnlockKeyCommitment,
        guesses_remaining: u16,
    },
    VersionMismatch,
    NotRegistered,
    NoGuesses,
}

/// Request message for the third phase of recovery.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Recover3Request {
    pub version: RegistrationVersion,
    pub unlock_key_tag: UnlockKeyTag,
}

/// Response message for the third phase of recovery.
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Recover3Response {
    Ok {
        user_secret_encryption_key_scalar_share: UserSecretEncryptionKeyScalarShare,
        encrypted_user_secret: EncryptedUserSecret,
        encrypted_user_secret_commitment: EncryptedUserSecretCommitment,
    },
    VersionMismatch,
    NotRegistered,
    BadUnlockKeyTag {
        guesses_remaining: u16,
    },
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
        oprf::OprfKey,
        requests::{Register2Request, SecretsRequest, BODY_SIZE_LIMIT},
        types::{
            EncryptedUserSecret, EncryptedUserSecretCommitment, Policy, RegistrationVersion,
            UnlockKeyCommitment, UnlockKeyTag, UserSecretEncryptionKeyScalarShare,
        },
    };
    use curve25519_dalek::Scalar;
    use juicebox_sdk_marshalling as marshalling;

    #[test]
    fn test_request_body_size_limit() {
        let secrets_request = SecretsRequest::Register2(Box::new(Register2Request {
            version: RegistrationVersion::from([0xff; 16]),
            oprf_key: OprfKey::from([0x5; 32]),
            unlock_key_commitment: UnlockKeyCommitment::from([0xff; 32]),
            unlock_key_tag: UnlockKeyTag::from([0xff; 16]),
            user_secret_encryption_key_scalar_share: UserSecretEncryptionKeyScalarShare::from(
                Scalar::ONE,
            ),
            encrypted_user_secret: EncryptedUserSecret::from([0xff; 145]),
            encrypted_user_secret_commitment: EncryptedUserSecretCommitment::from([0xff; 16]),
            policy: Policy {
                num_guesses: u16::MAX,
            },
        }));
        let serialized = marshalling::to_vec(&secrets_request).unwrap();
        assert!(serialized.len() < BODY_SIZE_LIMIT);
    }
}
