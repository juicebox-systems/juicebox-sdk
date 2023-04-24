use argon2::{Algorithm, Argon2, ParamsBuilder, Version};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use loam_sdk_core::types::SecretBytes;
use secrecy::ExposeSecret;
use serde::Deserialize;
use serde_repr::{Deserialize_repr, Serialize_repr};

use crate::AuthToken;

#[derive(Clone, Debug, Deserialize_repr, Serialize_repr)]
#[repr(u8)]
pub enum PinHashingMode {
    /// No hashing, ensure a PIN of sufficient entropy is provided.
    None = 0,
    /// A tuned hash, secure for use on modern devices as of 2019 with low-entropy PINs.
    Standard2019,
    /// A fast hash used for testing. Do not use in production.
    FastInsecure,
}

impl From<u8> for PinHashingMode {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::None,
            1 => Self::Standard2019,
            2 => Self::FastInsecure,
            _ => panic!("unexected value {:?}", value),
        }
    }
}

#[derive(Debug, Deserialize)]
struct Claims {
    iss: String,
    sub: String,
}

impl TryFrom<&AuthToken> for Claims {
    type Error = &'static str;

    fn try_from(value: &AuthToken) -> Result<Self, Self::Error> {
        let (message, _) = value
            .0
            .expose_secret()
            .rsplit_once('.')
            .ok_or("Failed to split auth_token into signature and message")?;
        let (_, payload) = message
            .rsplit_once('.')
            .ok_or("Failed to split auth_token message into payload and header")?;
        let b64_decoded_payload = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| "Failed to base64 decode auth_token payload")?;
        serde_json::from_slice(&b64_decoded_payload)
            .map_err(|_| "Failed to json decode auth_token payload")
    }
}

struct Salt(Vec<u8>);

impl TryFrom<&AuthToken> for Salt {
    type Error = &'static str;

    fn try_from(value: &AuthToken) -> Result<Self, Self::Error> {
        let claims = Claims::try_from(value)?;
        let mut salt = claims.sub.into_bytes();
        salt.extend_from_slice(b"|");
        salt.extend_from_slice(&claims.iss.into_bytes());
        salt.resize(8, 0);
        Ok(Salt(salt))
    }
}

#[derive(Debug)]
/// A user-chosen password that may be low in entropy.
pub struct Pin(pub SecretBytes);

impl From<Vec<u8>> for Pin {
    fn from(value: Vec<u8>) -> Self {
        Self(SecretBytes::from(value))
    }
}

#[derive(Debug)]
/// The calculated hash of a user-chosen password.
pub struct HashedPin(pub SecretBytes);

impl From<Vec<u8>> for HashedPin {
    fn from(value: Vec<u8>) -> Self {
        Self(SecretBytes::from(value))
    }
}

impl Pin {
    pub fn hash(&self, mode: &PinHashingMode, auth_token: &AuthToken) -> Option<HashedPin> {
        match mode {
            PinHashingMode::None => Some(HashedPin(self.0.clone())),
            PinHashingMode::Standard2019 => {
                let params = ParamsBuilder::new()
                    .m_cost(1024 * 16)
                    .t_cost(32)
                    .p_cost(1)
                    .build()
                    .ok()?;
                self.argon2(params, auth_token)
            }
            PinHashingMode::FastInsecure => {
                let params = ParamsBuilder::new()
                    .m_cost(128)
                    .t_cost(1)
                    .p_cost(1)
                    .build()
                    .ok()?;
                self.argon2(params, auth_token)
            }
        }
    }

    fn argon2(&self, params: argon2::Params, auth_token: &AuthToken) -> Option<HashedPin> {
        let context = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let salt = Salt::try_from(auth_token).ok()?;
        let mut hashed_pin = vec![0u8; 64];
        context
            .hash_password_into(self.0.expose_secret(), &salt.0, &mut hashed_pin)
            .ok()?;
        Some(HashedPin::from(hashed_pin))
    }
}
