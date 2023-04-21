use argon2::{Algorithm, Argon2, ParamsBuilder, Version};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};

use crate::AuthToken;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum PinHashingMode {
    /// No hashing, ensure a PIN of sufficient entropy is provided.
    None,
    /// A tuned hash, secure for use on modern devices as of 2019 with low-entropy PINs.
    Standard2019,
    /// A fast hash used for testing. Do not use in production.
    FastInsecure,
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
        salt.extend_from_slice(&claims.iss.into_bytes());

        // pad out to min 8 bytes
        while salt.len() < 8 {
            salt.push(0);
        }

        Ok(Salt(salt))
    }
}

/// A user-chosen password that may be low in entropy.
#[derive(Clone)]
pub struct Pin(pub Vec<u8>);

impl std::fmt::Debug for Pin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("(redacted)")
    }
}

impl Pin {
    pub fn hash(&self, mode: &PinHashingMode, auth_token: &AuthToken) -> Option<Vec<u8>> {
        match mode {
            PinHashingMode::None => Some(self.0.clone()),
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

    fn argon2(&self, params: argon2::Params, auth_token: &AuthToken) -> Option<Vec<u8>> {
        let context = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let salt = Salt::try_from(auth_token).ok()?;
        let mut hashed_pin = [0u8; 64];
        context
            .hash_password_into(&self.0, &salt.0, &mut hashed_pin)
            .ok()?;
        Some(hashed_pin.to_vec())
    }
}
