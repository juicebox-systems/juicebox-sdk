use argon2::{Algorithm, Argon2, ParamsBuilder, Version};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use loam_sdk_core::types::SecretBytes;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
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

#[derive(Debug, Deserialize, Serialize)]
struct Claims {
    iss: String,
    sub: String,
}

impl TryFrom<&AuthToken> for Claims {
    type Error = &'static str;

    fn try_from(value: &AuthToken) -> Result<Self, Self::Error> {
        let (message, _) = value
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
        if salt.len() < 8 {
            salt.resize(8, 0);
        }
        Ok(Salt(salt))
    }
}

#[derive(Debug)]
/// A user-chosen password that may be low in entropy.
pub struct Pin(pub SecretBytes);

impl Pin {
    pub fn expose_secret(&self) -> &[u8] {
        self.0.expose_secret()
    }
}

impl From<Vec<u8>> for Pin {
    fn from(value: Vec<u8>) -> Self {
        Self(SecretBytes::from(value))
    }
}

#[derive(Debug)]
/// The calculated hash of a user-chosen password.
pub struct HashedPin(pub SecretBytes);

impl HashedPin {
    pub fn expose_secret(&self) -> &[u8] {
        self.0.expose_secret()
    }
}

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
            .hash_password_into(self.expose_secret(), &salt.0, &mut hashed_pin)
            .ok()?;
        Some(HashedPin::from(hashed_pin))
    }
}

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use loam_sdk_core::types::AuthToken;

    use crate::pin::{Claims, Pin, PinHashingMode, Salt};

    fn auth_token(claims: Claims) -> AuthToken {
        let claims_json = serde_json::to_string(&claims).unwrap();
        let b64_encoded_json = URL_SAFE_NO_PAD.encode(claims_json);
        AuthToken::from(format!("fake-header.{}.fake-signature", b64_encoded_json))
    }

    #[test]
    fn test_salt() {
        let auth_token = auth_token(Claims {
            iss: "tenant".to_string(),
            sub: "user".to_string(),
        });
        let salt = Salt::try_from(&auth_token).unwrap();
        assert_eq!(salt.0, b"user|tenant".to_vec());
    }

    #[test]
    fn test_salt_padding() {
        let auth_token = auth_token(Claims {
            iss: "t".to_string(),
            sub: "u".to_string(),
        });
        let salt = Salt::try_from(&auth_token).unwrap();
        let mut expected_salt = b"u|t".to_vec();
        expected_salt.push(0);
        expected_salt.push(0);
        expected_salt.push(0);
        expected_salt.push(0);
        expected_salt.push(0);
        assert_eq!(salt.0, expected_salt);
    }

    #[test]
    fn test_pin_hashing() {
        let auth_token = auth_token(Claims {
            iss: "tenant".to_string(),
            sub: "user".to_string(),
        });
        let pin = Pin::from(b"1234".to_vec());
        let hashed_pin = pin
            .hash(&PinHashingMode::Standard2019, &auth_token)
            .unwrap();
        let expected_hash: [u8; 64] = [
            174, 157, 21, 209, 154, 164, 208, 132, 117, 13, 235, 232, 136, 230, 142, 35, 123, 163,
            122, 118, 30, 101, 88, 19, 238, 219, 121, 188, 48, 31, 33, 146, 31, 8, 146, 109, 49,
            41, 213, 151, 95, 135, 224, 243, 231, 68, 46, 202, 71, 175, 147, 97, 83, 69, 147, 210,
            63, 68, 213, 127, 180, 64, 78, 184,
        ];
        assert_eq!(*hashed_pin.expose_secret(), expected_hash.to_vec());
    }

    #[test]
    fn test_no_hashing() {
        let auth_token = auth_token(Claims {
            iss: "tenant".to_string(),
            sub: "user".to_string(),
        });
        let pin = Pin::from(b"1234".to_vec());
        let hashed_pin = pin.hash(&PinHashingMode::None, &auth_token).unwrap();
        assert_eq!(*hashed_pin.expose_secret(), *pin.expose_secret());
    }
}
