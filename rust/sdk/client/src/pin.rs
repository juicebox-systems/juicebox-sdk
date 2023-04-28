use argon2::{Algorithm, Argon2, ParamsBuilder, Version};
use loam_sdk_core::types::{Salt, SecretBytes};
use secrecy::ExposeSecret;
use serde_repr::{Deserialize_repr, Serialize_repr};

/// A strategy for hashing the user provided [`Pin`]
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

#[derive(Debug)]
/// A user-chosen password that may be low in entropy.
pub struct Pin(SecretBytes);

impl Pin {
    /// Access the underlying secret bytes.
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
pub(crate) struct HashedPin(SecretBytes);

impl HashedPin {
    /// Access the underlying secret bytes.
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
    pub(crate) fn hash(&self, mode: &PinHashingMode, salt: &Salt) -> Option<HashedPin> {
        match mode {
            PinHashingMode::None => Some(HashedPin(self.0.clone())),
            PinHashingMode::Standard2019 => {
                let params = ParamsBuilder::new()
                    .m_cost(1024 * 16)
                    .t_cost(32)
                    .p_cost(1)
                    .build()
                    .ok()?;
                self.argon2(params, salt)
            }
            PinHashingMode::FastInsecure => {
                let params = ParamsBuilder::new()
                    .m_cost(128)
                    .t_cost(1)
                    .p_cost(1)
                    .build()
                    .ok()?;
                self.argon2(params, salt)
            }
        }
    }

    fn argon2(&self, params: argon2::Params, salt: &Salt) -> Option<HashedPin> {
        let context = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut hashed_pin = vec![0u8; 64];
        context
            .hash_password_into(self.expose_secret(), salt.expose_secret(), &mut hashed_pin)
            .ok()?;
        Some(HashedPin::from(hashed_pin))
    }
}

#[cfg(test)]
mod tests {
    use loam_sdk_core::types::Salt;

    use crate::pin::{Pin, PinHashingMode};

    #[test]
    fn test_pin_hashing() {
        let salt = Salt::from(b"user|tenant".to_vec());
        let pin = Pin::from(b"1234".to_vec());
        let hashed_pin = pin.hash(&PinHashingMode::Standard2019, &salt).unwrap();
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
        let salt = Salt::new_random();
        let pin = Pin::from(b"1234".to_vec());
        let hashed_pin = pin.hash(&PinHashingMode::None, &salt).unwrap();
        assert_eq!(*hashed_pin.expose_secret(), *pin.expose_secret());
    }
}
