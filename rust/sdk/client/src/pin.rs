use crate::types::{UserSecretAccessKey, UserSecretEncryptionKey};
use argon2::{Algorithm, Argon2, Params, ParamsBuilder, Version};
use loam_sdk_core::types::{Salt, SecretBytes};
use secrecy::{ExposeSecret, Zeroize};
use serde_repr::{Deserialize_repr, Serialize_repr};

/// A strategy for hashing the user provided [`Pin`]
#[derive(Clone, Debug, Deserialize_repr, Serialize_repr)]
#[repr(u8)]
pub enum PinHashingMode {
    /// A tuned hash, secure for use on modern devices as of 2019 with low-entropy PINs.
    Standard2019,
    /// A fast hash used for testing. Do not use in production.
    FastInsecure,
}

impl From<u8> for PinHashingMode {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Standard2019,
            1 => Self::FastInsecure,
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

impl Pin {
    pub(crate) fn hash(
        &self,
        mode: &PinHashingMode,
        salt: &Salt,
    ) -> Option<(UserSecretAccessKey, UserSecretEncryptionKey)> {
        match mode {
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
                    .m_cost(Params::MIN_M_COST)
                    .t_cost(Params::MIN_T_COST)
                    .p_cost(Params::MIN_P_COST)
                    .build()
                    .ok()?;
                self.argon2(params, salt)
            }
        }
    }

    fn argon2(
        &self,
        params: argon2::Params,
        salt: &Salt,
    ) -> Option<(UserSecretAccessKey, UserSecretEncryptionKey)> {
        let mut hashed_pin = vec![0u8; 64];

        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(self.expose_secret(), salt.expose_secret(), &mut hashed_pin)
            .ok()?;

        let derived_keys = (
            UserSecretAccessKey::from(hashed_pin[..32].to_vec()),
            UserSecretEncryptionKey::from(hashed_pin[32..].to_vec()),
        );

        hashed_pin.zeroize();

        Some(derived_keys)
    }
}

#[cfg(test)]
mod tests {
    use crate::pin::{Pin, PinHashingMode};
    use loam_sdk_core::types::Salt;

    #[test]
    fn test_pin_hashing() {
        let salt = Salt::from(b"user|tenant".to_vec());
        let pin = Pin::from(b"1234".to_vec());
        let (access_key, encryption_key) = pin.hash(&PinHashingMode::Standard2019, &salt).unwrap();
        let expected_access_key: [u8; 32] = [
            174, 157, 21, 209, 154, 164, 208, 132, 117, 13, 235, 232, 136, 230, 142, 35, 123, 163,
            122, 118, 30, 101, 88, 19, 238, 219, 121, 188, 48, 31, 33, 146,
        ];
        let expected_encryption_key: [u8; 32] = [
            31, 8, 146, 109, 49, 41, 213, 151, 95, 135, 224, 243, 231, 68, 46, 202, 71, 175, 147,
            97, 83, 69, 147, 210, 63, 68, 213, 127, 180, 64, 78, 184,
        ];
        assert_eq!(*access_key.expose_secret(), expected_access_key.to_vec());
        assert_eq!(
            *encryption_key.expose_secret(),
            expected_encryption_key.to_vec()
        );
    }
}
