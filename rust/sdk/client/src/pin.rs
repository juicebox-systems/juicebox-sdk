use crate::types::{UserSecretAccessKey, UserSecretEncryptionKey};
use argon2::{Algorithm, Argon2, Params, ParamsBuilder, Version};
use loam_sdk_core::types::{Salt, SecretBytesVec};
use secrecy::{ExposeSecret, Zeroize};
use serde_repr::{Deserialize_repr, Serialize_repr};

/// A strategy for hashing the user provided [`Pin`]
#[derive(Copy, Clone, Debug, Deserialize_repr, Eq, PartialEq, Serialize_repr)]
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
pub struct Pin(SecretBytesVec);

impl Pin {
    /// Access the underlying secret bytes.
    pub fn expose_secret(&self) -> &[u8] {
        self.0.expose_secret()
    }
}

impl From<Vec<u8>> for Pin {
    fn from(value: Vec<u8>) -> Self {
        Self(SecretBytesVec::from(value))
    }
}

impl Pin {
    pub(crate) fn hash(
        &self,
        mode: PinHashingMode,
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
            UserSecretAccessKey::try_from(hashed_pin[..32].to_vec()).unwrap(),
            UserSecretEncryptionKey::try_from(hashed_pin[32..].to_vec()).unwrap(),
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
        let salt = Salt::from([5; 32]);
        let pin = Pin::from(b"1234".to_vec());
        let (access_key, encryption_key) = pin.hash(PinHashingMode::Standard2019, &salt).unwrap();
        let expected_access_key: [u8; 32] = [
            45, 200, 138, 25, 91, 126, 44, 32, 38, 38, 95, 185, 234, 240, 137, 173, 29, 248, 232,
            128, 244, 100, 58, 153, 80, 223, 244, 132, 65, 180, 64, 158,
        ];
        let expected_encryption_key: [u8; 32] = [
            244, 174, 18, 34, 213, 125, 130, 107, 42, 124, 149, 36, 197, 138, 48, 133, 114, 180,
            133, 167, 244, 153, 79, 127, 237, 14, 128, 79, 86, 47, 120, 118,
        ];
        assert_eq!(*access_key.expose_secret(), expected_access_key.to_vec());
        assert_eq!(
            *encryption_key.expose_secret(),
            expected_encryption_key.to_vec()
        );
    }
}
