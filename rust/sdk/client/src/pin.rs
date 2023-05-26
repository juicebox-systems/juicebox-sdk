use std::str::FromStr;

use crate::types::{UserSecretAccessKey, UserSecretEncryptionKey};
use argon2::{Algorithm, Argon2, Params, ParamsBuilder, Version};
use juicebox_sdk_core::types::{Salt, SecretBytesVec};
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

impl FromStr for PinHashingMode {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Standard2019" => Ok(Self::Standard2019),
            "FastInsecure" => Ok(Self::FastInsecure),
            _ => Err("unexpected value"),
        }
    }
}

impl ToString for PinHashingMode {
    fn to_string(&self) -> String {
        match self {
            Self::Standard2019 => "Standard2019".to_owned(),
            Self::FastInsecure => "FastInsecure".to_owned(),
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
    use juicebox_sdk_core::types::Salt;

    #[test]
    fn test_pin_hashing() {
        let salt = Salt::from([5; 16]);
        let pin = Pin::from(b"1234".to_vec());
        let (access_key, encryption_key) = pin.hash(PinHashingMode::Standard2019, &salt).unwrap();
        let expected_access_key: [u8; 32] = [
            250, 122, 193, 108, 118, 82, 58, 127, 80, 184, 73, 2, 230, 142, 48, 164, 97, 0, 162,
            119, 27, 95, 248, 237, 86, 240, 196, 193, 182, 35, 230, 61,
        ];
        let expected_encryption_key: [u8; 32] = [
            130, 251, 98, 220, 131, 58, 101, 94, 114, 250, 200, 58, 77, 123, 38, 170, 36, 224, 90,
            92, 252, 95, 186, 106, 101, 91, 147, 161, 4, 175, 91, 40,
        ];
        assert_eq!(*access_key.expose_secret(), expected_access_key.to_vec());
        assert_eq!(
            *encryption_key.expose_secret(),
            expected_encryption_key.to_vec()
        );
    }
}
