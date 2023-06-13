use crate::{
    types::{UserSecretAccessKey, UserSecretEncryptionKey},
    UserInfo,
};
use argon2::{Algorithm, Argon2, Params, ParamsBuilder, Version};
use juicebox_sdk_core::types::{Salt, SecretBytesVec};
use secrecy::{ExposeSecret, Zeroize};
use serde::{Deserialize, Serialize};

/// A strategy for hashing the user provided [`Pin`]
#[derive(Copy, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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
        info: &UserInfo,
    ) -> Option<(UserSecretAccessKey, UserSecretEncryptionKey)> {
        match mode {
            PinHashingMode::Standard2019 => {
                let params = ParamsBuilder::new()
                    .m_cost(1024 * 16)
                    .t_cost(32)
                    .p_cost(1)
                    .build()
                    .ok()?;
                self.argon2(params, salt, info)
            }
            PinHashingMode::FastInsecure => {
                let params = ParamsBuilder::new()
                    .m_cost(Params::MIN_M_COST)
                    .t_cost(Params::MIN_T_COST)
                    .p_cost(Params::MIN_P_COST)
                    .build()
                    .ok()?;
                self.argon2(params, salt, info)
            }
        }
    }

    fn argon2(
        &self,
        params: argon2::Params,
        salt: &Salt,
        info: &UserInfo,
    ) -> Option<(UserSecretAccessKey, UserSecretEncryptionKey)> {
        let mut hashed_pin = vec![0u8; 64];

        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(
                self.expose_secret(),
                [salt.expose_secret(), info.expose_secret()]
                    .concat()
                    .as_slice(),
                &mut hashed_pin,
            )
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
    use crate::{
        pin::{Pin, PinHashingMode},
        UserInfo,
    };
    use juicebox_sdk_core::types::Salt;

    #[test]
    fn test_pin_hashing() {
        let salt = Salt::from([5; 16]);
        let pin = Pin::from(b"1234".to_vec());
        let info = UserInfo::from(b"artemis".to_vec());
        let (access_key, encryption_key) = pin
            .hash(PinHashingMode::Standard2019, &salt, &info)
            .unwrap();
        let expected_access_key: [u8; 32] = [
            92, 165, 41, 92, 46, 155, 98, 107, 169, 38, 32, 51, 142, 47, 160, 234, 42, 206, 254,
            17, 136, 238, 137, 133, 137, 48, 129, 218, 206, 167, 164, 188,
        ];
        let expected_encryption_key: [u8; 32] = [
            235, 70, 249, 19, 37, 95, 102, 137, 152, 169, 242, 91, 241, 216, 191, 38, 92, 51, 86,
            63, 101, 33, 79, 27, 171, 251, 176, 63, 182, 14, 186, 20,
        ];
        assert_eq!(*access_key.expose_secret(), expected_access_key.to_vec());
        assert_eq!(
            *encryption_key.expose_secret(),
            expected_encryption_key.to_vec()
        );
    }
}
