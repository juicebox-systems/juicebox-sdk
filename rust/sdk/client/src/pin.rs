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
                [
                    &(salt.expose_secret().len() as u32).to_le_bytes(),
                    salt.expose_secret(),
                    &(info.expose_secret().len() as u32).to_le_bytes(),
                    info.expose_secret(),
                ]
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
            219, 189, 174, 194, 242, 53, 30, 101, 138, 242, 120, 255, 220, 150, 60, 46, 176, 40,
            187, 237, 133, 51, 227, 10, 183, 63, 28, 40, 29, 207, 40, 47,
        ];
        let expected_encryption_key: [u8; 32] = [
            92, 89, 67, 194, 238, 53, 33, 114, 249, 151, 69, 130, 14, 236, 130, 129, 134, 136, 49,
            174, 139, 51, 63, 150, 145, 75, 25, 232, 77, 184, 253, 174,
        ];
        assert_eq!(*access_key.expose_secret(), expected_access_key.to_vec());
        assert_eq!(
            *encryption_key.expose_secret(),
            expected_encryption_key.to_vec()
        );
    }
}
