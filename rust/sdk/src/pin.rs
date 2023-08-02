use crate::{types::UserSecretEncryptionKeySeed, UserInfo};
use argon2::{Algorithm, Argon2, Params, ParamsBuilder, Version};
use juicebox_marshalling::to_be4;
use juicebox_realm_api::types::{RegistrationVersion, SecretBytesVec, UserSecretAccessKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

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
        version: &RegistrationVersion,
        info: &UserInfo,
    ) -> Option<(UserSecretAccessKey, UserSecretEncryptionKeySeed)> {
        match mode {
            PinHashingMode::Standard2019 => {
                let params = ParamsBuilder::new()
                    .m_cost(1024 * 16)
                    .t_cost(32)
                    .p_cost(1)
                    .build()
                    .ok()?;
                self.argon2(params, version, info)
            }
            PinHashingMode::FastInsecure => {
                let params = ParamsBuilder::new()
                    .m_cost(Params::MIN_M_COST)
                    .t_cost(Params::MIN_T_COST)
                    .p_cost(Params::MIN_P_COST)
                    .build()
                    .ok()?;
                self.argon2(params, version, info)
            }
        }
    }

    fn argon2(
        &self,
        params: argon2::Params,
        version: &RegistrationVersion,
        info: &UserInfo,
    ) -> Option<(UserSecretAccessKey, UserSecretEncryptionKeySeed)> {
        let mut hashed_pin = vec![0u8; 64];

        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(
                self.expose_secret(),
                [
                    &to_be4(version.expose_secret().len()),
                    version.expose_secret().as_slice(),
                    &to_be4(info.expose_secret().len()),
                    info.expose_secret(),
                ]
                .concat()
                .as_slice(),
                &mut hashed_pin,
            )
            .ok()?;

        let access_key_bytes: [u8; 32] = hashed_pin[..32].try_into().unwrap();
        let encryption_key_seed_bytes: [u8; 32] = hashed_pin[32..].try_into().unwrap();

        let derived_keys = (
            UserSecretAccessKey::from(access_key_bytes),
            UserSecretEncryptionKeySeed::from(encryption_key_seed_bytes),
        );

        hashed_pin.zeroize();

        Some(derived_keys)
    }
}

#[cfg(test)]
mod tests {
    use juicebox_realm_api::types::RegistrationVersion;

    use crate::{
        pin::{Pin, PinHashingMode},
        UserInfo,
    };

    #[test]
    fn test_pin_hashing() {
        let salt = RegistrationVersion::from([5; 16]);
        let pin = Pin::from(b"1234".to_vec());
        let info = UserInfo::from(b"artemis".to_vec());
        let (access_key, encryption_key_seed) = pin
            .hash(PinHashingMode::Standard2019, &salt, &info)
            .unwrap();
        let expected_access_key: [u8; 32] = [
            41, 53, 218, 132, 201, 116, 35, 179, 127, 52, 87, 35, 27, 135, 124, 230, 172, 32, 147,
            80, 29, 114, 85, 219, 238, 29, 235, 9, 165, 216, 130, 27,
        ];
        let expected_encryption_key_seed: [u8; 32] = [
            135, 200, 201, 181, 211, 234, 159, 234, 131, 182, 172, 106, 100, 226, 91, 151, 196,
            114, 44, 164, 228, 11, 234, 37, 35, 239, 234, 38, 33, 37, 226, 42,
        ];
        assert_eq!(*access_key.expose_secret(), expected_access_key);
        assert_eq!(
            *encryption_key_seed.expose_secret(),
            expected_encryption_key_seed
        );
    }
}
