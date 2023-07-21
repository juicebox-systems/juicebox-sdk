use blake2::{Blake2s256, Blake2sMac256, Digest};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::ChaCha20Poly1305;
use curve25519_dalek::Scalar;
use digest::{KeyInit, Mac};
use instant::{Duration, Instant};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use std::fmt::{self, Debug};

use url::Url;

use juicebox_sdk_core::types::{
    EncryptedUserSecret, MaskedUnlockKeyScalarShare, OprfResult, RealmId, SecretBytesArray,
    SecretBytesVec, SessionId, UnlockKeyScalarHash,
};
use juicebox_sdk_noise::client as noise;

/// A remote service that the client interacts with directly.
///
/// This struct describes how clients communicate with a realm. A realm is a
/// remote service that clients interact with to register and recover their
/// PIN-protected secrets. Clients distribute their trust across multiple
/// realms, which can run different software and hardware and can be operated
/// independently.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct Realm {
    /// A unique identifier specified by the realm.
    #[serde(with = "hex_realm_id")]
    pub id: RealmId,
    /// The network address to connect to the service.
    pub address: Url,
    /// A long-lived public key for which a hardware backed service
    /// maintains a matching private key. Software realms do not
    /// require public keys.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "hex_public_key"
    )]
    pub public_key: Option<Vec<u8>>,
}

impl Debug for Realm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Realm")
            .field("id", &self.id)
            .field("address", &self.address.as_str())
            .finish_non_exhaustive()
    }
}

mod hex_realm_id {
    use serde::de::Deserializer;
    use serde::ser::Serializer;
    use serde::Deserialize;
    use std::str::FromStr;

    use super::RealmId;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<RealmId, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        RealmId::from_str(&s).map_err(serde::de::Error::custom)
    }

    pub fn serialize<S>(id: &RealmId, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{id:?}"))
    }
}

mod hex_public_key {
    use serde::de::Deserializer;
    use serde::ser::Serializer;
    use serde::Deserialize;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        match Option::<String>::deserialize(deserializer)? {
            Some(s) => {
                let key = hex::decode(s).map_err(serde::de::Error::custom)?;
                Ok(Some(key))
            }
            None => Ok(None),
        }
    }

    pub fn serialize<S>(public_key: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match public_key {
            None => serializer.serialize_none(),
            Some(key) => {
                let s = hex::encode(key);
                serializer.serialize_str(&s)
            }
        }
    }
}

/// The maximum allowed bytes for a [`UserSecret`].
pub const MAX_USER_SECRET_LENGTH: usize = 128;

/// The nonce used for encrypting / decrypting a [`UserSecret`].
/// Since a new randomly seeded encryption key is generated every
/// time we encrypt a [`UserSecret`], it is safe to use a fixed nonce.
const USER_SECRET_ENCRYPTION_NONCE: [u8; 12] = [0u8; 12];

/// A user-chosen secret with a maximum length of 128-bytes.
#[derive(Clone, Debug)]
pub struct UserSecret(SecretBytesVec);

impl UserSecret {
    /// Access the underlying secret bytes.
    pub fn expose_secret(&self) -> &[u8] {
        self.0.expose_secret()
    }

    pub(crate) fn encrypt(&self, encryption_key: &UserSecretEncryptionKey) -> EncryptedUserSecret {
        let cipher = ChaCha20Poly1305::new(encryption_key.expose_secret().into());
        let padded_secret = PaddedUserSecret::from(self);
        cipher
            .encrypt(
                &USER_SECRET_ENCRYPTION_NONCE.into(),
                padded_secret.expose_secret().as_slice(),
            )
            .map(EncryptedUserSecret::try_from)
            .expect("secret encryption failed")
            .unwrap()
    }

    pub(crate) fn decrypt(
        encrypted_secret: &EncryptedUserSecret,
        encryption_key: &UserSecretEncryptionKey,
    ) -> Self {
        let cipher = ChaCha20Poly1305::new(encryption_key.expose_secret().into());
        let padded_secret = cipher
            .decrypt(
                &USER_SECRET_ENCRYPTION_NONCE.into(),
                encrypted_secret.expose_secret().as_slice(),
            )
            .map(|s| PaddedUserSecret::try_from(s).expect("incorrectly sized padded secret"))
            .expect("secret decryption failed");
        UserSecret::from(&padded_secret)
    }
}

impl From<Vec<u8>> for UserSecret {
    fn from(value: Vec<u8>) -> Self {
        assert!(
            value.len() <= MAX_USER_SECRET_LENGTH,
            "secret exceeds the maximum of {} bytes",
            MAX_USER_SECRET_LENGTH
        );
        Self(SecretBytesVec::from(value))
    }
}

/// A padded representation of a [`UserSecret`].
///
/// # Note
///
/// The first byte represents the unpadded length, followed
/// by the unpadded data, and then null bytes to fill up
/// to [`MAX_USER_SECRET_LENGTH`].
struct PaddedUserSecret(SecretBytesArray<129>);

impl PaddedUserSecret {
    /// Access the underlying secret bytes.
    pub fn expose_secret(&self) -> &[u8; 129] {
        self.0.expose_secret()
    }
}

impl From<&UserSecret> for PaddedUserSecret {
    fn from(value: &UserSecret) -> Self {
        let mut padded_secret = value.expose_secret().to_vec();
        padded_secret.insert(0, padded_secret.len().try_into().unwrap());
        padded_secret.resize(MAX_USER_SECRET_LENGTH + 1, 0);
        Self::try_from(padded_secret).unwrap()
    }
}

impl From<&PaddedUserSecret> for UserSecret {
    fn from(value: &PaddedUserSecret) -> Self {
        let unpadded_length = usize::from(value.expose_secret()[0]);
        UserSecret::from(value.expose_secret()[1..=unpadded_length].to_vec())
    }
}

impl TryFrom<Vec<u8>> for PaddedUserSecret {
    type Error = &'static str;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(Self(SecretBytesArray::try_from(value)?))
    }
}

/// A seed value derived from the user's [`Pin`](crate::pin::Pin) with Argon2.
///
/// This is the user-known portion of the [`UserSecretEncryptionKey`].
pub(crate) struct UserSecretEncryptionKeySeed(SecretBytesArray<32>);

impl UserSecretEncryptionKeySeed {
    /// Access the underlying secret bytes.
    pub fn expose_secret(&self) -> &[u8; 32] {
        self.0.expose_secret()
    }
}

impl From<[u8; 32]> for UserSecretEncryptionKeySeed {
    fn from(value: [u8; 32]) -> Self {
        Self(SecretBytesArray::from(value))
    }
}

/// A random scalar that is secret shared and distributed to realms
/// during registration.
///
/// This is the recoverable portion of the [`UserSecretEncryptionKey`].
#[derive(Clone, Debug)]
pub(crate) struct UserSecretEncryptionKeyScalar(Scalar);

impl UserSecretEncryptionKeyScalar {
    pub fn new(scalar: Scalar) -> Self {
        Self(scalar)
    }

    pub fn new_random() -> Self {
        Self(Scalar::random(&mut OsRng))
    }

    pub fn expose_secret(&self) -> &Scalar {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

/// A key used to encrypt the [`UserSecret`], derived from the
/// user's [`PIN`](crate::pin).
#[derive(Clone, Debug)]
pub(crate) struct UserSecretEncryptionKey(SecretBytesArray<32>);

impl UserSecretEncryptionKey {
    /// Derive a key from the user-known seed and the scalar (which
    /// may have been recovered from the realm).
    pub fn derive(
        seed: &UserSecretEncryptionKeySeed,
        scalar: &UserSecretEncryptionKeyScalar,
    ) -> Self {
        let label = b"User Secret Encryption Key";
        let mac: [u8; 32] = <Blake2sMac256 as Mac>::new(seed.expose_secret().into())
            .chain_update((label.len() as u32).to_le_bytes())
            .chain_update(label)
            .chain_update((scalar.as_bytes().len() as u32).to_le_bytes())
            .chain_update(scalar.as_bytes())
            .finalize()
            .into_bytes()
            .into();
        UserSecretEncryptionKey(SecretBytesArray::from(mac))
    }

    /// Access the underlying secret bytes.
    pub fn expose_secret(&self) -> &[u8; 32] {
        self.0.expose_secret()
    }
}

impl From<[u8; 32]> for UserSecretEncryptionKey {
    fn from(value: [u8; 32]) -> Self {
        Self(SecretBytesArray::from(value))
    }
}

/// Additional data added to the salt for a user's PIN. The chosen
/// data must be consistent between registration and recovery or
/// recovery will fail. This data does not need to be a well-kept
/// secret. A user's ID is a reasonable choice, but even the name
/// of the company or service could be viable if nothing else is
/// available.
///
/// This data is used to prevent a malicious [`Realm`] from
/// forcing use of a salt with a precomputed password table.
#[derive(Clone, Debug)]
pub struct UserInfo(SecretBytesVec);

impl UserInfo {
    /// Access the underlying secret bytes.
    pub fn expose_secret(&self) -> &[u8] {
        self.0.expose_secret()
    }
}

impl From<Vec<u8>> for UserInfo {
    fn from(value: Vec<u8>) -> Self {
        Self(SecretBytesVec::from(value))
    }
}

/// A random scalar used to derived the [`UnlockKey`](juicebox_sdk_core::types::UnlockKey) and prove
/// knowledge of the [`UserSecretAccessKey`](juicebox_sdk_core::types::UserSecretAccessKey).
pub struct UnlockKeyScalar(Scalar);

impl UnlockKeyScalar {
    pub fn new(scalar: Scalar) -> Self {
        Self(scalar)
    }

    pub fn new_random() -> Self {
        Self(Scalar::random(&mut OsRng))
    }

    pub fn expose_secret(&self) -> &Scalar {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    pub fn as_hash(&self) -> UnlockKeyScalarHash {
        let hash: [u8; 32] = Blake2s256::digest(self.as_bytes()).into();
        UnlockKeyScalarHash::from(hash)
    }
}

/// A share of the [`UnlockKeyScalar`].
#[derive(Clone, Debug)]
pub(crate) struct UnlockKeyScalarShare(SecretBytesArray<32>);

impl UnlockKeyScalarShare {
    pub fn expose_secret(&self) -> &[u8; 32] {
        self.0.expose_secret()
    }

    pub fn unmask(masked_share: &MaskedUnlockKeyScalarShare, oprf_result: &OprfResult) -> Self {
        Self::from((masked_share.as_scalar() - oprf_result.as_scalar()).to_bytes())
    }

    pub fn mask(&self, oprf_result: &OprfResult) -> MaskedUnlockKeyScalarShare {
        MaskedUnlockKeyScalarShare::from((self.as_scalar() + oprf_result.as_scalar()).to_bytes())
    }

    pub fn as_scalar(&self) -> Scalar {
        Scalar::from_canonical_bytes(*self.expose_secret()).unwrap()
    }
}

impl From<[u8; 32]> for UnlockKeyScalarShare {
    fn from(value: [u8; 32]) -> Self {
        Self::from(Scalar::from_canonical_bytes(value).unwrap())
    }
}

impl From<Scalar> for UnlockKeyScalarShare {
    fn from(value: Scalar) -> Self {
        Self(SecretBytesArray::from(value.to_bytes()))
    }
}

/// An established Noise communication channel.
///
/// After `last_used + lifetime`, the session is considered expired and should
/// be discarded.
#[derive(Debug)]
pub(crate) struct Session {
    pub session_id: SessionId,
    pub transport: noise::Transport,
    pub lifetime: Duration,
    pub last_used: Instant,
}

#[cfg(test)]
mod tests {
    use juicebox_sdk_core::types::{MaskedUnlockKeyScalarShare, OprfResult};

    use crate::types::{
        EncryptedUserSecret, PaddedUserSecret, UnlockKeyScalarShare, UserSecret,
        UserSecretEncryptionKey, MAX_USER_SECRET_LENGTH,
    };

    #[test]
    fn test_unlock_key_share_masking() {
        let oprf_result = OprfResult::from([10u8; 64]);

        let unmasked_share = vec![
            248, 158, 161, 253, 178, 255, 152, 10, 230, 184, 147, 150, 19, 185, 200, 215, 192, 174,
            12, 126, 85, 68, 178, 163, 25, 140, 26, 245, 221, 126, 133, 15,
        ];

        let masked_share = MaskedUnlockKeyScalarShare::from([
            13, 109, 221, 215, 211, 213, 202, 96, 143, 149, 85, 1, 34, 103, 252, 232, 231, 222,
            141, 70, 178, 169, 96, 89, 148, 205, 20, 130, 246, 70, 74, 7,
        ]);

        let s = UnlockKeyScalarShare::unmask(&masked_share, &oprf_result);
        assert_eq!(s.expose_secret().as_slice(), unmasked_share);

        let m = s.mask(&oprf_result);
        assert_eq!(m.expose_secret(), masked_share.expose_secret());
    }

    #[test]
    fn test_secret_padding() {
        let short_secret = UserSecret::from(vec![1, 2, 3, 0, 4, 5, 0]);
        let mut expected_padded_secret = vec![7u8, 1, 2, 3, 0, 4, 5, 0];
        expected_padded_secret.resize(MAX_USER_SECRET_LENGTH + 1, 0);
        assert_eq!(
            PaddedUserSecret::from(&short_secret)
                .expose_secret()
                .to_vec(),
            expected_padded_secret
        );
        assert_eq!(
            UserSecret::from(&PaddedUserSecret::from(&short_secret)).expose_secret(),
            short_secret.expose_secret()
        );

        let long_secret = UserSecret::from(vec![5; MAX_USER_SECRET_LENGTH]);
        expected_padded_secret = vec![5; MAX_USER_SECRET_LENGTH];
        expected_padded_secret.insert(0, 128);
        assert_eq!(
            PaddedUserSecret::from(&long_secret)
                .expose_secret()
                .to_vec(),
            expected_padded_secret
        );
        assert_eq!(
            UserSecret::from(&PaddedUserSecret::from(&long_secret)).expose_secret(),
            long_secret.expose_secret()
        );

        let empty_secret = UserSecret::from(vec![]);
        assert_eq!(
            PaddedUserSecret::from(&empty_secret).expose_secret(),
            &[0; MAX_USER_SECRET_LENGTH + 1]
        );
        assert_eq!(
            UserSecret::from(&PaddedUserSecret::from(&empty_secret)).expose_secret(),
            empty_secret.expose_secret()
        );
    }

    #[test]
    fn test_secret_encryption() {
        let secret = UserSecret::from(b"artemis".to_vec());
        let key = UserSecretEncryptionKey::from([8; 32]);
        let encrypted_secret = secret.encrypt(&key);
        let expected_encrypted_secret = vec![
            1, 134, 178, 251, 18, 193, 244, 162, 122, 194, 0, 239, 255, 128, 253, 39, 199, 249,
            145, 226, 252, 83, 165, 81, 50, 46, 17, 1, 94, 108, 224, 139, 51, 137, 152, 176, 230,
            203, 184, 172, 75, 181, 206, 151, 188, 22, 100, 113, 224, 151, 68, 63, 202, 164, 225,
            84, 155, 141, 169, 49, 255, 75, 1, 95, 250, 34, 92, 203, 156, 129, 84, 16, 20, 149, 49,
            86, 63, 245, 116, 36, 82, 116, 215, 136, 197, 154, 126, 99, 99, 127, 79, 29, 23, 74,
            172, 149, 20, 2, 43, 102, 29, 82, 89, 102, 225, 83, 64, 229, 247, 232, 194, 207, 6,
            129, 183, 46, 4, 52, 205, 109, 240, 64, 67, 15, 226, 185, 186, 54, 162, 20, 219, 250,
            162, 103, 164, 76, 121, 87, 140, 147, 118, 109, 107, 35, 7,
        ];
        assert_eq!(&expected_encrypted_secret, encrypted_secret.expose_secret());
    }

    #[test]
    fn test_secret_decryption() {
        let key = UserSecretEncryptionKey::from([8; 32]);
        let encrypted_secret = EncryptedUserSecret::try_from(vec![
            1, 134, 178, 251, 18, 193, 244, 162, 122, 194, 0, 239, 255, 128, 253, 39, 199, 249,
            145, 226, 252, 83, 165, 81, 50, 46, 17, 1, 94, 108, 224, 139, 51, 137, 152, 176, 230,
            203, 184, 172, 75, 181, 206, 151, 188, 22, 100, 113, 224, 151, 68, 63, 202, 164, 225,
            84, 155, 141, 169, 49, 255, 75, 1, 95, 250, 34, 92, 203, 156, 129, 84, 16, 20, 149, 49,
            86, 63, 245, 116, 36, 82, 116, 215, 136, 197, 154, 126, 99, 99, 127, 79, 29, 23, 74,
            172, 149, 20, 2, 43, 102, 29, 82, 89, 102, 225, 83, 64, 229, 247, 232, 194, 207, 6,
            129, 183, 46, 4, 52, 205, 109, 240, 64, 67, 15, 226, 185, 186, 54, 162, 20, 219, 250,
            162, 103, 164, 76, 121, 87, 140, 147, 118, 109, 107, 35, 7,
        ])
        .unwrap();
        let secret = UserSecret::decrypt(&encrypted_secret, &key);
        let expected_secret = b"artemis".to_vec();
        assert_eq!(&expected_secret, secret.expose_secret());
    }
}
