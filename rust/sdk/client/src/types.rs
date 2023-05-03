use blake2::Blake2s256;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::ChaCha20Poly1305;
use digest::{Digest, KeyInit};
use hmac::{Mac, SimpleHmac};
use instant::{Duration, Instant};
use rand::rngs::OsRng;
use rand::RngCore;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt::{self, Debug};
use std::iter::zip;
use std::ops::Deref;
use url::Url;

use loam_sdk_core::types::{
    MaskedTgkShare, OprfCipherSuite, OprfResult, RealmId, SecretBytes, SessionId, UnlockTag,
};
use loam_sdk_noise::client as noise;

use crate::PinHashingMode;

/// A remote service that the client interacts with directly.
#[derive(Clone, Serialize, Deserialize)]
pub struct Realm {
    /// The network address to connect to the service.
    pub address: Url,
    /// A long-lived public key for which the service has the matching private
    /// key.
    pub public_key: Vec<u8>,
    /// A unique identifier specified by the realm.
    pub id: RealmId,
}

impl Debug for Realm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Realm")
            .field("id", &self.id)
            .field("address", &self.address.as_str())
            .finish_non_exhaustive()
    }
}

/// The parameters used to configure a [`Client`](crate::Client).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Configuration {
    /// The remote services that the client interacts with.
    ///
    /// There must be between `register_threshold` and 255 realms, inclusive.
    pub realms: Vec<Realm>,

    /// A registration will be considered successful if it's successful on at
    /// least this many realms.
    ///
    /// Must be between `recover_threshold` and `realms.len()`, inclusive.
    pub register_threshold: u8,

    /// A recovery (or an adversary) will need the cooperation of this many
    /// realms to retrieve the secret.
    ///
    /// Must be between `1` and `realms.len()`, inclusive.
    pub recover_threshold: u8,

    /// Defines how the provided PIN will be hashed before register and recover
    /// operations. Changing modes will make previous secrets stored on the realms
    /// inaccessible with the same PIN and should not be done without re-registering
    /// secrets.
    pub pin_hashing_mode: PinHashingMode,
}

#[derive(Debug)]
pub(crate) struct CheckedConfiguration(Configuration);

impl CheckedConfiguration {
    pub fn from(c: Configuration) -> Self {
        assert!(
            !c.realms.is_empty(),
            "Client needs at least one realm in Configuration"
        );

        assert_eq!(
            c.realms
                .iter()
                .map(|realm| realm.id)
                .collect::<HashSet<_>>()
                .len(),
            c.realms.len(),
            "realm IDs must be unique in Configuration"
        );

        // The secret sharing implementation (`sharks`) doesn't support more
        // than 255 shares.
        assert!(
            u8::try_from(c.realms.len()).is_ok(),
            "too many realms in Client configuration"
        );

        for realm in &c.realms {
            assert_eq!(
                realm.public_key.len(),
                32,
                "realm public keys must be 32 bytes" // (x25519 for now)
            );
        }

        assert!(
            1 <= c.recover_threshold,
            "Configuration recover_threshold must be at least 1"
        );
        assert!(
            usize::from(c.recover_threshold) <= c.realms.len(),
            "Configuration recover_threshold cannot exceed number of realms"
        );

        assert!(
            c.recover_threshold <= c.register_threshold,
            "Configuration register_threshold must be at least recover_threshold"
        );
        assert!(
            usize::from(c.register_threshold) <= c.realms.len(),
            "Configuration register_threshold cannot exceed number of realms"
        );

        Self(c)
    }
}

impl Deref for CheckedConfiguration {
    type Target = Configuration;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// The maximum allowed bytes for a [`UserSecret`].
pub const MAX_USER_SECRET_LENGTH: usize = 128;

/// A user-chosen secret with a maximum length of 128-bytes.
#[derive(Clone, Debug)]
pub struct UserSecret(SecretBytes);

impl UserSecret {
    /// Access the underlying secret bytes.
    pub fn expose_secret(&self) -> &[u8] {
        self.0.expose_secret()
    }

    pub(crate) fn encrypt(&self, encryption_key: &UserSecretEncryptionKey) -> EncryptedUserSecret {
        let cipher = ChaCha20Poly1305::new(encryption_key.expose_secret().into());
        let padded_secret = PaddedUserSecret::from(self);
        cipher
            .encrypt(&[0u8; 12].into(), padded_secret.expose_secret())
            .map(EncryptedUserSecret::from)
            .expect("secret encryption failed")
    }
}

impl From<Vec<u8>> for UserSecret {
    fn from(value: Vec<u8>) -> Self {
        assert!(value.len() <= MAX_USER_SECRET_LENGTH);
        Self(SecretBytes::from(value))
    }
}

/// A padded representation of a [`UserSecret`].
///
/// # Note
///
/// The first byte represents the unpadded length, followed
/// by the unpadded data, and then null bytes to fill up
/// to [`MAX_USER_SECRET_LENGTH`].
struct PaddedUserSecret(SecretBytes);

impl PaddedUserSecret {
    /// Access the underlying secret bytes.
    pub fn expose_secret(&self) -> &[u8] {
        self.0.expose_secret()
    }
}

impl From<&UserSecret> for PaddedUserSecret {
    fn from(value: &UserSecret) -> Self {
        let mut padded_secret = value.expose_secret().to_vec();
        padded_secret.insert(0, padded_secret.len().try_into().unwrap());
        padded_secret.resize(MAX_USER_SECRET_LENGTH + 1, 0);
        Self::from(padded_secret)
    }
}

impl From<&PaddedUserSecret> for UserSecret {
    fn from(value: &PaddedUserSecret) -> Self {
        let unpadded_length = usize::from(value.expose_secret()[0]);
        UserSecret::from(value.expose_secret()[1..=unpadded_length].to_vec())
    }
}

impl From<Vec<u8>> for PaddedUserSecret {
    fn from(value: Vec<u8>) -> Self {
        assert!(value.len() == MAX_USER_SECRET_LENGTH + 1);
        Self(SecretBytes::from(value))
    }
}

#[derive(Clone, Debug)]
pub(crate) struct EncryptedUserSecret(SecretBytes);

impl EncryptedUserSecret {
    /// Access the underlying secret bytes.
    pub fn expose_secret(&self) -> &[u8] {
        self.0.expose_secret()
    }

    pub(crate) fn decrypt(&self, encryption_key: &UserSecretEncryptionKey) -> UserSecret {
        let cipher = ChaCha20Poly1305::new(encryption_key.expose_secret().into());
        let padded_secret = cipher
            .decrypt(&[0u8; 12].into(), self.expose_secret())
            .map(PaddedUserSecret::from)
            .expect("secret decryption failed");
        UserSecret::from(&padded_secret)
    }
}

impl From<Vec<u8>> for EncryptedUserSecret {
    fn from(value: Vec<u8>) -> Self {
        assert_eq!(value.len(), 145);
        Self(SecretBytes::from(value))
    }
}

/// A user's access key, derived from the user's [`PIN`](crate::pin).
#[derive(Clone, Debug)]
pub(crate) struct AccessKey(SecretBytes);

impl AccessKey {
    /// Access the underlying secret bytes.
    pub fn expose_secret(&self) -> &[u8] {
        self.0.expose_secret()
    }
}

impl From<Vec<u8>> for AccessKey {
    fn from(value: Vec<u8>) -> Self {
        Self(SecretBytes::from(value))
    }
}

/// A key used to encrypt the [`UserSecret`], derived from the
/// user's [`PIN`](crate::pin).
#[derive(Clone, Debug)]
pub(crate) struct UserSecretEncryptionKey(SecretBytes);

impl UserSecretEncryptionKey {
    /// Access the underlying secret bytes.
    pub fn expose_secret(&self) -> &[u8] {
        self.0.expose_secret()
    }
}

impl From<Vec<u8>> for UserSecretEncryptionKey {
    fn from(value: Vec<u8>) -> Self {
        Self(SecretBytes::from(value))
    }
}

/// A random key that is used to derive secret-unlocking tags
/// ([`UnlockTag`]) for each realm.
pub(crate) struct TagGeneratingKey(SecretBytes);

impl TagGeneratingKey {
    /// Generates a new key with random data.
    pub fn new_random() -> Self {
        // The TGK should be one byte smaller than the OPRF output,
        // so that the TGK shares can be masked with the OPRF output.
        // The `sharks` library adds an extra byte for the x-coordinate.
        let mut tgk = vec![0u8; oprf_output_size() - 1];
        OsRng.fill_bytes(&mut tgk);
        Self::from(tgk)
    }

    /// Computes a derived secret-unlocking tag for the realm.
    pub fn tag(&self, realm_id: &[u8]) -> UnlockTag {
        let mut mac = <SimpleHmac<Blake2s256> as Mac>::new_from_slice(self.expose_secret())
            .expect("failed to initialize HMAC");
        mac.update(realm_id);
        UnlockTag::from(mac.finalize().into_bytes().to_vec())
    }

    pub fn expose_secret(&self) -> &[u8] {
        self.0.expose_secret()
    }
}

impl From<Vec<u8>> for TagGeneratingKey {
    fn from(value: Vec<u8>) -> Self {
        Self(SecretBytes::from(value))
    }
}

/// Error return type for [`TgkShare::try_from_masked`].
#[derive(Debug)]
pub(crate) struct LengthMismatchError;

/// A share of the [`TagGeneratingKey`].
///
/// The version of this that is XORed with `OPRF(PIN)` is
/// [`MaskedTgkShare`](super::types::MaskedTgkShare).
#[derive(Clone)]
pub(crate) struct TgkShare(pub sharks::Share);

impl Debug for TgkShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TgkShare(REDACTED)")
    }
}

impl TgkShare {
    pub fn try_from_masked(
        masked_share: &MaskedTgkShare,
        oprf_pin: &[u8],
    ) -> Result<Self, LengthMismatchError> {
        if masked_share.expose_secret().len() == oprf_pin.len() {
            let share: Vec<u8> = zip(oprf_pin, masked_share.expose_secret())
                .map(|(a, b)| a ^ b)
                .collect();
            match sharks::Share::try_from(share.as_slice()) {
                Ok(share) => Ok(Self(share)),
                Err(_) => Err(LengthMismatchError),
            }
        } else {
            Err(LengthMismatchError)
        }
    }

    pub fn mask(&self, oprf_pin: &OprfResult) -> MaskedTgkShare {
        let share = Vec::from(&self.0);
        assert_eq!(oprf_pin.0.len(), share.len());
        let vec: Vec<u8> = zip(oprf_pin.0, share).map(|(a, b)| a ^ b).collect();
        MaskedTgkShare::from(vec)
    }
}

pub(crate) fn oprf_output_size() -> usize {
    <OprfCipherSuite as voprf::CipherSuite>::Hash::output_size()
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
    use crate::types::{
        EncryptedUserSecret, PaddedUserSecret, UserSecret, UserSecretEncryptionKey,
        MAX_USER_SECRET_LENGTH,
    };

    #[test]
    fn test_secret_padding() {
        let short_secret = UserSecret::from(vec![1, 2, 3, 0, 4, 5, 0]);
        let mut expected_padded_secret = vec![7, 1, 2, 3, 0, 4, 5, 0];
        expected_padded_secret.resize(MAX_USER_SECRET_LENGTH + 1, 0);
        assert_eq!(
            PaddedUserSecret::from(&short_secret).expose_secret(),
            &expected_padded_secret
        );
        assert_eq!(
            UserSecret::from(&PaddedUserSecret::from(&short_secret)).expose_secret(),
            short_secret.expose_secret()
        );

        let long_secret = UserSecret::from(vec![5; MAX_USER_SECRET_LENGTH]);
        expected_padded_secret = vec![5; MAX_USER_SECRET_LENGTH];
        expected_padded_secret.insert(0, 128);
        assert_eq!(
            PaddedUserSecret::from(&long_secret).expose_secret(),
            &expected_padded_secret
        );
        assert_eq!(
            UserSecret::from(&PaddedUserSecret::from(&long_secret)).expose_secret(),
            long_secret.expose_secret()
        );

        let empty_secret = UserSecret::from(vec![]);
        assert_eq!(
            PaddedUserSecret::from(&empty_secret).expose_secret(),
            &vec![0; MAX_USER_SECRET_LENGTH + 1]
        );
        assert_eq!(
            UserSecret::from(&PaddedUserSecret::from(&empty_secret)).expose_secret(),
            empty_secret.expose_secret()
        );
    }

    #[test]
    fn test_secret_encryption() {
        let secret = UserSecret::from(b"artemis".to_vec());
        let key = UserSecretEncryptionKey::from(vec![8; 32]);
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
        let key = UserSecretEncryptionKey::from(vec![8; 32]);
        let encrypted_secret = EncryptedUserSecret::from(vec![
            1, 134, 178, 251, 18, 193, 244, 162, 122, 194, 0, 239, 255, 128, 253, 39, 199, 249,
            145, 226, 252, 83, 165, 81, 50, 46, 17, 1, 94, 108, 224, 139, 51, 137, 152, 176, 230,
            203, 184, 172, 75, 181, 206, 151, 188, 22, 100, 113, 224, 151, 68, 63, 202, 164, 225,
            84, 155, 141, 169, 49, 255, 75, 1, 95, 250, 34, 92, 203, 156, 129, 84, 16, 20, 149, 49,
            86, 63, 245, 116, 36, 82, 116, 215, 136, 197, 154, 126, 99, 99, 127, 79, 29, 23, 74,
            172, 149, 20, 2, 43, 102, 29, 82, 89, 102, 225, 83, 64, 229, 247, 232, 194, 207, 6,
            129, 183, 46, 4, 52, 205, 109, 240, 64, 67, 15, 226, 185, 186, 54, 162, 20, 219, 250,
            162, 103, 164, 76, 121, 87, 140, 147, 118, 109, 107, 35, 7,
        ]);
        let secret = encrypted_secret.decrypt(&key);
        let expected_secret = b"artemis".to_vec();
        assert_eq!(&expected_secret, secret.expose_secret());
    }
}
