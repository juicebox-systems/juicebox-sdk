use digest::Digest;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use std::collections::HashSet;
use std::fmt::{self, Debug};
use std::iter::zip;
use std::ops::Deref;
use std::time::{Duration, Instant};
use url::Url;

use loam_sdk_core::types::{
    MaskedTgkShare, OprfCipherSuite, OprfResult, RealmId, SessionId, UnlockTag,
};
use loam_sdk_noise::client as noise;

/// A remote service that the client interacts with directly.
#[derive(Clone)]
pub struct Realm {
    /// The network address to connect to the service.
    pub address: Url,
    /// A long-lived public key for which the service has the matching private
    /// key.
    pub public_key: Vec<u8>,
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

#[derive(Debug)]
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

/// A user-chosen password that may be low in entropy.
#[derive(Clone)]
pub struct Pin(pub Vec<u8>);

impl Debug for Pin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("(redacted)")
    }
}

/// A user-chosen secret.
///
/// # Warning
///
/// If the secrets vary in length (such as passwords), the caller should add
/// padding to obscure the secrets' length. Values of this type are assumed
/// to already include such padding.
#[derive(Clone)]
pub struct UserSecret(pub Vec<u8>);

impl Debug for UserSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("(redacted)")
    }
}

/// A random key that is used to derive secret-unlocking tags
/// ([`UnlockTag`]) for each realm.
pub(crate) struct TagGeneratingKey(pub Vec<u8>);

impl TagGeneratingKey {
    /// Generates a new key with random data.
    pub fn new_random() -> Self {
        // The TGK should be one byte smaller than the OPRF output,
        // so that the TGK shares can be masked with the OPRF output.
        // The `sharks` library adds an extra byte for the x-coordinate.
        let mut tgk = vec![0u8; oprf_output_size() - 1];
        OsRng.fill_bytes(&mut tgk);
        Self(tgk)
    }

    /// Computes a derived secret-unlocking tag for the realm.
    pub fn tag(&self, realm_id: &[u8]) -> UnlockTag {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0).expect("failed to initialize HMAC");
        mac.update(realm_id);
        UnlockTag(mac.finalize().into_bytes().to_vec())
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
        f.write_str("(redacted)")
    }
}

impl TgkShare {
    pub fn try_from_masked(
        masked_share: &MaskedTgkShare,
        oprf_pin: &[u8],
    ) -> Result<Self, LengthMismatchError> {
        if masked_share.0.len() == oprf_pin.len() {
            let share: Vec<u8> = zip(oprf_pin, &masked_share.0).map(|(a, b)| a ^ b).collect();
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
        MaskedTgkShare(zip(oprf_pin.0, share).map(|(a, b)| a ^ b).collect())
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
