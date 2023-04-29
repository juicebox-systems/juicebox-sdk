extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use core::fmt::{self, Debug, Display};
use rand_core::{CryptoRng, RngCore};
use secrecy::{
    CloneableSecret, DebugSecret, ExposeSecret, SecretString, SerializableSecret, Zeroize,
};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use super::marshalling::serialize_secret;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretBytes(Vec<u8>);
impl Zeroize for SecretBytes {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
impl SerializableSecret for SecretBytes {}
impl CloneableSecret for SecretBytes {}
impl DebugSecret for SecretBytes {}
impl ExposeSecret<Vec<u8>> for SecretBytes {
    fn expose_secret(&self) -> &Vec<u8> {
        &self.0
    }
}
impl From<Vec<u8>> for SecretBytes {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

pub type OprfCipherSuite = voprf::Ristretto255;
pub type OprfBlindedInput = voprf::BlindedElement<OprfCipherSuite>;
pub type OprfBlindedResult = voprf::EvaluationElement<OprfCipherSuite>;
pub type OprfClient = voprf::OprfClient<OprfCipherSuite>;
pub type OprfServer = voprf::OprfServer<OprfCipherSuite>;
pub struct OprfResult(pub digest::Output<<OprfCipherSuite as voprf::CipherSuite>::Hash>);

impl Debug for OprfResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("(redacted)")
    }
}

/// A private root key used to derive keys for each user-generation's OPRF.
#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct OprfKey(SecretBytes);

impl OprfKey {
    /// Generates a new oprf key with random data.
    #[allow(clippy::slow_vector_initialization)]
    pub fn new_random<T: RngCore + CryptoRng + Send>(rng: &mut T) -> Option<Self> {
        let mut seed = Vec::with_capacity(32);
        seed.resize(32, 0);
        rng.fill_bytes(&mut seed);

        let secret_key =
            voprf::derive_key::<OprfCipherSuite>(&seed, &[], voprf::Mode::Oprf).ok()?;
        Some(Self::from(secret_key.as_bytes().to_vec()))
    }

    pub fn expose_secret(&self) -> &[u8] {
        self.0.expose_secret()
    }
}

impl From<Vec<u8>> for OprfKey {
    fn from(value: Vec<u8>) -> Self {
        Self(SecretBytes::from(value))
    }
}

/// A unique 16-byte identifier for a [`Realm`](struct.Realm.html).
#[derive(Copy, Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct RealmId(pub [u8; 16]);

impl Debug for RealmId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Represents the authority to act as a particular user.
///
/// Tokens use the base64-encoded JWT format with the HS256 hash-based
/// validation algorithm. The keys used to generate and verify tokens are
/// specific to each tenant. To be acceptable, a token must include the
/// following claims:
///
/// - an issuer (`iss`) set to the tenant's ID,
/// - a subject (`sub`) set to the user's ID,
/// - an audience (`aud`) of "loam.me",
/// - an expiration time (`exp`) in the future,
/// - a not-valid before time (`nbf`) in the past, and
/// - a lifetime (difference between `nbf` and `exp`) of less than 1 day.
///
/// Additionally, the token must include the key ID (`kid`) in the JWT header.
/// This uses the format `{issuer}:{version}`, like "acme:32" and should be
/// provided to the issuer alongside the key.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuthToken(#[serde(serialize_with = "serialize_secret")] pub SecretString);

impl AuthToken {
    pub fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

impl From<SecretString> for AuthToken {
    fn from(value: SecretString) -> Self {
        AuthToken(value)
    }
}

impl From<String> for AuthToken {
    fn from(value: String) -> Self {
        AuthToken(SecretString::from(value))
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Salt(SecretBytes);

impl ConstantTimeEq for Salt {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.expose_secret().ct_eq(other.expose_secret())
    }
}

impl Salt {
    /// Generates a new salt with random data.
    #[allow(clippy::slow_vector_initialization)]
    pub fn new_random<T: RngCore + CryptoRng + Send>(rng: &mut T) -> Self {
        let mut salt = Vec::with_capacity(32);
        salt.resize(32, 0);
        rng.fill_bytes(&mut salt);
        Self::from(salt)
    }

    pub fn expose_secret(&self) -> &[u8] {
        self.0.expose_secret()
    }
}

impl From<Vec<u8>> for Salt {
    fn from(value: Vec<u8>) -> Self {
        Self(SecretBytes::from(value))
    }
}

/// Used to distinguish different secure communication channels for a single
/// user.
///
/// This is useful in case a user has multiple concurrent Noise sessions (from
/// one or more clients). The IDs are opaque and are chosen randomly by the
/// client. If the chosen IDs collide, the user might see extra errors and have
/// to retry, but that's the worst that should happen. Session IDs need not be
/// confidential.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct SessionId(pub u32);

/// A share of the user's secret.
///
/// The client needs a threshold number of such shares to recover the user's
/// secret.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct UserSecretShare(#[serde(serialize_with = "serialize_secret")] SecretBytes);

impl UserSecretShare {
    /// Access the underlying secret bytes.
    pub fn expose_secret(&self) -> &[u8] {
        self.0.expose_secret()
    }
}

impl From<Vec<u8>> for UserSecretShare {
    fn from(value: Vec<u8>) -> Self {
        Self(SecretBytes::from(value))
    }
}

/// Defines restrictions on how a secret may be accessed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Policy {
    /// The number of guesses allowed before the secret can no longer be
    /// accessed.
    ///
    /// This should be set to a small number greater than 0. Lower numbers have
    /// a smaller risk that an adversary could guess the PIN to unlock the
    /// secret, but they have a larger risk that the user will get accidentally
    /// locked out due to typos and transient errors.
    pub num_guesses: u16,
}

/// A share of the tag-generating key that has been XORed with
/// `OPRF(PIN)`.
///
/// The client sends this to a realm during registration and gets it back from
/// the realm during recovery.
///
/// The client needs the correct PIN and a threshold number of such shares and
/// OPRF results to recover the tag-generating key.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct MaskedTgkShare(SecretBytes);

impl MaskedTgkShare {
    pub fn expose_secret(&self) -> &[u8] {
        self.0.expose_secret()
    }
}

impl From<Vec<u8>> for MaskedTgkShare {
    fn from(value: Vec<u8>) -> Self {
        Self(SecretBytes::from(value))
    }
}

/// A pseudo-random value that the client assigns to a realm when registering a
/// share of the user's secret and must provide to the realm during recovery to
/// get back the share.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct UnlockTag(SecretBytes);

impl ConstantTimeEq for UnlockTag {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.expose_secret().ct_eq(other.expose_secret())
    }
}

impl UnlockTag {
    pub fn expose_secret(&self) -> &[u8] {
        self.0.expose_secret()
    }
}

impl From<Vec<u8>> for UnlockTag {
    fn from(value: Vec<u8>) -> Self {
        Self(SecretBytes::from(value))
    }
}

/// Identifies a version of a PIN-protected secret record.
///
/// Every time the user registers a new PIN-protected secret, that will have a
/// larger generation number than any before it.
///
/// # Note
///
/// Generation numbers are an implementation detail. They are exposed publicly
/// for the purpose of error messages only.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct GenerationNumber(pub u64);

impl Display for GenerationNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}
