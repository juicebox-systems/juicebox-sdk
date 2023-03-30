extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::{self, Debug, Display};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

pub type OprfCipherSuite = voprf::Ristretto255;
pub type OprfBlindedInput = voprf::BlindedElement<OprfCipherSuite>;
pub type OprfBlindedResult = voprf::EvaluationElement<OprfCipherSuite>;
pub type OprfClient = voprf::OprfClient<OprfCipherSuite>;
pub struct OprfResult(pub digest::Output<<OprfCipherSuite as voprf::CipherSuite>::Hash>);

impl Debug for OprfResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("(redacted)")
    }
}

#[derive(Copy, Clone, Deserialize, Eq, Hash, PartialEq, Serialize)]
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
#[derive(Clone, Deserialize, Serialize)]
pub struct AuthToken {
    pub tenant: String,
    pub user: String,
    pub signature: Vec<u8>,
}

impl Debug for AuthToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "(auth token for {:?})", self.user)
    }
}

/// A share of the user's secret.
///
/// The client needs a threshold number of such shares to recover the user's
/// secret.
#[derive(Clone, Serialize, Deserialize)]
pub struct UserSecretShare(pub Vec<u8>);

impl From<Vec<u8>> for UserSecretShare {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl Debug for UserSecretShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("(redacted)")
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
#[derive(Clone, Serialize, Deserialize)]
pub struct MaskedTgkShare(pub Vec<u8>);

impl Debug for MaskedTgkShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("(redacted)")
    }
}

/// A pseudo-random value that the client assigns to a realm when registering a
/// share of the user's secret and must provide to the realm during recovery to
/// get back the share.
#[derive(Clone, Serialize, Deserialize)]
pub struct UnlockTag(pub Vec<u8>);

impl Debug for UnlockTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("(redacted)")
    }
}

impl ConstantTimeEq for UnlockTag {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
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
