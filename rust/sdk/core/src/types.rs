extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use blake2::{Blake2s256, Blake2sMac256, Digest};
use curve25519_dalek::Scalar;
use digest::Mac;

use core::{
    fmt::{self, Debug},
    str::FromStr,
};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use juicebox_sdk_marshalling::bytes;

#[derive(Clone, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct SecretBytesArray<const N: usize>(#[serde(with = "bytes")] [u8; N]);

impl<const N: usize> SecretBytesArray<N> {
    pub fn expose_secret(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> Zeroize for SecretBytesArray<N> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl<const N: usize> Drop for SecretBytesArray<N> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<const N: usize> Debug for SecretBytesArray<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytesArray(REDACTED)")
    }
}

impl<const N: usize> From<[u8; N]> for SecretBytesArray<N> {
    fn from(value: [u8; N]) -> Self {
        Self(value)
    }
}

impl<const N: usize> TryFrom<Vec<u8>> for SecretBytesArray<N> {
    type Error = &'static str;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(Self(
            TryInto::<[u8; N]>::try_into(value).map_err(|_| "incorrectly sized secret array")?,
        ))
    }
}

#[derive(Clone, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct SecretBytesVec(#[serde(with = "bytes")] Vec<u8>);

impl SecretBytesVec {
    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }
}

impl Zeroize for SecretBytesVec {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for SecretBytesVec {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Debug for SecretBytesVec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytesVec(REDACTED)")
    }
}

impl From<Vec<u8>> for SecretBytesVec {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

#[derive(Clone, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct SecretString(String);

impl SecretString {
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl Zeroize for SecretString {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString(REDACTED)")
    }
}

impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self(value)
    }
}

pub type OprfCipherSuite = voprf::Ristretto255;
pub type OprfBlindedElement = voprf::BlindedElement<OprfCipherSuite>;
pub type OprfEvaluationElement = voprf::EvaluationElement<OprfCipherSuite>;
pub type OprfClient = voprf::OprfClient<OprfCipherSuite>;
pub type OprfServer = voprf::OprfServer<OprfCipherSuite>;
pub type OprfHash = digest::Output<<OprfCipherSuite as voprf::CipherSuite>::Hash>;
pub const OPRF_KEY_INFO: &[u8] = b"juicebox-oprf";

#[derive(Debug)]
pub struct OprfResult(SecretBytesArray<64>);

impl From<OprfHash> for OprfResult {
    fn from(value: OprfHash) -> Self {
        Self(SecretBytesArray(Into::<[u8; 64]>::into(value)))
    }
}

impl From<[u8; 64]> for OprfResult {
    fn from(value: [u8; 64]) -> Self {
        Self(SecretBytesArray::from(value))
    }
}

impl OprfResult {
    pub fn expose_secret(&self) -> &[u8; 64] {
        self.0.expose_secret()
    }

    pub fn as_scalar(&self) -> Scalar {
        Scalar::from_bytes_mod_order(Blake2s256::digest(self.expose_secret()).into())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OprfBlindedInput(SecretBytesArray<32>);

impl From<OprfBlindedElement> for OprfBlindedInput {
    fn from(value: OprfBlindedElement) -> Self {
        Self(SecretBytesArray::from(Into::<[u8; 32]>::into(
            value.serialize(),
        )))
    }
}

impl From<[u8; 32]> for OprfBlindedInput {
    fn from(value: [u8; 32]) -> Self {
        Self(SecretBytesArray::from(value))
    }
}

impl OprfBlindedInput {
    pub fn expose_secret(&self) -> OprfBlindedElement {
        OprfBlindedElement::deserialize(self.0.expose_secret()).expect("invalid blinded element")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OprfBlindedResult(SecretBytesArray<32>);

impl From<OprfEvaluationElement> for OprfBlindedResult {
    fn from(value: OprfEvaluationElement) -> Self {
        Self(SecretBytesArray::from(Into::<[u8; 32]>::into(
            value.serialize(),
        )))
    }
}

impl From<[u8; 32]> for OprfBlindedResult {
    fn from(value: [u8; 32]) -> Self {
        Self(SecretBytesArray::from(value))
    }
}

impl OprfBlindedResult {
    pub fn expose_secret(&self) -> OprfEvaluationElement {
        OprfEvaluationElement::deserialize(self.0.expose_secret())
            .expect("invalid evaluation element")
    }
}

/// A private root seed derived by the client and used
/// to derive the per-realm [`OprfSeed`].
pub struct OprfRootSeed(SecretBytesArray<32>);

impl OprfRootSeed {
    pub fn derive(
        unlock_key_scalar_hash: &UnlockKeyScalarHash,
        user_secret_access_key: &UserSecretAccessKey,
    ) -> Self {
        let label = b"Oprf Root Seed";
        let oprf_root_seed: [u8; 32] =
            <Blake2sMac256 as Mac>::new(unlock_key_scalar_hash.expose_secret().into())
                .chain_update((label.len() as u32).to_le_bytes())
                .chain_update(label)
                .chain_update((user_secret_access_key.expose_secret().len() as u32).to_le_bytes())
                .chain_update(user_secret_access_key.expose_secret())
                .finalize()
                .into_bytes()
                .into();
        Self(SecretBytesArray::from(oprf_root_seed))
    }

    pub fn expose_secret(&self) -> &[u8; 32] {
        self.0.expose_secret()
    }
}

/// A private per-realm oprf seed derived by the client from
/// the [`OprfRootSeed`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OprfSeed(SecretBytesArray<32>);

impl OprfSeed {
    pub fn derive(root_seed: &OprfRootSeed, realm_id: &RealmId) -> Self {
        let label = b"Oprf Seed";
        let seed: [u8; 32] = <Blake2sMac256 as Mac>::new(root_seed.expose_secret().into())
            .chain_update((label.len() as u32).to_le_bytes())
            .chain_update(label)
            .chain_update((realm_id.0.len() as u32).to_le_bytes())
            .chain_update(realm_id.0)
            .finalize()
            .into_bytes()
            .into();
        Self::from(seed)
    }

    pub fn expose_secret(&self) -> &[u8; 32] {
        self.0.expose_secret()
    }
}

impl From<[u8; 32]> for OprfSeed {
    fn from(value: [u8; 32]) -> Self {
        Self(SecretBytesArray::from(value))
    }
}

/// A unique identifier for a realm.
///
/// A realm is a remote service that clients interact with to register and
/// recover their PIN-protected secrets. Clients distribute their trust across
/// multiple realms, which can run different software and hardware and can be
/// operated independently.
#[derive(Copy, Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct RealmId(#[serde(with = "bytes")] pub [u8; 16]);

impl RealmId {
    /// Generates a new id with random data.
    pub fn new_random<T: RngCore + CryptoRng + Send>(rng: &mut T) -> Self {
        let mut id = [0; 16];
        rng.fill_bytes(&mut id);
        Self(id)
    }
}

impl Debug for RealmId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for RealmId {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let vec = hex::decode(s.replace('-', "")).map_err(|_| "failed to decode hex id")?;
        Ok(Self(vec.try_into().map_err(|_| "invalid id length")?))
    }
}

/// Represents the authority to act as a particular user.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuthToken(pub SecretString);

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

/// A unique version used to determine if different realms represent the
/// same registration.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct RegistrationVersion(SecretBytesArray<16>);

impl RegistrationVersion {
    /// Generates a new version with random data.
    pub fn new_random<T: RngCore + CryptoRng + Send>(rng: &mut T) -> Self {
        let mut version = [0; 16];
        rng.fill_bytes(&mut version);
        Self::from(version)
    }

    pub fn expose_secret(&self) -> &[u8; 16] {
        self.0.expose_secret()
    }
}

impl From<[u8; 16]> for RegistrationVersion {
    fn from(value: [u8; 16]) -> Self {
        Self(SecretBytesArray::from(value))
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

/// A share of the encryption key scalar.
///
/// The client needs a threshold number of such shares, along with the PIN,
/// to recover the user's encryption key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserSecretEncryptionKeyScalarShare(SecretBytesArray<32>);

impl UserSecretEncryptionKeyScalarShare {
    /// Access the underlying secret bytes.
    pub fn expose_secret(&self) -> &[u8; 32] {
        self.0.expose_secret()
    }

    pub fn as_scalar(&self) -> Scalar {
        Scalar::from_canonical_bytes(*self.expose_secret()).unwrap()
    }
}

impl From<[u8; 32]> for UserSecretEncryptionKeyScalarShare {
    fn from(value: [u8; 32]) -> Self {
        Self::from(Scalar::from_canonical_bytes(value).unwrap())
    }
}

impl From<Scalar> for UserSecretEncryptionKeyScalarShare {
    fn from(value: Scalar) -> Self {
        Self(SecretBytesArray::from(value.to_bytes()))
    }
}

/// A padded and encrypted copy of the user's secret.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct EncryptedUserSecret(SecretBytesArray<145>);

impl EncryptedUserSecret {
    /// Access the underlying secret bytes.
    pub fn expose_secret(&self) -> &[u8; 145] {
        self.0.expose_secret()
    }
}

impl TryFrom<Vec<u8>> for EncryptedUserSecret {
    type Error = &'static str;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(Self(SecretBytesArray::try_from(value)?))
    }
}

impl From<[u8; 145]> for EncryptedUserSecret {
    fn from(value: [u8; 145]) -> Self {
        Self(SecretBytesArray::from(value))
    }
}

/// An access key derived from the user's PIN, used to recover
/// and register the user's secret.
#[derive(Clone, Debug)]
pub struct UserSecretAccessKey(SecretBytesArray<32>);

impl UserSecretAccessKey {
    /// Access the underlying secret bytes.
    pub fn expose_secret(&self) -> &[u8; 32] {
        self.0.expose_secret()
    }
}

impl From<[u8; 32]> for UserSecretAccessKey {
    fn from(value: [u8; 32]) -> Self {
        Self(SecretBytesArray::from(value))
    }
}

/// Defines restrictions on how a secret may be accessed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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

/// A derived key that is used to derive secret-unlocking tags ([`UnlockKeyTag`])
/// for each realm.
///
/// This key is derived from the random [`UnlockKeyScalar`].
pub struct UnlockKey(SecretBytesArray<32>);

impl UnlockKey {
    pub fn derive(hash: &UnlockKeyScalarHash) -> Self {
        let label = b"Unlock Key";
        let mac: [u8; 32] = <Blake2sMac256 as Mac>::new(hash.expose_secret().into())
            .chain_update((label.len() as u32).to_le_bytes())
            .chain_update(label)
            .finalize()
            .into_bytes()
            .into();
        Self(SecretBytesArray::from(mac))
    }

    pub fn expose_secret(&self) -> &[u8; 32] {
        self.0.expose_secret()
    }
}

impl From<[u8; 32]> for UnlockKey {
    fn from(value: [u8; 32]) -> Self {
        Self(SecretBytesArray::from(value))
    }
}

/// A share of the [`UnlockKeyScalar`] that has been added to a scalar
/// derived from an [`OprfResult`].
///
/// The client sends this to a realm during registration and gets it back from
/// the realm during recovery.
///
/// The client needs the correct PIN and a threshold number of such shares and
/// OPRF results to recover the unlock key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MaskedUnlockKeyScalarShare(SecretBytesArray<32>);

impl MaskedUnlockKeyScalarShare {
    pub fn expose_secret(&self) -> &[u8; 32] {
        self.0.expose_secret()
    }

    pub fn as_scalar(&self) -> Scalar {
        Scalar::from_canonical_bytes(*self.expose_secret()).unwrap()
    }
}

impl From<[u8; 32]> for MaskedUnlockKeyScalarShare {
    fn from(value: [u8; 32]) -> Self {
        Self::from(Scalar::from_canonical_bytes(value).unwrap())
    }
}

impl From<Scalar> for MaskedUnlockKeyScalarShare {
    fn from(value: Scalar) -> Self {
        Self(SecretBytesArray::from(value.to_bytes()))
    }
}

/// A hash of the [`UnlockKeyScalar`] used to derive the
/// [`UnlockKey`] and the [`UnlockKeyCommitment`]
pub struct UnlockKeyScalarHash(SecretBytesArray<32>);

impl UnlockKeyScalarHash {
    pub fn expose_secret(&self) -> &[u8; 32] {
        self.0.expose_secret()
    }
}

impl From<[u8; 32]> for UnlockKeyScalarHash {
    fn from(value: [u8; 32]) -> Self {
        UnlockKeyScalarHash(SecretBytesArray::from(value))
    }
}

/// A pseudo-random value that the client assigns to a realm when registering a
/// share of the user's secret and must provide to the realm during recovery to
/// get back the share.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UnlockKeyTag(SecretBytesArray<16>);

impl ConstantTimeEq for UnlockKeyTag {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.expose_secret().ct_eq(other.expose_secret())
    }
}

impl UnlockKeyTag {
    /// Computes a derived secret-unlocking tag for the realm.
    pub fn derive(unlock_key: &UnlockKey, realm_id: &RealmId) -> Self {
        let label = b"Unlock Key Tag";
        let mac: [u8; 32] = <Blake2sMac256 as Mac>::new(unlock_key.expose_secret().into())
            .chain_update((label.len() as u32).to_le_bytes())
            .chain_update(label)
            .chain_update((realm_id.0.len() as u32).to_le_bytes())
            .chain_update(realm_id.0)
            .finalize()
            .into_bytes()
            .into();
        let mac_prefix: [u8; 16] = mac[..16].try_into().unwrap();
        Self::from(mac_prefix)
    }

    pub fn expose_secret(&self) -> &[u8; 16] {
        self.0.expose_secret()
    }
}

impl From<[u8; 16]> for UnlockKeyTag {
    fn from(value: [u8; 16]) -> Self {
        Self(SecretBytesArray::from(value))
    }
}

/// A commitment used to verify correctness of a realm
/// before using its [`UserSecretEncryptionKeyScalarShare`]
/// in recovery and avoid a Denial-of-Service attack by
/// a misbheaving realm.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedUserSecretCommitment(SecretBytesArray<16>);

impl ConstantTimeEq for EncryptedUserSecretCommitment {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.expose_secret().ct_eq(other.expose_secret())
    }
}

impl EncryptedUserSecretCommitment {
    pub fn derive(
        unlock_key: &UnlockKey,
        realm_id: &RealmId,
        encryption_key_scalar_share: &UserSecretEncryptionKeyScalarShare,
        encrypted_secret: &EncryptedUserSecret,
    ) -> Self {
        let label = b"Encrypted User Secret Commitment";
        let mac: [u8; 32] = <Blake2sMac256 as Mac>::new(unlock_key.expose_secret().into())
            .chain_update((label.len() as u32).to_le_bytes())
            .chain_update(label)
            .chain_update((realm_id.0.len() as u32).to_le_bytes())
            .chain_update(realm_id.0)
            .chain_update((encryption_key_scalar_share.expose_secret().len() as u32).to_le_bytes())
            .chain_update(encryption_key_scalar_share.expose_secret())
            .chain_update((encrypted_secret.expose_secret().len() as u32).to_le_bytes())
            .chain_update(encrypted_secret.expose_secret())
            .finalize()
            .into_bytes()
            .into();
        let mac_prefix: [u8; 16] = mac[..16].try_into().unwrap();
        Self::from(mac_prefix)
    }

    pub fn expose_secret(&self) -> &[u8; 16] {
        self.0.expose_secret()
    }
}

impl From<[u8; 16]> for EncryptedUserSecretCommitment {
    fn from(value: [u8; 16]) -> Self {
        Self(SecretBytesArray::from(value))
    }
}

/// A commitment used to verify recovery of an [`UnlockKey`] and
/// from a set of realms and avoid a Denial-of-Service attack by
/// a misbheaving realm.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct UnlockKeyCommitment(SecretBytesArray<32>);

impl ConstantTimeEq for UnlockKeyCommitment {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.expose_secret().ct_eq(other.expose_secret())
    }
}

impl UnlockKeyCommitment {
    pub fn derive(hash: &UnlockKeyScalarHash, access_key: &UserSecretAccessKey) -> Self {
        let commitment_label = b"Unlock Key Commitment";
        let mac: [u8; 32] = <Blake2sMac256 as Mac>::new(hash.expose_secret().into())
            .chain_update((commitment_label.len() as u32).to_le_bytes())
            .chain_update(commitment_label)
            .chain_update((access_key.expose_secret().len() as u32).to_le_bytes())
            .chain_update(access_key.expose_secret())
            .finalize()
            .into_bytes()
            .into();
        Self(SecretBytesArray::from(mac))
    }

    pub fn expose_secret(&self) -> &[u8; 32] {
        self.0.expose_secret()
    }
}

impl From<[u8; 32]> for UnlockKeyCommitment {
    fn from(value: [u8; 32]) -> Self {
        Self(SecretBytesArray::from(value))
    }
}

#[cfg(test)]
mod tests {
    use crate::types::{SecretBytesArray, SecretBytesVec};
    use zeroize::Zeroize;

    #[test]
    fn test_secret_byte_vec_redaction() {
        let secret_bytes = SecretBytesVec::from(b"some secret".to_vec());
        assert_eq!(format!("{:?}", secret_bytes), "SecretBytesVec(REDACTED)");
    }

    #[test]
    fn test_secret_byte_vec_zeroize() {
        let mut secret_bytes = SecretBytesVec::from(b"some secret".to_vec());
        secret_bytes.zeroize();
        assert_eq!(secret_bytes, SecretBytesVec::from(vec![]));
    }

    #[test]
    fn test_secret_byte_array_redaction() {
        let secret_bytes = SecretBytesArray::from([5; 32]);
        assert_eq!(format!("{:?}", secret_bytes), "SecretBytesArray(REDACTED)");
    }

    #[test]
    fn test_secret_byte_array_zeroize() {
        let mut secret_bytes = SecretBytesArray::from([5; 32]);
        secret_bytes.zeroize();
        assert_eq!(secret_bytes, SecretBytesArray::from([0; 32]));
    }
}
