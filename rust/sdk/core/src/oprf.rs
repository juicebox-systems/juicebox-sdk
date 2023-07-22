use blake2::{Blake2b512, Digest};
use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint, Scalar};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::types::{SecretBytesArray, UnlockKey, UnlockKeyCommitment};

#[derive(Debug)]
pub struct OprfResult(SecretBytesArray<64>);

impl OprfResult {
    pub fn evaluate(key: &OprfKey, input: &[u8]) -> Self {
        let result_point =
            key.as_scalar() * RistrettoPoint::from_uniform_bytes(&Blake2b512::digest(input).into());
        let result_hash: [u8; 64] = Blake2b512::digest(result_point.compress().as_bytes()).into();
        Self::from(result_hash)
    }

    pub fn blind_evaluate(
        blinding_factor: &OprfBlindingFactor,
        blinded_result: &OprfBlindedResult,
    ) -> Self {
        let result_point = blinding_factor.as_scalar().invert() * blinded_result.as_point();
        let result_hash: [u8; 64] = Blake2b512::digest(result_point.compress().as_bytes()).into();
        Self::from(result_hash)
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

    pub fn derive_commitment_and_key(&self) -> (UnlockKeyCommitment, UnlockKey) {
        let digest: [u8; 64] = Blake2b512::digest(self.expose_secret()).into();
        let commitment_bytes: [u8; 32] = digest[..32].try_into().unwrap();
        let key_bytes: [u8; 32] = digest[32..].try_into().unwrap();
        (
            UnlockKeyCommitment::from(commitment_bytes),
            UnlockKey::from(key_bytes),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OprfBlindingFactor(SecretBytesArray<32>);

impl OprfBlindingFactor {
    pub fn new_random<Rng: RngCore + CryptoRng + Send>(rng: &mut Rng) -> Self {
        Self::from(Scalar::random(rng))
    }

    pub fn expose_secret(&self) -> &[u8; 32] {
        self.0.expose_secret()
    }

    pub fn as_scalar(&self) -> Scalar {
        Scalar::from_canonical_bytes(*self.expose_secret()).unwrap()
    }
}

impl From<Scalar> for OprfBlindingFactor {
    fn from(value: Scalar) -> Self {
        Self(SecretBytesArray::from(value.to_bytes()))
    }
}

impl From<[u8; 32]> for OprfBlindingFactor {
    fn from(value: [u8; 32]) -> Self {
        Self::from(Scalar::from_canonical_bytes(value).unwrap())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OprfBlindedInput(SecretBytesArray<32>);

impl From<[u8; 32]> for OprfBlindedInput {
    fn from(value: [u8; 32]) -> Self {
        Self(SecretBytesArray::from(value))
    }
}

impl From<&RistrettoPoint> for OprfBlindedInput {
    fn from(value: &RistrettoPoint) -> Self {
        Self::from(value.compress().to_bytes())
    }
}

impl OprfBlindedInput {
    pub fn new<Rng: RngCore + CryptoRng + Send>(
        input: &[u8],
        rng: &mut Rng,
    ) -> (Self, OprfBlindingFactor) {
        let blinding_factor = OprfBlindingFactor::new_random(rng);
        (
            Self::new_deterministic(&blinding_factor, input),
            blinding_factor,
        )
    }

    pub fn new_deterministic(blinding_factor: &OprfBlindingFactor, input: &[u8]) -> Self {
        let input_hash: [u8; 64] = Blake2b512::digest(input).into();
        let input_point = RistrettoPoint::from_uniform_bytes(&input_hash);
        Self::from(
            (input_point * blinding_factor.as_scalar())
                .compress()
                .to_bytes(),
        )
    }

    pub fn expose_secret(&self) -> &[u8; 32] {
        self.0.expose_secret()
    }

    pub fn as_point(&self) -> RistrettoPoint {
        CompressedRistretto::from_slice(self.expose_secret())
            .unwrap()
            .decompress()
            .unwrap()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OprfBlindedResult(SecretBytesArray<32>);

impl From<[u8; 32]> for OprfBlindedResult {
    fn from(value: [u8; 32]) -> Self {
        Self(SecretBytesArray::from(value))
    }
}

impl From<&RistrettoPoint> for OprfBlindedResult {
    fn from(value: &RistrettoPoint) -> Self {
        Self::from(value.compress().to_bytes())
    }
}

impl OprfBlindedResult {
    pub fn new(key: &OprfKey, blinded_input: &OprfBlindedInput) -> Self {
        let result = key.as_scalar() * blinded_input.as_point();
        Self::from(result.compress().to_bytes())
    }

    pub fn expose_secret(&self) -> &[u8; 32] {
        self.0.expose_secret()
    }

    pub fn as_point(&self) -> RistrettoPoint {
        CompressedRistretto::from_slice(self.expose_secret())
            .unwrap()
            .decompress()
            .unwrap()
    }
}

/// A share of the root oprf key scalar, utilized as a per-realm oprf key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OprfKey(SecretBytesArray<32>);

impl OprfKey {
    pub fn new_random<T: RngCore + CryptoRng + Send>(rng: &mut T) -> Self {
        Self::from(Scalar::random(rng))
    }

    pub fn expose_secret(&self) -> &[u8; 32] {
        self.0.expose_secret()
    }

    pub fn as_scalar(&self) -> Scalar {
        Scalar::from_canonical_bytes(*self.expose_secret()).unwrap()
    }
}

impl From<[u8; 32]> for OprfKey {
    fn from(value: [u8; 32]) -> Self {
        Self::from(Scalar::from_canonical_bytes(value).unwrap())
    }
}

impl From<Scalar> for OprfKey {
    fn from(value: Scalar) -> Self {
        Self(SecretBytesArray::from(value.to_bytes()))
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_oprf_result() {
        let secret = b"artemis";
        let key = OprfKey::from([
            29, 181, 125, 159, 44, 121, 25, 81, 214, 74, 46, 197, 64, 127, 189, 119, 195, 77, 22,
            114, 136, 198, 73, 191, 65, 81, 63, 225, 149, 208, 21, 15,
        ]);
        let blinding_factor = OprfBlindingFactor::from([
            29, 150, 89, 69, 129, 23, 32, 163, 176, 242, 76, 179, 51, 121, 96, 3, 134, 11, 8, 71,
            141, 200, 214, 29, 206, 26, 140, 188, 180, 212, 233, 14,
        ]);

        let blinded_input = OprfBlindedInput::new_deterministic(&blinding_factor, secret);
        assert_eq!(
            blinded_input.expose_secret(),
            &[
                108, 120, 154, 208, 220, 142, 12, 171, 2, 35, 125, 188, 49, 51, 143, 183, 195, 234,
                98, 143, 46, 97, 2, 207, 245, 135, 32, 112, 121, 209, 141, 126
            ]
        );

        let blinded_result = OprfBlindedResult::new(&key, &blinded_input);
        assert_eq!(
            blinded_result.expose_secret(),
            &[
                46, 211, 185, 145, 237, 111, 103, 242, 217, 87, 185, 172, 8, 120, 1, 100, 117, 47,
                199, 213, 213, 17, 17, 244, 124, 154, 101, 215, 247, 232, 130, 119
            ]
        );

        let blinded_evaluate_result = OprfResult::blind_evaluate(&blinding_factor, &blinded_result);
        assert_eq!(
            blinded_evaluate_result.expose_secret(),
            &[
                51, 160, 133, 43, 187, 77, 218, 232, 66, 58, 98, 71, 205, 128, 182, 119, 91, 179,
                207, 200, 235, 101, 250, 127, 251, 75, 10, 8, 24, 64, 80, 161, 145, 124, 14, 212,
                45, 202, 204, 192, 224, 99, 36, 181, 31, 119, 180, 14, 197, 232, 186, 172, 183,
                195, 195, 204, 231, 100, 183, 15, 121, 35, 192, 147
            ]
        );

        let evaluate_result = OprfResult::evaluate(&key, secret);
        assert_eq!(
            evaluate_result.expose_secret(),
            blinded_evaluate_result.expose_secret()
        );
    }
}
