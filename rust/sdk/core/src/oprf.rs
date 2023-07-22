use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint, Scalar};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

use juicebox_sdk_marshalling::bytes;

use crate::types::SecretBytesArray;

#[derive(Debug)]
pub struct OprfResult(SecretBytesArray<64>);

impl OprfResult {
    pub fn evaluate(key: &OprfKey, input: &[u8]) -> Self {
        let input_hash = Sha512::digest(input).into();
        let result_point = key.as_scalar() * RistrettoPoint::from_uniform_bytes(&input_hash);
        let result_hash: [u8; 64] = Sha512::new()
            .chain_update(input_hash)
            .chain_update(result_point.compress().as_bytes())
            .finalize()
            .into();
        Self::from(result_hash)
    }

    pub fn blind_evaluate(
        blinding_factor: &OprfBlindingFactor,
        blinded_result: &OprfBlindedResult,
        input: &[u8],
    ) -> Self {
        let result_point = blinding_factor.as_scalar().invert() * blinded_result.as_point();
        let result_hash: [u8; 64] = Sha512::new()
            .chain_update(Sha512::digest(input))
            .chain_update(result_point.compress().as_bytes())
            .finalize()
            .into();
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
}

#[derive(Debug)]
pub struct OprfBlindingFactor(Scalar);

impl OprfBlindingFactor {
    pub fn new_random<Rng: RngCore + CryptoRng + Send>(rng: &mut Rng) -> Self {
        Self(Scalar::random(rng))
    }

    pub fn as_scalar(&self) -> &Scalar {
        &self.0
    }

    pub fn to_scalar(&self) -> Scalar {
        self.0
    }
}

impl From<Scalar> for OprfBlindingFactor {
    fn from(value: Scalar) -> Self {
        Self(value)
    }
}

impl TryFrom<[u8; 32]> for OprfBlindingFactor {
    type Error = &'static str;

    fn try_from(value: [u8; 32]) -> Result<Self, Self::Error> {
        Ok(Self(
            Option::from(Scalar::from_canonical_bytes(value)).ok_or("invalid scalar")?,
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OprfBlindedInput(#[serde(with = "bytes")] RistrettoPoint);

impl From<RistrettoPoint> for OprfBlindedInput {
    fn from(value: RistrettoPoint) -> Self {
        Self(value)
    }
}

impl TryFrom<[u8; 32]> for OprfBlindedInput {
    type Error = &'static str;

    fn try_from(value: [u8; 32]) -> Result<Self, Self::Error> {
        Ok(Self(
            CompressedRistretto(value)
                .decompress()
                .ok_or("invalid point")?,
        ))
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
        let input_hash: [u8; 64] = Sha512::digest(input).into();
        let input_point = RistrettoPoint::from_uniform_bytes(&input_hash);
        Self(input_point * blinding_factor.as_scalar())
    }

    pub fn as_point(&self) -> &RistrettoPoint {
        &self.0
    }

    pub fn to_point(&self) -> RistrettoPoint {
        self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OprfBlindedResult(#[serde(with = "bytes")] RistrettoPoint);

impl From<RistrettoPoint> for OprfBlindedResult {
    fn from(value: RistrettoPoint) -> Self {
        Self(value)
    }
}

impl TryFrom<[u8; 32]> for OprfBlindedResult {
    type Error = &'static str;

    fn try_from(value: [u8; 32]) -> Result<Self, Self::Error> {
        Ok(Self(
            CompressedRistretto(value)
                .decompress()
                .ok_or("invalid point")?,
        ))
    }
}

impl OprfBlindedResult {
    pub fn new(key: &OprfKey, blinded_input: &OprfBlindedInput) -> Self {
        let result = key.as_scalar() * blinded_input.as_point();
        Self(result)
    }

    pub fn as_point(&self) -> &RistrettoPoint {
        &self.0
    }

    pub fn to_point(&self) -> RistrettoPoint {
        self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OprfKey(#[serde(with = "bytes")] Scalar);

impl OprfKey {
    pub fn new_random<T: RngCore + CryptoRng + Send>(rng: &mut T) -> Self {
        Self(Scalar::random(rng))
    }

    pub fn as_scalar(&self) -> &Scalar {
        &self.0
    }

    pub fn to_scalar(&self) -> Scalar {
        self.0
    }
}

impl From<Scalar> for OprfKey {
    fn from(value: Scalar) -> Self {
        Self(value)
    }
}

impl TryFrom<[u8; 32]> for OprfKey {
    type Error = &'static str;

    fn try_from(value: [u8; 32]) -> Result<Self, Self::Error> {
        Ok(Self(
            Option::from(Scalar::from_canonical_bytes(value)).ok_or("invalid scalar")?,
        ))
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_oprf_result() {
        let secret = b"artemis";
        let key = OprfKey::try_from([
            29, 181, 125, 159, 44, 121, 25, 81, 214, 74, 46, 197, 64, 127, 189, 119, 195, 77, 22,
            114, 136, 198, 73, 191, 65, 81, 63, 225, 149, 208, 21, 15,
        ])
        .unwrap();
        let blinding_factor = OprfBlindingFactor::try_from([
            29, 150, 89, 69, 129, 23, 32, 163, 176, 242, 76, 179, 51, 121, 96, 3, 134, 11, 8, 71,
            141, 200, 214, 29, 206, 26, 140, 188, 180, 212, 233, 14,
        ])
        .unwrap();

        let blinded_input = OprfBlindedInput::new_deterministic(&blinding_factor, secret);
        assert_eq!(
            blinded_input.as_point().compress().as_bytes(),
            &[
                116, 97, 37, 114, 167, 113, 232, 226, 76, 200, 142, 210, 253, 211, 197, 200, 96,
                217, 79, 195, 192, 3, 215, 24, 215, 88, 11, 23, 88, 187, 37, 78
            ]
        );

        let blinded_result = OprfBlindedResult::new(&key, &blinded_input);
        assert_eq!(
            blinded_result.as_point().compress().as_bytes(),
            &[
                246, 19, 49, 96, 5, 159, 137, 58, 236, 248, 150, 174, 77, 79, 156, 116, 103, 103,
                4, 188, 140, 8, 190, 17, 79, 143, 205, 140, 121, 35, 79, 120
            ]
        );

        let blinded_evaluate_result =
            OprfResult::blind_evaluate(&blinding_factor, &blinded_result, secret);
        assert_eq!(
            blinded_evaluate_result.expose_secret(),
            &[
                11, 50, 119, 87, 118, 83, 26, 193, 165, 194, 90, 59, 10, 9, 249, 10, 34, 86, 26,
                111, 187, 234, 37, 91, 85, 237, 206, 177, 255, 185, 159, 14, 192, 102, 28, 50, 136,
                56, 4, 230, 83, 170, 203, 114, 84, 199, 206, 155, 54, 59, 228, 160, 206, 61, 239,
                65, 238, 235, 30, 98, 16, 89, 95, 240
            ]
        );

        let evaluate_result = OprfResult::evaluate(&key, secret);
        assert_eq!(
            evaluate_result.expose_secret(),
            blinded_evaluate_result.expose_secret()
        );
    }
}
