use blake2::{Blake2b512, Digest};
use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint, Scalar};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use juicebox_sdk_marshalling::bytes;

use crate::types::SecretBytesArray;

#[derive(Debug)]
pub struct OprfResult(SecretBytesArray<64>);

impl OprfResult {
    pub fn evaluate(key: &OprfKey, input: &[u8]) -> Self {
        let input_hash = Blake2b512::digest(input).into();
        let result_point = key.as_scalar() * RistrettoPoint::from_uniform_bytes(&input_hash);
        let result_hash: [u8; 64] = Blake2b512::new()
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
        let result_hash: [u8; 64] = Blake2b512::new()
            .chain_update(Blake2b512::digest(input))
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
        let input_hash: [u8; 64] = Blake2b512::digest(input).into();
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
                108, 120, 154, 208, 220, 142, 12, 171, 2, 35, 125, 188, 49, 51, 143, 183, 195, 234,
                98, 143, 46, 97, 2, 207, 245, 135, 32, 112, 121, 209, 141, 126
            ]
        );

        let blinded_result = OprfBlindedResult::new(&key, &blinded_input);
        assert_eq!(
            blinded_result.as_point().compress().as_bytes(),
            &[
                46, 211, 185, 145, 237, 111, 103, 242, 217, 87, 185, 172, 8, 120, 1, 100, 117, 47,
                199, 213, 213, 17, 17, 244, 124, 154, 101, 215, 247, 232, 130, 119
            ]
        );

        let blinded_evaluate_result =
            OprfResult::blind_evaluate(&blinding_factor, &blinded_result, secret);
        assert_eq!(
            blinded_evaluate_result.expose_secret(),
            &[
                166, 13, 57, 28, 156, 172, 104, 98, 203, 124, 46, 72, 87, 126, 195, 201, 80, 211,
                135, 165, 141, 117, 173, 155, 157, 8, 133, 206, 121, 162, 69, 157, 146, 62, 65,
                109, 255, 12, 38, 39, 10, 52, 186, 48, 46, 96, 57, 40, 203, 73, 167, 134, 146, 1,
                183, 123, 133, 254, 81, 77, 205, 247, 126, 128
            ]
        );

        let evaluate_result = OprfResult::evaluate(&key, secret);
        assert_eq!(
            evaluate_result.expose_secret(),
            blinded_evaluate_result.expose_secret()
        );
    }
}
