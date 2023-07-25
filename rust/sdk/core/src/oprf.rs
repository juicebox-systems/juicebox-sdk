use curve25519_dalek::{
    edwards::CompressedEdwardsY, ristretto::CompressedRistretto, RistrettoPoint, Scalar,
};
use ed25519_dalek::{Signature, SignatureError, Signer, SigningKey, VerifyingKey};
use elliptic_curve::hash2curve::{ExpandMsg, ExpandMsgXmd, Expander};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

use juicebox_sdk_marshalling::bytes;

use crate::types::{i2osp_2, SecretBytesArray};

#[derive(Debug)]
pub struct OprfResult(SecretBytesArray<64>);

impl OprfResult {
    pub fn evaluate(key: &OprfPrivateKey, input: &[u8]) -> Self {
        let evaluated_element = key.as_scalar() * hash_to_group(input);
        Self::new(&evaluated_element, input)
    }

    pub fn blind_evaluate(
        blinding_factor: &OprfBlindingFactor,
        blinded_result: &OprfBlindedResult,
        input: &[u8],
    ) -> Self {
        let evaluated_element = blinding_factor.as_scalar().invert() * blinded_result.as_point();
        Self::new(&evaluated_element, input)
    }

    fn new(evaluated_element: &RistrettoPoint, input: &[u8]) -> Self {
        let result_hash: [u8; 64] = Sha512::new()
            .chain_update(i2osp_2(input.len()))
            .chain_update(input)
            .chain_update(i2osp_2(32))
            .chain_update(evaluated_element.compress().as_bytes())
            .chain_update(b"Finalize")
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
        Self(blinding_factor.as_scalar() * hash_to_group(input))
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
    pub fn new(key: &OprfPrivateKey, blinded_input: &OprfBlindedInput) -> Self {
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
pub struct OprfPrivateKey(#[serde(with = "bytes")] Scalar);

impl OprfPrivateKey {
    pub fn new_random<T: RngCore + CryptoRng + Send>(rng: &mut T) -> Self {
        Self(Scalar::random(rng))
    }

    pub fn public_key(&self) -> OprfPublicKey {
        OprfPublicKey(RistrettoPoint::mul_base(self.as_scalar()))
    }

    pub fn as_scalar(&self) -> &Scalar {
        &self.0
    }

    pub fn to_scalar(&self) -> Scalar {
        self.0
    }
}

impl From<Scalar> for OprfPrivateKey {
    fn from(value: Scalar) -> Self {
        Self(value)
    }
}

impl TryFrom<[u8; 32]> for OprfPrivateKey {
    type Error = &'static str;

    fn try_from(value: [u8; 32]) -> Result<Self, Self::Error> {
        Ok(Self(
            Option::from(Scalar::from_canonical_bytes(value)).ok_or("invalid scalar")?,
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OprfPublicKey(#[serde(with = "bytes")] RistrettoPoint);

impl OprfPublicKey {
    pub fn to_signed(&self, signing_key: &OprfSigningKey) -> OprfSignedPublicKey {
        let signature = signing_key.0.sign(self.as_point().compress().as_bytes());
        OprfSignedPublicKey {
            public_key: self.clone(),
            verifying_key: signing_key.verifying_key(),
            signature: SecretBytesArray::from(signature.to_bytes()),
        }
    }

    pub fn as_point(&self) -> &RistrettoPoint {
        &self.0
    }

    pub fn to_point(&self) -> RistrettoPoint {
        self.0
    }
}

impl From<RistrettoPoint> for OprfPublicKey {
    fn from(value: RistrettoPoint) -> Self {
        Self(value)
    }
}

impl TryFrom<[u8; 32]> for OprfPublicKey {
    type Error = &'static str;

    fn try_from(value: [u8; 32]) -> Result<Self, Self::Error> {
        Ok(Self(
            CompressedRistretto(value)
                .decompress()
                .ok_or("invalid point")?,
        ))
    }
}

#[derive(Debug)]
pub struct OprfSigningKey(SigningKey);

impl OprfSigningKey {
    pub fn new_random<T: RngCore + CryptoRng + Send>(rng: &mut T) -> Self {
        Self(SigningKey::generate(rng))
    }

    pub fn verifying_key(&self) -> OprfVerifyingKey {
        OprfVerifyingKey(CompressedEdwardsY(self.0.verifying_key().to_bytes()))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct OprfVerifyingKey(#[serde(with = "bytes")] CompressedEdwardsY);

impl From<[u8; 32]> for OprfVerifyingKey {
    fn from(value: [u8; 32]) -> Self {
        Self(CompressedEdwardsY(value))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OprfSignedPublicKey {
    pub public_key: OprfPublicKey,
    pub verifying_key: OprfVerifyingKey,
    pub signature: SecretBytesArray<64>,
}

impl OprfSignedPublicKey {
    pub fn verify(&self) -> Result<(), SignatureError> {
        VerifyingKey::from(
            self.verifying_key
                .0
                .decompress()
                .ok_or(SignatureError::default())?,
        )
        .verify_strict(
            self.public_key.as_point().compress().as_bytes(),
            &Signature::from(self.signature.expose_secret()),
        )
    }
}

fn hash_to_group(input: &[u8]) -> RistrettoPoint {
    let mut uniform_bytes = [0u8; 64];
    ExpandMsgXmd::<Sha512>::expand_message(
        &[input],
        &[b"HashToGroup-OPRFV1-\0-ristretto255-SHA512"],
        64,
    )
    .unwrap()
    .fill_bytes(&mut uniform_bytes);

    RistrettoPoint::from_uniform_bytes(&uniform_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Vector<'a> {
        key: [u8; 32],             // skSm
        input: &'a [u8],           // Input
        blinding_factor: [u8; 32], // Blind
        blinded_input: [u8; 32],   // BlindedElement
        blinded_result: [u8; 32],  // EvaluationElement
        result: [u8; 64],          // Output
    }

    #[test]
    fn test_oprf_result() {
        // The OPRF test vectors taken from:
        // https://github.com/cfrg/draft-irtf-cfrg-voprf/blob/draft-irtf-cfrg-voprf-19/draft-irtf-cfrg-voprf.md
        let vectors = [
            Vector {
                key: [
                    0x5e, 0xbc, 0xea, 0x5e, 0xe3, 0x70, 0x23, 0xcc, 0xb9, 0xfc, 0x2d, 0x20, 0x19,
                    0xf9, 0xd7, 0x73, 0x7b, 0xe8, 0x55, 0x91, 0xae, 0x86, 0x52, 0xff, 0xa9, 0xef,
                    0x0f, 0x4d, 0x37, 0x06, 0x3b, 0x0e,
                ],
                input: &[0x00],
                blinding_factor: [
                    0x64, 0xd3, 0x7a, 0xed, 0x22, 0xa2, 0x7f, 0x51, 0x91, 0xde, 0x1c, 0x1d, 0x69,
                    0xfa, 0xdb, 0x89, 0x9d, 0x88, 0x62, 0xb5, 0x8e, 0xb4, 0x22, 0x00, 0x29, 0xe0,
                    0x36, 0xec, 0x4c, 0x1f, 0x67, 0x06,
                ],
                blinded_input: [
                    0x60, 0x9a, 0x0a, 0xe6, 0x8c, 0x15, 0xa3, 0xcf, 0x69, 0x03, 0x76, 0x64, 0x61,
                    0x30, 0x7e, 0x5c, 0x8b, 0xb2, 0xf9, 0x5e, 0x7e, 0x65, 0x50, 0xe1, 0xff, 0xa2,
                    0xdc, 0x99, 0xe4, 0x12, 0x80, 0x3c,
                ],
                blinded_result: [
                    0x7e, 0xc6, 0x57, 0x8a, 0xe5, 0x12, 0x09, 0x58, 0xeb, 0x2d, 0xb1, 0x74, 0x57,
                    0x58, 0xff, 0x37, 0x9e, 0x77, 0xcb, 0x64, 0xfe, 0x77, 0xb0, 0xb2, 0xd8, 0xcc,
                    0x91, 0x7e, 0xa0, 0x86, 0x9c, 0x7e,
                ],
                result: [
                    0x52, 0x77, 0x59, 0xc3, 0xd9, 0x36, 0x6f, 0x27, 0x7d, 0x8c, 0x60, 0x20, 0x41,
                    0x8d, 0x96, 0xbb, 0x39, 0x3b, 0xa2, 0xaf, 0xb2, 0x0f, 0xf9, 0x0d, 0xf2, 0x3f,
                    0xb7, 0x70, 0x82, 0x64, 0xe2, 0xf3, 0xab, 0x91, 0x35, 0xe3, 0xbd, 0x69, 0x95,
                    0x58, 0x51, 0xde, 0x4b, 0x1f, 0x9f, 0xe8, 0xa0, 0x97, 0x33, 0x96, 0x71, 0x9b,
                    0x79, 0x12, 0xba, 0x9e, 0xe8, 0xaa, 0x7d, 0x0b, 0x5e, 0x24, 0xbc, 0xf6,
                ],
            },
            Vector {
                key: [
                    0x5e, 0xbc, 0xea, 0x5e, 0xe3, 0x70, 0x23, 0xcc, 0xb9, 0xfc, 0x2d, 0x20, 0x19,
                    0xf9, 0xd7, 0x73, 0x7b, 0xe8, 0x55, 0x91, 0xae, 0x86, 0x52, 0xff, 0xa9, 0xef,
                    0x0f, 0x4d, 0x37, 0x06, 0x3b, 0x0e,
                ],
                input: &[
                    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
                    0x5a, 0x5a, 0x5a, 0x5a,
                ],
                blinding_factor: [
                    0x64, 0xd3, 0x7a, 0xed, 0x22, 0xa2, 0x7f, 0x51, 0x91, 0xde, 0x1c, 0x1d, 0x69,
                    0xfa, 0xdb, 0x89, 0x9d, 0x88, 0x62, 0xb5, 0x8e, 0xb4, 0x22, 0x00, 0x29, 0xe0,
                    0x36, 0xec, 0x4c, 0x1f, 0x67, 0x06,
                ],
                blinded_input: [
                    0xda, 0x27, 0xef, 0x46, 0x68, 0x70, 0xf5, 0xf1, 0x52, 0x96, 0x29, 0x98, 0x50,
                    0xaa, 0x08, 0x86, 0x29, 0x94, 0x5a, 0x17, 0xd1, 0xf5, 0xb7, 0xf5, 0xff, 0x04,
                    0x3f, 0x76, 0xb3, 0xc0, 0x64, 0x18,
                ],
                blinded_result: [
                    0xb4, 0xcb, 0xf5, 0xa4, 0xf1, 0xee, 0xda, 0x5a, 0x63, 0xce, 0x7b, 0x77, 0xc7,
                    0xd2, 0x3f, 0x46, 0x1d, 0xb3, 0xfc, 0xab, 0x0d, 0xd2, 0x8e, 0x4e, 0x17, 0xce,
                    0xcb, 0x5c, 0x90, 0xd0, 0x2c, 0x25,
                ],
                result: [
                    0xf4, 0xa7, 0x4c, 0x9c, 0x59, 0x24, 0x97, 0x37, 0x5e, 0x79, 0x6a, 0xa8, 0x37,
                    0xe9, 0x07, 0xb1, 0xa0, 0x45, 0xd3, 0x43, 0x06, 0xa7, 0x49, 0xdb, 0x9f, 0x34,
                    0x22, 0x1f, 0x7e, 0x75, 0x0c, 0xb4, 0xf2, 0xa6, 0x41, 0x3a, 0x6b, 0xf6, 0xfa,
                    0x5e, 0x19, 0xba, 0x63, 0x48, 0xeb, 0x67, 0x39, 0x34, 0xa7, 0x22, 0xa7, 0xed,
                    0xe2, 0xe7, 0x62, 0x13, 0x06, 0xd1, 0x89, 0x51, 0xe7, 0xcf, 0x2c, 0x73,
                ],
            },
        ];

        for vector in vectors.into_iter() {
            let key = OprfPrivateKey::try_from(vector.key).unwrap();
            let blinding_factor = OprfBlindingFactor::try_from(vector.blinding_factor).unwrap();

            let blinded_input = OprfBlindedInput::new_deterministic(&blinding_factor, vector.input);
            assert_eq!(
                blinded_input.as_point().compress().as_bytes(),
                &vector.blinded_input
            );

            let blinded_result = OprfBlindedResult::new(&key, &blinded_input);
            assert_eq!(
                blinded_result.as_point().compress().as_bytes(),
                &vector.blinded_result
            );

            let blinded_evaluate_result =
                OprfResult::blind_evaluate(&blinding_factor, &blinded_result, vector.input);
            assert_eq!(blinded_evaluate_result.expose_secret(), &vector.result);

            let evaluate_result = OprfResult::evaluate(&key, vector.input);
            assert_eq!(
                evaluate_result.expose_secret(),
                blinded_evaluate_result.expose_secret()
            );
        }
    }
}
