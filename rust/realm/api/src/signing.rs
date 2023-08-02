use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Signature, SignatureError, Signer, SigningKey, VerifyingKey};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use juicebox_marshalling::bytes;
use juicebox_oprf as oprf;

use crate::types::SecretBytesArray;

pub fn sign_public_key(
    public_key: oprf::PublicKey,
    signing_key: &OprfSigningKey,
) -> OprfSignedPublicKey {
    let signature = signing_key.0.sign(public_key.as_bytes());
    OprfSignedPublicKey {
        public_key,
        verifying_key: signing_key.verifying_key(),
        signature: SecretBytesArray::from(signature.to_bytes()),
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
    pub public_key: oprf::PublicKey,
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
            self.public_key.as_bytes(),
            &Signature::from(self.signature.expose_secret()),
        )
    }
}
