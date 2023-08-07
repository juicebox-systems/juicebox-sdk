extern crate alloc;

use alloc::vec::Vec;
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Signature, SignatureError, Signer, SigningKey, VerifyingKey};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use juicebox_marshalling::{bytes, to_be2};
use juicebox_oprf as oprf;

use crate::types::{RealmId, SecretBytesArray};

pub fn sign_public_key(
    public_key: oprf::PublicKey,
    realm_id: &RealmId,
    signing_key: &OprfSigningKey,
) -> OprfSignedPublicKey {
    let signature = signing_key
        .0
        .sign(&signature_msg(public_key.as_bytes(), realm_id));
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
    pub fn verify(&self, realm_id: &RealmId) -> Result<(), SignatureError> {
        VerifyingKey::from(
            self.verifying_key
                .0
                .decompress()
                .ok_or(SignatureError::default())?,
        )
        .verify_strict(
            &signature_msg(self.public_key.as_bytes(), realm_id),
            &Signature::from(self.signature.expose_secret()),
        )
    }
}

fn signature_msg(public_key_bytes: &[u8; 32], realm_id: &RealmId) -> Vec<u8> {
    [
        &to_be2(realm_id.0.len()),
        realm_id.0.as_slice(),
        &to_be2(public_key_bytes.len()),
        public_key_bytes,
    ]
    .concat()
}
