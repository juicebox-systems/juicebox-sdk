//! A proof that two discrete logs are equal, as needed to verify the server's
//! exponentiation in an OPRF.
//!
//! The DLEQ proofs are from
//! <https://crypto.stanford.edu/~dabo/cryptobook/BonehShoup_0_6.pdf> page 838,
//! which presents the Chaum-Pedersen protocol with a Fiat-Shamir transform and
//! an optimization for proof size.

use core::fmt;
use curve25519_dalek::ristretto::{
    CompressedRistretto as CompressedPoint, RistrettoPoint as Point,
};
use curve25519_dalek::traits::MultiscalarMul;
use curve25519_dalek::Scalar;
use digest::Digest;
use juicebox_marshalling::bytes;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use subtle::ConstantTimeEq;
use zeroize::ZeroizeOnDrop;

use super::PrecompressedPoint;

/// Produced by the OPRF server as evidence that it evaluated the function
/// correctly, then checked by the client with
/// [`verify_proof`](super::verify_proof).
#[derive(Clone, Deserialize, Eq, Serialize, ZeroizeOnDrop)]
pub struct Proof {
    #[serde(with = "bytes")]
    pub(crate) c: Scalar,

    #[serde(with = "bytes")]
    pub(crate) beta_z: Scalar,
}

impl fmt::Debug for Proof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Proof(REDACTED)")
    }
}

impl PartialEq for Proof {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.c.ct_eq(&other.c) & self.beta_z.ct_eq(&other.beta_z))
    }
}

pub(crate) fn generate_proof(
    rng: &mut impl CryptoRngCore,
    beta: &Scalar,          // OPRF private key
    u: &PrecompressedPoint, // OPRF blinded input
    v: &CompressedPoint,    // OPRF public key
    w: &PrecompressedPoint, // OPRF blinded output
) -> Proof {
    let beta_t = Scalar::random(rng);
    let v_t = Point::mul_base(&beta_t);
    let w_t = u.uncompressed * beta_t;
    let c = hash_to_challenge(
        &u.compressed,
        v,
        &w.compressed,
        &v_t.compress(),
        &w_t.compress(),
    );
    let beta_z = beta_t + beta * c;
    Proof { c, beta_z }
}

pub(crate) fn verify_proof(
    u: &PrecompressedPoint, // OPRF blinded input
    v: &PrecompressedPoint, // OPRF public key
    w: &PrecompressedPoint, // OPRF blinded output
    proof: &Proof,
) -> Result<(), &'static str> {
    let v_t = Point::mul_base(&proof.beta_z) - v.uncompressed * proof.c;

    // For `w_t` (but not `v_t`), the `multiscalar_mul` is faster on some
    // platforms.
    let w_t = Point::multiscalar_mul([proof.beta_z, -proof.c], [u.uncompressed, w.uncompressed]);
    debug_assert_eq!(
        w_t,
        u.uncompressed * proof.beta_z - w.uncompressed * proof.c
    );

    let c = hash_to_challenge(
        &u.compressed,
        &v.compressed,
        &w.compressed,
        &v_t.compress(),
        &w_t.compress(),
    );

    if bool::from(c.ct_eq(&proof.c)) {
        Ok(())
    } else {
        Err("invalid proof")
    }
}

fn hash_to_challenge(
    u: &CompressedPoint,
    v: &CompressedPoint,
    w: &CompressedPoint,
    v_t: &CompressedPoint,
    w_t: &CompressedPoint,
) -> Scalar {
    Scalar::from_hash(
        Sha512::new()
            // These values are all constant-size, so we don't need to include
            // their lengths.
            .chain_update(b"Juicebox_DLEQ_2023_1;")
            // `g` is omitted since it's a well-known constant
            // (`curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT`).
            .chain_update(u.as_bytes())
            .chain_update(v.as_bytes())
            .chain_update(w.as_bytes())
            .chain_update(v_t.as_bytes())
            .chain_update(w_t.as_bytes()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand_core::OsRng;

    #[test]
    fn test_basic() {
        let private_key = Scalar::random(&mut OsRng);
        let public_key = PrecompressedPoint::from(Point::mul_base(&private_key));
        let input = PrecompressedPoint::from(Point::random(&mut OsRng));
        let result = PrecompressedPoint::from(input.uncompressed * private_key);

        let proof = generate_proof(
            &mut OsRng,
            &private_key,
            &input,
            &public_key.compressed,
            &result,
        );

        assert!(verify_proof(&input, &public_key, &result, &proof).is_ok());
        assert!(verify_proof(
            &PrecompressedPoint::from(Point::random(&mut OsRng)),
            &public_key,
            &result,
            &proof
        )
        .is_err());
        assert!(verify_proof(
            &input,
            &PrecompressedPoint::from(Point::random(&mut OsRng)),
            &result,
            &proof
        )
        .is_err());
        assert!(verify_proof(
            &input,
            &public_key,
            &PrecompressedPoint::from(Point::random(&mut OsRng)),
            &proof
        )
        .is_err());
        assert!(verify_proof(
            &input,
            &public_key,
            &result,
            &Proof {
                c: Scalar::random(&mut OsRng),
                beta_z: proof.beta_z,
            }
        )
        .is_err());
        assert!(verify_proof(
            &input,
            &public_key,
            &result,
            &Proof {
                c: proof.c,
                beta_z: Scalar::random(&mut OsRng),
            }
        )
        .is_err());
    }

    #[test]
    fn test_proof_serialize() {
        let proof = Proof {
            c: -(Scalar::ONE + Scalar::ONE),
            beta_z: -Scalar::ONE,
        };
        let serialized = juicebox_marshalling::to_vec(&proof).unwrap();
        let overhead = 14;
        assert_eq!(serialized.len(), 32 + 32 + overhead);
        assert_eq!(
            hex::encode(&serialized),
            "a261635820ebd3f55c1a631258d69cf7a2def9de140000000000000000000000000000001066626574615f7a5820ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"
        );
        let unserialized: Proof = juicebox_marshalling::from_slice(&serialized).unwrap();
        assert_eq!(proof.c, unserialized.c,);
        assert_eq!(proof.beta_z, unserialized.beta_z);
    }
}
