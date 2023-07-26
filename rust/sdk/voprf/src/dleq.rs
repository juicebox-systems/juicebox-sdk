//! A proof that two discrete logs are equal, as needed for a VOPRF.
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
use juicebox_sdk_marshalling::bytes;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use subtle::ConstantTimeEq;
use zeroize::ZeroizeOnDrop;

use super::DecompressedPoint;

/// Produced by the VOPRF server as evidence that it evaluated the function
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
    beta: &Scalar,         // VOPRF private key
    u: &DecompressedPoint, // VOPRF blinded input
    v: &CompressedPoint,   // VOPRF public key
    w: &DecompressedPoint, // VOPRF blinded output
) -> Proof {
    let beta_t = Scalar::random(rng);
    let v_t = Point::mul_base(&beta_t);
    let w_t = u.uncompressed * beta_t;
    let c = hash_to_challenge(&u.compressed, v, &w.compressed, &v_t, &w_t);
    let beta_z = beta_t + beta * c;
    Proof { c, beta_z }
}

pub(crate) fn verify_proof(
    u: &DecompressedPoint, // VOPRF blinded input
    v: &DecompressedPoint, // VOPRF public key
    w: &DecompressedPoint, // VOPRF blinded output
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

    let c = hash_to_challenge(&u.compressed, &v.compressed, &w.compressed, &v_t, &w_t);

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
    v_t: &Point,
    w_t: &Point,
) -> Scalar {
    // `v_t` and `w_t` are only used as inputs to this hash. We can compress
    // them faster in batch, with the unwanted but harmless side-effect of
    // doubling them (scaling each one by a factor of 2).
    let doubled = Point::double_and_compress_batch([v_t, w_t]);
    let [double_v_t, double_w_t] = doubled[..] else {
        unreachable!("expected 2 doubled and compressed points");
    };
    debug_assert_eq!((v_t + v_t).compress(), double_v_t);
    debug_assert_eq!((w_t + w_t).compress(), double_w_t);

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
            .chain_update(double_v_t.as_bytes())
            .chain_update(double_w_t.as_bytes()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand_core::OsRng;

    #[test]
    fn test_basic() {
        let private_key = Scalar::random(&mut OsRng);
        let public_key = DecompressedPoint::from(Point::mul_base(&private_key));
        let input = DecompressedPoint::from(Point::random(&mut OsRng));
        let result = DecompressedPoint::from(input.uncompressed * private_key);

        let proof = generate_proof(
            &mut OsRng,
            &private_key,
            &input,
            &public_key.compressed,
            &result,
        );

        assert!(verify_proof(&input, &public_key, &result, &proof).is_ok());
        assert!(verify_proof(
            &DecompressedPoint::from(Point::random(&mut OsRng)),
            &public_key,
            &result,
            &proof
        )
        .is_err());
        assert!(verify_proof(
            &input,
            &DecompressedPoint::from(Point::random(&mut OsRng)),
            &result,
            &proof
        )
        .is_err());
        assert!(verify_proof(
            &input,
            &public_key,
            &DecompressedPoint::from(Point::random(&mut OsRng)),
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
        let serialized = juicebox_sdk_marshalling::to_vec(&proof).unwrap();
        let overhead = 14;
        assert_eq!(serialized.len(), 32 + 32 + overhead);
        assert_eq!(
            hex::encode(&serialized),
            "a261635820ebd3f55c1a631258d69cf7a2def9de140000000000000000000000000000001066626574615f7a5820ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"
        );
        let unserialized: Proof = juicebox_sdk_marshalling::from_slice(&serialized).unwrap();
        assert_eq!(proof.c, unserialized.c,);
        assert_eq!(proof.beta_z, unserialized.beta_z);
    }
}
