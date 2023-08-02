#![cfg_attr(not(test), no_std)]
#![doc = include_str!("../README.md")]

extern crate alloc;

use alloc::vec::Vec;
use core::iter::{repeat_with, Sum};
use core::ops::{Add, Mul};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::RistrettoPoint;
use itertools::Itertools;
use rand_core::{CryptoRng, RngCore};

/// A type that can be transformed into or recovered from
/// shares using Shamir's secret sharing.
pub trait Secret:
    Copy + Default + for<'a> Add<&'a Self, Output = Self> + for<'a> Mul<&'a Scalar, Output = Self> + Sum
{
    fn random<R: CryptoRng + RngCore + Send>(rng: &mut R) -> Self;
}

impl Secret for Scalar {
    fn random<R: CryptoRng + RngCore + Send>(rng: &mut R) -> Self {
        Self::random(rng)
    }
}

impl Secret for RistrettoPoint {
    fn random<R: CryptoRng + RngCore + Send>(rng: &mut R) -> Self {
        Self::random(rng)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Index(pub u32);

impl Index {
    pub fn as_scalar(&self) -> Scalar {
        Scalar::from(self.0)
    }
}

#[derive(Clone)]
pub struct Share<S: Secret> {
    pub index: Index,
    pub secret: S,
}

impl<S: Secret> core::fmt::Debug for Share<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Share(REDACTED)")
    }
}

/// Distributes secret into `count` shares that can be recovered when at
/// least `threshold` are provided.
pub fn create_shares<'a, Rng: CryptoRng + RngCore + Send, S: Secret>(
    secret: &'a S,
    threshold: u32,
    count: u32,
    rng: &'a mut Rng,
) -> impl Iterator<Item = Share<S>> + 'a {
    assert!(threshold > 0);
    assert!(count > 0);
    assert!(threshold <= count);

    let random_coefficients = repeat_with(|| S::random(rng))
        .take((threshold - 1) as usize)
        .collect::<Vec<_>>();

    (1..=count).map(Index).map(move |index| {
        let share_secret = random_coefficients
            .iter()
            .fold(S::default(), |acc, coefficient| {
                (acc + coefficient) * &index.as_scalar()
            })
            + secret;
        Share {
            index,
            secret: share_secret,
        }
    })
}

#[derive(Debug)]
pub enum RecoverSecretError {
    DuplicateShares,
}

/// Attempts to recover a secret from a provided set of shares.
///
/// If at least `threshold` created shares are provided, the `secret`
/// used in creation will be recovered.
///
/// Less than `threshold` shares or shares that don't all originate
/// from the same `create` operation will result in a `secret` being
/// recovered that does not match the original.
pub fn recover_secret<S: Secret>(shares: &[Share<S>]) -> Result<S, RecoverSecretError> {
    shares
        .iter()
        .enumerate()
        .map(|(i, share)| {
            let others = shares[..i].iter().chain(&shares[i + 1..]);
            let numerator: Scalar = others
                .clone()
                .map(|other_share| other_share.index.as_scalar())
                .product();
            let denominator: Scalar = others
                .map(|other_share| other_share.index.as_scalar() - share.index.as_scalar())
                .product();

            if denominator == Scalar::ZERO {
                Err(RecoverSecretError::DuplicateShares)
            } else {
                let lagrange_coefficient = numerator * denominator.invert();
                Ok(share.secret * &lagrange_coefficient)
            }
        })
        .sum()
}

#[derive(Debug)]
pub enum RecoverSecretCombinatoriallyError {
    NoValidCombinations,
}

/// Attempts to recover from each `threshold` combination of shares, giving
/// the caller an attempt to validate the resulting secret after each recovery,
/// e.g. by comparing it to a known MAC computed before the original shares
/// were produced. This allows recovery from a set of shares that may potentially
/// contain invalid shares, but still have enough material to recover the secret.
pub fn recover_secret_combinatorially<Validator, S: Secret, T>(
    shares: &[Share<S>],
    threshold: u32,
    validator: Validator,
) -> Result<T, RecoverSecretCombinatoriallyError>
where
    Validator: Fn(S) -> Option<T>,
{
    if shares.len() < threshold as usize {
        return Err(RecoverSecretCombinatoriallyError::NoValidCombinations);
    }

    for shares in shares.iter().cloned().combinations(threshold as usize) {
        if let Ok(secret) = recover_secret(&shares) {
            if let Some(result) = validator(secret) {
                return Ok(result);
            }
        };
    }
    Err(RecoverSecretCombinatoriallyError::NoValidCombinations)
}

#[cfg(test)]
mod tests {
    use super::*;
    use itertools::Itertools;
    use rand_core::OsRng;

    #[test]
    fn test_all_scalar_shares() {
        enumerate_counts_and_thresholds(10, |count, threshold| {
            let secret = Scalar::random(&mut OsRng);

            let generated_shares: Vec<_> =
                create_shares(&secret, threshold, count, &mut OsRng).collect();
            assert_eq!(generated_shares.len(), count as usize);

            for share in &generated_shares {
                assert_ne!(secret, share.secret);
            }

            let reconstructed_secret = recover_secret(&generated_shares);
            assert!(reconstructed_secret.is_ok());
            assert_eq!(reconstructed_secret.unwrap(), secret);
        });
    }

    #[test]
    fn test_all_elem_shares() {
        enumerate_counts_and_thresholds(10, |count, threshold| {
            let secret = RistrettoPoint::random(&mut OsRng);

            let generated_shares: Vec<_> =
                create_shares(&secret, threshold, count, &mut OsRng).collect();
            assert_eq!(generated_shares.len(), count as usize);

            for share in &generated_shares {
                assert_ne!(secret, share.secret);
            }

            let reconstructed_secret = recover_secret(&generated_shares);
            assert!(reconstructed_secret.is_ok());
            assert_eq!(reconstructed_secret.unwrap(), secret);
        });
    }

    #[test]
    fn test_threshold_recreation() {
        enumerate_counts_and_thresholds(10, |count, threshold| {
            let secret = Scalar::random(&mut OsRng);

            let generated_shares: Vec<_> =
                create_shares(&secret, threshold, count, &mut OsRng).collect();

            for shares in generated_shares
                .into_iter()
                .combinations(threshold as usize)
            {
                let reconstructed_secret = recover_secret(&shares);
                assert!(reconstructed_secret.is_ok());
                assert_eq!(reconstructed_secret.unwrap(), secret);
            }
        });
    }

    #[test]
    fn test_less_than_threshold_recreation() {
        enumerate_counts_and_thresholds(10, |count, threshold| {
            let secret = Scalar::random(&mut OsRng);

            let generated_shares: Vec<_> =
                create_shares(&secret, threshold, count, &mut OsRng).collect();

            for shares in generated_shares
                .into_iter()
                .combinations((threshold - 1) as usize)
            {
                let reconstructed_secret = recover_secret(&shares);
                assert!(reconstructed_secret.is_ok());
                assert_ne!(reconstructed_secret.unwrap(), secret);
            }
        });
    }

    #[test]
    fn test_more_than_threshold_recreation() {
        enumerate_counts_and_thresholds(10, |count, threshold| {
            let secret = Scalar::random(&mut OsRng);

            let generated_shares: Vec<_> =
                create_shares(&secret, threshold, count, &mut OsRng).collect();

            for shares in generated_shares
                .into_iter()
                .combinations((threshold + 1) as usize)
            {
                let reconstructed_secret = recover_secret(&shares);
                assert!(reconstructed_secret.is_ok());
                assert_eq!(reconstructed_secret.unwrap(), secret);
            }
        });
    }

    #[test]
    fn test_recover_combinatorially() {
        enumerate_counts_and_thresholds(10, |count, threshold| {
            let secret = Scalar::random(&mut OsRng);

            let generated_shares: Vec<_> =
                create_shares(&secret, threshold, count, &mut OsRng).collect();

            let recover_shares: Vec<_> = generated_shares
                .into_iter()
                .enumerate()
                .map(|(i, s)| {
                    if i < (count - threshold) as usize {
                        return Share {
                            index: s.index,
                            secret: Scalar::random(&mut OsRng),
                        };
                    }
                    s
                })
                .collect();

            let reconstructed_secret =
                recover_secret_combinatorially(&recover_shares, threshold, |s| {
                    if s == secret {
                        Some(s)
                    } else {
                        None
                    }
                });
            assert!(reconstructed_secret.is_ok());
            assert_eq!(reconstructed_secret.unwrap(), secret);
        });
    }

    fn enumerate_counts_and_thresholds(max_count: u32, test: impl Fn(u32, u32)) {
        assert!(max_count > 1);
        for i in 2..=max_count {
            for j in 2..=i {
                test(i, j)
            }
        }
    }
}
