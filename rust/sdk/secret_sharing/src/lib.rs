#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use core::iter::{repeat_with, zip};
use curve25519_dalek::scalar::Scalar;
use itertools::Itertools;
use rand_core::{CryptoRng, RngCore};

use juicebox_sdk_core::types::SecretBytesArray;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Secret(SecretBytesArray<32>);
impl Secret {
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

impl From<[u8; 32]> for Secret {
    fn from(value: [u8; 32]) -> Self {
        Self::from(Scalar::from_canonical_bytes(value).unwrap())
    }
}

impl From<Scalar> for Secret {
    fn from(value: Scalar) -> Self {
        Self(SecretBytesArray::from(value.to_bytes()))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Index(pub u32);

impl Index {
    pub fn as_scalar(&self) -> Scalar {
        Scalar::from(self.0 as u64)
    }
}

#[derive(Clone)]
pub struct Share {
    pub index: Index,
    pub secret: Secret,
}

impl core::fmt::Debug for Share {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Share(REDACTED)")
    }
}

#[derive(Debug)]
pub enum SecretSharingError {
    DuplicateShares,
    NoValidCombinations,
}

/// Distributes secret into `count` shares that can be recovered when at
/// least `threshold` are provided.
pub fn create_shares<'a, Rng: RngCore + CryptoRng + Send>(
    secret: &'a Secret,
    threshold: u32,
    count: u32,
    rng: &'a mut Rng,
) -> impl Iterator<Item = Share> + 'a {
    assert!(threshold > 0);
    assert!(count > 0);
    assert!(threshold <= count);

    let random_coefficients = repeat_with(|| Scalar::random(rng))
        .take((threshold - 1) as usize)
        .collect::<Vec<_>>();

    (1..=count).map(Index).map(move |index| {
        let value_scalar = random_coefficients
            .iter()
            .fold(Scalar::ZERO, |acc, coefficient| {
                (acc + coefficient) * index.as_scalar()
            })
            + secret.as_scalar();
        Share {
            index,
            secret: Secret::from(value_scalar),
        }
    })
}

/// Attempts to recover a secret from a provided set of shares.
///
/// If at least `threshold` created shares are provided, the `secret`
/// used in creation will be recovered.
///
/// Less than `threshold` shares or shares that don't all originate
/// from the same `create` operation will result in a `secret` being
/// recovered that does not match the original.
pub fn recover_secret(shares: &[Share]) -> Result<Secret, SecretSharingError> {
    let lagrange_coefficients: Vec<Scalar> = shares
        .iter()
        .enumerate()
        .map(|(i, share)| {
            let numerator = shares
                .iter()
                .enumerate()
                .filter(|&(j, _)| j != i)
                .fold(Scalar::ONE, |acc, (_, other_share)| {
                    acc * other_share.index.as_scalar()
                });
            let denominator = shares.iter().enumerate().filter(|&(j, _)| j != i).fold(
                Scalar::ONE,
                |acc, (_, other_share)| {
                    acc * (other_share.index.as_scalar() - share.index.as_scalar())
                },
            );

            if denominator == Scalar::ZERO {
                return Err(SecretSharingError::DuplicateShares);
            }

            Ok(numerator * denominator.invert())
        })
        .collect::<Result<Vec<_>, SecretSharingError>>()?;

    Ok(Secret::from(
        zip(lagrange_coefficients, shares).fold(Scalar::ZERO, |secret, (coefficient, share)| {
            secret + (coefficient * share.secret.as_scalar())
        }),
    ))
}

/// Attempts to recover from each `threshold` combination of shares, giving
/// the caller an attempt to validate the resulting secret after each recovery,
/// e.g. by comparing it to a known MAC computed before the original shares
/// were produced. This allows recovery from a set of shares that may potentially
/// contain invalid shares, but still have enough material to recover the secret.
pub fn recover_secret_combinatorially<Validator>(
    shares: &[Share],
    threshold: u32,
    validator: Validator,
) -> Result<Secret, SecretSharingError>
where
    Validator: Fn(&Secret) -> bool,
{
    if shares.len() < threshold as usize {
        return Err(SecretSharingError::NoValidCombinations);
    }

    for shares in shares.iter().cloned().combinations(threshold as usize) {
        match recover_secret(&shares) {
            Ok(secret) if validator(&secret) => return Ok(secret),
            _ => {}
        };
    }
    Err(SecretSharingError::NoValidCombinations)
}

#[cfg(test)]
mod tests {
    use super::*;
    use itertools::Itertools;
    use rand_core::OsRng;

    #[test]
    fn test_all_shares() {
        enumerate_counts_and_thresholds(10, |count, threshold| {
            let secret = Secret::new_random(&mut OsRng);

            let generated_shares: Vec<_> =
                create_shares(&secret, threshold, count, &mut OsRng).collect();
            assert_eq!(generated_shares.len(), count as usize);

            for share in &generated_shares {
                assert_ne!(secret.as_scalar(), share.secret.as_scalar());
            }

            let reconstructed_secret = recover_secret(&generated_shares);
            assert!(reconstructed_secret.is_ok());
            assert_eq!(reconstructed_secret.unwrap(), secret);
        });
    }

    #[test]
    fn test_threshold_recreation() {
        enumerate_counts_and_thresholds(10, |count, threshold| {
            let secret = Secret::new_random(&mut OsRng);

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
            let secret = Secret::new_random(&mut OsRng);

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
            let secret = Secret::new_random(&mut OsRng);

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
            let secret = Secret::new_random(&mut OsRng);

            let generated_shares: Vec<_> =
                create_shares(&secret, threshold, count, &mut OsRng).collect();

            let recover_shares: Vec<_> = generated_shares
                .into_iter()
                .enumerate()
                .map(|(i, s)| {
                    if i < (count - threshold) as usize {
                        return Share {
                            index: s.index,
                            secret: Secret::from(Scalar::random(&mut OsRng)),
                        };
                    }
                    s
                })
                .collect();

            let reconstructed_secret =
                recover_secret_combinatorially(&recover_shares, threshold, |s| s == &secret);
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
