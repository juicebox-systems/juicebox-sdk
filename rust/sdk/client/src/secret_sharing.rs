use curve25519_dalek::scalar::Scalar;
use itertools::Itertools;
use rand::rngs::OsRng;
use std::{fmt::Debug, iter::zip};

use juicebox_sdk_core::types::SecretBytesArray;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub(crate) struct ShareIndex(pub u32);

impl ShareIndex {
    pub(crate) fn as_scalar(&self) -> Scalar {
        Scalar::from(self.0 as u64)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ShareValue(SecretBytesArray<32>);
impl ShareValue {
    pub fn expose_secret(&self) -> &[u8; 32] {
        self.0.expose_secret()
    }

    pub fn as_scalar(&self) -> Scalar {
        Scalar::from_canonical_bytes(*self.expose_secret()).unwrap()
    }
}

impl From<[u8; 32]> for ShareValue {
    fn from(value: [u8; 32]) -> Self {
        Self(SecretBytesArray::from(value))
    }
}

impl From<Scalar> for ShareValue {
    fn from(value: Scalar) -> Self {
        Self(SecretBytesArray::from(value.to_bytes()))
    }
}

#[derive(Clone)]
pub(crate) struct Share {
    pub index: ShareIndex,
    pub value: ShareValue,
}

impl Debug for Share {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
pub(crate) fn create(
    secret: &Scalar,
    threshold: u32,
    count: u32,
) -> impl Iterator<Item = Share> + '_ {
    assert!(threshold > 0);
    assert!(count > 0);
    assert!(threshold <= count);

    let random_coefficients = std::iter::repeat_with(|| Scalar::random(&mut OsRng))
        .take((threshold - 1) as usize)
        .collect::<Vec<_>>();

    (1..=count).map(ShareIndex).map(move |index| {
        let value_scalar = random_coefficients
            .iter()
            .fold(Scalar::ZERO, |acc, coefficient| {
                (acc + coefficient) * index.as_scalar()
            })
            + secret;
        Share {
            index,
            value: ShareValue::from(value_scalar),
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
pub(crate) fn recover(shares: &[Share]) -> Result<Scalar, SecretSharingError> {
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

    Ok(
        zip(lagrange_coefficients, shares).fold(Scalar::ZERO, |secret, (coefficient, share)| {
            secret + (coefficient * share.value.as_scalar())
        }),
    )
}

/// Attempts to recover from each `threshold` combination of shares, giving
/// the caller an attempt to validate the resulting secret after each recovery,
/// e.g. by comparing it to a known MAC computed before the original shares
/// were produced. This allows recovery from a set of shares that may potentially
/// contain invalid shares, but still have enough material to recover the secret.
pub(crate) fn recover_combinatorially<Validator>(
    shares: &[Share],
    threshold: u32,
    validator: Validator,
) -> Result<Scalar, SecretSharingError>
where
    Validator: Fn(Scalar) -> bool,
{
    if shares.len() < threshold as usize {
        return Err(SecretSharingError::NoValidCombinations);
    }

    for shares in shares.iter().cloned().combinations(threshold as usize) {
        match recover(&shares) {
            Ok(secret) if validator(secret) => return Ok(secret),
            _ => {}
        };
    }
    Err(SecretSharingError::NoValidCombinations)
}

#[cfg(test)]
mod tests {
    use super::*;
    use itertools::Itertools;

    #[test]
    fn test_all_shares() {
        let secret = Scalar::random(&mut OsRng);
        let threshold = 6;
        let shares = 10;

        let generated_shares: Vec<_> = create(&secret, threshold, shares).collect();
        assert_eq!(generated_shares.len(), shares as usize);

        for share in &generated_shares {
            assert_ne!(secret.as_bytes(), share.value.expose_secret());
        }

        let reconstructed_secret = recover(&generated_shares);
        assert!(reconstructed_secret.is_ok());
        assert_eq!(reconstructed_secret.unwrap(), secret);
    }

    #[test]
    fn test_threshold_recreation() {
        let secret = Scalar::random(&mut OsRng);
        let threshold = 6;
        let shares = 10;

        let generated_shares: Vec<_> = create(&secret, threshold, shares).collect();

        for shares in generated_shares
            .into_iter()
            .combinations(threshold as usize)
        {
            let reconstructed_secret = recover(&shares);
            assert!(reconstructed_secret.is_ok());
            assert_eq!(reconstructed_secret.unwrap(), secret);
        }
    }

    #[test]
    fn test_less_than_threshold_recreation() {
        let secret = Scalar::random(&mut OsRng);
        let threshold = 6;
        let shares = 10;

        let generated_shares: Vec<_> = create(&secret, threshold, shares).collect();

        for shares in generated_shares
            .into_iter()
            .combinations((threshold - 1) as usize)
        {
            let reconstructed_secret = recover(&shares);
            assert!(reconstructed_secret.is_ok());
            assert_ne!(reconstructed_secret.unwrap(), secret);
        }
    }

    #[test]
    fn test_more_than_threshold_recreation() {
        let secret = Scalar::random(&mut OsRng);
        let threshold = 6;
        let shares = 10;

        let generated_shares: Vec<_> = create(&secret, threshold, shares).collect();

        for shares in generated_shares
            .into_iter()
            .combinations((threshold + 1) as usize)
        {
            let reconstructed_secret = recover(&shares);
            assert!(reconstructed_secret.is_ok());
            assert_eq!(reconstructed_secret.unwrap(), secret);
        }
    }

    #[test]
    fn test_recover_combinatorially() {
        let secret = Scalar::random(&mut OsRng);
        let threshold = 6;
        let shares = 10;

        let generated_shares: Vec<_> = create(&secret, threshold, shares).collect();

        let recover_shares: Vec<_> = generated_shares
            .into_iter()
            .enumerate()
            .map(|(i, s)| {
                if i < 4 {
                    return Share {
                        index: s.index,
                        value: ShareValue::from(Scalar::random(&mut OsRng)),
                    };
                }
                s
            })
            .collect();

        let reconstructed_secret =
            recover_combinatorially(&recover_shares, threshold, |s| s == secret);
        assert!(reconstructed_secret.is_ok());
        assert_eq!(reconstructed_secret.unwrap(), secret);
    }
}
