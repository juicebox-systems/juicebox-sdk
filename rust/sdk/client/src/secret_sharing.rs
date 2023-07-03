use std::fmt::Debug;

use juicebox_sdk_core::types::SecretBytesVec;
use rand::rngs::OsRng;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SharePosition(pub u8);

#[derive(Clone, Debug)]
pub(crate) struct ShareBytes(SecretBytesVec);
impl ShareBytes {
    pub fn expose_secret(&self) -> &[u8] {
        self.0.expose_secret()
    }
}

impl From<&[u8]> for ShareBytes {
    fn from(value: &[u8]) -> Self {
        Self(SecretBytesVec::from(value.to_vec()))
    }
}

pub(crate) struct Share(sharks::Share);

impl Debug for Share {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Share(REDACTED)")
    }
}

impl Share {
    pub fn try_from(
        position: &SharePosition,
        bytes: &ShareBytes,
    ) -> Result<Share, SecretSharingError> {
        sharks::Share::try_from(
            std::iter::once(position.0)
                .chain(bytes.expose_secret().iter().copied())
                .collect::<Vec<_>>()
                .as_slice(),
        )
        .map(Share)
        .map_err(|_| SecretSharingError::Assertion)
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        self.0.y.iter().map(|y| y.0).collect()
    }
}

#[derive(Debug)]
pub enum SecretSharingError {
    Assertion,
}

pub(crate) fn generate(secret: &[u8], threshold: u8, shares: usize) -> Vec<Share> {
    sharks::Sharks(threshold)
        .dealer_rng(secret, &mut OsRng)
        .take(shares)
        .map(Share)
        .collect()
}

pub(crate) fn reconstruct<'a, T>(shares: T, threshold: u8) -> Result<Vec<u8>, SecretSharingError>
where
    T: IntoIterator<Item = &'a Share>,
    T::IntoIter: Iterator<Item = &'a Share>,
{
    sharks::Sharks(threshold)
        .recover(shares.into_iter().map(|s| &s.0))
        .map_err(|_| SecretSharingError::Assertion)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_share_try_from_valid() {
        let position = SharePosition(1);
        let bytes: &[u8] = &[1, 2, 3];
        let share_bytes = ShareBytes::from(bytes);
        let result = Share::try_from(&position, &share_bytes);
        assert!(result.is_ok());
        let share = result.unwrap();
        assert_eq!(share.0.x.0, position.0);
        assert_eq!(share.0.y.iter().map(|y| y.0).collect::<Vec<_>>(), bytes);
    }

    #[test]
    fn test_share_try_from_invalid() {
        let position = SharePosition(0);
        let bytes: &[u8] = &[];
        let share_bytes = ShareBytes::from(bytes);
        let result = Share::try_from(&position, &share_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_share_as_bytes() {
        let bytes: &[u8] = &[1, 2, 3];
        let raw_share: &[u8] = &[1, 1, 2, 3];
        let share = Share(sharks::Share::try_from(raw_share).unwrap());
        assert_eq!(share.as_bytes(), bytes);
    }

    #[test]
    fn test_generate_and_reconstruct() {
        let secret: &[u8] = &[1, 2, 3, 4, 5];
        let threshold = 2;
        let shares = 5;

        let generated_shares = generate(secret, threshold, shares);
        assert_eq!(generated_shares.len(), shares);

        for share in &generated_shares {
            assert_eq!(secret.len(), share.as_bytes().len());
            assert_ne!(secret, share.as_bytes());
        }

        let reconstructed_secret = reconstruct(&generated_shares, threshold);
        assert!(reconstructed_secret.is_ok());
        assert_eq!(reconstructed_secret.unwrap(), secret);
    }
}
