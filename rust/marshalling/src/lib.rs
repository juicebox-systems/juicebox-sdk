#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Display;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

pub mod bytes;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SerializationError(pub String);

impl Display for SerializationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Serialization error: {}", self.0)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeserializationError(pub String);

impl Display for DeserializationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Deserialization error: {}", self.0)
    }
}

pub fn to_vec<T: Serialize>(val: &T) -> Result<Vec<u8>, SerializationError> {
    let mut bytes = Vec::new();
    match ciborium::ser::into_writer(val, &mut bytes) {
        Ok(_) => Ok(bytes),
        Err(e) => Err(SerializationError(e.to_string())),
    }
}

pub fn from_slice<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, DeserializationError> {
    ciborium::de::from_reader(bytes).map_err(|e| DeserializationError(e.to_string()))
}

/// Converts the provided integer into a 2 byte array in big-endian
/// (network) byte order or panics if it is too large to fit.
pub fn to_be2<T: TryInto<u16>>(value: T) -> [u8; 2] {
    // Note: `value` may be secret, so don't include it in the error message.
    match value.try_into() {
        Ok(value) => value.to_be_bytes(),
        Err(_) => panic!("integer larger than 2 bytes"),
    }
}

/// Converts the provided integer into a 4 byte array in big-endian
/// (network) byte order or panics if it is too large to fit.
pub fn to_be4<T: TryInto<u32>>(value: T) -> [u8; 4] {
    // Note: `value` may be secret, so don't include it in the error message.
    match value.try_into() {
        Ok(value) => value.to_be_bytes(),
        Err(_) => panic!("integer larger than 4 bytes"),
    }
}

/// Converts the provided integer into a 8 byte array in big-endian
/// (network) byte order or panics if it is too large to fit.
pub fn to_be8<T: TryInto<u64>>(value: T) -> [u8; 8] {
    // Note: `value` may be secret, so don't include it in the error message.
    match value.try_into() {
        Ok(value) => value.to_be_bytes(),
        Err(_) => panic!("integer larger than 8 bytes"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::catch_unwind;

    #[test]
    fn test_to_be() {
        assert_eq!(to_be2(0), [0, 0]);
        assert_eq!(to_be2(0x0123), [0x01, 0x23]);
        assert_eq!(to_be2(u16::MAX), [0xff, 0xff]);
        assert_eq!(to_be4(0x01234567u32), [0x01, 0x23, 0x45, 0x67]);
        assert_eq!(to_be4(u32::MAX), [0xff, 0xff, 0xff, 0xff]);
        assert_eq!(
            to_be8(0x0123456789abcdefu64),
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
        );
        assert_eq!(
            to_be8(u64::MAX),
            [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        );
    }

    #[test]
    fn test_to_be_panics() {
        // It's important that the full panic message does not include the
        // potentially-secret input. This doesn't use
        // ```
        // #[should_panic(expected = "...")]
        // ```
        // since that only checks if the expected string is a
        // substring of the panic message.
        assert_eq!(
            *catch_unwind(|| to_be2(1u64 << 16))
                .unwrap_err()
                .downcast::<&str>()
                .unwrap(),
            "integer larger than 2 bytes"
        );
        assert_eq!(
            *catch_unwind(|| to_be2(-1i16))
                .unwrap_err()
                .downcast::<&str>()
                .unwrap(),
            "integer larger than 2 bytes"
        );
        assert_eq!(
            *catch_unwind(|| to_be4(1u64 << 32))
                .unwrap_err()
                .downcast::<&str>()
                .unwrap(),
            "integer larger than 4 bytes"
        );
        assert_eq!(
            *catch_unwind(|| to_be4(-1i32))
                .unwrap_err()
                .downcast::<&str>()
                .unwrap(),
            "integer larger than 4 bytes"
        );
        assert_eq!(
            *catch_unwind(|| to_be8(1u128 << 64))
                .unwrap_err()
                .downcast::<&str>()
                .unwrap(),
            "integer larger than 8 bytes"
        );
        assert_eq!(
            *catch_unwind(|| to_be8(-1i64))
                .unwrap_err()
                .downcast::<&str>()
                .unwrap(),
            "integer larger than 8 bytes"
        );
    }
}
