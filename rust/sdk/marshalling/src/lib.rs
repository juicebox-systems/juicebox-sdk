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
