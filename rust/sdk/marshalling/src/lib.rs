#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

pub mod bytes;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SerializationError(String);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeserializationError(String);

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

/// Used in conjunction with the [`secrecy`] crate to serialize secrets.
///
/// # Example
///
/// ```
/// use juicebox_sdk_core::marshalling::{from_slice, serialize_secret, to_vec};
/// use secrecy::{ExposeSecret, SecretString};
/// use serde::{Deserialize, Serialize};
///
/// #[derive(Clone, Debug, Deserialize, Serialize)]
/// struct Token(#[serde(serialize_with = "serialize_secret")] pub SecretString);
///
/// let token = Token(SecretString::from(String::from("hi")));
/// assert_eq!(
///     "hi",
///     from_slice::<Token>(&to_vec(&token).unwrap())
///         .unwrap()
///         .0
///         .expose_secret()
/// );
/// ```
pub fn serialize_secret<Ser, Sec, In>(secret: &Sec, serializer: Ser) -> Result<Ser::Ok, Ser::Error>
where
    Ser: serde::ser::Serializer,
    Sec: secrecy::ExposeSecret<In>,
    In: Serialize,
{
    secret.expose_secret().serialize(serializer)
}
