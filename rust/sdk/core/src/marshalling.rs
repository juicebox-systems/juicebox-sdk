extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

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

pub(crate) mod bytes {
    extern crate alloc;
    use alloc::format;

    pub fn serialize<Ser, const N: usize>(
        bytes: &[u8; N],
        serializer: Ser,
    ) -> Result<Ser::Ok, Ser::Error>
    where
        Ser: serde::ser::Serializer,
    {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, De, const N: usize>(deserializer: De) -> Result<[u8; N], De::Error>
    where
        De: serde::de::Deserializer<'de>,
    {
        struct BytesVisitor<const N: usize>;

        impl<'de, const N: usize> serde::de::Visitor<'de> for BytesVisitor<N> {
            type Value = [u8; N];

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str(&format!("byte array of length {}", N))
            }

            fn visit_borrowed_bytes<E>(self, v: &'de [u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v.len() == N {
                    let mut value = [0u8; N];
                    value.copy_from_slice(v);
                    Ok(value)
                } else {
                    Err(serde::de::Error::invalid_length(N, &self))
                }
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_borrowed_bytes(v)
            }
        }

        deserializer.deserialize_bytes(BytesVisitor::<N>)
    }
}

#[cfg(test)]
mod tests {
    use crate::types::SecretBytesArray;
    use secrecy::ExposeSecret;

    #[test]
    fn test_bytes() {
        let slice = &[15; 16];
        let slice_length = u8::try_from(slice.len()).unwrap();

        let mut serialized_secret_bytes: Vec<u8> = Vec::new();
        ciborium::ser::into_writer(
            &SecretBytesArray::from(*slice),
            &mut serialized_secret_bytes,
        )
        .unwrap();

        // cbor bytes are tagged with 0x40 & length (a simplification, this gets more complicated for larger length values)
        let bytes_marker = 0x40;
        let mut expected_serialized_bytes = vec![bytes_marker + slice_length];
        expected_serialized_bytes.extend_from_slice(slice);

        assert_eq!(serialized_secret_bytes, expected_serialized_bytes);

        let mut serialized_array: Vec<u8> = Vec::new();
        ciborium::ser::into_writer(slice, &mut serialized_array).unwrap();

        // cbor arrays are tagged with 0x80 & length (a simplification, this gets more complicated for larger length values)
        let array_marker: u8 = 0x80;
        let mut expected_serialized_array = vec![array_marker + slice_length];
        expected_serialized_array.extend_from_slice(slice);

        assert_eq!(serialized_array, expected_serialized_array);

        let deserialized_secret_bytes_array: SecretBytesArray<16> =
            ciborium::de::from_reader(expected_serialized_bytes.as_slice()).unwrap();
        assert_eq!(deserialized_secret_bytes_array.expose_secret(), slice);

        let deserialized_array: [u8; 16] =
            ciborium::de::from_reader(expected_serialized_array.as_slice()).unwrap();
        assert_eq!(&deserialized_array, slice);
    }
}
