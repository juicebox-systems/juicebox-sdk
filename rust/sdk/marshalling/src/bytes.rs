//! Serde helpers for serializing byte arrays and vectors.
extern crate alloc;
use alloc::vec::Vec;
use core::fmt;
use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint, Scalar};

pub fn serialize<Ser, B>(bytes: &B, serializer: Ser) -> Result<Ser::Ok, Ser::Error>
where
    Ser: serde::ser::Serializer,
    B: Bytes,
{
    bytes.serialize(serializer)
}

pub fn deserialize<'de, De, B>(deserializer: De) -> Result<B, De::Error>
where
    De: serde::de::Deserializer<'de>,
    B: Bytes,
{
    B::deserialize(deserializer)
}

pub trait Bytes: Sized {
    fn serialize<Ser>(&self, serializer: Ser) -> Result<Ser::Ok, Ser::Error>
    where
        Ser: serde::ser::Serializer;

    fn deserialize<'de, De>(deserializer: De) -> Result<Self, De::Error>
    where
        De: serde::de::Deserializer<'de>;
}

impl<const N: usize> Bytes for [u8; N] {
    fn serialize<Ser>(&self, serializer: Ser) -> Result<Ser::Ok, Ser::Error>
    where
        Ser: serde::ser::Serializer,
    {
        serializer.serialize_bytes(self)
    }

    fn deserialize<'de, De>(deserializer: De) -> Result<Self, De::Error>
    where
        De: serde::de::Deserializer<'de>,
    {
        struct Visitor<const N: usize>;

        impl<'de, const N: usize> serde::de::Visitor<'de> for Visitor<N> {
            type Value = [u8; N];

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_fmt(format_args!("byte array of length {}", N))
            }

            fn visit_bytes<E>(self, slice: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Self::Value::try_from(slice)
                    .map_err(|_| serde::de::Error::invalid_length(slice.len(), &self))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut buf: Vec<u8> = Vec::with_capacity(N);
                while let Some(x) = seq.next_element()? {
                    buf.push(x);
                }
                self.visit_bytes(&buf)
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

impl Bytes for Vec<u8> {
    fn serialize<Ser>(&self, serializer: Ser) -> Result<Ser::Ok, Ser::Error>
    where
        Ser: serde::ser::Serializer,
    {
        serializer.serialize_bytes(self)
    }

    fn deserialize<'de, De>(deserializer: De) -> Result<Self, De::Error>
    where
        De: serde::de::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Vec<u8>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("Vec<u8>")
            }

            fn visit_bytes<E>(self, slice: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(slice.to_vec())
            }

            fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(value)
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut buf: Vec<u8> = match seq.size_hint() {
                    Some(hint) => Vec::with_capacity(hint),
                    None => Vec::new(),
                };
                while let Some(x) = seq.next_element()? {
                    buf.push(x);
                }
                Ok(buf)
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

impl Bytes for Scalar {
    fn serialize<Ser>(&self, serializer: Ser) -> Result<Ser::Ok, Ser::Error>
    where
        Ser: serde::ser::Serializer,
    {
        serializer.serialize_bytes(self.as_bytes())
    }

    fn deserialize<'de, De>(deserializer: De) -> Result<Self, De::Error>
    where
        De: serde::de::Deserializer<'de>,
    {
        let bytes = <[u8; 32]>::deserialize(deserializer)?;
        Option::from(Scalar::from_canonical_bytes(bytes)).ok_or(serde::de::Error::invalid_value(
            serde::de::Unexpected::Bytes(&bytes),
            &"a valid Scalar",
        ))
    }
}

impl Bytes for RistrettoPoint {
    fn serialize<Ser>(&self, serializer: Ser) -> Result<Ser::Ok, Ser::Error>
    where
        Ser: serde::ser::Serializer,
    {
        serializer.serialize_bytes(self.compress().as_bytes())
    }

    fn deserialize<'de, De>(deserializer: De) -> Result<Self, De::Error>
    where
        De: serde::de::Deserializer<'de>,
    {
        let bytes = <[u8; 32]>::deserialize(deserializer)?;
        CompressedRistretto(bytes)
            .decompress()
            .ok_or(serde::de::Error::invalid_value(
                serde::de::Unexpected::Bytes(&bytes),
                &"a valid RistrettoPoint",
            ))
    }
}

#[cfg(test)]
mod tests {
    use crate::{bytes, from_slice, to_vec};
    use serde::{Deserialize, Serialize};

    // A `[u8; N]` wrapper type that uses `serde(with = "bytes")`.
    #[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct BytesArray<const N: usize>(#[serde(with = "bytes")] [u8; N]);

    // A `Vec<u8>` wrapper type that uses `serde(with = "bytes")`.
    #[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct BytesVec(#[serde(with = "bytes")] Vec<u8>);

    fn expected_serialized_bytes(input: &[u8]) -> Vec<u8> {
        // cbor bytes are tagged with 0x40 & length (a simplification, this
        // gets more complicated for larger length values)
        let len = u8::try_from(input.len()).unwrap();
        if len > 0x17 {
            unimplemented!("bigger integer encoding");
        }
        let bytes_marker = 0x40;
        let mut buf = vec![bytes_marker + len];
        buf.extend_from_slice(input);
        buf
    }

    #[test]
    fn test_array_bytes() {
        let input = BytesArray([0xff; 16]);
        let serialized = to_vec(&input).unwrap();
        assert_eq!(serialized, expected_serialized_bytes(&input.0));
        let output: BytesArray<16> = from_slice(&serialized).unwrap();
        assert_eq!(input, output);
    }

    #[test]
    fn test_array_bytes_error() {
        let input = BytesArray([0xff; 16]);
        let serialized = to_vec(&input).unwrap();
        assert_eq!(serialized, expected_serialized_bytes(&input.0));
        let result = from_slice::<BytesArray<10>>(&serialized);
        assert!(format!("{:?}", result.unwrap_err())
            .contains("invalid length 16, expected byte array of length 10"));
    }

    #[test]
    fn test_array_bytes_from_inefficient() {
        let input = [0xff; 16];
        let serialized = to_vec(&input).unwrap();
        assert_eq!(33, serialized.len());
        let output: BytesArray<16> = from_slice(&serialized).unwrap();
        assert_eq!(input, output.0);
    }

    #[test]
    fn test_vec_bytes() {
        let input = BytesVec(vec![15; 16]);
        let serialized = to_vec(&input).unwrap();
        assert_eq!(serialized, expected_serialized_bytes(&input.0));
        let output: BytesVec = from_slice(&serialized).unwrap();
        assert_eq!(input, output);
    }

    #[test]
    fn test_vec_bytes_from_inefficient() {
        let input = vec![0xff; 16];
        let serialized = to_vec(&input).unwrap();
        assert_eq!(33, serialized.len());
        let output: BytesVec = from_slice(&serialized).unwrap();
        assert_eq!(input, output.0);
    }
}
