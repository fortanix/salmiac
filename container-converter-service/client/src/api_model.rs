use rustc_serialize::base64::{FromBase64, ToBase64, STANDARD};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use serde::de::Error as DeserializeError;
use std::ops::{Deref, DerefMut};
use std::fmt;
use std::convert::TryFrom;
use rustc_serialize::hex::{FromHex, ToHex};

pub use crate::generated::*;

/// Arbitrary binary data that is serialized/deserialized to/from base 64 string.
#[derive(Default, Clone, Debug, Eq, PartialEq, Hash)]
pub struct Blob(Vec<u8>);

impl From<Vec<u8>> for Blob {
    fn from(d: Vec<u8>) -> Self {
        Blob(d)
    }
}

impl From<String> for Blob {
    fn from(s: String) -> Self {
        Blob(s.into_bytes())
    }
}

impl<'a> From<&'a str> for Blob {
    fn from(s: &str) -> Self {
        Blob(s.as_bytes().to_owned())
    }
}

impl From<Blob> for Vec<u8> {
    fn from(d: Blob) -> Self {
        d.0
    }
}

impl Deref for Blob {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Blob {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Serialize for Blob {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_base64(STANDARD))
    }
}

impl<'de> Deserialize<'de> for Blob {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl<'a> serde::de::Visitor<'a> for Visitor {
            type Value = Blob;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "base64-encoded string")
            }

            fn visit_str<E: de::Error>(self, string: &str) -> Result<Blob, E> {
                Ok(Blob(string.from_base64().map_err(|_| {
                    de::Error::invalid_value(de::Unexpected::Str(string), &"base64 encoded string")
                })?))
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}

impl AsRef<[u8]> for Blob {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HexString(Vec<u8>);

impl HexString {
    pub fn new<T: Into<Vec<u8>>>(bytes: T) -> HexString {
        HexString(bytes.into())
    }

    pub fn from_str(hex_string: &str) -> Result<HexString, String> {
        Ok(HexString(hex_string.from_hex().map_err(|e| e.to_string())?))
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

impl Deref for HexString {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for HexString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.to_hex())
    }
}

impl<'de> Deserialize<'de> for HexString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<HexString, D::Error> {
        struct Visitor;

        impl<'a> serde::de::Visitor<'a> for Visitor {
            type Value = HexString;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "hex encoded string")
            }

            fn visit_str<E: DeserializeError>(self, string: &str) -> Result<HexString, E> {
                Ok(HexString::from_str(string)
                    .map_err(|_| DeserializeError::invalid_value(serde::de::Unexpected::Str(string), &"hex encoded string"))?)
            }
        }

        deserializer.deserialize_string(Visitor)
    }
}

impl Serialize for HexString {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl TryFrom<&str> for HexString {
    type Error = String;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        HexString::from_str(s)
    }
}

impl From<Vec<u8>> for HexString {
    fn from(v: Vec<u8>) -> Self {
        HexString(v)
    }
}

impl From<HexString> for String {
    fn from(h: HexString) -> Self {
        h.to_string()
    }
}

impl From<HexString> for Vec<u8> {
    fn from(h: HexString) -> Self {
        h.into_inner()
    }
}