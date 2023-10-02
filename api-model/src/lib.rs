/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

pub mod converter;
pub mod enclave;

#[cfg(feature = "serde")]
use serde::de::{Error};
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use std::ops::Deref;
use std::fmt;
use std::convert::TryFrom;

/// Contains raw bytes of a hex decoded string
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HexString(Vec<u8>);

impl HexString {
    /// Creates a new instance of `HexString` from raw bytes
    pub fn new<T: Into<Vec<u8>>>(bytes: T) -> HexString {
        HexString(bytes.into())
    }

    /// Decodes a hex string `hex_string` into raw bytes
    /// # Returns
    /// An instance of `Ok(HexString)` if `hex_string` represents a valid hex encoded string or
    /// an instance of `Err(String)` otherwise.
    pub fn from_str(hex_string: &str) -> Result<HexString, String> {
        Ok(HexString(hex::decode(hex_string).map_err(|e| e.to_string())?))
    }

    /// Returns raw bytes consuming `self`
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
        f.write_str(&hex::encode(&self.0))
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for HexString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<HexString, D::Error> {
        struct Visitor;

        impl<'a> serde::de::Visitor<'a> for Visitor {
            type Value = HexString;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "hex encoded string")
            }

            fn visit_str<E: Error>(self, string: &str) -> Result<HexString, E> {
                Ok(HexString::from_str(string)
                    .map_err(|_| Error::invalid_value(serde::de::Unexpected::Str(string), &"hex encoded string"))?)
            }
        }

        deserializer.deserialize_string(Visitor)
    }
}

#[cfg(feature = "serde")]
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

/// Describes an arbitrary memory size in bytes
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ByteUnit(u64);

impl ByteUnit {

    /// Creates a new instance of `ByteUnit` from raw value
    pub fn new<T: Into<u64>>(value: T) -> ByteUnit {
        ByteUnit(value.into())
    }

    /// Parses memory size encoded as a string into a memory size in bytes
    /// # String format
    /// (digit*)(size_unit), where size_unit describes memory measurement unit and can be one of the following:
    /// K(k) - kilobyte
    /// M(m) - megabyte
    /// G(g) - gigabyte
    /// # Returns
    /// An instance of `Ok(ByteUnit)` if `value` represents a valid memory size string or
    /// an instance of `Err(String)` otherwise.
    pub fn from_str(value: &str) -> Result<ByteUnit, String> {
        fn parse_value(value: &str) -> Result<u64, String> {
            let multiplier = {
                if let Some(last_char) = value.chars().last() {
                    match last_char {
                        'K' | 'k' => Ok(1024),
                        'M' | 'm' => Ok(1024 * 1024),
                        'G' | 'g' => Ok(1024 * 1024 * 1024),
                        digit if digit.is_digit(10) => Ok(1),
                        other => Err(format!("unrecognized unit '{}'", other)),
                    }?
                } else {
                    return Ok(0)
                }
            };

            let value_str = if multiplier == 1 {
                value
            } else if value.len() < 2 {
                return Err("no value specified".to_owned())
            } else {
                &value[..value.len() - 1] // remove size suffix
            };

            u64::from_str_radix(value_str, 10)
                .map(|v| v * multiplier)
                .map_err(|_| "invalid value specified".to_owned())
        }
        parse_value(value).map(|e| ByteUnit(e))
    }

    /// Returns memory size in bytes
    pub fn to_inner(&self) -> u64 {
        self.0
    }

    /// Returns memory size in mega bytes
    pub fn to_mb(&self) -> u64 {
        self.0 / 1024 / 1024
    }
}


impl fmt::Display for ByteUnit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { self.0.fmt(f) }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for ByteUnit {

    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<ByteUnit, D::Error> {
        struct Visitor;

        impl<'a> serde::de::Visitor<'a> for Visitor {

            type Value = ByteUnit;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "number of bytes")
            }

            fn visit_str<E: Error>(self, string: &str) -> Result<ByteUnit, E> {
                ByteUnit::from_str(string)
                    .map_err(|_| Error::invalid_value(serde::de::Unexpected::Str(string), &"number of bytes"))
            }

        }

        deserializer.deserialize_string(Visitor)
    }
}

#[cfg(feature = "serde")]
impl Serialize for ByteUnit {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl TryFrom<&str> for ByteUnit {
    type Error = String;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        ByteUnit::from_str(s)
    }
}

impl From<u64> for ByteUnit {
    fn from(v: u64) -> ByteUnit {
        ByteUnit(v)
    }
}

impl From<ByteUnit> for u64 {
    fn from(h: ByteUnit) -> u64 { h.to_inner() }
}

#[cfg(test)]
pub mod tests {
    use crate::{ByteUnit, HexString};

    #[test]
    pub fn test_byte_unit_conversion() {
        let bytes = ByteUnit::from_str("2000").unwrap();

        assert_eq!(bytes.to_inner(), 2000);

        let kilobytes = ByteUnit::from_str("1K").unwrap();

        assert_eq!(kilobytes.to_inner(), 1024);

        let megabytes = ByteUnit::from_str("1M").unwrap();

        assert_eq!(megabytes.to_inner(), 1024 * 1024);

        let gigabytes = ByteUnit::from_str("1G").unwrap();

        assert_eq!(gigabytes.to_inner(), 1024 * 1024 * 1024);
    }

    #[test]
    fn hex_string_from_str() {
        let test_cases = ["0123456789abcdefABCDEF", "0123456789abcdefABCDEF000000"];
        for i in 0..test_cases.len() {
            let reference = &test_cases[i];

            let result = HexString::from_str(reference).unwrap();

            assert_eq!(reference.to_lowercase(), result.to_string());
        }
    }

    #[test]
    fn hex_string_correct_decode() {
        let test_cases = "48656c6c6f20776f726c6421";
        let reference = "Hello world!".to_owned().into_bytes();

        let result = HexString::from_str(test_cases).unwrap();

        assert_eq!(reference, result.into_inner());
    }
    
    #[cfg(feature = "serde")]
    #[test]
    pub fn test_byte_unit_serialization() {
        let bytes = ByteUnit::new(123 as u64);

        let result = serde_json::to_string(&bytes).expect("Serialize ok");

        assert_eq!(result, "\"123\"");
    }

    #[cfg(feature = "serde")]
    #[test]
    pub fn test_byte_unit_deserialization_correct_pass() {
        let test_cases = ["\"\"", "\"123\"", "\"1K\"", "\"1k\"", "\"1M\"", "\"1m\"", "\"1G\"", "\"1g\""];
        let references: [u64; 8] = [0, 123, 1 * 1024, 1 * 1024, 1 * 1024 * 1024, 1 * 1024 * 1024, 1 * 1024 * 1024 * 1024, 1 * 1024 * 1024 * 1024];

        for i in 0..test_cases.len() {
            let test_case = &test_cases[i];

            let result: ByteUnit = serde_json::from_str(test_case).expect("Deserialize ok");
            assert_eq!(result.to_inner(), references[i])
        }
    }

    #[cfg(feature = "serde")]
    #[test]
    pub fn test_byte_unit_deserialization_incorrect_pass() {
        let test_cases = ["\"1D\"", "\"1Kd\"", "\"1M1\"",];
        for i in 0..test_cases.len() {
            let test_case = &test_cases[i];

            let result: Result<ByteUnit, _> = serde_json::from_str(test_case);
            assert!(result.is_err())
        }
    }

    #[cfg(feature = "serde")]
    #[test]
    pub fn test_hex_string_serialization_correct_pass() {
        let test_case = "0123456789abcdefABCDEF";
        let reference = format!("\"{}\"", test_case);
        let hex_string = HexString::from_str(test_case).unwrap();

        let result = serde_json::to_string(&hex_string).expect("Serialize ok");


        assert_eq!(result, reference.to_lowercase());
    }

    #[cfg(feature = "serde")]
    #[test]
    pub fn test_hex_string_deserialization_correct_pass() {
        let test_cases = ["0123456789abcdefABCDEF", ""];
        for i in 0..test_cases.len() {
            let reference = &test_cases[i];

            let result: HexString = serde_json::from_str(&format!("\"{}\"", reference)).expect("Deserialization ok");

            assert_eq!(result.to_string(), reference.to_lowercase());
        }
    }

    #[cfg(feature = "serde")]
    #[test]
    pub fn test_hex_string_deserialization_incorrect_pass() {
        let test_cases = [format!("\"{}\"", "123XYZ"), format!("\"{}\"", "xyz")];
        for i in 0..test_cases.len() {
            let test_case = &test_cases[i];

            let result: Result<HexString, _> = serde_json::from_str(test_case);
            assert!(result.is_err())
        }
    }
}
