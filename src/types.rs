// Copyright (c) 2015, 2016, 2020, 2025 Mark Lee
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

//! Common authentication types.

use crate::parsing::unraveled_map_value;
use crypto_hash;
use hex::FromHex;
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use thiserror::Error;
use unicase::UniCase;

/// Allowable hash algorithms for the `algorithm` parameter.
#[derive(Clone, Debug, PartialEq)]
pub enum HashAlgorithm {
    /// `MD5`
    Md5,
    /// `MD5-sess`
    Md5Session,
    /// `SHA-256`
    Sha256,
    /// `SHA-256-sess`
    Sha256Session,
    /// `SHA-512-256`
    Sha512256,
    /// `SHA-512-256-sess`
    Sha512256Session,
}

/// Errors relating to parsing/serializing digest authorization.
#[derive(Debug, Error)]
pub enum AuthorizationError {
    /// Parse errors for the nonce_count parameter.
    #[error("Could not parse nonce count")]
    ParseNonceCount,
    /// Parse errors around the qop (quality of protection) parameter.
    #[error("Unknown quality of protection parameter: {0}")]
    UnknownQop(String),
    /// Unknown/unsupported digest hash algorithm.
    #[error("Unknown hash algorithm: {0}")]
    UnknownAlgorithm(String),
}

impl FromStr for HashAlgorithm {
    type Err = AuthorizationError;

    fn from_str(s: &str) -> Result<HashAlgorithm, AuthorizationError> {
        match s {
            "MD5" => Ok(HashAlgorithm::Md5),
            "MD5-sess" => Ok(HashAlgorithm::Md5Session),
            "SHA-256" => Ok(HashAlgorithm::Sha256),
            "SHA-256-sess" => Ok(HashAlgorithm::Sha256Session),
            "SHA-512-256" => Ok(HashAlgorithm::Sha512256),
            "SHA-512-256-sess" => Ok(HashAlgorithm::Sha512256Session),
            _ => Err(AuthorizationError::UnknownAlgorithm(s.to_string())),
        }
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            HashAlgorithm::Md5 => write!(f, "MD5"),
            HashAlgorithm::Md5Session => write!(f, "MD5-sess"),
            HashAlgorithm::Sha256 => write!(f, "SHA-256"),
            HashAlgorithm::Sha256Session => write!(f, "SHA-256-sess"),
            HashAlgorithm::Sha512256 => write!(f, "SHA-512-256"),
            HashAlgorithm::Sha512256Session => write!(f, "SHA-512-256-sess"),
        }
    }
}

impl HashAlgorithm {
    fn to_algorithm(&self) -> crypto_hash::Algorithm {
        match *self {
            HashAlgorithm::Md5 | HashAlgorithm::Md5Session => crypto_hash::Algorithm::MD5,
            HashAlgorithm::Sha256 | HashAlgorithm::Sha256Session => crypto_hash::Algorithm::SHA256,
            HashAlgorithm::Sha512256 | HashAlgorithm::Sha512256Session => {
                crypto_hash::Algorithm::SHA512
            }
        }
    }

    /// Generate a hexadecimal representation of the output of a cryptographic hash function, given
    /// `data` and the algorithm.
    pub fn hex_digest(&self, data: &[u8]) -> String {
        let mut digest = crypto_hash::hex_digest(self.to_algorithm(), data);
        if *self == HashAlgorithm::Sha512256 || *self == HashAlgorithm::Sha256Session {
            digest.truncate(64);
        }

        digest
    }
}

/// Convenience type for nonce counts.
#[derive(Clone, Debug, PartialEq)]
pub struct NonceCount(pub u32);

impl FromStr for NonceCount {
    type Err = AuthorizationError;
    fn from_str(s: &str) -> Result<NonceCount, AuthorizationError> {
        match Vec::from_hex(s) {
            Ok(bytes) => {
                let mut count: u32 = 0;
                count |= (bytes[0] as u32) << 24;
                count |= (bytes[1] as u32) << 16;
                count |= (bytes[2] as u32) << 8;
                count |= bytes[3] as u32;
                Ok(NonceCount(count))
            }
            _ => Err(AuthorizationError::ParseNonceCount),
        }
    }
}

impl fmt::Display for NonceCount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let NonceCount(value) = *self;
        write!(f, "{:08x}", value)
    }
}

impl NonceCount {
    /// Extracts an `NonceCount` object from a map of header parameters.
    /// Returns an error if the value is not a valid nonce count.
    pub fn from_parameters(
        map: &HashMap<UniCase<String>, String>,
    ) -> Result<Option<NonceCount>, AuthorizationError> {
        if let Some(value) = unraveled_map_value(map, "nc") {
            match NonceCount::from_str(&value[..]) {
                Ok(count) => Ok(Some(count)),
                Err(err) => Err(err),
            }
        } else {
            Ok(None)
        }
    }
}

/// Allowable values for the `qop`, or "quality of protection" parameter.
#[derive(Clone, Debug, PartialEq)]
pub enum Qop {
    /// `auth`
    Auth,
    /// `auth-int`
    AuthInt,
}

impl FromStr for Qop {
    type Err = AuthorizationError;
    fn from_str(s: &str) -> Result<Qop, AuthorizationError> {
        match s {
            "auth" => Ok(Qop::Auth),
            "auth-int" => Ok(Qop::AuthInt),
            _ => Err(AuthorizationError::UnknownQop(s.to_string())),
        }
    }
}

impl fmt::Display for Qop {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Qop::Auth => write!(f, "auth"),
            Qop::AuthInt => write!(f, "auth-int"),
        }
    }
}

impl Qop {
    /// Extracts a `Qop` object from a map of header parameters.
    /// Returns an error if the value is not a valid qop value.
    pub fn from_parameters(
        map: &HashMap<UniCase<String>, String>,
    ) -> Result<Option<Qop>, AuthorizationError> {
        if let Some(value) = unraveled_map_value(map, "qop") {
            match Qop::from_str(&value[..]) {
                Ok(converted) => Ok(Some(converted)),
                Err(err) => Err(err),
            }
        } else {
            Ok(None)
        }
    }
}
