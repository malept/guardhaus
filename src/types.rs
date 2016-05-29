// Copyright (c) 2015, 2016 Mark Lee
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

use hex::FromHex;
use hyper::error::Error;
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use super::parsing::unraveled_map_value;
use unicase::UniCase;

/// Allowable values for the `qop`, or "quality of protection" parameter.
#[derive(Clone, Debug, PartialEq)]
pub enum Qop {
    /// `auth`
    Auth,
    /// `auth-int`
    AuthInt,
}

impl FromStr for Qop {
    type Err = Error;
    fn from_str(s: &str) -> Result<Qop, Error> {
        match s {
            "auth" => Ok(Qop::Auth),
            "auth-int" => Ok(Qop::AuthInt),
            _ => Err(Error::Header),
        }
    }
}

impl fmt::Display for Qop {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Qop::Auth => write!(f, "{}", "auth"),
            Qop::AuthInt => write!(f, "{}", "auth-int"),
        }
    }
}

impl Qop {
    /// Extracts a `Qop` object from a map of header parameters.
    /// Returns an error if the value is not a valid qop value.
    pub fn from_parameters(map: &HashMap<UniCase<String>, String>) -> Result<Option<Qop>, Error> {
        if let Some(value) = unraveled_map_value(map, "qop") {
            match Qop::from_str(&value[..]) {
                Ok(converted) => Ok(Some(converted)),
                Err(_) => Err(Error::Header),
            }
        } else {
            Ok(None)
        }
    }
}

/// Convenience type for nonce counts.
#[derive(Clone, Debug, PartialEq)]
pub struct NonceCount(pub u32);

impl FromStr for NonceCount {
    type Err = Error;
    fn from_str(s: &str) -> Result<NonceCount, Error> {
        match Vec::from_hex(s) {
            Ok(bytes) => {
                let mut count: u32 = 0;
                count |= (bytes[0] as u32) << 24;
                count |= (bytes[1] as u32) << 16;
                count |= (bytes[2] as u32) << 8;
                count |= bytes[3] as u32;
                Ok(NonceCount(count))
            }
            _ => Err(Error::Header),
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
    pub fn from_parameters(map: &HashMap<UniCase<String>, String>)
                           -> Result<Option<NonceCount>, Error> {
        if let Some(value) = unraveled_map_value(map, "nc") {
            match NonceCount::from_str(&value[..]) {
                Ok(count) => Ok(Some(count)),
                _ => Err(Error::Header),
            }
        } else {
            Ok(None)
        }
    }
}
