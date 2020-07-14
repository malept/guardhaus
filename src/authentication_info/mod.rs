// Copyright (c) 2016, 2017, 2020 Mark Lee
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

//! An implementation of the `Authentication-Info` header.

use super::types::{NonceCount, Qop};
use hyper::header::parsing::from_one_raw_str;
use hyper::header::{Formatter, Header, Raw};
use hyper::{Error as HyperError, Result as HyperResult};
use parsing::{append_parameter, parse_parameters, unraveled_map_value};
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use unicase::UniCase;

mod test;

/// Parameters for the `Authentication-Info` header.
#[derive(Clone, PartialEq, Debug)]
pub struct AuthenticationInfo {
    /// The digest of the entity body, parameter name `digest` in RFC 2069, `rspauth` otherwise
    pub digest: Option<String>,
    /// `nextnonce` - per RFC 7616, "the nonce the server wishes the client to use for a future
    /// authentication response."
    pub next_nonce: Option<String>,
    /// Quality of protection
    pub qop: Option<Qop>,
    /// Cryptographic nonce from the client
    pub client_nonce: Option<String>,
    /// Nonce count, parameter name `nc`
    pub nonce_count: Option<NonceCount>,
}

fn parse_digest(map: &HashMap<UniCase<String>, String>) -> Result<Option<String>, HyperError> {
    if let Some(rspauth) = unraveled_map_value(map, "rspauth") {
        if unraveled_map_value(map, "digest").is_some() {
            Err(HyperError::Header)
        } else {
            Ok(Some(rspauth))
        }
    } else if let Some(digest) = unraveled_map_value(map, "digest") {
        Ok(Some(digest))
    } else {
        Ok(None)
    }
}

impl FromStr for AuthenticationInfo {
    type Err = HyperError;

    fn from_str(s: &str) -> Result<AuthenticationInfo, HyperError> {
        let parameters = parse_parameters(s);
        let digest = parse_digest(&parameters)?;
        let qop = Qop::from_parameters(&parameters)?;
        let client_nonce = unraveled_map_value(&parameters, "cnonce");
        let nonce_count = NonceCount::from_parameters(&parameters)?;

        if qop.is_some() && (digest.is_none() || client_nonce.is_none() || nonce_count.is_none()) {
            return Err(HyperError::Header);
        }

        Ok(AuthenticationInfo {
            digest,
            next_nonce: unraveled_map_value(&parameters, "nextnonce"),
            qop,
            client_nonce,
            nonce_count,
        })
    }
}

impl Header for AuthenticationInfo {
    fn header_name() -> &'static str {
        "Authentication-Info"
    }

    fn parse_header(raw: &Raw) -> HyperResult<AuthenticationInfo> {
        from_one_raw_str(raw).and_then(|s: String| AuthenticationInfo::from_str(&s[..]))
    }

    fn fmt_header(&self, f: &mut Formatter) -> fmt::Result {
        f.fmt_line(self)
    }
}

impl fmt::Display for AuthenticationInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut serialized = String::new();

        if let Some(ref digest) = self.digest {
            append_parameter(&mut serialized, "rspauth", digest, true);
        }

        if let Some(ref next_nonce) = self.next_nonce {
            append_parameter(&mut serialized, "nextnonce", next_nonce, true);
        }

        if let Some(ref qop) = self.qop {
            append_parameter(&mut serialized, "qop", &qop.to_string(), false);
        }

        if let Some(ref client_nonce) = self.client_nonce {
            append_parameter(&mut serialized, "cnonce", client_nonce, true);
        }

        if let Some(ref nonce_count) = self.nonce_count {
            append_parameter(&mut serialized, "nc", &nonce_count.to_string(), false);
        }

        write!(f, "{}", serialized)
    }
}
