// Copyright (c) 2016, 2017, 2020, 2025 Mark Lee
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

use crate::parsing::{DigestParameters, parse_parameters, unraveled_map_value};
use crate::types::{NonceCount, Qop};
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use unicase::UniCase;

mod test;

type HeadersResult<T> = Result<T, headers::Error>;

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

fn parse_digest(map: &HashMap<UniCase<String>, String>) -> HeadersResult<Option<String>> {
    if let Some(rspauth) = unraveled_map_value(map, "rspauth") {
        if unraveled_map_value(map, "digest").is_some() {
            Err(headers::Error::invalid())
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
    type Err = headers::Error;

    fn from_str(s: &str) -> HeadersResult<AuthenticationInfo> {
        let parameters = parse_parameters(s);
        let digest = parse_digest(&parameters)?;
        let qop = match Qop::from_parameters(&parameters) {
            Ok(val) => val,
            Err(_) => return Err(headers::Error::invalid()),
        };
        let client_nonce = unraveled_map_value(&parameters, "cnonce");
        let nonce_count = match NonceCount::from_parameters(&parameters) {
            Ok(val) => val,
            Err(_) => return Err(headers::Error::invalid()),
        };

        if qop.is_some() && (digest.is_none() || client_nonce.is_none() || nonce_count.is_none()) {
            return Err(headers::Error::invalid());
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

impl headers::Header for AuthenticationInfo {
    fn name() -> &'static http::HeaderName {
        static NAME: http::HeaderName = http::HeaderName::from_static("authentication-info");
        &NAME
    }

    fn decode<'i, I>(values: &mut I) -> HeadersResult<Self>
    where
        I: Iterator<Item = &'i headers::HeaderValue>,
    {
        let value = values.next().ok_or_else(headers::Error::invalid)?;
        Self::from_str(
            value
                .to_str()
                .expect("Could not serialize Authentication-Info header value"),
        )
    }

    fn encode<E>(&self, values: &mut E)
    where
        E: Extend<headers::HeaderValue>,
    {
        let value = headers::HeaderValue::from_str(&self.to_string())
            .expect("Could not generate HeaderValue for Authentication-Info");
        values.extend(std::iter::once(value));
    }
}

impl fmt::Display for AuthenticationInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut parameters = DigestParameters::new();

        if let Some(ref digest) = self.digest {
            parameters.append("rspauth", digest, true);
        }

        if let Some(ref next_nonce) = self.next_nonce {
            parameters.append("nextnonce", next_nonce, true);
        }

        if let Some(ref qop) = self.qop {
            parameters.append("qop", &qop.to_string(), false);
        }

        if let Some(ref client_nonce) = self.client_nonce {
            parameters.append("cnonce", client_nonce, true);
        }

        if let Some(ref nonce_count) = self.nonce_count {
            parameters.append("nc", &nonce_count.to_string(), false);
        }

        write!(f, "{}", parameters)
    }
}
