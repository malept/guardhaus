// Copyright (c) 2016 Mark Lee
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

//! An implementation of the Authentication-Info header.

use hyper::{Error as HyperError, Result as HyperResult};
use hyper::header::Header;
use hyper::header::parsing::from_one_raw_str;
use parsing::{parse_parameters, unraveled_map_value};
use std::str::FromStr;

mod test;

#[derive(Clone, PartialEq, Debug)]
struct AuthenticationInfo {
    /// The digest of the entity body.
    digest: Option<String>,
    /// `nextnonce` - per RFC 2069, "the nonce the server wishes the client to use for the next
    /// authentication response."
    next_nonce: Option<String>,
}

impl FromStr for AuthenticationInfo {
    type Err = HyperError;

    fn from_str(s: &str) -> Result<AuthenticationInfo, HyperError> {
        let parameters = parse_parameters(s);
        Ok(AuthenticationInfo {
            digest: unraveled_map_value(&parameters, "digest"),
            next_nonce: unraveled_map_value(&parameters, "nextnonce"),
        })
    }
}

impl Header for AuthenticationInfo {
    fn header_name() -> &'static str {
        "Authentication-info"
    }

    fn parse_header(raw: &[Vec<u8>]) -> HyperResult<AuthenticationInfo> {
        from_one_raw_str(raw).and_then(|s: String| {
            AuthenticationInfo::from_str(&s[..])
        })
    }
}
