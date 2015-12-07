// Copyright (c) 2015 Mark Lee

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

//! An HTTP Digest implementation for [Hyper](http://hyper.rs)'s `Authentication` header.

use hyper::error::Error;
use hyper::header::parsing::from_comma_delimited;
use hyper::header::Scheme;
use hyper::method::Method;
use rustc_serialize::hex::FromHex;
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use unicase::UniCase;
use url::percent_encoding::percent_decode;

/// Allowable hash algorithms for the `algorithm` parameter.
#[derive(Clone, Debug, PartialEq)]
pub enum HashAlgorithm {
    /// `MD5`
    MD5,
    /// `MD5-sess`
    MD5Session,
}

impl FromStr for HashAlgorithm {
    type Err = Error;
    fn from_str(s: &str) -> Result<HashAlgorithm, Error> {
        match s {
            "MD5" => Ok(HashAlgorithm::MD5),
            "MD5-sess" => Ok(HashAlgorithm::MD5Session),
            _ => Err(Error::Header),
        }
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            HashAlgorithm::MD5 => write!(f, "{}", "MD5"),
            HashAlgorithm::MD5Session => write!(f, "{}", "MD5-sess"),
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

/// Parameters for the `Authorization` header when using the `Digest` scheme.
///
/// The parameters are described in more detail in
/// [RFC 2617](https://tools.ietf.org/html/rfc2617#section-3.2.2).
/// Unless otherwise noted, the parameter name maps to the struct variable name.
#[derive(Clone, PartialEq, Debug)]
pub struct Digest {
    /// User name.
    pub username: String,
    /// Authentication realm.
    pub realm: String,
    /// Cryptographic nonce.
    pub nonce: String,
    /// Nonce count, parameter name `nc`. Optional only in RFC2067 mode.
    pub nonce_count: Option<u32>,
    /// The hexadecimal digest of the payload as described by the RFCs.
    pub response: String,
    /// Either the absolute path or URI of the HTTP request, parameter name `uri`.
    pub request_uri: String,
    /// The hash algorithm to use when generating the `response`.
    pub algorithm: HashAlgorithm,
    /// Quality of protection. Optional only in RFC2067 mode.
    pub qop: Option<Qop>,
    /// Cryptographic nonce from the client. Optional only in RFC2067 mode.
    pub client_nonce: Option<String>,
    /// Optional opaque string.
    pub opaque: Option<String>,
}

fn append_parameter(serialized: &mut String, key: &str, value: &String, quoted: bool) {
    if serialized.len() > 0 {
        serialized.push_str(", ")
    }
    serialized.push_str(key);
    serialized.push_str("=");
    if quoted {
        serialized.push_str("\"");
    }
    serialized.push_str(value);
    if quoted {
        serialized.push_str("\"");
    }
}

impl Scheme for Digest {
    fn scheme() -> Option<&'static str> {
        Some("Digest")
    }

    fn fmt_scheme(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut serialized = String::new();
        append_parameter(&mut serialized, "username", &self.username, true);
        append_parameter(&mut serialized, "realm", &self.realm, true);
        append_parameter(&mut serialized, "nonce", &self.nonce, true);
        if let Some(nonce_count) = self.nonce_count {
            append_parameter(&mut serialized,
                             "nc",
                             &format!("{:08x}", nonce_count),
                             false);
        }
        append_parameter(&mut serialized, "response", &self.response, true);
        append_parameter(&mut serialized, "uri", &self.request_uri, true);
        append_parameter(&mut serialized,
                         "algorithm",
                         &format!("{}", self.algorithm),
                         false);
        if let Some(ref qop) = self.qop {
            append_parameter(&mut serialized, "qop", &format!("{}", qop), false);
        }
        if let Some(ref client_nonce) = self.client_nonce {
            append_parameter(&mut serialized, "cnonce", client_nonce, true);
        }
        if let Some(ref opaque) = self.opaque {
            append_parameter(&mut serialized, "opaque", opaque, true);
        }
        write!(f, "{}", serialized)
    }
}

fn unraveled_map_value(map: &HashMap<UniCase<String>, String>, key: &str) -> Option<String> {
    let value = match map.get(&UniCase(key.to_string())) {
        Some(v) => v,
        None => return None,
    };
    match String::from_utf8(percent_decode(value.as_bytes())) {
        Ok(string) => Some(string),
        Err(_) => None,
    }
}

impl FromStr for Digest {
    type Err = Error;
    fn from_str(s: &str) -> Result<Digest, Error> {
        let bytearr = &[String::from(s).into_bytes()];
        let parameters: Vec<String> = from_comma_delimited(bytearr).unwrap();
        let mut param_map: HashMap<UniCase<String>, String> =
            HashMap::with_capacity(parameters.len());
        for parameter in parameters {
            let parts: Vec<&str> = parameter.splitn(2, '=').collect();
            param_map.insert(UniCase(parts[0].trim().to_string()).clone(),
                             parts[1].trim().trim_matches('"').to_string().clone());
        }
        let username: String;
        let realm: String;
        let nonce: String;
        let nonce_count: Option<u32>;
        let response: String;
        let request_uri: String;
        let algorithm: HashAlgorithm;
        let qop: Option<Qop>;
        match unraveled_map_value(&param_map, "username") {
            Some(value) => username = value,
            None => return Err(Error::Header),
        }
        match unraveled_map_value(&param_map, "realm") {
            Some(value) => realm = value,
            None => return Err(Error::Header),
        }
        match unraveled_map_value(&param_map, "nonce") {
            Some(value) => nonce = value,
            None => return Err(Error::Header),
        }
        if let Some(value) = unraveled_map_value(&param_map, "nc") {
            match (&value[..]).from_hex() {
                Ok(bytes) => {
                    let mut count: u32 = 0;
                    count |= (bytes[0] as u32) << 24;
                    count |= (bytes[1] as u32) << 16;
                    count |= (bytes[2] as u32) << 8;
                    count |= bytes[3] as u32;
                    nonce_count = Some(count)
                }
                _ => return Err(Error::Header),
            }
        } else {
            nonce_count = None;
        }
        match unraveled_map_value(&param_map, "response") {
            Some(value) => response = value,
            None => return Err(Error::Header),
        }
        match unraveled_map_value(&param_map, "uri") {
            Some(value) => request_uri = value,
            None => return Err(Error::Header),
        }
        if let Some(value) = unraveled_map_value(&param_map, "algorithm") {
            match HashAlgorithm::from_str(&value[..]) {
                Ok(converted) => algorithm = converted,
                Err(_) => return Err(Error::Header),
            }
        } else {
            algorithm = HashAlgorithm::MD5;
        }
        if let Some(value) = unraveled_map_value(&param_map, "qop") {
            match Qop::from_str(&value[..]) {
                Ok(converted) => qop = Some(converted),
                Err(_) => return Err(Error::Header),
            }
        } else {
            qop = None;
        }
        Ok(Digest {
            username: username,
            realm: realm,
            nonce: nonce,
            nonce_count: nonce_count,
            response: response,
            request_uri: request_uri,
            algorithm: algorithm,
            qop: qop,
            client_nonce: unraveled_map_value(&param_map, "cnonce"),
            opaque: unraveled_map_value(&param_map, "opaque"),
        })
    }
}

fn format_simple_a1(username: String, realm: String, password: String) -> String {
    format!("{}:{}:{}", username, realm, password)
}

fn generate_simple_a1(digest: &Digest, password: String) -> String {
    format_simple_a1(digest.username.clone(), digest.realm.clone(), password)
}

/// Generates a simple hexadecimal digest from an A1 value and given algorithm.
///
/// This is intended to be used in applications that use the `htdigest` style of secret hash
/// generation.
///
/// To see how a simple A1 value is constructed, see
/// [RFC 2617, section 3.2.2.2](https://tools.ietf.org/html/rfc2617#section-3.2.2.2).
/// This is the definition when the algorithm is "unspecified".
pub fn generate_simple_hashed_a1(algorithm: &HashAlgorithm,
                                 username: String,
                                 realm: String,
                                 password: String)
                                 -> String {
    hash_value(algorithm, format_simple_a1(username, realm, password))
}

// RFC 2617, Section 3.2.2.2
fn generate_a1(digest: &Digest, password: String) -> Result<String, Error> {
    match digest.algorithm {
        HashAlgorithm::MD5 => Ok(generate_simple_a1(digest, password)),
        HashAlgorithm::MD5Session => {
            if let Some(ref client_nonce) = digest.client_nonce {
                let hashed_simple_a1 = hash_value(&HashAlgorithm::MD5,
                                                  generate_simple_a1(digest, password));
                Ok(format!("{}:{}:{}", hashed_simple_a1, digest.nonce, client_nonce))
            } else {
                Err(Error::Header)
            }
        }
    }
}

/// Generates a hexadecimal digest from an A1 value.
///
/// To see how an A1 value is constructed, see
/// [RFC 2617, section 3.2.2.2](https://tools.ietf.org/html/rfc2617#section-3.2.2.2).
fn generate_hashed_a1(digest: &Digest, password: String) -> Result<String, Error> {
    if let Ok(a1) = generate_a1(digest, password) {
        Ok(hash_value(&digest.algorithm, a1))
    } else {
        Err(Error::Header)
    }
}

// RFC 2617, Section 3.2.2.3
fn generate_a2(digest: &Digest, method: Method, entity_body: String) -> String {
    match digest.qop {
        Some(Qop::AuthInt) => {
            format!("{}:{}:{}",
                    method,
                    digest.request_uri,
                    hash_value(&digest.algorithm, entity_body))
        }
        _ => format!("{}:{}", method, digest.request_uri),
    }
}

fn generate_hashed_a2(digest: &Digest, method: Method, entity_body: String) -> String {
    hash_value(&digest.algorithm, generate_a2(digest, method, entity_body))
}

fn hash_value(algorithm: &HashAlgorithm, value: String) -> String {
    use crypto::digest::Digest;
    use crypto::md5::Md5;

    match *algorithm {
        HashAlgorithm::MD5 |
        HashAlgorithm::MD5Session => {
            let mut md5 = Md5::new();
            md5.input_str(&value[..]);
            md5.result_str().to_string()
        }
    }
}

fn generate_kd(algorithm: &HashAlgorithm, secret: String, data: String) -> String {
    let value = format!("{}:{}", secret, data);
    hash_value(algorithm, value)
}

/// Generates a digest, given an HTTP request and a password.
///
/// `entity_body` is defined in
/// [RFC2616, secion 7.2](https://tools.ietf.org/html/rfc2616#section-7.2).
pub fn generate_digest_using_password(digest: &Digest,
                                      method: Method,
                                      entity_body: String,
                                      password: String)
                                      -> Result<String, Error> {
    if let Ok(a1) = generate_hashed_a1(digest, password) {
        generate_digest_using_hashed_a1(digest, method, entity_body, a1)
    } else {
        Err(Error::Header)
    }
}

/// Generates a digest, given an HTTP request and a hexadecimal digest of an A1 string.
///
/// `entity_body` is defined in
/// [RFC2616, secion 7.2](https://tools.ietf.org/html/rfc2616#section-7.2).
///
/// This is intended to be used in applications that use the `htdigest` style of secret hash
/// generation.
pub fn generate_digest_using_hashed_a1(digest: &Digest,
                                       method: Method,
                                       entity_body: String,
                                       a1: String)
                                       -> Result<String, Error> {
    let a2 = generate_hashed_a2(digest, method, entity_body);
    let data: String;
    if let Some(ref qop) = digest.qop {
        match *qop {
            Qop::Auth | Qop::AuthInt => {
                if digest.client_nonce.is_none() || digest.nonce_count.is_none() {
                    return Err(Error::Header);
                }
                let nonce = digest.nonce.clone();
                let nonce_count = digest.nonce_count.clone().unwrap();
                let client_nonce = digest.client_nonce.clone().unwrap();
                data = format!("{}:{:08x}:{}:{}:{}",
                               nonce,
                               nonce_count,
                               client_nonce,
                               qop,
                               a2);
            }
        }
    } else {
        data = format!("{}:{}", digest.nonce, a2);
    }
    Ok(generate_kd(&digest.algorithm, a1, data))
}

/// Validates a `Digest.response`, given an HTTP request and a password.
///
/// `entity_body` is defined in
/// [RFC2616, secion 7.2](https://tools.ietf.org/html/rfc2616#section-7.2).
pub fn validate_digest_using_password(digest: &Digest,
                                      method: Method,
                                      entity_body: String,
                                      password: String)
                                      -> bool {
    if let Ok(hex_digest) = generate_digest_using_password(digest, method, entity_body, password) {
        hex_digest == digest.response
    } else {
        false
    }
}

/// Validates a `Digest.response`, given an HTTP request and a hexadecimal digest of an A1 string.
///
/// `entity_body` is defined in
/// [RFC2616, secion 7.2](https://tools.ietf.org/html/rfc2616#section-7.2).
///
/// This is intended to be used in applications that use the `htdigest` style of secret hash
/// generation.
pub fn validate_digest_using_hashed_a1(digest: &Digest,
                                       method: Method,
                                       entity_body: String,
                                       a1: String)
                                       -> bool {
    if let Ok(hex_digest) = generate_digest_using_hashed_a1(digest, method, entity_body, a1) {
        hex_digest == digest.response
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_scheme() {
        use hyper::header::Scheme;
        use super::Digest;

        assert_eq!(Digest::scheme(), Some("Digest"))
    }

    #[test]
    fn test_basic_parse_header() {
        use hyper::header::{Authorization, Header};
        use super::HashAlgorithm;

        let expected = Authorization(rfc2617_digest_header(HashAlgorithm::MD5));
        let actual =
            Header::parse_header(&[b"Digest username=\"Mufasa\",\
                realm=\"testrealm@host.com\",\
                nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",\
                uri=\"/dir/index.html\",\
                qop=auth,\
                nc=00000001,\
                cnonce=\"0a4f113b\",\
                response=\"6629fae49393a05397450978507c4ef1\",\
                opaque=\"5ccc069c403ebaf9f0171e9517f40e41\""
                                       .to_vec()][..]);
        assert_eq!(actual.ok(), Some(expected))
    }

    #[test]
    fn test_parse_header_with_no_username() {
        use hyper::header::{Authorization, Header};
        use super::Digest;

        let header: Result<Authorization<Digest>, _> =
            Header::parse_header(&[b"Digest\
                realm=\"testrealm@host.com\",\
                nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",\
                uri=\"/dir/index.html\",\
                qop=auth,\
                nc=00000001,\
                cnonce=\"0a4f113b\",\
                response=\"6629fae49393a05397450978507c4ef1\",\
                opaque=\"5ccc069c403ebaf9f0171e9517f40e41\""
                                       .to_vec()][..]);
        assert!(header.is_err())
    }

    #[test]
    fn test_parse_header_with_no_realm() {
        use hyper::header::{Authorization, Header};
        use super::Digest;

        let header: Result<Authorization<Digest>, _> =
            Header::parse_header(&[b"Digest username=\"Mufasa\",\
                nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",\
                uri=\"/dir/index.html\",\
                qop=auth,\
                nc=00000001,\
                cnonce=\"0a4f113b\",\
                response=\"6629fae49393a05397450978507c4ef1\",\
                opaque=\"5ccc069c403ebaf9f0171e9517f40e41\""
                                       .to_vec()][..]);
        assert!(header.is_err())
    }

    #[test]
    fn test_parse_header_with_no_nonce() {
        use hyper::header::{Authorization, Header};
        use super::Digest;

        let header: Result<Authorization<Digest>, _> =
            Header::parse_header(&[b"Digest username=\"Mufasa\",\
                realm=\"testrealm@host.com\",\
                uri=\"/dir/index.html\",\
                qop=auth,\
                nc=00000001,\
                cnonce=\"0a4f113b\",\
                response=\"6629fae49393a05397450978507c4ef1\",\
                opaque=\"5ccc069c403ebaf9f0171e9517f40e41\""
                                       .to_vec()][..]);
        assert!(header.is_err())
    }

    #[test]
    fn test_parse_header_with_no_response() {
        use hyper::header::{Authorization, Header};
        use super::Digest;

        let header: Result<Authorization<Digest>, _> =
            Header::parse_header(&[b"Digest username=\"Mufasa\",\
                realm=\"testrealm@host.com\",\
                nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",\
                uri=\"/dir/index.html\",\
                qop=auth,\
                nc=00000001,\
                cnonce=\"0a4f113b\",\
                opaque=\"5ccc069c403ebaf9f0171e9517f40e41\""
                                       .to_vec()][..]);
        assert!(header.is_err())
    }

    #[test]
    fn test_parse_header_with_no_request_uri() {
        use hyper::header::{Authorization, Header};
        use super::Digest;

        let header: Result<Authorization<Digest>, _> =
            Header::parse_header(&[b"Digest username=\"Mufasa\",\
                realm=\"testrealm@host.com\",\
                nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",\
                qop=auth,\
                nc=00000001,\
                cnonce=\"0a4f113b\",\
                response=\"6629fae49393a05397450978507c4ef1\",\
                opaque=\"5ccc069c403ebaf9f0171e9517f40e41\""
                                       .to_vec()][..]);
        assert!(header.is_err())
    }

    #[test]
    fn test_parse_header_with_md5_algorithm() {
        use hyper::header::{Authorization, Header};
        use super::HashAlgorithm;

        let expected = Authorization(rfc2617_digest_header(HashAlgorithm::MD5));
        let actual =
            Header::parse_header(&[b"Digest username=\"Mufasa\",\
                realm=\"testrealm@host.com\",\
                nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",\
                uri=\"/dir/index.html\",\
                algorithm=MD5,\
                qop=auth,\
                nc=00000001,\
                cnonce=\"0a4f113b\",\
                response=\"6629fae49393a05397450978507c4ef1\",\
                opaque=\"5ccc069c403ebaf9f0171e9517f40e41\""
                                       .to_vec()][..]);
        assert_eq!(actual.ok(), Some(expected))
    }

    #[test]
    fn test_parse_header_with_md5_sess_algorithm() {
        use hyper::header::{Authorization, Header};
        use super::HashAlgorithm;

        let expected = Authorization(rfc2617_digest_header(HashAlgorithm::MD5Session));
        let actual =
            Header::parse_header(&[b"Digest username=\"Mufasa\",\
                realm=\"testrealm@host.com\",\
                nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",\
                uri=\"/dir/index.html\",\
                algorithm=MD5-sess,\
                qop=auth,\
                nc=00000001,\
                cnonce=\"0a4f113b\",\
                response=\"6629fae49393a05397450978507c4ef1\",\
                opaque=\"5ccc069c403ebaf9f0171e9517f40e41\""
                                       .to_vec()][..]);
        assert_eq!(actual.ok(), Some(expected))
    }

    #[test]
    fn test_parse_header_with_invalid_algorithm() {
        use hyper::header::{Authorization, Header};
        use super::Digest;

        let header: Result<Authorization<Digest>, _> =
            Header::parse_header(&[b"Digest username=\"Mufasa\",\
                realm=\"testrealm@host.com\",\
                nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",\
                uri=\"/dir/index.html\",\
                algorithm=invalid,\
                qop=auth,\
                nc=00000001,\
                cnonce=\"0a4f113b\",\
                response=\"6629fae49393a05397450978507c4ef1\",\
                opaque=\"5ccc069c403ebaf9f0171e9517f40e41\""
                                       .to_vec()][..]);
        assert!(header.is_err())
    }

    #[test]
    fn test_parse_header_with_auth_int_qop() {
        use hyper::header::{Authorization, Header};
        use super::{HashAlgorithm, Qop};

        let mut digest = rfc2617_digest_header(HashAlgorithm::MD5);
        digest.qop = Some(Qop::AuthInt);
        let expected = Authorization(digest);
        let actual =
            Header::parse_header(&[b"Digest username=\"Mufasa\",\
                realm=\"testrealm@host.com\",\
                nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",\
                uri=\"/dir/index.html\",\
                algorithm=MD5,\
                qop=auth-int,\
                nc=00000001,\
                cnonce=\"0a4f113b\",\
                response=\"6629fae49393a05397450978507c4ef1\",\
                opaque=\"5ccc069c403ebaf9f0171e9517f40e41\""
                                       .to_vec()][..]);
        assert_eq!(actual.ok(), Some(expected))
    }

    #[test]
    fn test_parse_header_with_bad_qop() {
        use hyper::header::{Authorization, Header};
        use super::Digest;

        let header: Result<Authorization<Digest>, _> =
            Header::parse_header(&[b"Digest username=\"Mufasa\",\
                realm=\"testrealm@host.com\",\
                nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",\
                uri=\"/dir/index.html\",\
                qop=badvalue,\
                nc=00000001,\
                cnonce=\"0a4f113b\",\
                response=\"6629fae49393a05397450978507c4ef1\",\
                opaque=\"5ccc069c403ebaf9f0171e9517f40e41\""
                                       .to_vec()][..]);
        assert!(header.is_err())
    }

    #[test]
    fn test_parse_header_with_bad_nonce_count() {
        use hyper::header::{Authorization, Header};
        use super::Digest;

        let header: Result<Authorization<Digest>, _> =
            Header::parse_header(&[b"Digest username=\"Mufasa\",\
                realm=\"testrealm@host.com\",\
                nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",\
                uri=\"/dir/index.html\",\
                qop=auth,\
                nc=badhexvalue,\
                cnonce=\"0a4f113b\",\
                response=\"6629fae49393a05397450978507c4ef1\",\
                opaque=\"5ccc069c403ebaf9f0171e9517f40e41\""
                                       .to_vec()][..]);
        assert!(header.is_err())
    }

    #[test]
    fn test_fmt_scheme() {
        use hyper::header::{Authorization, Headers};

        let digest = rfc2069_a1_digest_header();
        let mut headers = Headers::new();
        headers.set(Authorization(digest));

        assert_eq!(headers.to_string(),
                   "Authorization: Digest username=\"Mufasa\", realm=\"testrealm@host.com\", \
                    nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", \
                    response=\"1949323746fe6a43ef61f9606e7febea\", uri=\"/dir/index.html\", \
                    algorithm=MD5\r\n")
    }

    #[test]
    fn test_fmt_scheme_for_md5_sess_algorithm() {
        use hyper::header::{Authorization, Headers};
        use super::HashAlgorithm;

        let digest = rfc2617_digest_header(HashAlgorithm::MD5Session);
        let mut headers = Headers::new();
        headers.set(Authorization(digest));

        assert_eq!(headers.to_string(),
                   "Authorization: Digest username=\"Mufasa\", realm=\"testrealm@host.com\", \
                    nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", nc=00000001, \
                    response=\"6629fae49393a05397450978507c4ef1\", uri=\"/dir/index.html\", \
                    algorithm=MD5-sess, qop=auth, cnonce=\"0a4f113b\", \
                    opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"\r\n")
    }

    #[test]
    fn test_generate_simple_hashed_a1() {
        use super::generate_simple_hashed_a1;

        let digest = rfc2069_a1_digest_header();
        let expected = "939e7578ed9e3c518a452acee763bce9";
        let actual = generate_simple_hashed_a1(&digest.algorithm,
                                               digest.username,
                                               digest.realm,
                                               "Circle Of Life".to_string());
        assert_eq!(expected, actual)
    }

    #[test]
    fn test_generate_a1() {
        use super::generate_a1;

        let digest = rfc2069_a1_digest_header();
        let password = "CircleOfLife".to_string();
        let expected = "Mufasa:testrealm@host.com:CircleOfLife";
        let a1 = generate_a1(&digest, password);
        assert!(a1.is_ok());
        assert_eq!(expected, a1.unwrap())
    }

    #[test]
    fn test_generate_a1_for_md5_sess() {
        use super::{generate_a1, HashAlgorithm};

        let digest = rfc2617_digest_header(HashAlgorithm::MD5Session);
        let password = "Circle Of Life".to_string();
        let a1 = generate_a1(&digest, password);
        assert!(a1.is_ok());
        let expected = format!("939e7578ed9e3c518a452acee763bce9:{}:{}",
                               digest.nonce,
                               digest.client_nonce.unwrap());
        assert_eq!(expected, a1.unwrap())
    }

    #[test]
    fn test_generate_a1_for_md5_sess_without_client_nonce() {
        use super::{generate_a1, HashAlgorithm};

        let mut digest = rfc2617_digest_header(HashAlgorithm::MD5Session);
        digest.client_nonce = None;
        let password = "Circle Of Life".to_string();
        let a1 = generate_a1(&digest, password);
        assert!(a1.is_err())
    }

    #[test]
    fn test_generate_hashed_a1() {
        use super::generate_hashed_a1;

        let digest = rfc2069_a1_digest_header();
        let expected = "939e7578ed9e3c518a452acee763bce9";
        let hashed_a1 = generate_hashed_a1(&digest, "Circle Of Life".to_string());
        assert!(hashed_a1.is_ok());
        assert_eq!(expected, hashed_a1.unwrap())
    }

    #[test]
    fn test_generate_hashed_a1_for_md5_sess_without_client_nonce() {
        use super::{generate_hashed_a1, HashAlgorithm};

        let mut digest = rfc2617_digest_header(HashAlgorithm::MD5Session);
        digest.client_nonce = None;
        let password = "Circle Of Life".to_string();
        let a1 = generate_hashed_a1(&digest, password);
        assert!(a1.is_err())
    }

    #[test]
    fn test_generate_a2() {
        use hyper::method::Method;
        use super::generate_a2;

        let digest = rfc2069_a2_digest_header();
        let expected = "GET:/dir/index.html";
        let actual = generate_a2(&digest, Method::Get, "".to_string());
        assert_eq!(expected, actual)
    }

    #[test]
    fn test_generate_hashed_a2() {
        use hyper::method::Method;
        use super::generate_hashed_a2;

        let digest = rfc2069_a2_digest_header();
        let expected = "39aff3a2bab6126f332b942af96d3366";
        let actual = generate_hashed_a2(&digest, Method::Get, "".to_string());
        assert_eq!(expected, actual)
    }

    #[test]
    fn test_generate_digest_from_header() {
        use hyper::header::{Authorization, Header};
        use hyper::method::Method;
        use super::{Digest, generate_digest_using_password};

        let password = "CircleOfLife".to_string();
        let header: Authorization<Digest> =
            Header::parse_header(&[b"Digest username=\"Mufasa\",\
                realm=\"testrealm@host.com\",\
                nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",\
                uri=\"/dir/index.html\",\
                response=\"1949323746fe6a43ef61f9606e7febea\",\
                opaque=\"5ccc069c403ebaf9f0171e9517f40e41\""
                                       .to_vec()][..])
                .unwrap();

        let hex_digest = generate_digest_using_password(&header.0,
                                                        Method::Get,
                                                        "".to_string(),
                                                        password);
        assert!(hex_digest.is_ok());
        assert_eq!(header.0.response, hex_digest.unwrap())
    }

    #[test]
    fn test_generate_digest_from_passport_http_header() {
        use hyper::header::{Authorization, Header};
        use hyper::method::Method;
        use super::{Digest, generate_digest_using_password};

        let password = "secret".to_string();
        let header: Authorization<Digest> =
            Header::parse_header(&[b"Digest username=\"bob\",\
                realm=\"Users\",\
                nonce=\"NOIEDJ3hJtqSKaty8KF8xlkaYbItAkiS\",
                uri=\"/\",\
                response=\"22e3e0a9bbefeb9d229905230cb9ddc8\""
                                       .to_vec()][..])
                .unwrap();

        let hex_digest = generate_digest_using_password(&header.0,
                                                        Method::Head,
                                                        "".to_string(),
                                                        password);
        assert!(hex_digest.is_ok());
        assert_eq!(header.0.response, hex_digest.unwrap())
    }

    #[test]
    fn test_generate_digest_using_password_and_md5_session_sans_client_nonce() {
        use hyper::method::Method;
        use super::{generate_digest_using_password, HashAlgorithm};

        let password = "Circle Of Life".to_string();
        let mut digest = rfc2617_digest_header(HashAlgorithm::MD5Session);
        digest.client_nonce = None;
        let hex_digest = generate_digest_using_password(&digest,
                                                        Method::Get,
                                                        "".to_string(),
                                                        password);
        assert!(hex_digest.is_err())
    }

    #[test]
    fn test_generate_digest_using_hashed_a1() {
        use hyper::method::Method;
        use super::{generate_digest_using_hashed_a1, HashAlgorithm};

        let hashed_a1 = "939e7578ed9e3c518a452acee763bce9".to_string();
        let digest = rfc2617_digest_header(HashAlgorithm::MD5);
        let hex_digest = generate_digest_using_hashed_a1(&digest,
                                                         Method::Get,
                                                         "".to_string(),
                                                         hashed_a1);
        assert!(hex_digest.is_ok());
        assert_eq!(digest.response, hex_digest.unwrap())
    }

    #[test]
    fn test_generate_digest_using_hashed_a1_with_auth_int_qop() {
        use hyper::method::Method;
        use super::{generate_digest_using_hashed_a1, HashAlgorithm, Qop};

        let hashed_a1 = "939e7578ed9e3c518a452acee763bce9".to_string();
        let expected = "7b9be1c2def9d4ad657b26ac8bc651a0".to_string();
        let mut digest = rfc2617_digest_header(HashAlgorithm::MD5);
        digest.qop = Some(Qop::AuthInt);
        let hex_digest = generate_digest_using_hashed_a1(&digest,
                                                         Method::Get,
                                                         "foo=bar".to_string(),
                                                         hashed_a1);
        assert!(hex_digest.is_ok());
        assert_eq!(expected, hex_digest.unwrap())
    }

    #[test]
    fn test_generate_digest_using_hashed_a1_with_auth_int_qop_sans_nonce_count() {
        use hyper::method::Method;
        use super::{generate_digest_using_hashed_a1, HashAlgorithm, Qop};

        let hashed_a1 = "939e7578ed9e3c518a452acee763bce9".to_string();
        let mut digest = rfc2617_digest_header(HashAlgorithm::MD5);
        digest.qop = Some(Qop::AuthInt);
        digest.nonce_count = None;
        let hex_digest = generate_digest_using_hashed_a1(&digest,
                                                         Method::Get,
                                                         "foo=bar".to_string(),
                                                         hashed_a1);
        assert!(hex_digest.is_err())
    }

    #[test]
    fn test_generate_digest_using_hashed_a1_with_auth_int_qop_sans_client_nonce() {
        use hyper::method::Method;
        use super::{generate_digest_using_hashed_a1, HashAlgorithm, Qop};

        let hashed_a1 = "939e7578ed9e3c518a452acee763bce9".to_string();
        let mut digest = rfc2617_digest_header(HashAlgorithm::MD5);
        digest.qop = Some(Qop::AuthInt);
        digest.client_nonce = None;
        let hex_digest = generate_digest_using_hashed_a1(&digest,
                                                         Method::Get,
                                                         "foo=bar".to_string(),
                                                         hashed_a1);
        assert!(hex_digest.is_err())
    }

    #[test]
    fn test_generate_digest_using_hashed_a1_sans_qop() {
        use hyper::method::Method;
        use super::{generate_digest_using_hashed_a1, HashAlgorithm};

        let hashed_a1 = "939e7578ed9e3c518a452acee763bce9".to_string();
        let expected = "670fd8c2df070c60b045671b8b24ff02".to_string();
        let mut digest = rfc2617_digest_header(HashAlgorithm::MD5);
        digest.qop = None;
        let hex_digest = generate_digest_using_hashed_a1(&digest,
                                                         Method::Get,
                                                         "".to_string(),
                                                         hashed_a1);
        assert!(hex_digest.is_ok());
        assert_eq!(expected, hex_digest.unwrap())
    }

    #[test]
    fn test_validate_digest_using_password() {
        use hyper::header::{Authorization, Header};
        use hyper::method::Method;
        use super::{Digest, validate_digest_using_password};

        let password = "Circle of Life".to_string();
        // From RFC 7616 and the result from Firefox
        let header: Authorization<Digest> =
            Header::parse_header(&[b"Digest username=\"Mufasa\",\
                realm=\"http-auth@example.org\",\
                nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\",\
                uri=\"/dir/index.html\",\
                algorithm=MD5,\
                response=\"65e4930cfb0b33cb53405ecea0705cec\",\
                opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\",\
                qop=auth,\
                nc=00000001,\
                cnonce=\"b24ce2519b8cdb10\""
                                       .to_vec()][..])
                .unwrap();
        let validated = validate_digest_using_password(&header.0,
                                                       Method::Get,
                                                       "".to_string(),
                                                       password.clone());
        assert!(validated);
        let mut digest = header.0.clone();
        digest.client_nonce = Some("somethingelse".to_string());
        let validated_second_cnonce = validate_digest_using_password(&digest,
                                                                     Method::Get,
                                                                     "".to_string(),
                                                                     password);
        assert!(!validated_second_cnonce);
    }

    #[test]
    fn test_validate_digest_using_hashed_a1() {
        use hyper::method::Method;
        use super::{validate_digest_using_hashed_a1, HashAlgorithm};

        let hashed_a1 = "3d78807defe7de2157e2b0b6573a855f".to_string();
        let mut digest = rfc7616_digest_header(HashAlgorithm::MD5,
                                               "8ca523f5e9506fed4657c9700eebdbec");
        let validated = validate_digest_using_hashed_a1(&digest,
                                                        Method::Get,
                                                        "".to_string(),
                                                        hashed_a1.clone());
        assert!(validated);
        digest.client_nonce = Some("different".to_string());
        let validated_second_cnonce = validate_digest_using_hashed_a1(&digest,
                                                                      Method::Get,
                                                                      "".to_string(),
                                                                      hashed_a1);
        assert!(!validated_second_cnonce);
    }

    fn rfc2069_digest_header(realm: &str) -> super::Digest {
        super::Digest {
            username: "Mufasa".to_string(),
            realm: realm.to_string(),
            nonce: "dcd98b7102dd2f0e8b11d0f600bfb0c093".to_string(),
            nonce_count: None,
            // The response from RFC 2069's example seems very wrong, so this is the "correct" one.
            // Verified using Firefox and also in the RFC's errata:
            // https://www.rfc-editor.org/errata_search.php?rfc=2069
            response: "1949323746fe6a43ef61f9606e7febea".to_string(),
            request_uri: "/dir/index.html".to_string(),
            algorithm: super::HashAlgorithm::MD5,
            qop: None,
            client_nonce: None,
            opaque: None,
        }
    }

    fn rfc2069_a1_digest_header() -> super::Digest {
        rfc2069_digest_header("testrealm@host.com")
    }

    fn rfc2069_a2_digest_header() -> super::Digest {
        rfc2069_digest_header("myhost@testrealm.com")
    }

    fn rfc2617_digest_header(algorithm: super::HashAlgorithm) -> super::Digest {
        super::Digest {
            username: "Mufasa".to_string(),
            realm: "testrealm@host.com".to_string(),
            nonce: "dcd98b7102dd2f0e8b11d0f600bfb0c093".to_string(),
            nonce_count: Some(1),
            response: "6629fae49393a05397450978507c4ef1".to_string(),
            request_uri: "/dir/index.html".to_string(),
            algorithm: algorithm,
            qop: Some(super::Qop::Auth),
            client_nonce: Some("0a4f113b".to_string()),
            opaque: Some("5ccc069c403ebaf9f0171e9517f40e41".to_string()),
        }
    }

    // See: RFC 7616, Section 3.9.1
    fn rfc7616_digest_header(algorithm: super::HashAlgorithm, response: &str) -> super::Digest {
        super::Digest {
            username: "Mufasa".to_string(),
            realm: "http-auth@example.org".to_string(),
            nonce: "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v".to_string(),
            nonce_count: Some(1),
            response: response.to_string(),
            request_uri: "/dir/index.html".to_string(),
            algorithm: algorithm,
            qop: Some(super::Qop::Auth),
            client_nonce: Some("f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ".to_string()),
            opaque: Some("FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS".to_string()),
        }
    }
}
