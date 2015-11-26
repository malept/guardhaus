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

#[derive(Clone, Debug, PartialEq)]
pub enum HashAlgorithm {
    MD5,
    MD5Session,
}

impl FromStr for HashAlgorithm {
    type Err = Error;
    fn from_str(s: &str) -> Result<HashAlgorithm, Error> {
        match s {
            "MD5" => Ok(HashAlgorithm::MD5),
            "MD5-sess" => Ok(HashAlgorithm::MD5Session),
            _ => Err(Error::Header)
        }
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct Digest {
    pub username: String,
    pub realm: String,
    pub nonce: String,
    pub nonce_count: Option<u32>, // nc
    pub response: String,
    pub request_uri: String,
    pub algorithm: HashAlgorithm,
    // quality of protection
    pub qop: Option<String>,
    pub client_nonce: Option<String>,
    pub opaque: Option<String>,
}

fn append_parameter(serialized: &mut String, key: &str, value: &String) {
    if serialized.len() > 0 {
        serialized.push_str(", ")
    }
    serialized.push_str(key);
    serialized.push_str("=\"");
    serialized.push_str(value);
    serialized.push_str("\"")
}

impl Scheme for Digest {
    fn scheme() -> Option<&'static str> {
        Some("Digest")
    }

    fn fmt_scheme(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut serialized = String::new();
        append_parameter(&mut serialized, "username", &self.username);
        append_parameter(&mut serialized, "realm", &self.realm);
        append_parameter(&mut serialized, "nonce", &self.nonce);
        append_parameter(&mut serialized, "response", &self.response);
        append_parameter(&mut serialized, "uri", &self.request_uri);
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
                },
                _ => return Err(Error::Header)
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
                Err(_) => return Err(Error::Header)
            }
        } else {
            algorithm = HashAlgorithm::MD5;
        }
        Ok(Digest {
            username: username,
            realm: realm,
            nonce: nonce,
            nonce_count: nonce_count,
            response: response,
            request_uri: request_uri,
            algorithm: algorithm,
            qop: unraveled_map_value(&param_map, "qop"),
            client_nonce: unraveled_map_value(&param_map, "cnonce"),
            opaque: unraveled_map_value(&param_map, "opaque"),
        })
    }
}

fn generate_simple_a1(digest: &Digest, password: String) -> String {
    format!("{}:{}:{}", digest.username, digest.realm, password)
}

// RFC 2617, Section 3.2.2.2
fn generate_a1(digest: &Digest, password: String) -> Result<String, Error> {
    match digest.algorithm {
        HashAlgorithm::MD5 => Ok(generate_simple_a1(digest, password)),
        HashAlgorithm::MD5Session => {
            if let Some(ref client_nonce) = digest.client_nonce {
                let hashed_simple_a1 = hash_value(&HashAlgorithm::MD5, generate_simple_a1(digest, password));
                Ok(format!("{}:{}:{}", hashed_simple_a1, digest.nonce, client_nonce))
            } else {
                Err(Error::Header)
            }
        }
    }
}

pub fn generate_hashed_a1(digest: &Digest, password: String) -> Result<String, Error> {
    if let Ok(a1) = generate_a1(digest, password) {
        Ok(hash_value(&digest.algorithm, a1))
    } else {
        Err(Error::Header)
    }
}

// RFC 2617, Section 3.2.2.3
fn generate_a2(digest: &Digest, method: Method) -> String {
    format!("{}:{}", method, digest.request_uri)
}

fn generate_hashed_a2(digest: &Digest, method: Method) -> String {
    hash_value(&digest.algorithm, generate_a2(digest, method))
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
        },
    }
}

fn generate_kd(algorithm: &HashAlgorithm, secret: String, data: String) -> String {
    let value = format!("{}:{}", secret, data);
    hash_value(algorithm, value)
}

pub fn generate_digest_using_password(digest: &Digest, method: Method, password: String) -> Result<String, Error> {
    if let Ok(a1) = generate_hashed_a1(digest, password) {
        Ok(generate_digest_using_hashed_a1(digest, method, a1))
    } else {
        Err(Error::Header)
    }
}

pub fn generate_digest_using_hashed_a1(digest: &Digest, method: Method, a1: String) -> String {
    let a2 = generate_hashed_a2(digest, method);
    generate_kd(&digest.algorithm, a1, format!("{}:{}", digest.nonce, a2))
}

pub fn validate_digest_using_password(digest: &Digest, method: Method, password: String) -> bool {
    if let Ok(hex_digest) = generate_digest_using_password(digest, method, password) {
        hex_digest == digest.response
    } else {
        false
    }
}

pub fn validate_digest_using_hashed_a1(digest: &Digest, method: Method, a1: String) -> bool {
    generate_digest_using_hashed_a1(digest, method, a1) == digest.response
}

#[cfg(test)]
mod test {
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
        let actual = Header::parse_header(
            &[b"Digest username=\"Mufasa\",\
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

        let header: Result<Authorization<Digest>, _> = Header::parse_header(
            &[b"Digest\
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

        let header: Result<Authorization<Digest>, _> = Header::parse_header(
            &[b"Digest username=\"Mufasa\",\
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

        let header: Result<Authorization<Digest>, _> = Header::parse_header(
            &[b"Digest username=\"Mufasa\",\
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

        let header: Result<Authorization<Digest>, _> = Header::parse_header(
            &[b"Digest username=\"Mufasa\",\
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

        let header: Result<Authorization<Digest>, _> = Header::parse_header(
            &[b"Digest username=\"Mufasa\",\
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
        let actual = Header::parse_header(
            &[b"Digest username=\"Mufasa\",\
                realm=\"testrealm@host.com\",\
                nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",\
                uri=\"/dir/index.html\",\
                algorithm=\"MD5\",\
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
        let actual = Header::parse_header(
            &[b"Digest username=\"Mufasa\",\
                realm=\"testrealm@host.com\",\
                nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",\
                uri=\"/dir/index.html\",\
                algorithm=\"MD5-sess\",\
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

        let header: Result<Authorization<Digest>, _> = Header::parse_header(
            &[b"Digest username=\"Mufasa\",\
                realm=\"testrealm@host.com\",\
                nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",\
                uri=\"/dir/index.html\",\
                algorithm=\"invalid\",\
                qop=auth,\
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

        let header: Result<Authorization<Digest>, _> = Header::parse_header(
            &[b"Digest username=\"Mufasa\",\
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
                    response=\"1949323746fe6a43ef61f9606e7febea\", uri=\"/dir/index.html\"\r\n")
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
        let expected = format!("939e7578ed9e3c518a452acee763bce9:{}:{}", digest.nonce, digest.client_nonce.unwrap());
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
        let actual = generate_a2(&digest, Method::Get);
        assert_eq!(expected, actual)
    }

    #[test]
    fn test_generate_hashed_a2() {
        use hyper::method::Method;
        use super::generate_hashed_a2;

        let digest = rfc2069_a2_digest_header();
        let expected = "39aff3a2bab6126f332b942af96d3366";
        let actual = generate_hashed_a2(&digest, Method::Get);
        assert_eq!(expected, actual)
    }

    #[test]
    fn test_generate_digest_from_header() {
        use hyper::header::{Authorization, Header};
        use hyper::method::Method;
        use super::{Digest, generate_digest_using_password};

        let password = "CircleOfLife".to_string();
        let header: Authorization<Digest> = Header::parse_header(
            &[b"Digest username=\"Mufasa\",\
                realm=\"testrealm@host.com\",\
                nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",\
                uri=\"/dir/index.html\",\
                response=\"1949323746fe6a43ef61f9606e7febea\",\
                opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"".to_vec()][..]).unwrap();

        let hex_digest = generate_digest_using_password(&header.0, Method::Get, password);
        assert!(hex_digest.is_ok());
        assert_eq!(header.0.response, hex_digest.unwrap())
    }

    #[test]
    fn test_generate_digest_from_passport_http_header() {
        use hyper::header::{Authorization, Header};
        use hyper::method::Method;
        use super::{Digest, generate_digest_using_password};

        let password = "secret".to_string();
        let header: Authorization<Digest> = Header::parse_header(
            &[b"Digest username=\"bob\",\
                realm=\"Users\",\
                nonce=\"NOIEDJ3hJtqSKaty8KF8xlkaYbItAkiS\",
                uri=\"/\",\
                response=\"22e3e0a9bbefeb9d229905230cb9ddc8\"".to_vec()][..]).unwrap();

        let hex_digest = generate_digest_using_password(&header.0, Method::Head, password);
        assert!(hex_digest.is_ok());
        assert_eq!(header.0.response, hex_digest.unwrap())
    }

    #[test]
    fn test_generate_digest_using_hashed_a1() {
        use hyper::method::Method;
        use super::{generate_digest_using_hashed_a1, HashAlgorithm};

        let hashed_a1 = "939e7578ed9e3c518a452acee763bce9".to_string();
        let expected = "670fd8c2df070c60b045671b8b24ff02".to_string();
        let digest = rfc2617_digest_header(HashAlgorithm::MD5);
        let hex_digest = generate_digest_using_hashed_a1(&digest, Method::Get, hashed_a1);
        assert_eq!(expected, hex_digest)
    }

    fn rfc2069_digest_header(realm: &str) -> super::Digest {
        super::Digest {
            username: "Mufasa".to_string(),
            realm: realm.to_string(),
            nonce: "dcd98b7102dd2f0e8b11d0f600bfb0c093".to_string(),
            nonce_count: None,
            // The response from RFC 2069's example seems very wrong, so this is the "correct" one.
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
            qop: Some("auth".to_string()),
            client_nonce: Some("0a4f113b".to_string()),
            opaque: Some("5ccc069c403ebaf9f0171e9517f40e41".to_string()),
        }
    }
}
