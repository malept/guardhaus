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
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use unicase::UniCase;
use url::percent_encoding::percent_decode;

pub enum HashAlgorithm {
    MD5
}

#[derive(Clone, PartialEq, Debug)]
pub struct Digest {
    pub username: String,
    pub realm: String,
    pub nonce: String,
    pub response: String,
    pub request_uri: String,
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
        let response: String;
        let request_uri: String;
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
        match unraveled_map_value(&param_map, "response") {
            Some(value) => response = value,
            None => return Err(Error::Header),
        }
        match unraveled_map_value(&param_map, "uri") {
            Some(value) => request_uri = value,
            None => return Err(Error::Header),
        }
        Ok(Digest {
            username: username,
            realm: realm,
            nonce: nonce,
            response: response,
            request_uri: request_uri,
        })
    }
}

// RFC 2617, Section 3.2.2.2
fn generate_a1(digest: &Digest, password: String) -> String {
    format!("{}:{}:{}", digest.username, digest.realm, password)
}

fn generate_hashed_a1(algorithm: &HashAlgorithm, digest: &Digest, password: String) -> String {
    hash_value(algorithm, generate_a1(digest, password))
}

// RFC 2617, Section 3.2.2.3
fn generate_a2(digest: &Digest, method: Method) -> String {
    format!("{}:{}", method, digest.request_uri)
}

fn generate_hashed_a2(algorithm: &HashAlgorithm, digest: &Digest, method: Method) -> String {
    hash_value(algorithm, generate_a2(digest, method))
}

fn hash_value(algorithm: &HashAlgorithm, value: String) -> String {
    use crypto::digest::Digest;
    use crypto::md5::Md5;

    match *algorithm {
        HashAlgorithm::MD5 => {
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

pub fn generate_digest(digest: &Digest, method: Method, password: String) -> String {
    let algorithm = &HashAlgorithm::MD5;
    let a1 = generate_hashed_a1(algorithm, digest, password);
    let a2 = generate_hashed_a2(algorithm, digest, method);
    generate_kd(algorithm, a1, format!("{}:{}", digest.nonce, a2))
}

pub fn validate_digest(digest: &Digest, method: Method, password: String) -> bool {
    generate_digest(digest, method, password) == digest.response
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
        use super::Digest;

        let expected = Authorization(Digest {
            username: "Mufasa".to_string(),
            realm: "testrealm@host.com".to_string(),
            nonce: "dcd98b7102dd2f0e8b11d0f600bfb0c093".to_string(),
            response: "6629fae49393a05397450978507c4ef1".to_string(),
            request_uri: "/dir/index.html".to_string(),
        });
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
    fn test_fmt_scheme() {
        use hyper::header::{Authorization, Headers};
        use super::Digest;

        let digest = Digest {
            username: "Mufasa".to_string(),
            realm: "testrealm@host.com".to_string(),
            nonce: "dcd98b7102dd2f0e8b11d0f600bfb0c093".to_string(),
            response: "6629fae49393a05397450978507c4ef1".to_string(),
            request_uri: "/dir/index.html".to_string(),
        };
        let mut headers = Headers::new();
        headers.set(Authorization(digest));

        assert_eq!(headers.to_string(),
                   "Authorization: Digest username=\"Mufasa\", realm=\"testrealm@host.com\", \
                    nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", \
                    response=\"6629fae49393a05397450978507c4ef1\", uri=\"/dir/index.html\"\r\n")
    }

    #[test]
    fn test_generate_a1() {
        use super::generate_a1;

        let digest = rfc2069_a1_digest_header();
        let password = "CircleOfLife".to_string();
        let expected = "Mufasa:testrealm@host.com:CircleOfLife";
        let actual = generate_a1(&digest, password);
        assert_eq!(expected, actual)
    }

    #[test]
    fn test_generate_hashed_a1() {
        use super::{generate_hashed_a1, HashAlgorithm};

        let digest = rfc2069_a1_digest_header();
        let expected = "939e7578ed9e3c518a452acee763bce9";
        let actual = generate_hashed_a1(&HashAlgorithm::MD5, &digest, "Circle Of Life".to_string());
        assert_eq!(expected, actual)
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
        use super::{generate_hashed_a2, HashAlgorithm};

        let digest = rfc2069_a2_digest_header();
        let expected = "39aff3a2bab6126f332b942af96d3366";
        let actual = generate_hashed_a2(&HashAlgorithm::MD5, &digest, Method::Get);
        assert_eq!(expected, actual)
    }

    #[test]
    fn test_generate_digest_from_header() {
        use hyper::header::{Authorization, Header};
        use hyper::method::Method;
        use super::{Digest, generate_digest};

        let password = "CircleOfLife".to_string();
        let header: Authorization<Digest> = Header::parse_header(
            &[b"Digest username=\"Mufasa\",\
                realm=\"testrealm@host.com\",\
                nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",\
                uri=\"/dir/index.html\",\
                response=\"1949323746fe6a43ef61f9606e7febea\",\
                opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"".to_vec()][..]).unwrap();

        assert_eq!(header.0.response, generate_digest(&header.0, Method::Get, password))
    }

    #[test]
    fn test_generate_digest_from_passport_http_header() {
        use hyper::header::{Authorization, Header};
        use hyper::method::Method;
        use super::{Digest, generate_digest};

        let password = "secret".to_string();
        let header: Authorization<Digest> = Header::parse_header(
            &[b"Digest username=\"bob\",\
                realm=\"Users\",\
                nonce=\"NOIEDJ3hJtqSKaty8KF8xlkaYbItAkiS\",
                uri=\"/\",\
                response=\"22e3e0a9bbefeb9d229905230cb9ddc8\"".to_vec()][..]).unwrap();

        assert_eq!(header.0.response, generate_digest(&header.0, Method::Head, password))
    }

    fn rfc2069_digest_header(realm: &str) -> super::Digest {
        super::Digest {
            username: "Mufasa".to_string(),
            realm: realm.to_string(),
            nonce: "dcd98b7102dd2f0e8b11d0f600bfb0c093".to_string(),
            // The response from RFC 2069's example seems very wrong, so this is the "correct" one.
            response: "1949323746fe6a43ef61f9606e7febea".to_string(),
            request_uri: "/dir/index.html".to_string(),
        }
    }

    fn rfc2069_a1_digest_header() -> super::Digest {
        rfc2069_digest_header("testrealm@host.com")
    }

    fn rfc2069_a2_digest_header() -> super::Digest {
        rfc2069_digest_header("myhost@testrealm.com")
    }
}
