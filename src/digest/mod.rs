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

//! An HTTP Digest implementation for [Hyper](http://hyper.rs)'s `Authorization` header.

use hyper::error::Error;
use hyper::header::{Charset, Scheme};
use hyper::header::parsing::{ExtendedValue, parse_extended_value};
use hyper::method::Method;
use parsing::{append_parameter, parse_parameters, unraveled_map_value};
use rustc_serialize::hex::{FromHex, ToHex};
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use unicase::UniCase;

mod test;
mod test_helper;

/// Allowable hash algorithms for the `algorithm` parameter.
#[derive(Clone, Debug, PartialEq)]
pub enum HashAlgorithm {
    /// `MD5`
    MD5,
    /// `MD5-sess`
    MD5Session,
    /// `SHA-256`
    SHA256,
    /// `SHA-256-sess`
    SHA256Session,
    /// `SHA-512-256`
    SHA512256,
    /// `SHA-512-256-sess`
    SHA512256Session,
}

impl FromStr for HashAlgorithm {
    type Err = Error;

    fn from_str(s: &str) -> Result<HashAlgorithm, Error> {
        match s {
            "MD5" => Ok(HashAlgorithm::MD5),
            "MD5-sess" => Ok(HashAlgorithm::MD5Session),
            "SHA-256" => Ok(HashAlgorithm::SHA256),
            "SHA-256-sess" => Ok(HashAlgorithm::SHA256Session),
            "SHA-512-256" => Ok(HashAlgorithm::SHA512256),
            "SHA-512-256-sess" => Ok(HashAlgorithm::SHA512256Session),
            _ => Err(Error::Header),
        }
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            HashAlgorithm::MD5 => write!(f, "{}", "MD5"),
            HashAlgorithm::MD5Session => write!(f, "{}", "MD5-sess"),
            HashAlgorithm::SHA256 => write!(f, "{}", "SHA-256"),
            HashAlgorithm::SHA256Session => write!(f, "{}", "SHA-256-sess"),
            HashAlgorithm::SHA512256 => write!(f, "{}", "SHA-512-256"),
            HashAlgorithm::SHA512256Session => write!(f, "{}", "SHA-512-256-sess"),
        }
    }
}

/// Represents a `username` (or user hash, if the header's `userhash` parameter is `true`).
#[derive(Clone, Debug, PartialEq)]
pub enum Username {
    /// Either an ASCII-encoded username, or a userhash (if the header's `userhash` parameter is
    /// `true`).
    Plain(String),
    /// An RFC 5987-encoded username.
    Encoded(ExtendedValue),
}

impl fmt::Display for Username {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Username::Plain(ref username) => write!(f, "{}", username),
            Username::Encoded(ref encoded) => write!(f, "{}", encoded),
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
    /// Either the user name or the user hash (if `userhash` is `true` - see [RFC 7616, section
    /// 3.4.4](https://tools.ietf.org/html/rfc7616#section-3.4.4)).
    pub username: Username,
    /// Authentication realm.
    pub realm: String,
    /// Cryptographic nonce.
    pub nonce: String,
    /// Nonce count, parameter name `nc`. Optional only in RFC 2067 mode.
    pub nonce_count: Option<u32>,
    /// The hexadecimal digest of the payload as described by the RFCs.
    pub response: String,
    /// Either the absolute path or URI of the HTTP request, parameter name `uri`.
    pub request_uri: String,
    /// The hash algorithm to use when generating the `response`.
    pub algorithm: HashAlgorithm,
    /// Quality of protection. Optional only in RFC 2067 mode.
    pub qop: Option<Qop>,
    /// Cryptographic nonce from the client. Optional only in RFC 2067 mode.
    pub client_nonce: Option<String>,
    /// Optional opaque string.
    pub opaque: Option<String>,
    /// The character set to use when generating the A1 value or the userhash. Added for RFC 7616.
    pub charset: Option<Charset>,
    /// Whether `username` is a userhash. Added for RFC 7616.
    pub userhash: bool,
}

impl Scheme for Digest {
    fn scheme() -> Option<&'static str> {
        Some("Digest")
    }

    fn fmt_scheme(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut serialized = String::new();
        match self.username {
            Username::Plain(ref username) => {
                append_parameter(&mut serialized, "username", &username, true)
            }
            Username::Encoded(ref encoded) => {
                append_parameter(&mut serialized, "username*", &format!("{}", encoded), false)
            }
        }
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
        if let Some(ref charset) = self.charset {
            append_parameter(&mut serialized, "charset", &format!("{}", charset), false);
        }
        if self.userhash {
            append_parameter(&mut serialized, "userhash", &"true", false);
        }
        write!(f, "{}", serialized)
    }
}

fn parse_username(map: &HashMap<UniCase<String>, String>) -> Result<Username, Error> {
    if let Some(value) = unraveled_map_value(&map, "username") {
        if unraveled_map_value(&map, "username*").is_some() {
            Err(Error::Header)
        } else {
            Ok(Username::Plain(value))
        }
    } else if let Some(encoded) = unraveled_map_value(&map, "username*") {
        if let Some(userhash) = unraveled_map_value(&map, "userhash") {
            if userhash == "true" {
                return Err(Error::Header);
            }
        }

        if let Ok(extended_value) = parse_extended_value(&encoded) {
            Ok(Username::Encoded(extended_value))
        } else {
            Err(Error::Header)
        }
    } else {
        Err(Error::Header)
    }
}

fn parse_nonce_count(hex: &str) -> Result<u32, Error> {
    match hex.from_hex() {
        Ok(bytes) => {
            let mut count: u32 = 0;
            count |= (bytes[0] as u32) << 24;
            count |= (bytes[1] as u32) << 16;
            count |= (bytes[2] as u32) << 8;
            count |= bytes[3] as u32;
            Ok(count)
        }
        _ => Err(Error::Header),
    }
}

impl FromStr for Digest {
    type Err = Error;
    fn from_str(s: &str) -> Result<Digest, Error> {
        let param_map = parse_parameters(s);
        let username: Username;
        let realm: String;
        let nonce: String;
        let nonce_count: Option<u32>;
        let response: String;
        let request_uri: String;
        let algorithm: HashAlgorithm;
        let qop: Option<Qop>;
        let charset: Option<Charset>;
        let userhash: bool;
        match parse_username(&param_map) {
            Ok(value) => username = value,
            Err(err) => return Err(err),
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
            match parse_nonce_count(&value[..]) {
                Ok(count) => nonce_count = Some(count),
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
        if let Some(value) = unraveled_map_value(&param_map, "charset") {
            let utf8 = UniCase("utf-8".to_owned());
            charset = if UniCase(value.clone()) == utf8 {
                Some(Charset::Ext("UTF-8".to_owned()))
            } else {
                return Err(Error::Header);
            }
        } else {
            charset = None;
        }
        if let Some(value) = unraveled_map_value(&param_map, "userhash") {
            match &value[..] {
                "true" => userhash = true,
                "false" => userhash = false,
                _ => return Err(Error::Header),
            }
        } else {
            userhash = false;
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
            charset: charset,
            userhash: userhash,
        })
    }
}

/// Generates a userhash, as defined in
/// [RFC 7616, section 3.4.4](https://tools.ietf.org/html/rfc7616#section-3.4.4).
pub fn generate_userhash(algorithm: &HashAlgorithm, username: Vec<u8>, realm: String) -> String {
    let mut to_hash = username.clone();
    to_hash.push(b':');
    to_hash.append(&mut realm.into_bytes());
    hash_value(algorithm, to_hash)
}

/// Validates a userhash (as defined in
/// [RFC 7616, section 3.4.4](https://tools.ietf.org/html/rfc7616#section-3.4.4)), given a
/// `Digest` header.
///
/// If userhash is `false`, returns `false`.
pub fn validate_userhash(digest: &Digest, username: Username) -> bool {
    match digest.username {
        Username::Plain(ref userhash) => {
            let name = match username {
                Username::Plain(value) => value.into_bytes(),
                Username::Encoded(encoded) => encoded.value,
            };
            *userhash == generate_userhash(&digest.algorithm, name, digest.realm.clone())
        }
        Username::Encoded(_) => false,
    }
}

fn generate_simple_a1(username: Username, realm: String, password: String) -> Vec<u8> {
    let mut a1: Vec<u8> = match username {
        Username::Plain(name) => name.clone().into_bytes(),
        Username::Encoded(encoded) => encoded.value.clone(),
    };
    a1.push(b':');
    a1.append(&mut realm.into_bytes());
    a1.push(b':');
    a1.append(&mut password.into_bytes());

    a1
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
                                 username: Username,
                                 realm: String,
                                 password: String)
                                 -> String {
    hash_value(algorithm, generate_simple_a1(username, realm, password))
}

// RFC 2617, Section 3.2.2.2
fn generate_a1(digest: &Digest, username: Username, password: String) -> Result<Vec<u8>, Error> {
    let realm = digest.realm.clone();
    match digest.algorithm {
        HashAlgorithm::MD5 |
        HashAlgorithm::SHA256 |
        HashAlgorithm::SHA512256 => Ok(generate_simple_a1(username, realm, password)),

        HashAlgorithm::MD5Session |
        HashAlgorithm::SHA256Session |
        HashAlgorithm::SHA512256Session => {
            if let Some(ref client_nonce) = digest.client_nonce {
                let simple_hashed_a1 = hash_value(&digest.algorithm,
                                                  generate_simple_a1(username, realm, password));
                let mut a1 = simple_hashed_a1.into_bytes();
                a1.push(b':');
                a1.append(&mut digest.nonce.clone().into_bytes());
                a1.push(b':');
                a1.append(&mut client_nonce.clone().into_bytes());
                Ok(a1)
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
fn generate_hashed_a1(digest: &Digest,
                      username: Username,
                      password: String)
                      -> Result<String, Error> {
    if let Ok(a1) = generate_a1(digest, username, password) {
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
                    hash_value_from_string(&digest.algorithm, entity_body))
        }
        _ => format!("{}:{}", method, digest.request_uri),
    }
}

fn generate_hashed_a2(digest: &Digest, method: Method, entity_body: String) -> String {
    hash_value_from_string(&digest.algorithm, generate_a2(digest, method, entity_body))
}

fn hash_value_from_string(algorithm: &HashAlgorithm, value: String) -> String {
    hash_value(algorithm, value.into_bytes())
}

fn hash_value(algorithm: &HashAlgorithm, value: Vec<u8>) -> String {
    use openssl::crypto::hash::{hash, Type};

    let hash_type = match *algorithm {
        HashAlgorithm::MD5 |
        HashAlgorithm::MD5Session => Type::MD5,
        HashAlgorithm::SHA256 |
        HashAlgorithm::SHA256Session => Type::SHA256,
        HashAlgorithm::SHA512256 |
        HashAlgorithm::SHA512256Session => Type::SHA512,
    };

    let digest = hash(hash_type, &value[..]);
    let mut hex_digest = digest.to_hex();
    if *algorithm == HashAlgorithm::SHA512256 || *algorithm == HashAlgorithm::SHA512256Session {
        hex_digest.truncate(64);
    }

    hex_digest
}

fn generate_kd(algorithm: &HashAlgorithm, secret: String, data: String) -> String {
    let value = format!("{}:{}", secret, data);
    hash_value_from_string(algorithm, value)
}

fn generate_digest_using_username_and_password(digest: &Digest,
                                               method: Method,
                                               entity_body: String,
                                               username: Username,
                                               password: String)
                                               -> Result<String, Error> {
    if let Ok(a1) = generate_hashed_a1(digest, username, password) {
        generate_digest_using_hashed_a1(digest, method, entity_body, a1)
    } else {
        Err(Error::Header)
    }
}

/// Generates a digest, given an HTTP request and a password.
///
/// `entity_body` is defined in
/// [RFC 2616, secion 7.2](https://tools.ietf.org/html/rfc2616#section-7.2).
pub fn generate_digest_using_password(digest: &Digest,
                                      method: Method,
                                      entity_body: String,
                                      password: String)
                                      -> Result<String, Error> {
    if let Ok(a1) = generate_hashed_a1(digest, digest.username.clone(), password) {
        generate_digest_using_hashed_a1(digest, method, entity_body, a1)
    } else {
        Err(Error::Header)
    }
}

/// Generates a digest, given an HTTP request and a hexadecimal digest of an A1 string.
///
/// `entity_body` is defined in
/// [RFC 2616, secion 7.2](https://tools.ietf.org/html/rfc2616#section-7.2).
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
                let nonce_count = digest.nonce_count.expect("No nonce count found");
                let client_nonce = digest.client_nonce.clone().expect("No client nonce found");
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

fn validate_digest_using_username_and_password(digest: &Digest,
                                               method: Method,
                                               entity_body: String,
                                               username: Username,
                                               password: String)
                                               -> bool {
    if let Ok(hex_digest) = generate_digest_using_username_and_password(digest,
                                                                        method,
                                                                        entity_body,
                                                                        username,
                                                                        password) {
        hex_digest == digest.response
    } else {
        false
    }
}

/// Validates a `Digest.response`, given an HTTP request and a password.
///
/// `entity_body` is defined in
/// [RFC 2616, secion 7.2](https://tools.ietf.org/html/rfc2616#section-7.2).
pub fn validate_digest_using_password(digest: &Digest,
                                      method: Method,
                                      entity_body: String,
                                      password: String)
                                      -> bool {
    validate_digest_using_username_and_password(digest,
                                                method,
                                                entity_body,
                                                digest.username.clone(),
                                                password)
}

/// Validates a `Digest.username` and `Digest.response`, given an HTTP request, a username,
/// and a password. If a userhash is specified, that is validated first.
///
/// `entity_body` is defined in
/// [RFC 2616, secion 7.2](https://tools.ietf.org/html/rfc2616#section-7.2).
pub fn validate_digest_using_userhash_and_password(digest: &Digest,
                                                   method: Method,
                                                   entity_body: String,
                                                   username: Username,
                                                   password: String)
                                                   -> bool {
    if digest.userhash && !validate_userhash(digest, username.clone()) {
        return false;
    }
    validate_digest_using_username_and_password(digest, method, entity_body, username, password)
}

/// Validates a `Digest.response`, given an HTTP request and a hexadecimal digest of an A1 string.
///
/// `entity_body` is defined in
/// [RFC 2616, secion 7.2](https://tools.ietf.org/html/rfc2616#section-7.2).
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
