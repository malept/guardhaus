// Copyright (c) 2015, 2016, 2017, 2020, 2025 Mark Lee
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

#![allow(dead_code)]

use crate::digest::{Digest, Username};
use crate::parsing::fromheaders::ExtendedValue;
use crate::parsing::test_helper;
use crate::types::{HashAlgorithm, NonceCount, Qop};
use headers::HeaderValue;
use headers::authorization::Credentials;

fn serialize_headers(headers: headers::HeaderMap) -> Result<String, http::header::ToStrError> {
    let mut serialized = String::new();
    for (name, value) in headers.iter() {
        serialized.push_str(name.as_str());
        serialized.push_str(": ");
        serialized.push_str(value.to_str()?);
        serialized.push('\r');
        serialized.push('\n');
    }

    Ok(serialized)
}

pub fn assert_parsed_header_equal(expected: Digest, data: &str) {
    assert!(data.starts_with("Digest "));
    let digest_params = data
        .get(7..)
        .expect("Header value should be at least 7 chars");
    let actual: Digest = digest_params
        .parse()
        .expect("Could not parse digest params");
    assert_eq!(expected, actual);
}

pub fn assert_header_parsing_error(data: &str) {
    test_helper::assert_header_parsing_error(data)
}

pub fn assert_serialized_header_equal(digest: Digest, actual: &str) {
    let mut headers = headers::HeaderMap::new();
    let credentials = format!(
        "Digest {}",
        digest
            .encode()
            .to_str()
            .expect("Could not serialize Digest credentials")
    );
    headers.insert(
        http::header::AUTHORIZATION,
        HeaderValue::from_str(credentials.as_str())
            .expect("Could not deserialize Digest credentials"),
    );
    let expected = serialize_headers(headers).expect("Could not serialize headers");
    assert_eq!(expected, format!("{}\r\n", actual))
}

pub fn parse_digest_header(data: &str) -> Digest {
    assert!(data.starts_with("Digest "));
    let digest_params = data
        .get(7..)
        .expect("Header value should be at least 7 chars");
    let header_value = HeaderValue::from_str(digest_params).expect("Could not parse digest header");
    match Digest::decode(&header_value) {
        Some(digest) => digest,
        None => panic!("Could not decode header into Digest struct"),
    }
}

pub fn rfc2069_username() -> Username {
    Username::Plain("Mufasa".to_owned())
}

fn rfc2069_digest_header(realm: &str) -> Digest {
    Digest {
        username: rfc2069_username(),
        realm: realm.to_owned(),
        nonce: "dcd98b7102dd2f0e8b11d0f600bfb0c093".to_owned(),
        nonce_count: None,
        // The response from RFC 2069's example seems very wrong, so this is the "correct" one.
        // Verified using Firefox and also in the RFC's errata:
        // https://www.rfc-editor.org/errata_search.php?rfc=2069
        response: "1949323746fe6a43ef61f9606e7febea".to_owned(),
        request_uri: "/dir/index.html".to_owned(),
        algorithm: HashAlgorithm::Md5,
        qop: None,
        client_nonce: None,
        opaque: None,
        charset: None,
        userhash: false,
    }
}

pub fn rfc2069_a1_digest_header() -> Digest {
    rfc2069_digest_header("testrealm@host.com")
}

pub fn rfc2069_a2_digest_header() -> Digest {
    rfc2069_digest_header("myhost@testrealm.com")
}

pub fn rfc2617_digest_header(algorithm: HashAlgorithm) -> Digest {
    Digest {
        username: rfc2069_username(),
        realm: "testrealm@host.com".to_owned(),
        nonce: "dcd98b7102dd2f0e8b11d0f600bfb0c093".to_owned(),
        nonce_count: Some(NonceCount(1)),
        response: "6629fae49393a05397450978507c4ef1".to_owned(),
        request_uri: "/dir/index.html".to_owned(),
        algorithm,
        qop: Some(Qop::Auth),
        client_nonce: Some("0a4f113b".to_owned()),
        opaque: Some("5ccc069c403ebaf9f0171e9517f40e41".to_owned()),
        charset: None,
        userhash: false,
    }
}

// See: RFC 7616, Section 3.9.2
// https://datatracker.ietf.org/doc/html/rfc7616#section-3.9.2
pub fn rfc7616_username() -> Username {
    let result: Result<ExtendedValue, headers::Error> = "UTF-8''J%C3%A4s%C3%B8n%20Doe".parse();
    Username::Encoded(result.expect("Could not parse extended value"))
}

// See: RFC 7616, Section 3.9.1
// https://datatracker.ietf.org/doc/html/rfc7616#section-3.9.1
pub fn rfc7616_digest_header(algorithm: HashAlgorithm, response: &str) -> Digest {
    Digest {
        username: rfc2069_username(),
        realm: "http-auth@example.org".to_owned(),
        nonce: "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v".to_owned(),
        nonce_count: Some(NonceCount(1)),
        response: response.to_owned(),
        request_uri: "/dir/index.html".to_owned(),
        algorithm,
        qop: Some(Qop::Auth),
        client_nonce: Some("f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ".to_owned()),
        opaque: Some("FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS".to_owned()),
        charset: None,
        userhash: false,
    }
}

pub fn rfc7616_sha512_256_header(username: String, userhash: bool) -> Digest {
    use crate::parsing::fromheaders::Charset;

    Digest {
        username: Username::Plain(username),
        realm: "api@example.org".to_owned(),
        nonce: "5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK".to_owned(),
        nonce_count: Some(NonceCount(1)),
        response: "ae66e67d6b427bd3f120414a82e4acff38e8ecd9101d6c861229025f607a79dd".to_owned(),
        request_uri: "/doe.json".to_owned(),
        algorithm: HashAlgorithm::Sha512256,
        qop: Some(Qop::Auth),
        client_nonce: Some("NTg6RKcb9boFIAS3KrFK9BGeh+iDa/sm6jUMp2wds69v".to_owned()),
        opaque: Some("HRPCssKJSGjCrkzDg8OhwpzCiGPChXYjwrI2QmXDnsOS".to_owned()),
        charset: Some(Charset::UTF_8),
        userhash,
    }
}
