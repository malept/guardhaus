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

#![allow(dead_code)]

use hyper::header::{Authorization, Header, Headers};
use hyper::header::parsing::parse_extended_value;
use parsing::test_helper;
use super::{Digest, HashAlgorithm, Username};
use super::super::types::Qop;

pub fn assert_parsed_header_equal(expected: Authorization<Digest>, data: &str) {
    test_helper::assert_parsed_header_equal(expected, data)
}

pub fn assert_header_parsing_error(data: &str) {
    test_helper::assert_header_parsing_error::<Authorization<Digest>>(data)
}

pub fn assert_serialized_header_equal(digest: Digest, actual: &str) {
    let mut headers = Headers::new();
    headers.set(Authorization(digest));
    assert_eq!(headers.to_string(), format!("{}\r\n", actual))
}

pub fn parse_digest_header(data: &str) -> Authorization<Digest> {
    let bytestring = data.to_owned().into_bytes();
    Header::parse_header(&[bytestring][..]).expect("Could not parse digest header")
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
        algorithm: HashAlgorithm::MD5,
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
        nonce_count: Some(1),
        response: "6629fae49393a05397450978507c4ef1".to_owned(),
        request_uri: "/dir/index.html".to_owned(),
        algorithm: algorithm,
        qop: Some(Qop::Auth),
        client_nonce: Some("0a4f113b".to_owned()),
        opaque: Some("5ccc069c403ebaf9f0171e9517f40e41".to_owned()),
        charset: None,
        userhash: false,
    }
}

pub fn rfc7616_username() -> Username {
    let result = parse_extended_value("UTF-8''J%C3%A4s%C3%B8n%20Doe");
    Username::Encoded(result.expect("Could not parse extended value"))
}

// See: RFC 7616, Section 3.9.1
pub fn rfc7616_digest_header(algorithm: HashAlgorithm, response: &str) -> Digest {
    Digest {
        username: rfc2069_username(),
        realm: "http-auth@example.org".to_owned(),
        nonce: "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v".to_owned(),
        nonce_count: Some(1),
        response: response.to_owned(),
        request_uri: "/dir/index.html".to_owned(),
        algorithm: algorithm,
        qop: Some(Qop::Auth),
        client_nonce: Some("f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ".to_owned()),
        opaque: Some("FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS".to_owned()),
        charset: None,
        userhash: false,
    }
}

pub fn rfc7616_sha512_256_header(username: String, userhash: bool) -> Digest {
    use hyper::header::Charset;

    Digest {
        username: Username::Plain(username),
        realm: "api@example.org".to_owned(),
        nonce: "5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK".to_owned(),
        nonce_count: Some(1),
        response: "ae66e67d6b427bd3f120414a82e4acff38e8ecd9101d6c861229025f607a79dd".to_owned(),
        request_uri: "/doe.json".to_owned(),
        algorithm: HashAlgorithm::SHA512256,
        qop: Some(Qop::Auth),
        client_nonce: Some("NTg6RKcb9boFIAS3KrFK9BGeh+iDa/sm6jUMp2wds69v".to_owned()),
        opaque: Some("HRPCssKJSGjCrkzDg8OhwpzCiGPChXYjwrI2QmXDnsOS".to_owned()),
        charset: Some(Charset::Ext("UTF-8".to_owned())),
        userhash: userhash,
    }
}
