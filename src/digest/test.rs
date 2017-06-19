// Copyright (c) 2015, 2016, 2017 Mark Lee
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

#![cfg(test)]
use hyper::Method;
use hyper::header::{Authorization, Header, Raw, Scheme};
use hyper::header::parsing::parse_extended_value;
use super::{Digest, Username};
use super::super::types::{HashAlgorithm, Qop};
use super::test_helper::{assert_header_parsing_error, assert_parsed_header_equal,
                         assert_serialized_header_equal, parse_digest_header,
                         rfc2069_a1_digest_header, rfc2069_a2_digest_header, rfc2069_username,
                         rfc2617_digest_header, rfc7616_digest_header, rfc7616_sha512_256_header,
                         rfc7616_username};

#[test]
fn test_display_sha256_for_hashalgorithm() {
    assert_eq!("SHA-256", format!("{}", HashAlgorithm::SHA256))
}

#[test]
fn test_display_sha256session_for_hashalgorithm() {
    assert_eq!("SHA-256-sess", format!("{}", HashAlgorithm::SHA256Session))
}

#[test]
fn test_display_sha512_256_for_hashalgorithm() {
    assert_eq!("SHA-512-256", format!("{}", HashAlgorithm::SHA512256))
}

#[test]
fn test_display_sha512_256session_for_hashalgorithm() {
    assert_eq!("SHA-512-256-sess",
               format!("{}", HashAlgorithm::SHA512256Session))
}

#[test]
fn test_scheme() {
    assert_eq!(Digest::scheme(), Some("Digest"))
}

#[test]
fn test_basic_parse_header() {
    let expected = Authorization(rfc2617_digest_header(HashAlgorithm::MD5));
    let actual = Header::parse_header(&Raw::from(
        "Digest \
        username=\"Mufasa\", \
        realm=\"testrealm@host.com\", \
        nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", \
        uri=\"/dir/index.html\", \
        qop=auth, \
        nc=00000001, \
        cnonce=\"0a4f113b\", \
        response=\"6629fae49393a05397450978507c4ef1\", \
        opaque=\"5ccc069c403ebaf9f0171e9517f40e41\""
    ));
    assert_eq!(actual.ok(), Some(expected))
}

#[test]
fn test_parse_header_with_no_username() {
    assert_header_parsing_error("Digest realm=\"testrealm@host.com\", \
                                 nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", \
                                 uri=\"/dir/index.html\", qop=auth, nc=00000001, \
                                 cnonce=\"0a4f113b\", \
                                 response=\"6629fae49393a05397450978507c4ef1\", \
                                 opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"")
}

#[test]
fn test_parse_header_with_both_username_params() {
    assert_header_parsing_error("Digest username=\"multiple\", username*=UTF-8''multiple, \
                                 realm=\"testrealm@host.com\", \
                                 nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", \
                                 uri=\"/dir/index.html\", qop=auth, nc=00000001, \
                                 cnonce=\"0a4f113b\", \
                                 response=\"6629fae49393a05397450978507c4ef1\", \
                                 opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"")
}

#[test]
fn test_parse_header_with_encoded_username_and_userhash() {
    assert_header_parsing_error("Digest username*=UTF-8''encoded, realm=\"testrealm@host.com\", \
                                 nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", \
                                 uri=\"/dir/index.html\", qop=auth, nc=00000001, \
                                 cnonce=\"0a4f113b\", \
                                 response=\"6629fae49393a05397450978507c4ef1\", \
                                 opaque=\"5ccc069c403ebaf9f0171e9517f40e41\", userhash=true")
}

#[test]
fn test_parse_header_with_no_realm() {
    assert_header_parsing_error("Digest username=\"Mufasa\", \
                                 nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", \
                                 uri=\"/dir/index.html\", qop=auth, nc=00000001, \
                                 cnonce=\"0a4f113b\", \
                                 response=\"6629fae49393a05397450978507c4ef1\", \
                                 opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"")
}

#[test]
fn test_parse_header_with_no_nonce() {
    assert_header_parsing_error("Digest username=\"Mufasa\", realm=\"testrealm@host.com\", \
                                 uri=\"/dir/index.html\", qop=auth, nc=00000001, \
                                 cnonce=\"0a4f113b\", \
                                 response=\"6629fae49393a05397450978507c4ef1\", \
                                 opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"")
}

#[test]
fn test_parse_header_with_no_response() {
    assert_header_parsing_error("Digest username=\"Mufasa\", realm=\"testrealm@host.com\", \
                                 nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", \
                                 uri=\"/dir/index.html\", qop=auth, nc=00000001, \
                                 cnonce=\"0a4f113b\", opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"")
}

#[test]
fn test_parse_header_with_no_request_uri() {
    assert_header_parsing_error("Digest username=\"Mufasa\", realm=\"testrealm@host.com\", \
                                 nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", qop=auth, \
                                 nc=00000001, cnonce=\"0a4f113b\", \
                                 response=\"6629fae49393a05397450978507c4ef1\", \
                                 opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"")
}

#[test]
fn test_parse_header_with_invalid_charset() {
    assert_header_parsing_error("Digest username=\"Mufasa\", realm=\"testrealm@host.com\", \
                                 nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", \
                                 uri=\"/dir/index.html\", qop=auth, nc=00000001, \
                                 cnonce=\"0a4f113b\", \
                                 response=\"6629fae49393a05397450978507c4ef1\", \
                                 opaque=\"5ccc069c403ebaf9f0171e9517f40e41\", charset=invalid")
}

#[test]
fn test_parse_header_with_md5_algorithm() {
    let expected = Authorization(rfc2617_digest_header(HashAlgorithm::MD5));
    let actual = Header::parse_header(&Raw::from(
        "Digest \
        username=\"Mufasa\", \
        realm=\"testrealm@host.com\", \
        nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", \
        uri=\"/dir/index.html\", \
        algorithm=MD5, \
        qop=auth, \
        nc=00000001, \
        cnonce=\"0a4f113b\", \
        response=\"6629fae49393a05397450978507c4ef1\", \
        opaque=\"5ccc069c403ebaf9f0171e9517f40e41\""
    ));
    assert_eq!(actual.ok(), Some(expected))
}

#[test]
fn test_parse_header_with_md5_sess_algorithm() {
    let expected = Authorization(rfc2617_digest_header(HashAlgorithm::MD5Session));
    let actual = Header::parse_header(&Raw::from(
        "Digest \
        username=\"Mufasa\", \
        realm=\"testrealm@host.com\", \
        nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", \
        uri=\"/dir/index.html\", \
        algorithm=MD5-sess, \
        qop=auth, \
        nc=00000001, \
        cnonce=\"0a4f113b\", \
        response=\"6629fae49393a05397450978507c4ef1\", \
        opaque=\"5ccc069c403ebaf9f0171e9517f40e41\""
    ));
    assert_eq!(actual.ok(), Some(expected))
}

#[test]
fn test_parse_header_with_invalid_algorithm() {
    assert_header_parsing_error("Digest username=\"Mufasa\", realm=\"testrealm@host.com\", \
                                 nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", \
                                 uri=\"/dir/index.html\", algorithm=invalid, qop=auth, \
                                 nc=00000001, cnonce=\"0a4f113b\", \
                                 response=\"6629fae49393a05397450978507c4ef1\", \
                                 opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"")
}

#[test]
fn test_parse_header_with_auth_int_qop() {
    let mut digest = rfc2617_digest_header(HashAlgorithm::MD5);
    digest.qop = Some(Qop::AuthInt);
    assert_parsed_header_equal(Authorization(digest),
                               "Digest username=\"Mufasa\", realm=\"testrealm@host.com\", \
                                nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", \
                                uri=\"/dir/index.html\", algorithm=MD5, qop=auth-int, \
                                nc=00000001, cnonce=\"0a4f113b\", \
                                response=\"6629fae49393a05397450978507c4ef1\", \
                                opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"")
}

#[test]
fn test_parse_header_with_bad_qop() {
    assert_header_parsing_error("Digest username=\"Mufasa\", realm=\"testrealm@host.com\", \
                                 nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", \
                                 uri=\"/dir/index.html\", qop=badvalue, nc=00000001, \
                                 cnonce=\"0a4f113b\", \
                                 response=\"6629fae49393a05397450978507c4ef1\", \
                                 opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"")
}

#[test]
fn test_parse_header_with_bad_nonce_count() {
    assert_header_parsing_error("Digest username=\"Mufasa\", realm=\"testrealm@host.com\", \
                                 nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", \
                                 uri=\"/dir/index.html\", qop=auth, nc=badhexvalue, \
                                 cnonce=\"0a4f113b\", \
                                 response=\"6629fae49393a05397450978507c4ef1\", \
                                 opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"")
}

#[test]
fn test_parse_header_with_explicitly_no_userhash() {
    let expected = Authorization(rfc2617_digest_header(HashAlgorithm::SHA256));
    assert_parsed_header_equal(expected,
                               "Digest username=\"Mufasa\", realm=\"testrealm@host.com\", \
                                nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", \
                                uri=\"/dir/index.html\", algorithm=SHA-256, qop=auth, \
                                nc=00000001, cnonce=\"0a4f113b\", \
                                response=\"6629fae49393a05397450978507c4ef1\", \
                                opaque=\"5ccc069c403ebaf9f0171e9517f40e41\", userhash=false")
}

#[test]
fn test_parse_header_with_invalid_userhash_flag() {
    assert_header_parsing_error("Digest username=\"Mufasa\", realm=\"testrealm@host.com\", \
                                 nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", \
                                 uri=\"/dir/index.html\", algorithm=SHA-256, qop=auth, \
                                 nc=00000001, cnonce=\"0a4f113b\", \
                                 response=\"6629fae49393a05397450978507c4ef1\", \
                                 opaque=\"5ccc069c403ebaf9f0171e9517f40e41\", userhash=invalid")
}

#[test]
fn test_fmt_scheme() {
    assert_serialized_header_equal(rfc2069_a1_digest_header(),
                                   "Authorization: Digest username=\"Mufasa\", \
                                    realm=\"testrealm@host.com\", \
                                    nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", \
                                    response=\"1949323746fe6a43ef61f9606e7febea\", \
                                    uri=\"/dir/index.html\", algorithm=MD5")
}

#[test]
fn test_fmt_scheme_for_md5_sess_algorithm() {
    assert_serialized_header_equal(rfc2617_digest_header(HashAlgorithm::MD5Session),
                                   "Authorization: Digest username=\"Mufasa\", \
                                    realm=\"testrealm@host.com\", \
                                    nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", nc=00000001, \
                                    response=\"6629fae49393a05397450978507c4ef1\", \
                                    uri=\"/dir/index.html\", algorithm=MD5-sess, qop=auth, \
                                    cnonce=\"0a4f113b\", \
                                    opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"")
}

#[test]
fn test_fmt_scheme_with_userhash() {
    let userhash = "488869477bf257147b804c45308cd62ac4e25eb717b12b298c79e62dcea254ec";
    let digest = rfc7616_sha512_256_header(userhash.to_owned(), true);
    let expected = format!("Authorization: Digest username=\"{}\", realm=\"api@example.org\", \
                            nonce=\"5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK\", nc=00000001, \
                            response=\"ae66e67d6b427bd3f120414a82e4acff38e8ecd9101d6c861229025f60\
                            7a79dd\", uri=\"/doe.json\", algorithm=SHA-512-256, qop=auth, \
                            cnonce=\"NTg6RKcb9boFIAS3KrFK9BGeh+iDa/sm6jUMp2wds69v\", \
                            opaque=\"HRPCssKJSGjCrkzDg8OhwpzCiGPChXYjwrI2QmXDnsOS\", \
                            charset=UTF-8, userhash=true",
                           userhash);
    assert_serialized_header_equal(digest, &expected[..])
}

#[test]
fn test_fmt_scheme_with_extended_username() {
    let mut digest = rfc7616_sha512_256_header("".to_owned(), false);
    digest.username = rfc7616_username();
    let expected = "Authorization: Digest username*=UTF-8''J%C3%A4s%C3%B8n%20Doe, \
                    realm=\"api@example.org\", \
                    nonce=\"5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK\", nc=00000001, \
                    response=\"ae66e67d6b427bd3f120414a82e4acff38e8ecd9101d6c861229025f607a79dd\", \
                    uri=\"/doe.json\", algorithm=SHA-512-256, qop=auth, \
                    cnonce=\"NTg6RKcb9boFIAS3KrFK9BGeh+iDa/sm6jUMp2wds69v\", \
                    opaque=\"HRPCssKJSGjCrkzDg8OhwpzCiGPChXYjwrI2QmXDnsOS\", charset=UTF-8";
    assert_serialized_header_equal(digest, expected)
}

#[test]
fn test_userhash() {
    let expected = "488869477bf257147b804c45308cd62ac4e25eb717b12b298c79e62dcea254ec".to_owned();
    if let Username::Encoded(username) = rfc7616_username() {
        let actual = Digest::userhash(&HashAlgorithm::SHA512256,
                                      username.value,
                                      "api@example.org".to_owned());
        assert_eq!(expected, actual);
    } else {
        panic!("Bad username");
    }
}

#[test]
fn test_validate_userhash() {
    let userhash = "488869477bf257147b804c45308cd62ac4e25eb717b12b298c79e62dcea254ec".to_owned();
    let digest = rfc7616_sha512_256_header(userhash, true);

    assert!(digest.validate_userhash(rfc7616_username()));
}

#[test]
fn test_validate_userhash_with_plain_username() {
    let userhash = "74f54fe2c8045a5ffda7d02fd97f1716".to_owned();
    let mut digest = rfc2069_a1_digest_header();
    digest.username = Username::Plain(userhash);

    assert!(digest.validate_userhash(rfc2069_username()));
}

#[test]
fn test_validate_userhash_with_invalid_encoded_username() {
    let mut digest = rfc7616_digest_header(HashAlgorithm::SHA256, "");
    let extended_value = parse_extended_value("UTF-8''hello").expect("Could not parse");
    digest.username = Username::Encoded(extended_value);

    assert!(!digest.validate_userhash(rfc7616_username()));
}

#[test]
fn test_simple_hashed_a1() {
    let digest = rfc2069_a1_digest_header();
    let expected = "939e7578ed9e3c518a452acee763bce9";
    let actual = Digest::simple_hashed_a1(&digest.algorithm,
                                          digest.username,
                                          digest.realm,
                                          "Circle Of Life".to_owned());
    assert_eq!(expected, actual)
}

#[test]
fn test_a1() {
    let digest = rfc2069_a1_digest_header();
    let password = "CircleOfLife".to_owned();
    let expected = "Mufasa:testrealm@host.com:CircleOfLife"
        .to_owned()
        .into_bytes();
    let a1 = digest.a1(digest.username.clone(), password);
    assert!(a1.is_ok());
    assert_eq!(expected, a1.unwrap())
}

#[test]
fn test_a1_for_md5_sess() {
    let digest = rfc2617_digest_header(HashAlgorithm::MD5Session);
    let password = "Circle Of Life".to_owned();
    let a1 = digest.a1(digest.username.clone(), password);
    assert!(a1.is_ok());
    let expected = format!("939e7578ed9e3c518a452acee763bce9:{}:{}",
                           digest.nonce,
                           digest.client_nonce.unwrap())
        .into_bytes();
    assert_eq!(expected, a1.unwrap())
}

#[test]
fn test_a1_for_md5_sess_without_client_nonce() {
    let mut digest = rfc2617_digest_header(HashAlgorithm::MD5Session);
    digest.client_nonce = None;
    let password = "Circle Of Life".to_owned();
    let a1 = digest.a1(digest.username.clone(), password);
    assert!(a1.is_err())
}

#[test]
fn test_hashed_a1() {
    let digest = rfc2069_a1_digest_header();
    let expected = "939e7578ed9e3c518a452acee763bce9";
    let hashed_a1 = digest.hashed_a1(digest.username.clone(), "Circle Of Life".to_owned());
    assert!(hashed_a1.is_ok());
    assert_eq!(expected, hashed_a1.unwrap())
}

#[test]
fn test_hashed_a1_for_md5_sess_without_client_nonce() {
    let mut digest = rfc2617_digest_header(HashAlgorithm::MD5Session);
    digest.client_nonce = None;
    let password = "Circle Of Life".to_owned();
    let a1 = digest.hashed_a1(digest.username.clone(), password);
    assert!(a1.is_err())
}

#[test]
fn test_a2() {
    let digest = rfc2069_a2_digest_header();
    let expected = "GET:/dir/index.html";
    let actual = digest.a2(Method::Get, b"");
    assert_eq!(expected, actual)
}

#[test]
fn test_hashed_a2() {
    let digest = rfc2069_a2_digest_header();
    let expected = "39aff3a2bab6126f332b942af96d3366";
    let actual = digest.hashed_a2(Method::Get, b"");
    assert_eq!(expected, actual)
}

#[test]
fn test_from_header() {
    let password = "CircleOfLife".to_owned();
    let header: Authorization<Digest> = Header::parse_header(&Raw::from(
        "Digest \
            username=\"Mufasa\", \
            realm=\"testrealm@host.com\", \
            nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", \
            uri=\"/dir/index.html\", \
            response=\"1949323746fe6a43ef61f9606e7febea\", \
            opaque=\"5ccc069c403ebaf9f0171e9517f40e41\""
    )).unwrap();

    let hex_digest = header
        .0
        .using_password(Method::Get, b"", password);
    assert!(hex_digest.is_ok());
    assert_eq!(header.0.response, hex_digest.unwrap())
}

#[test]
fn test_from_passport_http_header() {
    let password = "secret".to_owned();
    let header = parse_digest_header("Digest username=\"bob\", realm=\"Users\", \
                                      nonce=\"NOIEDJ3hJtqSKaty8KF8xlkaYbItAkiS\", uri=\"/\", \
                                      response=\"22e3e0a9bbefeb9d229905230cb9ddc8\"");

    let hex_digest = header
        .0
        .using_password(Method::Head, b"", password);
    assert!(hex_digest.is_ok());
    assert_eq!(header.0.response, hex_digest.unwrap())
}

#[test]
fn test_using_password_and_md5_session_sans_client_nonce() {
    let password = "Circle Of Life".to_owned();
    let mut digest = rfc2617_digest_header(HashAlgorithm::MD5Session);
    digest.client_nonce = None;
    let hex_digest = digest.using_password(Method::Get, b"", password);
    assert!(hex_digest.is_err())
}

#[test]
fn test_using_password_and_sha256() {
    let password = "Circle of Life".to_owned();
    let digest = rfc7616_digest_header(HashAlgorithm::SHA256,
                                       "753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db58\
                                        56cb6c1");
    let hex_digest = digest.using_password(Method::Get, b"", password);
    assert!(hex_digest.is_ok());
    assert_eq!(digest.response, hex_digest.unwrap())
}

#[test]
fn test_using_hashed_a1() {
    let hashed_a1 = "939e7578ed9e3c518a452acee763bce9".to_owned();
    let digest = rfc2617_digest_header(HashAlgorithm::MD5);
    let hex_digest = digest.using_hashed_a1(Method::Get, b"", hashed_a1);
    assert!(hex_digest.is_ok());
    assert_eq!(digest.response, hex_digest.unwrap())
}

#[test]
fn test_using_hashed_a1_with_auth_int_qop() {
    let hashed_a1 = "939e7578ed9e3c518a452acee763bce9".to_owned();
    let expected = "7b9be1c2def9d4ad657b26ac8bc651a0".to_owned();
    let mut digest = rfc2617_digest_header(HashAlgorithm::MD5);
    digest.qop = Some(Qop::AuthInt);
    let hex_digest = digest.using_hashed_a1(Method::Get, b"foo=bar", hashed_a1);
    assert!(hex_digest.is_ok());
    assert_eq!(expected, hex_digest.unwrap())
}

#[test]
fn test_using_hashed_a1_with_auth_int_qop_sans_nonce_count() {
    let hashed_a1 = "939e7578ed9e3c518a452acee763bce9".to_owned();
    let mut digest = rfc2617_digest_header(HashAlgorithm::MD5);
    digest.qop = Some(Qop::AuthInt);
    digest.nonce_count = None;
    let hex_digest = digest.using_hashed_a1(Method::Get, b"foo=bar", hashed_a1);
    assert!(hex_digest.is_err())
}

#[test]
fn test_using_hashed_a1_with_auth_int_qop_sans_client_nonce() {
    let hashed_a1 = "939e7578ed9e3c518a452acee763bce9".to_owned();
    let mut digest = rfc2617_digest_header(HashAlgorithm::MD5);
    digest.qop = Some(Qop::AuthInt);
    digest.client_nonce = None;
    let hex_digest = digest.using_hashed_a1(Method::Get, b"foo=bar", hashed_a1);
    assert!(hex_digest.is_err())
}

#[test]
fn test_using_hashed_a1_sans_qop() {
    let hashed_a1 = "939e7578ed9e3c518a452acee763bce9".to_owned();
    let expected = "670fd8c2df070c60b045671b8b24ff02".to_owned();
    let mut digest = rfc2617_digest_header(HashAlgorithm::MD5);
    digest.qop = None;
    let hex_digest = digest.using_hashed_a1(Method::Get, b"", hashed_a1);
    assert!(hex_digest.is_ok());
    assert_eq!(expected, hex_digest.unwrap())
}

#[test]
fn test_validate_using_password() {
    let password = "Circle of Life".to_owned();
    // From RFC 7616 and the result from Firefox
    let header = parse_digest_header("Digest username=\"Mufasa\", \
                                      realm=\"http-auth@example.org\", \
                                      nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\", \
                                      uri=\"/dir/index.html\", algorithm=MD5, \
                                      response=\"65e4930cfb0b33cb53405ecea0705cec\", \
                                      opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\", \
                                      qop=auth, nc=00000001, cnonce=\"b24ce2519b8cdb10\"");
    assert!(header
                .0
                .validate_using_password(Method::Get, b"", password.clone()));
    let mut digest = header.0.clone();
    digest.client_nonce = Some("somethingelse".to_owned());
    assert!(!digest.validate_using_password(Method::Get, b"", password));
}

#[test]
fn test_validate_using_encoded_username_and_password() {
    // From RFC 7616
    let password = "Secret, or not?".to_owned();
    let header = parse_digest_header("Digest username*=UTF-8''J%C3%A4s%C3%B8n%20Doe, \
                                      realm=\"api@example.org\", uri=\"/doe.json\", \
                                      algorithm=SHA-512-256, \
                                      nonce=\"5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK\", \
                                      nc=00000001, \
                                      cnonce=\"NTg6RKcb9boFIAS3KrFK9BGeh+iDa/sm6jUMp2wds69v\", \
                                      qop=auth, \
                                      response=\"ae66e67d6b427bd3f120414a82e4acff38e8ecd9101d6c861229025f607a79dd\", \
                                      opaque=\"HRPCssKJSGjCrkzDg8OhwpzCiGPChXYjwrI2QmXDnsOS\", \
                                      userhash=false");
    assert!(header
                .0
                .validate_using_password(Method::Get, b"", password.clone()));
}

#[test]
fn test_validate_using_userhash_and_password() {
    // From RFC 7616
    let password = "Secret, or not?".to_owned();
    let header = parse_digest_header("Digest username=\"488869477bf257147b804c45308cd62ac4e25eb717b12b298c79e62dcea254ec\", \
                                      realm=\"api@example.org\", uri=\"/doe.json\", \
                                      algorithm=SHA-512-256, \
                                      nonce=\"5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK\", \
                                      nc=00000001, \
                                      cnonce=\"NTg6RKcb9boFIAS3KrFK9BGeh+iDa/sm6jUMp2wds69v\", \
                                      qop=auth, \
                                      response=\"ae66e67d6b427bd3f120414a82e4acff38e8ecd9101d6c861229025f607a79dd\", \
                                      opaque=\"HRPCssKJSGjCrkzDg8OhwpzCiGPChXYjwrI2QmXDnsOS\", \
                                      charset=UTF-8, userhash=true");
    assert!(header.0.validate_using_userhash_and_password(Method::Get,
                                                          b"",
                                                          rfc7616_username(),
                                                          password.clone()));

    let mut digest = header.0.clone();
    digest.userhash = false;
    digest.username = rfc7616_username();
    assert!(digest.validate_using_userhash_and_password(Method::Get,
                                                        b"",
                                                        rfc7616_username(),
                                                        password.clone()));

    digest.userhash = true;
    digest.username = Username::Plain("invalid".to_owned());

    assert!(!digest.validate_using_userhash_and_password(Method::Get,
                                                         b"",
                                                         rfc7616_username(),
                                                         password.clone()));
}

#[test]
fn test_validate_using_hashed_a1() {
    let hashed_a1 = "3d78807defe7de2157e2b0b6573a855f".to_owned();
    let mut digest = rfc7616_digest_header(HashAlgorithm::MD5, "8ca523f5e9506fed4657c9700eebdbec");
    assert!(digest.validate_using_hashed_a1(Method::Get, b"", hashed_a1.clone()));

    digest.client_nonce = Some("different".to_owned());
    assert!(!digest.validate_using_hashed_a1(Method::Get, b"", hashed_a1));
}
