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

#![cfg(test)]

use parsing::test_helper::{assert_header_parsing_error, assert_parsed_header_equal,
                           assert_serialized_header_equal};
use super::AuthenticationInfo;
use super::super::types::{NonceCount, Qop};

#[test]
fn test_parse_authentication_info_with_digest_and_nextnonce() {
    let expected = AuthenticationInfo {
        digest: Some("abcdef".to_owned()),
        next_nonce: Some("fedcba".to_owned()),
        qop: None,
        client_nonce: None,
        nonce_count: None,
    };
    assert_parsed_header_equal(expected, "nextnonce=\"fedcba\", rspauth=\"abcdef\"");
}

#[test]
fn test_parse_authentication_info_with_digest() {
    let expected = AuthenticationInfo {
        digest: Some("abcdef".to_owned()),
        next_nonce: None,
        qop: None,
        client_nonce: None,
        nonce_count: None,
    };
    assert_parsed_header_equal(expected, "rspauth=\"abcdef\"");
}

#[test]
fn test_parse_authentication_info_with_digest_and_rspauth() {
    assert_header_parsing_error::<AuthenticationInfo>("digest=\"abcdef\", rspauth=\"abcdef\"");
}

#[test]
fn test_parse_authentication_info_with_qop() {
    let expected = AuthenticationInfo {
        digest: Some("abcdef".to_owned()),
        next_nonce: None,
        qop: Some(Qop::Auth),
        client_nonce: Some("1234".to_owned()),
        nonce_count: Some(NonceCount(2)),
    };
    assert_parsed_header_equal(expected,
                               "qop=auth, rspauth=\"abcdef\", cnonce=\"1234\", nc=00000002");
}

#[test]
fn test_parse_authentication_info_with_qop_but_not_all_required_params() {
    // missing nc (nonce_count)
    assert_header_parsing_error::<AuthenticationInfo>("qop=auth, digest=\"abcd\", cnonce=\"1234\"");
}

#[test]
fn test_parse_authentication_info_with_bad_qop() {
    assert_header_parsing_error::<AuthenticationInfo>("qop=invalid");
}

#[test]
fn test_parse_authentication_info_with_nextnonce() {
    let expected = AuthenticationInfo {
        digest: None,
        next_nonce: Some("fedcba".to_owned()),
        qop: None,
        client_nonce: None,
        nonce_count: None,
    };
    assert_parsed_header_equal(expected, "nextnonce=\"fedcba\"");
}

#[test]
fn test_parse_authentication_info_with_bad_nonce_count() {
    assert_header_parsing_error::<AuthenticationInfo>("nc=-1");
}

#[test]
fn test_parse_authentication_info_with_digest_qop_cnonce_and_nc() {
    let expected = AuthenticationInfo {
        digest: Some("abcdef".to_owned()),
        next_nonce: None,
        qop: Some(Qop::Auth),
        client_nonce: Some("client nonce".to_owned()),
        nonce_count: Some(NonceCount(1)),
    };
    assert_parsed_header_equal(expected,
                               "qop=auth, rspauth=\"abcdef\", cnonce=\"client nonce\", \
                                nc=00000001");
}

#[test]
fn test_fmt_authentication_info_with_digest_and_nextnonce() {
    let header = AuthenticationInfo {
        digest: Some("abcdef".to_owned()),
        next_nonce: Some("fedcba".to_owned()),
        qop: None,
        client_nonce: None,
        nonce_count: None,
    };
    assert_serialized_header_equal(header,
                                   "Authentication-Info: rspauth=\"abcdef\", nextnonce=\"fedcba\"");
}

#[test]
fn test_fmt_authentication_info_with_digest() {
    let header = AuthenticationInfo {
        digest: Some("abcdef".to_owned()),
        next_nonce: None,
        qop: None,
        client_nonce: None,
        nonce_count: None,
    };
    assert_serialized_header_equal(header, "Authentication-Info: rspauth=\"abcdef\"");
}

#[test]
fn test_fmt_authentication_info_with_nextnonce() {
    let header = AuthenticationInfo {
        digest: None,
        next_nonce: Some("fedcba".to_owned()),
        qop: None,
        client_nonce: None,
        nonce_count: None,
    };
    assert_serialized_header_equal(header, "Authentication-Info: nextnonce=\"fedcba\"");
}

#[test]
fn test_fmt_authentication_info_with_qop() {
    let header = AuthenticationInfo {
        digest: None,
        next_nonce: None,
        qop: Some(Qop::AuthInt),
        client_nonce: None,
        nonce_count: None,
    };
    assert_serialized_header_equal(header, "Authentication-Info: qop=auth-int");
}

#[test]
fn test_fmt_authentication_info_with_client_nonce() {
    let header = AuthenticationInfo {
        digest: None,
        next_nonce: None,
        qop: None,
        client_nonce: Some("client nonce".to_owned()),
        nonce_count: None,
    };
    assert_serialized_header_equal(header, "Authentication-Info: cnonce=\"client nonce\"");
}

#[test]
fn test_fmt_authentication_info_with_nonce_count() {
    let header = AuthenticationInfo {
        digest: None,
        next_nonce: None,
        qop: None,
        client_nonce: None,
        nonce_count: Some(NonceCount(0xff)),
    };
    assert_serialized_header_equal(header, "Authentication-Info: nc=000000ff");
}
