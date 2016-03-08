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

use parsing::test_helper::{assert_parsed_header_equal, assert_serialized_header_equal};
use super::AuthenticationInfo;

#[test]
fn test_parse_authentication_info_with_digest_and_nextnonce() {
    let expected = AuthenticationInfo {
        digest: Some("abcdef".to_owned()),
        next_nonce: Some("fedcba".to_owned()),
    };
    assert_parsed_header_equal(expected, "nextnonce=\"fedcba\", digest=\"abcdef\"");
}

#[test]
fn test_parse_authentication_info_with_digest() {
    let expected = AuthenticationInfo {
        digest: Some("abcdef".to_owned()),
        next_nonce: None,
    };
    assert_parsed_header_equal(expected, "digest=\"abcdef\"");
}

#[test]
fn test_parse_authentication_info_with_nextnonce() {
    let expected = AuthenticationInfo {
        digest: None,
        next_nonce: Some("fedcba".to_owned()),
    };
    assert_parsed_header_equal(expected, "nextnonce=\"fedcba\"");
}

#[test]
fn test_fmt_authentication_info_with_digest_and_nextnonce() {
    let header = AuthenticationInfo {
        digest: Some("abcdef".to_owned()),
        next_nonce: Some("fedcba".to_owned()),
    };
    assert_serialized_header_equal(header,
                                   "Authentication-info: digest=\"abcdef\", nextnonce=\"fedcba\"");
}

#[test]
fn test_fmt_authentication_info_with_digest() {
    let header = AuthenticationInfo {
        digest: Some("abcdef".to_owned()),
        next_nonce: None,
    };
    assert_serialized_header_equal(header, "Authentication-info: digest=\"abcdef\"");
}

#[test]
fn test_fmt_authentication_info_with_nextnonce() {
    let header = AuthenticationInfo {
        digest: None,
        next_nonce: Some("fedcba".to_owned()),
    };
    assert_serialized_header_equal(header, "Authentication-info: nextnonce=\"fedcba\"");
}
