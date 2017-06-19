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

#![allow(dead_code)]

use hyper::header::{Header, Headers, Raw};
use std::fmt;

pub fn assert_parsed_header_equal<H: Header + PartialEq + fmt::Debug>(expected: H, data: &str) {
    let actual: Result<H, _> = H::parse_header(&Raw::from(data));
    assert_eq!(actual.ok(), Some(expected))
}

pub fn assert_header_parsing_error<H: Header>(data: &str) {
    let header: Result<H, _> = H::parse_header(&Raw::from(data));
    assert!(header.is_err())
}

pub fn assert_serialized_header_equal<H: Header>(header: H, actual: &str) {
    let mut headers = Headers::new();
    headers.set(header);
    assert_eq!(headers.to_string(), format!("{}\r\n", actual))
}
