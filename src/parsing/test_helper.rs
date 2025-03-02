// Copyright (c) 2015, 2016, 2017, 2025 Mark Lee
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

use httparse;

fn serialize_header(header: httparse::Header) -> Result<String, std::str::Utf8Error> {
    let mut serialized = String::new();
    serialized.push_str(header.name);
    serialized.push_str(": ");
    serialized.push_str(std::str::from_utf8(header.value)?);
    serialized.push('\r');
    serialized.push('\n');

    Ok(serialized)
}

pub fn assert_parsed_header_equal(expected: httparse::Header, data: &str) {
    let mut actual = [httparse::EMPTY_HEADER; 4];
    let res = httparse::parse_headers(data.as_bytes(), &mut actual);
    let (_, headers) = res.expect("Could not parse headers").unwrap();
    let header = headers[0];
    assert_eq!(header, expected)
}

pub fn assert_header_parsing_error(data: &str) {
    let mut actual = [httparse::EMPTY_HEADER; 4];
    let res = httparse::parse_headers(data.as_bytes(), &mut actual);
    assert!(res.is_err());
}

pub fn assert_serialized_header_equal(header: httparse::Header, actual: &str) {
    let expected = serialize_header(header).expect("Could not serialize headers");
    assert_eq!(expected, format!("{}\r\n", actual))
}
