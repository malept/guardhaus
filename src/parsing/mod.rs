// Copyright (c) 2015, 2016, 2017, 2020 Mark Lee
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

//! Utility functions to parse headers.

use hyper::header::parsing::from_comma_delimited;
use hyper::header::Raw;
use percent_encoding::percent_decode;
use std::collections::HashMap;
use unicase::UniCase;

pub mod test_helper;

/// Append a header parameter to a serialized header.
pub fn append_parameter(serialized: &mut String, key: &str, value: &str, quoted: bool) {
    if !serialized.is_empty() {
        serialized.push_str(", ")
    }
    serialized.push_str(key);
    serialized.push('=');
    if quoted {
        serialized.push('"');
    }
    serialized.push_str(value);
    if quoted {
        serialized.push('"');
    }
}

pub fn parse_parameters(s: &str) -> HashMap<UniCase<String>, String> {
    let parameters: Vec<String> =
        from_comma_delimited(&Raw::from(s)).expect("Could not parse header parameters");
    let mut param_map: HashMap<UniCase<String>, String> = HashMap::with_capacity(parameters.len());
    for parameter in parameters {
        let parts: Vec<&str> = parameter.splitn(2, '=').collect();
        param_map.insert(
            UniCase::new(parts[0].trim().to_owned()),
            parts[1].trim().trim_matches('"').to_owned(),
        );
    }

    param_map
}

pub fn unraveled_map_value(map: &HashMap<UniCase<String>, String>, key: &str) -> Option<String> {
    let value = match map.get(&UniCase::new(key.to_owned())) {
        Some(v) => v,
        None => return None,
    };
    match percent_decode(value.as_bytes()).decode_utf8() {
        Ok(string) => Some(string.into_owned()),
        Err(_) => None,
    }
}
