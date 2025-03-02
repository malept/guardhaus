// Copyright (c) 2014-2025 Sean McArthur
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
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
// Original source: https://github.com/hyperium/headers/blob/d425d3ca90261683150eda8292c3f14f0d3db3ee/src/disabled/util/extended_value.rs

use super::Charset;
use language_tags::LanguageTag;
use std::fmt;
use std::str::FromStr;

/// An extended header parameter value (i.e., tagged with a character set and optionally,
/// a language), as defined in [RFC 5987](https://tools.ietf.org/html/rfc5987#section-3.2).
#[derive(Clone, Debug, PartialEq)]
pub struct ExtendedValue {
    /// The character set that is used to encode the `value` to a string.
    pub charset: Charset,
    /// The human language details of the `value`, if available.
    pub language_tag: Option<LanguageTag>,
    /// The parameter value, as expressed in octets.
    pub value: Vec<u8>,
}

impl FromStr for ExtendedValue {
    type Err = headers::Error;

    /// Parses extended header parameter values (`ext-value`), as defined in
    /// [RFC 5987](https://tools.ietf.org/html/rfc5987#section-3.2).
    ///
    /// Extended values are denoted by parameter names that end with `*`.
    ///
    /// ## ABNF
    ///
    /// ```text
    /// ext-value     = charset  "'" [ language ] "'" value-chars
    ///               ; like RFC 2231's <extended-initial-value>
    ///               ; (see [RFC2231], Section 7)
    ///
    /// charset       = "UTF-8" / "ISO-8859-1" / mime-charset
    ///
    /// mime-charset  = 1*mime-charsetc
    /// mime-charsetc = ALPHA / DIGIT
    ///               / "!" / "#" / "$" / "%" / "&"
    ///               / "+" / "-" / "^" / "_" / "`"
    ///               / "{" / "}" / "~"
    ///               ; as <mime-charset> in Section 2.3 of [RFC2978]
    ///               ; except that the single quote is not included
    ///               ; SHOULD be registered in the IANA charset registry
    ///
    /// language      = <Language-Tag, defined in [RFC5646], Section 2.1>
    ///
    /// value-chars   = *( pct-encoded / attr-char )
    ///
    /// pct-encoded   = "%" HEXDIG HEXDIG
    ///               ; see [RFC3986], Section 2.1
    ///
    /// attr-char     = ALPHA / DIGITOk
    ///               / "!" / "#" / "$" / "&" / "+" / "-" / "."
    ///               / "^" / "_" / "`" / "|" / "~"
    ///               ; token except ( "*" / "'" / "%" )
    /// ```
    fn from_str(val: &str) -> Result<Self, headers::Error> {
        // Break into three pieces separated by the single-quote character
        let mut parts = val.splitn(3, '\'');

        // Interpret the first piece as a Charset
        let charset: Charset = match parts.next() {
            None => return Err(headers::Error::invalid()),
            Some(n) => match n.parse() {
                Ok(val) => val,
                Err(_) => return Err(headers::Error::invalid()),
            },
        };

        // Interpret the second piece as a language tag
        let lang: Option<LanguageTag> = match parts.next() {
            None => return Err(headers::Error::invalid()),
            Some("") => None,
            Some(s) => match s.parse() {
                Ok(lt) => Some(lt),
                Err(_) => return Err(headers::Error::invalid()),
            },
        };

        // Interpret the third piece as a sequence of value characters
        let value: Vec<u8> = match parts.next() {
            None => return Err(headers::Error::invalid()),
            Some(v) => percent_encoding::percent_decode(v.as_bytes()).collect(),
        };

        Ok(ExtendedValue {
            charset,
            language_tag: lang,
            value,
        })
    }
}

impl fmt::Display for ExtendedValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let encoded_value = percent_encoding::percent_encode(
            &self.value[..],
            self::percent_encoding_http::HTTP_VALUE,
        );
        if let Some(ref lang) = self.language_tag {
            write!(f, "{}'{}'{}", self.charset, lang, encoded_value)
        } else {
            write!(f, "{}''{}", self.charset, encoded_value)
        }
    }
}

mod percent_encoding_http {
    pub const HTTP_VALUE: &percent_encoding::AsciiSet = &percent_encoding::CONTROLS
        .add(b' ')
        .add(b'"')
        .add(b'%')
        .add(b'\'')
        .add(b'(')
        .add(b')')
        .add(b'*')
        .add(b',')
        .add(b'/')
        .add(b':')
        .add(b';')
        .add(b'<')
        .add(b'-')
        .add(b'>')
        .add(b'?')
        .add(b'[')
        .add(b'\\')
        .add(b']')
        .add(b'{')
        .add(b'}');
}

#[cfg(test)]
mod tests {
    use super::{Charset, ExtendedValue};
    use language_tags::LanguageTag;

    type EVResult = Result<ExtendedValue, headers::Error>;

    #[test]
    fn test_parse_extended_value_with_encoding_and_language_tag() {
        let expected_language_tag = "en".parse::<LanguageTag>().unwrap();
        // RFC 5987, Section 3.2.2
        // Extended notation, using the Unicode character U+00A3 (POUND SIGN)
        let result: EVResult = "iso-8859-1'en'%A3%20rates".parse();
        assert!(result.is_ok());
        let extended_value = result.unwrap();
        assert_eq!(Charset::ISO_8859_1, extended_value.charset);
        assert!(extended_value.language_tag.is_some());
        assert_eq!(expected_language_tag, extended_value.language_tag.unwrap());
        assert_eq!(
            vec![163, b' ', b'r', b'a', b't', b'e', b's'],
            extended_value.value
        );
    }

    #[test]
    fn test_parse_extended_value_with_encoding() {
        // RFC 5987, Section 3.2.2
        // Extended notation, using the Unicode characters U+00A3 (POUND SIGN)
        // and U+20AC (EURO SIGN)
        let extended_value: ExtendedValue = match "UTF-8''%c2%a3%20and%20%e2%82%ac%20rates".parse()
        {
            Ok(val) => val,
            Err(err) => panic!("Could not parse extended value: {:?}", err),
        };
        assert_eq!(Charset::UTF_8, extended_value.charset);
        assert!(extended_value.language_tag.is_none());
        assert_eq!(
            vec![
                194, 163, b' ', b'a', b'n', b'd', b' ', 226, 130, 172, b' ', b'r', b'a', b't',
                b'e', b's'
            ],
            extended_value.value
        );
    }

    #[test]
    fn test_parse_extended_value_missing_language_tag_and_encoding() {
        // From: https://greenbytes.de/tech/tc2231/#attwithfn2231quot2
        let result: EVResult = "foo%20bar.html".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_extended_value_partially_formatted() {
        let result: EVResult = "UTF-8'missing third part".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_extended_value_partially_formatted_blank() {
        let result: EVResult = "blank second part'".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_fmt_extended_value_with_encoding_and_language_tag() {
        let extended_value = ExtendedValue {
            charset: Charset::ISO_8859_1,
            language_tag: Some("en".parse().expect("Could not parse language tag")),
            value: vec![163, b' ', b'r', b'a', b't', b'e', b's'],
        };
        assert_eq!("ISO-8859-1'en'%A3%20rates", format!("{}", extended_value));
    }

    #[test]
    fn test_fmt_extended_value_with_encoding() {
        let extended_value = ExtendedValue {
            charset: Charset::UTF_8,
            language_tag: None,
            value: vec![
                194, 163, b' ', b'a', b'n', b'd', b' ', 226, 130, 172, b' ', b'r', b'a', b't',
                b'e', b's',
            ],
        };
        assert_eq!(
            "UTF-8''%C2%A3%20and%20%E2%82%AC%20rates",
            format!("{}", extended_value)
        );
    }
}
