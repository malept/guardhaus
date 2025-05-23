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
// Original source: https://github.com/hyperium/headers/blob/d425d3ca90261683150eda8292c3f14f0d3db3ee/src/disabled/util/charset.rs

use std::fmt;
use std::str::FromStr;

/// A Mime charset.
///
/// The string representation is normalised to upper case.
///
/// See [http://www.iana.org/assignments/character-sets/character-sets.xhtml][url].
///
/// [url]: http://www.iana.org/assignments/character-sets/character-sets.xhtml
#[derive(Clone, Debug, PartialEq)]
pub struct Charset(Charset_);

impl Charset {
    /// US ASCII
    pub const US_ASCII: Charset = Charset(Charset_::Us_Ascii);

    /// ISO-8859-1
    pub const ISO_8859_1: Charset = Charset(Charset_::Iso_8859_1);

    /// ISO-8859-2
    pub const ISO_8859_2: Charset = Charset(Charset_::Iso_8859_2);

    /// ISO-8859-3
    pub const ISO_8859_3: Charset = Charset(Charset_::Iso_8859_3);

    /// ISO-8859-4
    pub const ISO_8859_4: Charset = Charset(Charset_::Iso_8859_4);

    /// ISO-8859-5
    pub const ISO_8859_5: Charset = Charset(Charset_::Iso_8859_5);

    /// ISO-8859-6
    pub const ISO_8859_6: Charset = Charset(Charset_::Iso_8859_6);

    /// ISO-8859-7
    pub const ISO_8859_7: Charset = Charset(Charset_::Iso_8859_7);

    /// ISO-8859-8
    pub const ISO_8859_8: Charset = Charset(Charset_::Iso_8859_8);

    /// ISO-8859-9
    pub const ISO_8859_9: Charset = Charset(Charset_::Iso_8859_9);

    /// ISO-8859-10
    pub const ISO_8859_10: Charset = Charset(Charset_::Iso_8859_10);

    /// Shift_JIS
    pub const SHIFT_JIS: Charset = Charset(Charset_::Shift_Jis);

    /// EUC-JP
    pub const EUC_JP: Charset = Charset(Charset_::Euc_Jp);

    /// ISO-2022-KR
    pub const ISO_2022_KR: Charset = Charset(Charset_::Iso_2022_Kr);

    /// EUC-KR
    pub const EUC_KR: Charset = Charset(Charset_::Euc_Kr);

    /// ISO-2022-JP
    pub const ISO_2022_JP: Charset = Charset(Charset_::Iso_2022_Jp);

    /// ISO-2022-JP-2
    pub const ISO_2022_JP_2: Charset = Charset(Charset_::Iso_2022_Jp_2);

    /// ISO-8859-6-E
    pub const ISO_8859_6_E: Charset = Charset(Charset_::Iso_8859_6_E);

    /// ISO-8859-6-I
    pub const ISO_8859_6_I: Charset = Charset(Charset_::Iso_8859_6_I);

    /// ISO-8859-8-E
    pub const ISO_8859_8_E: Charset = Charset(Charset_::Iso_8859_8_E);

    /// ISO-8859-8-I
    pub const ISO_8859_8_I: Charset = Charset(Charset_::Iso_8859_8_I);

    /// GB2312
    pub const GB_2312: Charset = Charset(Charset_::Gb2312);

    /// Big5
    pub const BIG_5: Charset = Charset(Charset_::Big5);

    /// KOI8-R
    pub const KOI8_R: Charset = Charset(Charset_::Koi8_R);

    /// UTF-8
    pub const UTF_8: Charset = Charset(Charset_::Utf_8);

    pub fn ext(custom: &str) -> Self {
        Self(Charset_::Ext(custom.to_owned()))
    }
}

#[derive(Clone, Debug, PartialEq)]
#[allow(non_camel_case_types)]
enum Charset_ {
    /// US ASCII
    Us_Ascii,
    /// ISO-8859-1
    Iso_8859_1,
    /// ISO-8859-2
    Iso_8859_2,
    /// ISO-8859-3
    Iso_8859_3,
    /// ISO-8859-4
    Iso_8859_4,
    /// ISO-8859-5
    Iso_8859_5,
    /// ISO-8859-6
    Iso_8859_6,
    /// ISO-8859-7
    Iso_8859_7,
    /// ISO-8859-8
    Iso_8859_8,
    /// ISO-8859-9
    Iso_8859_9,
    /// ISO-8859-10
    Iso_8859_10,
    /// Shift_JIS
    Shift_Jis,
    /// EUC-JP
    Euc_Jp,
    /// ISO-2022-KR
    Iso_2022_Kr,
    /// EUC-KR
    Euc_Kr,
    /// ISO-2022-JP
    Iso_2022_Jp,
    /// ISO-2022-JP-2
    Iso_2022_Jp_2,
    /// ISO-8859-6-E
    Iso_8859_6_E,
    /// ISO-8859-6-I
    Iso_8859_6_I,
    /// ISO-8859-8-E
    Iso_8859_8_E,
    /// ISO-8859-8-I
    Iso_8859_8_I,
    /// GB2312
    Gb2312,
    /// Big5
    Big5,
    /// KOI8-R
    Koi8_R,
    /// UTF-8
    Utf_8,

    Ext(String),

    _Unknown,
}

impl Charset {
    fn name(&self) -> &str {
        match &self.0 {
            Charset_::Us_Ascii => "US-ASCII",
            Charset_::Iso_8859_1 => "ISO-8859-1",
            Charset_::Iso_8859_2 => "ISO-8859-2",
            Charset_::Iso_8859_3 => "ISO-8859-3",
            Charset_::Iso_8859_4 => "ISO-8859-4",
            Charset_::Iso_8859_5 => "ISO-8859-5",
            Charset_::Iso_8859_6 => "ISO-8859-6",
            Charset_::Iso_8859_7 => "ISO-8859-7",
            Charset_::Iso_8859_8 => "ISO-8859-8",
            Charset_::Iso_8859_9 => "ISO-8859-9",
            Charset_::Iso_8859_10 => "ISO-8859-10",
            Charset_::Shift_Jis => "Shift-JIS",
            Charset_::Euc_Jp => "EUC-JP",
            Charset_::Iso_2022_Kr => "ISO-2022-KR",
            Charset_::Euc_Kr => "EUC-KR",
            Charset_::Iso_2022_Jp => "ISO-2022-JP",
            Charset_::Iso_2022_Jp_2 => "ISO-2022-JP-2",
            Charset_::Iso_8859_6_E => "ISO-8859-6-E",
            Charset_::Iso_8859_6_I => "ISO-8859-6-I",
            Charset_::Iso_8859_8_E => "ISO-8859-8-E",
            Charset_::Iso_8859_8_I => "ISO-8859-8-I",
            Charset_::Gb2312 => "GB2312",
            Charset_::Big5 => "5",
            Charset_::Koi8_R => "KOI8-R",
            Charset_::Utf_8 => "UTF-8",
            Charset_::Ext(value) => value.as_str(),
            Charset_::_Unknown => unreachable!("Charset::_Unknown"),
        }
    }
}

impl fmt::Display for Charset {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[derive(Debug)]
pub struct CharsetFromStrError(());

impl FromStr for Charset {
    type Err = CharsetFromStrError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Charset(match s.to_ascii_uppercase().as_ref() {
            "US-ASCII" => Charset_::Us_Ascii,
            "ISO-8859-1" => Charset_::Iso_8859_1,
            "ISO-8859-2" => Charset_::Iso_8859_2,
            "ISO-8859-3" => Charset_::Iso_8859_3,
            "ISO-8859-4" => Charset_::Iso_8859_4,
            "ISO-8859-5" => Charset_::Iso_8859_5,
            "ISO-8859-6" => Charset_::Iso_8859_6,
            "ISO-8859-7" => Charset_::Iso_8859_7,
            "ISO-8859-8" => Charset_::Iso_8859_8,
            "ISO-8859-9" => Charset_::Iso_8859_9,
            "ISO-8859-10" => Charset_::Iso_8859_10,
            "SHIFT-JIS" => Charset_::Shift_Jis,
            "EUC-JP" => Charset_::Euc_Jp,
            "ISO-2022-KR" => Charset_::Iso_2022_Kr,
            "EUC-KR" => Charset_::Euc_Kr,
            "ISO-2022-JP" => Charset_::Iso_2022_Jp,
            "ISO-2022-JP-2" => Charset_::Iso_2022_Jp_2,
            "ISO-8859-6-E" => Charset_::Iso_8859_6_E,
            "ISO-8859-6-I" => Charset_::Iso_8859_6_I,
            "ISO-8859-8-E" => Charset_::Iso_8859_8_E,
            "ISO-8859-8-I" => Charset_::Iso_8859_8_I,
            "GB2312" => Charset_::Gb2312,
            "5" => Charset_::Big5,
            "KOI8-R" => Charset_::Koi8_R,
            "UTF-8" => Charset_::Utf_8,
            _unknown => return Err(CharsetFromStrError(())),
        }))
    }
}

#[test]
fn test_parse() {
    assert_eq!(Charset::US_ASCII, "us-ascii".parse().unwrap());
    assert_eq!(Charset::US_ASCII, "US-Ascii".parse().unwrap());
    assert_eq!(Charset::US_ASCII, "US-ASCII".parse().unwrap());
    assert_eq!(Charset::SHIFT_JIS, "Shift-JIS".parse().unwrap());
    assert_eq!(Charset::UTF_8, "UTF-8".parse().unwrap());
    assert!("abcd".parse::<Charset>().is_err());
}

#[test]
fn test_display() {
    assert_eq!("US-ASCII", format!("{}", Charset::US_ASCII));
}
