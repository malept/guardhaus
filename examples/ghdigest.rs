// Copyright (c) 2015, 2016, 2025 Mark Lee
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

use anyhow::Result;
use getopts::Options;
use guardhaus::digest::{Digest, Username};
use guardhaus::types::HashAlgorithm;
use rpassword::prompt_password;
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};

fn print_usage(program: &str, opts: &Options) {
    let brief = format!("Usage: {} [options] passwdfile realm username", program);
    print!("{}", opts.usage(&brief));
}

fn open_passwdfile(path: String, create_passwdfile: bool) -> io::Result<File> {
    if create_passwdfile {
        File::create(path)
    } else {
        OpenOptions::new().append(true).open(path)
    }
}

fn get_password() -> Result<String> {
    let password = prompt_password("Enter password: ")?;
    let confirmation = prompt_password("Re-enter password: ")?;
    if password == confirmation {
        Ok(password)
    } else {
        panic!("Passwords do not match")
    }
}

fn append_to_passwdfile(
    file: &mut File,
    username: &str,
    realm: &str,
    password: String,
) -> Result<()> {
    let hashed = Digest::simple_hashed_a1(
        &HashAlgorithm::Md5,
        Username::Plain(username.to_string()),
        realm.to_string(),
        password,
    );
    writeln!(file, "{}:{}:{}", username, realm, hashed)?;
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optflag("h", "help", "print this help menu");
    opts.optflag(
        "c",
        "",
        "Create the passwdfile. If passwdfile already exists, it is deleted first.",
    );

    let matches = opts.parse(&args[1..])?;
    if matches.opt_present("h") {
        print_usage(&program, &opts);
        return Ok(());
    }

    let create_passwdfile = matches.opt_present("c");

    if matches.free.len() >= 3 {
        let passwdfile_path = matches.free[0].clone();
        let realm = matches.free[1].as_ref();
        let username = matches.free[2].as_ref();
        let mut passwdfile = open_passwdfile(passwdfile_path, create_passwdfile)?;
        append_to_passwdfile(&mut passwdfile, username, realm, get_password()?)?;
    } else {
        print_usage(&program, &opts);
    }

    Ok(())
}
