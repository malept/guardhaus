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

extern crate getopts;
extern crate guardhaus;
extern crate rpassword;

use getopts::Options;
use guardhaus::digest::{Digest, HashAlgorithm, Username};
use rpassword::read_password;
use std::env;
use std::io;
use std::io::Write;
use std::fs::{File, OpenOptions};

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options] passwdfile realm username", program);
    print!("{}", opts.usage(&brief));
}

fn open_passwdfile(path: String, create_passwdfile: bool) -> io::Result<File> {
    if create_passwdfile {
        File::create(path)
    } else {
        OpenOptions::new().write(true).append(true).open(path)
    }
}

fn getpass(prompt: &str) -> String {
    println!("{}", prompt);
    match read_password() {
        Ok(password) => password,
        Err(failure) => panic!(failure.to_string()),
    }
}

fn get_password() -> String {
    let password = getpass("Enter password:");
    let confirmation = getpass("Re-enter password:");
    if password == confirmation {
        password
    } else {
        panic!("Passwords do not match")
    }
}

fn append_to_passwdfile(file: &mut File, username: String, realm: String, password: String) {
    let hashed = Digest::simple_hashed_a1(&HashAlgorithm::MD5,
                                           Username::Plain(username.clone()),
                                           realm.clone(),
                                           password);
    match write!(file, "{}:{}:{}\n", username, realm, hashed) {
        Err(failure) => panic!(failure.to_string()),
        _ => (),
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optflag("h", "help", "print this help menu");
    opts.optflag("c",
                 "",
                 "Create the passwdfile. If passwdfile already exists, it is deleted first.");

    let matches = match opts.parse(&args[1..]) {
        Ok(opt) => opt,
        Err(failure) => panic!(failure.to_string()),
    };

    if matches.opt_present("h") {
        print_usage(&program, opts);
        return;
    }

    let create_passwdfile = matches.opt_present("c");

    if matches.free.len() >= 3 {
        let passwdfile_path = matches.free[0].clone();
        let realm = matches.free[1].clone();
        let username = matches.free[2].clone();
        match open_passwdfile(passwdfile_path, create_passwdfile) {
            Ok(mut passwdfile) => {
                append_to_passwdfile(&mut passwdfile, username, realm, get_password())
            }
            Err(failure) => panic!(failure.to_string()),
        }
    } else {
        print_usage(&program, opts);
        return;
    };
}
