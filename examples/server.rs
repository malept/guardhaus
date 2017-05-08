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

extern crate guardhaus;
extern crate hyper;

use guardhaus::digest::{Digest, Username};
use hyper::header::Authorization;
use hyper::server::{Request, Response, Server};
use hyper::status::StatusCode;
use std::io::Read;

const LISTEN: &'static str = "127.0.0.1:1337";
const USERNAME: &'static str = "Spy";
const PASSWORD: &'static str = "vs. Spy";
// const REALM: &'static str = "MadMag";

fn needs_auth(mut req: Request, mut resp: Response) {
    let mut entity_body = String::new();
    if req.read_to_string(&mut entity_body).is_err() {
        *resp.status_mut() = StatusCode::BadRequest;
        return;
    }
    if let Some(auth) = req.headers.get::<Authorization<Digest>>() {
        let username = Username::Plain(USERNAME.to_owned());
        let password = PASSWORD.to_owned();
        if auth.0
               .validate_using_userhash_and_password(req.method,
                                                     entity_body,
                                                     username,
                                                     password) {
            *resp.status_mut() = StatusCode::Ok;
        } else {
            *resp.status_mut() = StatusCode::Forbidden;
        }
    } else {
        *resp.status_mut() = StatusCode::Unauthorized;
    }
}

fn main() {
    let server = Server::http(LISTEN).expect("Could not create HTTP server");
    let _guard = server.handle(needs_auth);
    println!("Listening on {}", LISTEN);
}
