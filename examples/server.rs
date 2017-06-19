// Copyright (c) 2016, 2017 Mark Lee
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

extern crate futures;
extern crate guardhaus;
extern crate hyper;

use futures::{Future, Stream};
use futures::future::FutureResult;
use guardhaus::digest::{Digest, Username};
use hyper::header::Authorization;
use hyper::server::{Http, Request, Response, Service};
use hyper::StatusCode;

const LISTEN: &'static str = "127.0.0.1:1337";
const USERNAME: &'static str = "Spy";
const PASSWORD: &'static str = "vs. Spy";
// const REALM: &'static str = "MadMag";

#[derive(Clone, Copy)]
struct AuthEndpoint;

impl Service for AuthEndpoint {
    type Request = Request;
    type Response = Response;
    type Error = hyper::Error;
    type Future = FutureResult<Response, hyper::Error>;

    fn call(&self, req: Request) -> Self::Future {
        let mut response = Response::new();
        let headers = req.headers().clone();
        if let Some(auth) = headers.get::<Authorization<Digest>>() {
            let username = Username::Plain(USERNAME.to_owned());
            let password = PASSWORD.to_owned();
            let method = req.method().clone();
            let entity_body = req.body().concat2().wait().unwrap().to_vec().clone();
            if auth.0.validate_using_userhash_and_password(
                method,
                entity_body.as_slice(),
                username,
                password,
            )
            {
                response.set_status(StatusCode::Ok);
            } else {
                response.set_status(StatusCode::Forbidden);
            }
        } else {
            response.set_status(StatusCode::Unauthorized);
        }
        futures::future::ok(response)
    }
}

fn main() {
    let server = Http::new()
        .bind(
            &LISTEN.parse().expect("Could not parse listen address"),
            || Ok(AuthEndpoint),
        )
        .expect("Could not create HTTP server");
    server.run().expect("Could not run HTTP server");
    println!("Listening on {}", LISTEN);
}
