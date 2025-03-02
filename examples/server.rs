// Copyright (c) 2016, 2017, 2025 Mark Lee
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

use axum::{
    Router,
    body::Body,
    extract::Request,
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::get,
};
use guardhaus::digest::{Digest, Username};
use headers::authorization::Credentials;

const USERNAME: &str = "Spy";
const PASSWORD: &str = "vs. Spy";
// const REALM: &'static str = "MadMag";

async fn auth(headers: HeaderMap, request: Request, next: Next) -> Result<Response, StatusCode> {
    if let Some(auth) = headers.get(http::header::AUTHORIZATION) {
        if let Some(digest) = Digest::decode(auth) {
            let username = Username::Plain(USERNAME.to_owned());
            let password = PASSWORD.to_owned();
            let method = request.method().clone();
            let (parts, body) = request.into_parts();
            let bytes: Vec<u8> = match axum::body::to_bytes(body, usize::MAX).await {
                Ok(b) => b.to_vec(),
                Err(_) => return Err(StatusCode::PAYLOAD_TOO_LARGE),
            };
            let data: Vec<u8> = bytes.to_vec();
            if digest.validate_using_userhash_and_password(method, &data, username, password) {
                let req = Request::from_parts(parts, Body::from(bytes));
                let response = next.run(req).await;
                Ok(response)
            } else {
                Err(StatusCode::FORBIDDEN)
            }
        } else {
            Err(StatusCode::BAD_REQUEST)
        }
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

#[tokio::main]
async fn main() {
    // build our application with a single route
    let app = Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .route_layer(middleware::from_fn(auth));

    // run our app, listening globally on port 1337
    let listener = tokio::net::TcpListener::bind("0.0.0.0:1337").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
