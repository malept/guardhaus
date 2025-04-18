# Guardhaus

[![CI Status](https://github.com/malept/guardhaus/workflows/CI/badge.svg?branch=main)](https://github.com/malept/guardhaus/actions?query=workflow%3ACI)
[![Coverage Status](https://codecov.io/gh/malept/guardhaus/graph/badge.svg?token=dtyMhcbE2w)](https://codecov.io/gh/malept/guardhaus)

Guardhaus is an HTTP authentication/authorization library, written in Rust.

## Features

* Support for HTTP digest authentication via the `Authorization` header (as specified in
  [RFC 7616](https://tools.ietf.org/html/rfc7616)) for the [`headers`](https://docs.rs/headers) crate
* Support for the HTTP `Authentication-Info` header (as specified in
  [RFC 7616, section 3.5](https://tools.ietf.org/html/rfc7616#section-3.5)) for the `headers` crate

## Usage

Requires Rust ≥ 1.85.0 (2024 edition).

Add `guardhaus` to your project's `Cargo.toml`. For more details, consult the
[Cargo guide](http://doc.crates.io/guide.html#adding-dependencies).

## Legal

Guardhaus is copyrighted under the terms of the MIT license. See LICENSE for details.
