#!/bin/bash

set -e

# load travis-cargo
pip install 'travis-cargo<0.2' --user

if test "$TRAVIS_RUST_VERSION" = "nightly"; then
    if ! cargo --list | grep -q clippy; then
        cargo install --git=https://github.com/arcnmx/cargo-clippy
    fi
fi
