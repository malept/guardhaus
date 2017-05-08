#!/bin/bash

set -e

# load travis-cargo
pip install 'travis-cargo<0.2' --user

if test "$TRAVIS_RUST_VERSION" = "nightly"; then
    cargo install --force clippy
fi
