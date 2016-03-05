#!/bin/bash

set -e

# Mostly from https://github.com/japaric/rust-everywhere
# Load the correct rust if it's not already there

case $TARGET in
  # Install standard libraries needed for cross compilation
  arm-unknown-linux-gnueabihf | \
  i686-apple-darwin | \
  i686-unknown-linux-gnu | \
  x86_64-unknown-linux-musl)
    if test "$TRAVIS_RUST_VERSION" = "stable"; then
        # e.g. 1.6.0
        version=$(rustc -V | cut -d' ' -f2)
    else
        version=$TRAVIS_RUST_VERSION
    fi
    tarball=rust-std-${version}-${TARGET}

    curl -Os http://static.rust-lang.org/dist/${tarball}.tar.gz

    tar xzf ${tarball}.tar.gz

    ${tarball}/install.sh --prefix=$(rustc --print sysroot)

    rm -r ${tarball}
    rm ${tarball}.tar.gz
    ;;
  # Nothing to do for native builds
  *) ;;
esac
