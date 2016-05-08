#!/bin/bash

set -e
# upload the documentation from the build with stable (automatically only actually
# runs on the master branch, not individual PRs)
if test "$TRAVIS_OS_NAME" = "linux"; then travis-cargo --only stable doc-upload; fi
# measure code coverage and upload to coveralls.io (the verify
# argument mitigates kcov crashes due to malformed debuginfo, at the
# cost of some speed <https://github.com/huonw/travis-cargo/issues/12>)
travis-cargo coveralls --no-sudo --verify --exclude-pattern=/test.rs
