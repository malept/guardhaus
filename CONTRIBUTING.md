# Contributing to Guardhaus

Guardhaus is a part of the Rust ecosystem. As such, all contributions to this project follow the
[Rust language's code of conduct](https://www.rust-lang.org/conduct.html) where appropriate.

This project is hosted at [GitHub](https://github.com/malept/guardhaus). Both pull requests and
issues of many different kinds are accepted.

## Filing Issues

Issues include bugs, questions, feedback, and feature requests. Before you file a new issue, please
make sure that your issue has not already been filed by someone else.

### Filing Bugs

When filing a bug, please include the following information:

* Operating system and version. If on Linux, please also include the distribution name.
* System architecture. Examples include: x86-64, x86, and ARMv7.
* Rust version that compiled Guardhaus.
* The version (and/or git revision) of Guardhaus.
* A detailed list of steps to reproduce the bug. A minimal testcase would be very helpful,
  if possible.
* If there any any error messages in the console, copying them in the bug summary will be
  very helpful.

## Finding a change to make

Want to contribute? Find an issue that fits your skillset.

## Filing Pull Requests

Please make sure your pull requests pass the continuous integration suite, by running `cargo test`
before creating your submission. The CI suite is also automatically run for every pull request.

Additionally, please make sure any code changes pass
[clippy](https://github.com/Manishearth/rust-clippy)'s linting and
[rustfmt](https://github.com/rust-lang-nursery/rustfmt)'s formatting rules. To run clippy:

```shell
cargo clippy --verbose --features=lint -- -Wclippy_pedantic
```
