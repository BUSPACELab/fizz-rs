# Fizz-rs

[![build](https://github.com/BUSPACELab/fizz-rs-dev/actions/workflows/ci.yml/badge.svg)](https://github.com/BUSPACELab/fizz-rs-dev/actions/workflows/ci.yml)

Rust FFI bindings for delegated credentials (DC) TLS with Fizz.

## Certificate and Keys

The underlying private key and SSL certificate must be explicitly configured to support delegated credentials (DC) at generation time.

We provide a `generate_certificate.sh` that generates a self-signed testing certificate with DC enabled.

Be sure to run the script to generate the testing certificate before running the example.
```bash
./generate_certificate.sh
cargo run --example generate_credential
```

### Dependencies

These dependencies need to be installed system-wide:

* [fizz](https://github.com/facebookincubator/fizz/): We used commit 2ba698d08cf0d42f4cfcb0a076e8a1ee8f3b8217, and added it as a gitsubmodule under `third_party/fizz/`.
* [folly](https://github.com/facebook/folly)
* glog, fmt
* libsodium, OpenSSL, libevent, and all other transitive dependencies of folly

We include building fizz, folly, and most of their dependencies in our `build.rs` workflow. However, in the interest of keeping
build time short, we configure fizz to rely on a few system-wide dependencies for popular libraries (specifically, libsodium, libevent, and a handful of others).

To ensure these dependencies are installed, please use the following command:
```bash
# Make sure you pull our submodules
git submodule init && git submodule update
# Install system-wide dependencies
cd third_party/fizz
python3 build/fbcode_builder/getdeps.py --allow-system-packages install-system-deps --recursive fizz
```

You only need to do this once. After which, `cargo build` and similar commands will be enough.

To confirm that everything is correct, run these commands:
```bash
cargo build  # tests that fizz can be built and the include paths are set correctly.
cargo test   # runs our tests and ensures the bridge is linked correctly
cargo run --example generate_credential  # runs an end-to-end delegated credentials workflow
```

### Notes

We used `-Wl,-rpath` to make sure that the generated binaries and tests can see `libglog.so.0`. This may not work
consistently when using this library as a transitive dependency with other cargo projects.

You may need to ensure that `LD_LIBRARY_PATH` is configured such that `libglog.so.0` is visible. You can find the exact version (or, retrieve and install the so yourself) by looking at 
`target/debug/build/fizz_rs-<hash>/out/fizz-install/installed/glog-<hash>/lib`.

## Demo

The demo directly contains a demo of an end to end flow using fizz_rs for delegated credentials.

First run the sidecar to generate the delegated credential and verification info at `/tmp/fizz_server.json` and `/tmp/fizz_client.json`
```bash
cd demo/fizz-sidecar
bazel run :sidecar
```

Then, run the server and client, which use the delegated credentials to do a TLS handshake.
```bash
cd /demo/fizz-rs
cargo run --bin server
# in a different terminal
cargo run --bin client
```
