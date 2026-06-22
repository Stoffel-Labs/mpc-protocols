# FFI module for Stoffel MPC

# Quick Start

The Rust crate is named `stoffelcrypto`; release builds produce the static and dynamic libraries used by the C examples.

###  Install cbindgen
```text
cargo install --force cbindgen
```

### Create header file for binding
```text
cbindgen --config ./mpc/src/ffi/c_bindings/cbindgen.toml --crate stoffelcrypto --output ./mpc/src/ffi/honey_badger_bindings.h
```

### Compile Rust codes
```text
cargo build -r
```
This creates `.a` and `.so`/`.dylib` files for `stoffelcrypto` in `./target/release/` (`./target/debug/` if running `cargo build`).

### Compile and run C test codes
```text
gcc ./mpc/src/ffi/tests/secret_share.c -L target/release -lstoffelcrypto -o ./mpc/src/ffi/share_test
gcc ./mpc/src/ffi/tests/rbc_test.c -L target/release -lstoffelcrypto -o ./mpc/src/ffi/rbc_test
gcc ./mpc/src/ffi/tests/network_test.c -L target/release -lstoffelcrypto -o ./mpc/src/ffi/network_test
```
```text
./mpc/src/ffi/share_test
./mpc/src/ffi/rbc_test
./mpc/src/ffi/network_test
```

