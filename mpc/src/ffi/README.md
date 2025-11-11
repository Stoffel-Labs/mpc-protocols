# ffi module for mpc

# Quick Start
//TODO - we can also inclue cbindgen in build.rs, so it will automatically generate .h file when running `cargo build`.
###  Install cbindgen
```text
cargo install --force cbindgen
```

### Create header file for binding
```text
cbindgen --config ./mpc/src/ffi/c_bindings/cbindgen.toml --crate stoffelmpc-mpc --output ./mpc/src/ffi/shamirshare.h
```

### Compile Rust codes
```text
cargo build -r
```
This should also create .a and .so/.dylib files for stoffelmpc in `./target/release/`. (in `./target/debug/` if running `cargo build`)

### Compile and run C test codes
```text
gcc ./mpc/src/ffi/tests/secret_share.c -L target/release -lstoffelmpc_mpc -o ./mpc/src/ffi/share_test
gcc ./mpc/src/ffi/tests/rbc_test.c -L target/release -lstoffelmpc_mpc -o ./mpc/src/ffi/rbc_test   
```
```text
./mpc/src/ffi/share_test
./mpc/src/ffi/rbc_test  
```

