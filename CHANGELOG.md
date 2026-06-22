# Changelog

All notable changes to this project will be documented in this file.

This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-06-22

Initial crates.io release of the Stoffel MPC protocol workspace.

### Published crates

- `stoffelcrypto` 0.1.0
- `stoffelmpc-network` 0.1.0

### Added

- Asynchronous HoneyBadgerMPC protocol implementation with preprocessing, Beaver triples, random sharing, distributed input/output, robust interpolation, batch reconstruction, and fixed-point arithmetic support.
- `stoffelcrypto` Rust library, static library, and dynamic library outputs for Rust and FFI consumers.
- `stoffelmpc-network` internal network adapters and deterministic fake/simulation networking used by the MPC test suite.
- Crates.io package metadata for release discoverability, including descriptions, Apache-2.0 licensing, repository/homepage links, documentation links, categories, and relevant search keywords.

### Changed

- Updated FFI documentation to use the published `stoffelcrypto` crate and library names.
- Added publish-ready version requirement for the `stoffelcrypto` dependency on `stoffelmpc-network` so packaging can resolve the internal workspace dependency.
- Centralized release metadata inherited from the workspace manifest.

### Fixed

- Release-gating clippy coverage for benches and tests by aligning manifest lint configuration with the crate's existing incremental cleanup policy.
- Minor benchmark clippy issues that blocked `cargo clippy --all-targets -- -D warnings`.

[0.1.0]: https://github.com/Stoffel-Labs/mpc-protocols/releases/tag/v0.1.0
