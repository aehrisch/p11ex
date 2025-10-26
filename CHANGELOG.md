# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- p11ex_cli: Add sub command `bench-aes-encrypt-block`.
- p11ex_cli: Also read token label from environment variable `P11EX_TOKEN_LABEL`.

### Fixed

- p11ex: Make search for slot by label more robust.
- p11ex_cli: Fix error message if AES key generation is not supported.
- p11ex_cli: Fix error messages in case slot can't be found.
- p11ex_cli: Read attributes carefully, increase compatibility.

## [0.3.0] - 2025-10-25

### Added

- Add `key-wrap` and `key-unwrap` commands to `p11ex_cli`.
- Add `kcv-gen` command to `p11ex_cli` to compute the fingerprint of secret keys .
