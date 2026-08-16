# ckb-system-scripts

[![Build Status](https://github.com/nervosnetwork/ckb-system-scripts/workflows/CI/badge.svg)](https://github.com/nervosnetwork/ckb-system-scripts/actions)
[![Crates.io](https://img.shields.io/crates/v/ckb-system-scripts)](https://crates.io/crates/ckb-system-scripts)

CKB's system scripts, which included in the system cells in the genesis block.

## Quick Start

The on-chain scripts live in `contracts/system-scripts` and are written in
Rust (targeting `riscv64imac-unknown-none-elf`). Build them, then run the
test suite:

```
make prepare
make build
make test
```

`make prepare` installs the RISC-V target (it is also listed in
`rust-toolchain.toml`), `make build` compiles the scripts into
`specs/cells`, and `make test` runs `cargo test`.

## Release

Tag and publish the release. GitHub Actions will publish the crate.
