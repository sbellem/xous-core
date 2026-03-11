# Guix Quickstart for Baochip Firmware

## Development Shell

Enter a reproducible dev shell with pinned channels:

    guix time-machine -C channels.scm -- shell -m manifest.scm

Then build firmware:

    cargo xtask dabao helloworld --no-verify

## Building Packages

Build a specific target (from repo root):

    guix time-machine -C channels.scm -- build -L guix -e '(@ (bao) bao1x-boot0)'

## Available Targets

| Package |
|---------|
| `bao1x-boot0` |
| `bao1x-boot1` |
| `bao1x-alt-boot1` |
| `bao1x-baremetal-dabao` |
| `dabao` |
| `dabao-helloworld` |
| `baosec` |
| `bootloader` |

## Channel Pinning

`channels.scm` (at repo root) pins the guix and baobit channels to specific commits.
To update, change the commit hashes in that file.

The baobit channel (`github.com/sbellem/baobit`) provides the Rust toolchain
(`rust-xous-toolchain`) with cross-compilation support for RISC-V targets.
