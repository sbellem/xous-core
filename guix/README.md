# Guix Quickstart for Baochip Firmware

All Guix commands are driven by `make -C guix` from the repo root,
or `make` from this directory.

## Development Shell

    make -C guix shell

Or manually:

    guix time-machine -C channels.scm -- shell -L guix -m manifest.scm

## Offline Container Shell

    guix time-machine -C channels.scm -- shell --container -L guix -m manifest.scm

Inside the container:

    xous-vendor-setup
    xous-build dabao helloworld --no-verify

`xous-vendor-setup` copies the vendored cargo config into `.cargo/`.
`xous-build` wraps `cargo xtask` with `--config`, `--git-describe`, and
`--git-rev` flags.

## Building Firmware (Guix packages)

    make -C guix boot0
    make -C guix dabao
    make -C guix firmware          # all targets at once

## Offline Development (regular shell)

    make -C guix vendor-setup

Then:

    xous-build dabao helloworld --no-verify

Or without the wrapper:

    cargo xtask dabao helloworld --config .cargo/vendor-config.toml --no-verify

Remove vendored config:

    make -C guix vendor-clean

Guix package builds (`make -C guix boot0` etc.) are unaffected — they use
their own sandboxed vendoring.

## Available Targets

| Package | Makefile |
|---------|----------|
| `bao1x-boot0` | `make boot0` |
| `bao1x-boot1` | `make boot1` |
| `bao1x-alt-boot1` | `make alt-boot1` |
| `bao1x-baremetal-dabao` | `make baremetal-dabao` |
| `dabao` | `make dabao` |
| `dabao-helloworld` | `make dabao-helloworld` |
| `dabao-ethapp` | `make dabao-ethapp` |
| `baosec` | `make baosec` |
| `bootloader` | `make bootloader` |
| `ethcli` | `make ethcli` |

## Options

    make -C guix boot0 DRY=1            # dry-run
    make -C guix boot0 SUBS=baobit      # baobit substitutes only
    make -C guix boot0 SUBS=none        # build from source
    make -C guix boot0 ROOT=boot0       # create GC root
    make -C guix boot0 CHECK=1          # verify reproducibility

Substitute presets: `all` (default), `official`, `baobit`, `community`, `none`.

## Channel Pinning

`channels.scm` (at repo root) pins the guix and baobit channels to specific
commits. To update, change the commit hashes in that file.

The baobit channel (`github.com/sbellem/baobit`) provides the Rust toolchain
(`rust-xous-toolchain`) with cross-compilation support for RISC-V targets.

## File Layout

    channels.scm            # Pin guix + baobit channels
    manifest.scm            # Dev shell packages (toolchain, vendor setup, ...)
    guix/
      Makefile               # Build orchestration
      bao.scm                # Firmware package definitions (shared with baobit)
      bao-crates.scm         # Crate + git dependency origins (shared with baobit)
      bao-config.scm         # Dev config (local-file source, git-describe version)
      ethcli.scm              # Host CLI package (ethcli)
      bao-vendor.scm         # Offline vendor packages (xous-vendor-deps, xous-vendor-setup, xous-build)
      firmware-manifest.scm  # All firmware packages for `make firmware`

`bao.scm` and `bao-crates.scm` are identical to baobit. The only difference
is `bao-config.scm`: dev uses `local-file` + live git; prod uses `git-fetch`
with pinned commits.
