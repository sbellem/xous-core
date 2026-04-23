# ethapp — production readiness assessment

**Status:** Developer preview / alpha. Not production-ready.
**Target hardware:** Baochip-1x (BAO1X2S4F-WA) running Xous OS.
**Companion tool:** `tools/ethcli` (host-side CLI over USB CDC-ACM serial).

**Board strategy decision (2026-04-20):** The current dabao development board
has no display. A hardware wallet without a trusted display cannot provide
hardware-wallet-grade security. Therefore:
- **dabao**: dev-only / testnet-only. Built with `dev-mode` + `autoapprove`.
  Firmware enforces a mainnet chain-ID guard that refuses to sign on
  Ethereum mainnet and major L2s (chain IDs 1, 10, 56, 137, 8453, 42161,
  etc.) to prevent accidental real-fund losses.
- **baosec** (or equivalent display-equipped board): production target. The
  GAM display integration (currently TODO stubs in `platform.rs`) will be
  wired up for this board class, completing the trusted-display path.

This document summarizes the current state of the Ethereum hardware-wallet
implementation, what works, and what's required before it could safely hold
real funds. It is intended to be honest about gaps — not a marketing piece.

The core architecture (untrusted host, trusted display, never-export keys)
is correct and matches every production hardware wallet. The cryptographic
primitives are solid. The single biggest gap is that the device's trusted
display is not yet wired up on real hardware, which currently invalidates
the security model.

---

## Architecture overview

```
┌────────── HOST (untrusted) ──────────┐    ┌──── DEVICE (trusted) ────┐
│                                       │    │                          │
│  ethcli (Rust CLI)                    │    │  ethapp (Xous service)   │
│   - clap subcommands                  │    │   - secp256k1 signing    │
│   - JSON-RPC client (chain queries,   │    │   - BIP32/BIP44 derive   │
│     broadcast)                        │    │   - tx parsing           │
│   - Builds unsigned RLP               │───▶│   - displays + confirms  │
│                                       │    │     on trusted screen    │
│                                       │◀───│   - returns v,r,s        │
│  Combines sig + tx, broadcasts        │    │                          │
└───────────────────────────────────────┘    └──────────────────────────┘
       USB CDC-ACM serial, 0xE7-framed binary protocol
```

- **Host** (`tools/ethcli`): standalone Rust workspace, talks to device over
  USB CDC-ACM with a 0xE7 magic-byte framed protocol. Constructs unsigned
  transactions, queries chain state via JSON-RPC, broadcasts signed txs.
- **Device** (`services/ethapp`): Xous-native service, registered as
  `ethapp.ethereum`. Receives requests via Xous IPC and via the serial
  frame dispatcher (in `services/usb-bao1x`). Holds the seed, derives
  keys, signs after on-device user confirmation.
- **Concurrency with text console**: `0xE7` frames are siphoned off in
  `usb-bao1x`'s `ConsoleListener`; non-`0xE7` bytes still flow to the
  text console keyboard injection, so `tio` and `ethcli` work in parallel.

---

## What's working

### Device firmware

- **Key derivation**: BIP32/BIP44 hierarchical, constant-time `k256` +
  `bip32` crates. Standard Ethereum path `m/44'/60'/account'/change/index`.
- **Seed lifecycle**:
  - Import 12/24-word BIP39 mnemonic (PBKDF2-HMAC-SHA512, 2048 rounds)
  - Import raw 64-byte seed
  - **Generate** new 24-word mnemonic from hardware TRNG with SHA-256
    checksum, derive seed (added during this iteration)
  - **Wipe** seed from memory + storage (added during this iteration)
  - All seed material wrapped in `Zeroize` / `ZeroizeOnDrop`
- **Transaction signing**: all 3 major Ethereum tx types
  - Legacy EIP-155 (with chain-ID-derived `v`)
  - EIP-2930 typed (access list)
  - EIP-1559 typed (fee market)
- **Message signing**: EIP-191 personal messages, EIP-712 typed data
  (both pre-hashed and structured)
- **PDDB persistent seed storage**: plumbed through `XousPlatform`
  (encrypted at rest, plausibly-deniable). Optional `pddb` Cargo feature;
  **not yet enabled in default xtask builds**.
- **IPC API** (`libs/ethapp-api`): typed client with rkyv serialization.
- **Integration tests**: `apps-dabao/ethapp-test` runs ~12 self-checks
  with `dev-mode` + `autoapprove` features.
- **Recent audit fixes** applied in commit `bd293f21e`.

### Transport layer

- USB CDC-ACM serial with 0xE7 magic-byte frame protocol
  - Wire format: `[0xE7] [len: u16 LE] [opcode: u8] [payload...]`
  - `usb-bao1x` intercepts frames in `ConsoleListener`, forwards to
    ethapp via the new `SerialFrame = 0x70` opcode (carrying
    `SerialFrameData { data: Vec<u8> }`)
  - State machine handles frames spanning multiple USB interrupts
  - Lazy IPC connection on first frame
- Coexists with text console (non-0xE7 bytes go to keyboard injection)

### Host CLI (`tools/ethcli`)

Standalone workspace, builds with `cargo build --release` or `nix build .#ethcli`.

| Command | Purpose | Needs device | Needs RPC |
|---|---|---|---|
| `ping` | health check | yes | no |
| `config` | device info | yes | no |
| `address [--index N]` | derive address | yes | no |
| `accounts [--count N]` | list addresses | yes | no |
| `generate-mnemonic` | new wallet (24 words on device screen) | yes | no |
| `import-mnemonic` | restore wallet (interactive prompt) | yes | no |
| `clear-seed` | wipe wallet | yes | no |
| `sign-message <msg>` | EIP-191 sign | yes | no |
| `sign-tx <rlp-hex>` | sign + emit broadcastable RLP | yes | no |
| `gen-tx <to> <wei>` | build + sign + emit | yes | no |
| `build-tx <to> <wei>` | offline unsigned RLP only | **no** | no |
| `tx-info --rpc-url URL` | nonce, gas, fees, balance | yes (for addr) | yes |
| `publish <hex> --rpc-url URL` | broadcast (alias: `broadcast`) | **no** | yes |

Three workflows are supported:

1. **Online all-in-one**: `tx-info` → `gen-tx` → `publish`
2. **Air-gapped**: `build-tx` (offline machine) → transfer hex →
   `sign-tx` (device-connected machine) → `publish` (online machine)
3. **Manual**: `sign-tx` with externally-built RLP

JSON-RPC client uses `ureq` + `rustls` (no system deps beyond libudev for
`serialport` USB enumeration on Linux).

### Build / packaging

- Nix flake at repo root:
  - `xous-build dabao ethapp-test --no-verify` → device firmware
  - `nix build .#dabao-helloworld`, `.#baosec`, `.#bao1x-boot0` etc. → device packages
  - `nix build .#ethcli` → host CLI
- Reproducible builds (vendored deps via Nix FOD, deterministic flags)
- `devShells.default` and `devShells.container` include `pkg-config` +
  `systemd` (libudev) on Linux for ethcli's `serialport`

---

## Critical gaps (security blockers)

These must be fixed before the wallet can hold real funds.

### C1. Trusted display not implemented on hardware

**Severity: critical — invalidates the entire security model.**

`services/ethapp/src/platform.rs` lines 167–217: `confirm_action` and
`show_transaction_review` are TODO stubs. They return
`Err(EthAppError::UiError)` unless the `autoapprove` Cargo feature is on
(which is documented as INSECURE).

Consequence:
- Without `autoapprove`: signing fails on real hardware (no user confirm)
- With `autoapprove`: device blindly signs anything the host sends

The on-device trusted display is the entire point of a hardware wallet.
Without it, the device is no more secure than a hot wallet running on a
compromised laptop. **This is the highest-priority item.**

### C2. Token metadata accepted unverified (CRITICAL-04)

`handle_provide_erc20_token_info` in `handlers.rs` caches token info
(ticker, decimals) with no signature verification. An attacker can claim
"this contract is USDC with 6 decimals" and the device will display the
fake ticker during signing. Currently flagged with `[UNVERIFIED]` prefix
in the displayed string, but the metadata is still cached and used.

Required: ECDSA verification of metadata against a trusted publisher key
(matching Ledger's signed metadata model).

### C3. No firmware authenticity / device attestation

- User has no way to verify the firmware running on the device is the real
  ethapp and not a compromised version.
- The `GetChallenge` opcode exists but no host-side pairing flow uses it.
- No anti-rollback for firmware updates.
- No secure-boot chain to a hardware root of trust on Baochip-1x.

Required: signed firmware images, host-side attestation challenge on
first connection, device key embedded at provisioning, host verifies
attestation against a vendor public key.

### C4. No PIN / passphrase protection

- Wallet unlock relies on PDDB unlock, which is system-wide and not
  wallet-specific. Anyone with physical access who knows the PDDB
  password gets the seed.
- No BIP39 passphrase ("25th word") support — major missing feature for
  plausible deniability and hot/cold wallet separation on the same device.
- No per-action PIN prompt for high-value transactions.

### C5. Side-channel and physical security unaddressed

- Code uses constant-time crypto primitives but no formal side-channel
  analysis has been performed.
- Baochip-1x is a general-purpose chip, not a certified secure element.
  Power analysis (SPA/DPA), EM emissions, voltage glitching, fault
  injection, and clock glitching all need evaluation.
- No tamper detection (case opening, voltage anomalies).
- No physical countermeasures equivalent to a Common Criteria EAL-5+
  secure element (which Ledger's ST33 provides).

### C6. Mnemonic backup verification is weak

After `generate-mnemonic`, the device shows the words and asks "have you
written them down?". User can press Yes without actually copying anything
and lose funds permanently. Real wallets enforce a verification quiz
(e.g. "what was word 12?" "what was word 23?") before considering the
backup confirmed.

---

## Important functional gaps

### F1. ethcli only builds legacy EIP-155 transactions

The device signs all 3 tx types, but `gen-tx` and `build-tx` only emit
legacy. Mainnet has been EIP-1559 since 2021; legacy is increasingly
rejected. Need a `--type 1559` flag or separate command that takes
`--max-fee` / `--priority-fee` and constructs the typed RLP.

### F2. No clear signing for contracts

Contract calls (ERC-20 transfers, swaps, approvals, etc.) display as raw
calldata `0xa9059cbb...` which users cannot meaningfully verify. Need:
- ABI database / 4byte.directory mirror, or vendor-signed ABI metadata
- Device-side decoder for known patterns
- ENS resolution on host with on-device confirmation of the resolved
  raw address

### F3. PDDB feature not enabled in default builds

`pddb = { ..., optional = true }` in `services/ethapp/Cargo.toml`.
Currently `xous-build dabao ethapp-test` does not pass
`--features ethapp/pddb`. Without it, the seed is in-memory only and
lost on reboot. Need to add the feature to xtask's auto-feature
injection for relevant targets.

### F4. EIP-712 has no host-side helper

Device signs full EIP-712 typed data, but `ethcli` has no
`sign-typed-data` command or JSON-spec parser. Common in DeFi flows
(Permit2, OpenSea orders, Snapshot voting).

### F5. No xpub export

Read-only "watching wallet" support requires exporting an extended
public key (xpub) so wallets like Sparrow / Frame can monitor balances
without the seed. Currently only bare addresses are exported.

### F6. No multi-account UX

Each `--index N` is independent; no concept of named accounts, account
discovery, or default account. PDDB could store labels.

---

## Operational and polish gaps

### O1. ethcli `Cargo.lock` not committed

`nix build .#ethcli` requires `services/ethapp/tools/ethcli/Cargo.lock`
to exist. Currently not committed because dev environment had no
network. Action: run `cargo build --release` once on a connected
machine, then commit the lock file.

### O2. No CI

Tests should run on every commit (unit, integration, lints, fmt).

### O3. No release artifacts

Need cross-platform host binaries (Linux/macOS/Windows) signed for
distribution. Need device firmware images produced reproducibly.

### O4. No external security audit

Production hardware wallets get reviewed by independent firms (e.g.
Trail of Bits, Cure53, NCC). The internal audit fixes in
`bd293f21e` are a good start but external eyes are required.

### O5. No documentation

- No threat model document
- No user-facing setup / recovery / troubleshooting guide
- No security model documentation for reviewers
- No reproducible-build instructions for users to verify their firmware

### O6. UX rough edges

- Status codes shown as raw bytes (`status: 0x03`) instead of friendly
  messages (`"no seed loaded"`)
- CLI only — no GUI; limits adoption
- No first-boot setup wizard

### O7. Recovery paths missing

- No recovery mode for bricked devices
- No factory reset firmware path
- No firmware update / rollback story

---

## Prioritized roadmap to production

### P0 — security blockers (must complete before any real-money use)

1. **Wire up real GAM display** in `platform.rs` — `confirm_action`,
   `show_transaction_review`, mnemonic display screens. Replace TODO
   stubs with actual modal calls. Without this, nothing else matters.
2. **Enable `pddb` feature** in xtask default build for production
   targets (so the seed actually persists across reboots).
3. **Implement signed firmware** + secure boot on Baochip-1x.
4. **Implement host pairing** using the existing `GetChallenge` opcode:
   first-connection device attestation, host stores the device's
   pairing key, mutual verification on subsequent connections.
5. **Implement metadata signature verification** (CRITICAL-04): ECDSA
   verification against a trusted publisher key before accepting any
   token / NFT / domain / method metadata.

### P1 — functional must-haves

6. **Mnemonic verification quiz** flow after `generate-mnemonic`.
7. **BIP39 passphrase** support (25th word).
8. **PIN-on-device** protection (in addition to PDDB unlock).
9. **EIP-1559 builder** in `ethcli` (`gen-tx --type 1559 --max-fee ... --priority-fee ...`).
10. **Clear signing** for ERC-20 transfer/approve, common DeFi calls.

### P2 — production polish

11. **External security audit** — at least one independent firm.
12. **Side-channel analysis** on Baochip-1x: power, EM, glitching.
13. **Tamper detection** (if Baochip hardware supports it).
14. **Documentation suite**: threat model, user guide, recovery,
    reproducible-build instructions.
15. **CI/CD**: tests on every commit, signed release artifacts.
16. **GUI / wallet integration**: MetaMask Snap, Frame integration,
    or first-party Tauri/Electron app.

### P3 — nice-to-have

17. xpub export for watch-only wallets
18. Address book / labels in PDDB
19. Multi-language device UI
20. Mobile companion app

---

## Honest summary

**What you have**: a well-architected developer preview where the
cryptographic core is solid, host/device separation is correct, and the
end-to-end sign-and-broadcast flow works in an emulator. Code quality
is reasonable, the build is reproducible, and the security model
matches industry standards.

**What you don't have**: anything resembling production. The single
most important feature of a hardware wallet — the trusted display
showing what the user is signing — is **not implemented** on real
hardware. Without that (C1), the device is functionally a hot wallet
with extra steps. Beyond that, the metadata-spoofing vulnerability
(C2), lack of firmware attestation (C3), and absence of an external
audit (O4) each individually disqualify the product from holding
non-trivial funds.

**Realistic positioning**:

- **Today**: suitable for CTF/research, internal team tooling,
  developer experimentation, teaching examples, and bench testing.
- **After P0**: usable for personal testnet/small-balance experiments
  with informed users.
- **After P0 + P1**: alpha-tier product; testnet only or invitation-only
  pilot.
- **After P0 + P1 + P2**: beta-tier product; could begin a public
  bug-bounty phase.
- **Production claim** requires: external audit pass, side-channel
  analysis, manufacturing process security, and ideally a track record
  of resolved bounty findings.

The host-side `ethcli` is in better shape than the device side and
could be released independently as a generic Ethereum CLI / RPC tool
without the hardware-wallet positioning.

---

*Last updated alongside the work in branch `ethapp-origins` (commits
`f0c83a682` through `f9a6fba0f0`).*
