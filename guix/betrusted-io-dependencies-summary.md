# Betrusted-io Git Dependencies for Guix Rust Packaging

## Executive Summary

Based on extensive research, here are the key betrusted-io Rust dependencies that will need to be packaged for Guix when building xous-core.

---

## Confirmed Git Dependencies

### 1. curve25519-dalek (WORKSPACE - 4 crates)

| Field | Value |
|-------|-------|
| **Repository** | https://github.com/betrusted-io/curve25519-dalek |
| **Upstream** | dalek-cryptography/curve25519-dalek |
| **Type** | **WORKSPACE** |
| **Stars** | 8 |

**Workspace Members:**
1. `curve25519-dalek` - Core elliptic curve arithmetic
2. `curve25519-dalek-derive` - Helper macros
3. `ed25519-dalek` - EdDSA digital signatures
4. `x25519-dalek` - Diffie-Hellman key exchange

**Packaging Implication:** Single git checkout provides FOUR crates. Requires:
- One package definition with `#:cargo-package-crates '("curve25519-dalek" "curve25519-dalek-derive" "ed25519-dalek" "x25519-dalek")`
- Four alias definitions in rust-crates.scm pointing to the same package

---

### 2. ring-xous (Single Crate)

| Field | Value |
|-------|-------|
| **Repository** | https://github.com/betrusted-io/ring-xous |
| **Upstream** | briansmith/ring |
| **Type** | **Single crate** (heavily modified) |
| **Stars** | 12 |
| **Description** | Pure-Rust port of Ring for 32-bit embedded targets |

**Key Notes:**
- Fork uses c2rust transpilation for Xous target
- Contains custom `src/c2rust/` directory
- Named `ring-xous` (NOT `ring`)
- Currently pinned at 0.16.x, with ongoing 0.17 migration work

**Packaging Implication:** Standard single-crate package, but may have unusual build requirements due to c2rust code.

---

### 3. hashes (WORKSPACE - 24+ crates) - **NEEDS VERIFICATION**

| Field | Value |
|-------|-------|
| **Repository** | https://github.com/betrusted-io/hashes |
| **Upstream** | RustCrypto/hashes |
| **Type** | **WORKSPACE** (if exists) |

**Potential Workspace Members (from upstream):**
- sha1, sha2, sha3
- md2, md4, md5
- blake2
- ripemd
- groestl, jh, skein
- whirlpool, tiger
- And ~12 more...

**⚠️ VERIFICATION NEEDED:** Must confirm this fork exists and inspect its Cargo.toml to determine actual members.

---

### 4. usbd-serial (Single Crate)

| Field | Value |
|-------|-------|
| **Repository** | https://github.com/betrusted-io/usbd-serial |
| **Upstream** | rust-embedded-community/usbd-serial |
| **Type** | **Single crate** |
| **Description** | CDC-ACM USB serial port class for usb-device |

---

### 5. xous-usb-hid (Single Crate)

| Field | Value |
|-------|-------|
| **Repository** | https://github.com/betrusted-io/xous-usb-hid |
| **Upstream** | usbd-hid |
| **Type** | **Single crate** |
| **Description** | USB HID library for Xous (keyboard, mouse, joystick) |

**Key Notes:**
- Fork is NOT no_std compatible anymore
- Modified for xous-core specific needs

---

### 6. xous-semver (Single Crate)

| Field | Value |
|-------|-------|
| **Repository** | https://github.com/betrusted-io/xous-semver |
| **Upstream** | Original |
| **Type** | **Single crate** |
| **Description** | Compact semantic versioning utility |

---

### 7. engine25519-as (Single Crate) - **DEPRECATED**

| Field | Value |
|-------|-------|
| **Repository** | https://github.com/betrusted-io/engine25519-as |
| **Upstream** | Original |
| **Type** | **Single crate** |
| **License** | **GPL-3.0** ⚠️ |
| **Status** | **DEPRECATED** - functionality rolled into curve25519-dalek |

Per RELEASE-v0.9.md: "engine-25519 crate now removed from source tree, as it is now deprecated since all the functionality was pulled into curve25519-dalek."

---

## NOT Rust Dependencies (Excluded)

| Repository | Purpose |
|------------|---------|
| betrusted-io/rust | Rust compiler fork for riscv32imac-unknown-xous-elf target |
| betrusted-io/rust-nightly | Nightly Rust builds with Xous patches |
| betrusted-io/gateware | Verilog IP submodules |
| betrusted-io/betrusted-soc | Python/Verilog SoC design |
| betrusted-io/betrusted-ec | Embedded controller (UP5K) |
| betrusted-io/crate-scraper | Build tooling (Python script) |

---

## xous-core Architecture Notes

### Monorepo Structure
xous-core is itself a **massive Cargo workspace** containing:
- `kernel/` - Core kernel
- `libs/` - Device driver libraries  
- `services/` - Middleware services
- `apps/`, `apps-dabao/`, `apps-baosec/` - Applications
- `xous-rs/`, `xous-ipc/` - API crates
- `utralib/` - Hardware register abstraction

### Build System
- Uses `cargo xtask` custom orchestration
- Verification mechanism checks crates.io deps match local versions
- Developers patch in root Cargo.toml and use `--no-verify`

### Custom Target
- Requires `riscv32imac-unknown-xous-elf` target
- Provided by betrusted-io/rust fork
- Guix will need special handling for custom Rust target

---

## Packaging Strategy

### For Each Workspace (curve25519-dalek, hashes):

```scheme
;; rust-sources.scm
(define-public rust-curve25519-dalek-workspace.COMMIT
  (let ((commit "COMMIT_HASH")
        (revision "0"))
    (package
      (name "rust-curve25519-dalek-workspace")
      (version (git-version "4.1.2" revision commit))
      (source (origin
                (method git-fetch)
                (uri (git-reference
                      (url "https://github.com/betrusted-io/curve25519-dalek")
                      (commit commit)))
                (file-name (git-file-name name version))
                (sha256 (base32 "..."))))
      (build-system cargo-build-system)
      (arguments
       (list #:skip-build? #t
             #:cargo-package-crates
             ''("curve25519-dalek" "curve25519-dalek-derive" 
                "ed25519-dalek" "x25519-dalek")))
      (inputs (cargo-inputs 'rust-curve25519-dalek-workspace.COMMIT))
      ...)))
```

```scheme
;; rust-crates.scm - aliases for each workspace member
(define rust-curve25519-dalek.COMMIT package:rust-curve25519-dalek-workspace.COMMIT)
(define rust-curve25519-dalek-derive.COMMIT package:rust-curve25519-dalek-workspace.COMMIT)
(define rust-ed25519-dalek.COMMIT package:rust-curve25519-dalek-workspace.COMMIT)
(define rust-x25519-dalek.COMMIT package:rust-curve25519-dalek-workspace.COMMIT)
```

### For Single-Crate Forks:

Standard cargo package definition - clone, generate lockfile, import deps.

---

## Next Steps

### CRITICAL - Need to Obtain:
1. **xous-core's Cargo.lock** - grep for `source = "git+https://github.com/betrusted-io/` to get exact list
2. **Exact commit hashes** for each git dependency
3. **Verify betrusted-io/hashes exists** and its workspace structure

### Process for Each Git Dependency:
1. Clone at exact commit xous-core uses
2. Check if workspace (`[workspace]` in Cargo.toml)
3. Generate Cargo.lock: `cargo generate-lockfile`
4. Import deps: `guix import crate --lockfile=Cargo.lock`
5. Create package definition
6. Create aliases if workspace

### Estimated Effort:
- **2 workspaces**: ~30+ crate aliases total
- **4-5 single-crate packages**: Standard effort
- **Each workspace's deps**: Separate import cycle needed
- **xous-core itself**: May need special handling for xtask build system

---

## References

- [xous-core README](https://github.com/betrusted-io/xous-core)
- [curve25519-dalek fork](https://github.com/betrusted-io/curve25519-dalek)
- [ring-xous](https://github.com/betrusted-io/ring-xous)
- [Xous Book](https://betrusted.io/xous-book/)
- [betrusted-io organization](https://github.com/betrusted-io)
- [Guix Cargo Workspaces Cookbook](https://guix.gnu.org/cookbook/en/html_node/Cargo-Workspaces-and-Development-Snapshots.html)
