# Secure Rust Dependency Vendoring for Guix Builds

## A Comprehensive Guide for Supply Chain Security

**Target Project:** xous-core  
**Build System:** GNU Guix (New Rust Packaging Model - 2025)  
**Threat Model:** Software Supply Chain Attacks

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [The New Guix Rust Packaging Model](#the-new-guix-rust-packaging-model)
3. [Threat Model](#threat-model)
4. [Security Architecture](#security-architecture)
5. [Trust Anchors](#trust-anchors)
6. [Implementation with the New Model](#implementation-with-the-new-model)
7. [Guix Integration](#guix-integration)
8. [Verification Procedures](#verification-procedures)
9. [Workflow](#workflow)
10. [Path to Fully Bootstrapped Rust](#path-to-fully-bootstrapped-rust)
11. [Limitations and Known Gaps](#limitations-and-known-gaps)
12. [Appendix: Tools and Scripts](#appendix-tools-and-scripts)

---

## Executive Summary

GNU Guix has merged a **new Rust packaging model** (June 2025) that fundamentally changes how Rust applications are packaged. This new model:

- Uses `Cargo.lock` as the source of truth for dependencies
- Stores crates as **sources** (origins), not packages
- Deprecates `#:cargo-inputs` and `#:cargo-development-inputs` (removal after Dec 31, 2026)
- Provides `cargo-inputs` procedure for dependency lookup
- Hides Rust libraries from the user interface

This document describes how to leverage the new model while maintaining supply chain security for high-assurance projects like xous-core.

### Key Security Measures

| Layer | Mechanism | Purpose |
|-------|-----------|---------|
| **Audit** | cargo-vet | Human review attestations |
| **Verify** | Software Heritage | Independent third-party verification |
| **Lock** | Cargo.lock + Guix lockfile importer | Deterministic dependency resolution |
| **Isolate** | Guix sandboxed builds | Network-free compilation |
| **Document** | Provenance records | Complete audit trail |

---

## The New Guix Rust Packaging Model

### Background

The previous Guix approach mapped one Rust crate to one Guix package. This caused problems:

- Thousands of library packages cluttered the user interface
- Built artifacts couldn't be reused (Rust compiles everything together)
- `#:cargo-inputs` was inconsistent with standard Guix inputs
- Circular dependencies required special handling

### What Changed

```
┌─────────────────────────────────────────────────────────────────┐
│                    OLD MODEL (Deprecated)                        │
│                                                                  │
│   (arguments                                                    │
│    (list #:cargo-inputs                                         │
│          (list rust-serde-1                                     │
│                rust-tokio-1)))                                  │
│                                                                  │
│   - Each crate = Guix package                                   │
│   - Recursive import from crates.io                             │
│   - Packages visible to users                                   │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                    NEW MODEL (Current)                           │
│                                                                  │
│   (inputs (cargo-inputs 'my-package))                           │
│                                                                  │
│   - Each crate = Guix origin (source only)                      │
│   - Import from Cargo.lock                                      │
│   - Libraries hidden from users                                 │
│   - Stored in rust-crates and rust-sources modules              │
└─────────────────────────────────────────────────────────────────┘
```

### New Module Structure

| Module | Purpose |
|--------|---------|
| `(gnu packages rust-crates)` | Auto-imported crate sources with `lookup-cargo-inputs` interface |
| `(gnu packages rust-sources)` | Complex definitions requiring manual work (workspaces, unbundling) |

### Import Workflow

```bash
# NEW: Import from Cargo.lock
guix import crate --lockfile=/path/to/Cargo.lock PACKAGE \
     --insert=gnu/packages/rust-crates.scm

# Short form
guix import -i gnu/packages/rust-crates.scm crate -f Cargo.lock PACKAGE
```

### Package Definition Style

```scheme
;; NEW STYLE (Current)
(define-public my-rust-app
  (package
    (name "my-rust-app")
    (version "1.0.0")
    (source
     (origin
       (method git-fetch)
       (uri (git-reference
             (url "https://github.com/org/repo")
             (commit "...")))
       (sha256 (base32 "..."))))
    (build-system cargo-build-system)
    ;; NEW: Use cargo-inputs procedure
    (inputs (cargo-inputs 'my-rust-app))
    (home-page "...")
    (synopsis "...")
    (description "...")
    (license license:asl2.0)))
```

### For Development (guix.scm)

```scheme
;; In your project's guix.scm
(use-modules (guix import crate))

(package
  (name "my-project")
  (version "0.1.0")
  (source (local-file "." #:recursive? #t))
  (build-system cargo-build-system)
  ;; Read directly from Cargo.lock
  (inputs (cargo-inputs-from-lockfile "Cargo.lock"))
  ...)
```

### Crate Modifications

The new model supports modifications via snippets:

```scheme
;; In rust-crates.scm - Modified crate
(define rust-libmimalloc-sys-0.1.24
  (crate-source "libmimalloc-sys" "0.1.24"
                "0s8ab4nc33qgk9jybpv0zxcb75jgwwjb7fsab1rkyjgdyr0gq1bp"
                #:snippet
                '(begin
                   (delete-file-recursively "c_src")
                   (delete-file "build.rs")
                   (with-output-to-file "build.rs"
                     (lambda _
                       (format #t "fn main() {~@
                        println!(\"cargo:rustc-link-lib=mimalloc\");~@
                        }~%"))))))

;; Replacement (points to rust-sources definition)
(define rust-pipewire-0.8.0 rust-pipewire-for-niri)

;; Deletion
(define rust-problematic-crate-1.0.0 #f)
```

---

## Threat Model

### Attack Vectors

| Vector | Description | Risk Level |
|--------|-------------|------------|
| **Compromised Maintainer** | Attacker gains access to crates.io account | Critical |
| **Dependency Confusion** | Malicious package with same name as internal dep | High |
| **Typosquatting** | Similar name attack (e.g., `serde` vs `serdee`) | High |
| **Index Poisoning** | Manipulation of crates.io index | High |
| **Git Ref Mutation** | Force-push or repo recreation | High |
| **Build Script Attacks** | Malicious `build.rs` or proc-macro | Critical |
| **Toolchain Compromise** | Backdoored rustc or cargo | Critical |
| **Transitive Dependencies** | Attack through nested dependency | High |

### Security Goals

1. **Reproducibility** - Same inputs always produce same outputs
2. **Auditability** - Every dependency traceable to its source
3. **Verifiability** - Independent verification of all artifacts
4. **Isolation** - Build process cannot fetch additional code

---

## Security Architecture

### How the New Model Helps Security

```
┌─────────────────────────────────────────────────────────────────┐
│                   SECURITY BENEFITS                              │
│                                                                  │
│   1. Cargo.lock is source of truth                              │
│      - Exact versions pinned                                    │
│      - Checksums recorded                                       │
│      - Guix imports from this                                   │
│                                                                  │
│   2. Sources stored, not artifacts                              │
│      - Can be audited                                           │
│      - Can be modified via snippets                             │
│      - Full transparency                                        │
│                                                                  │
│   3. Guix handles verification                                  │
│      - Hash verification on fetch                               │
│      - Reproducible builds                                      │
│      - Network isolation                                        │
│                                                                  │
│   4. Modifications are explicit                                 │
│      - Snippets visible in package definition                   │
│      - Replacements documented                                  │
│      - Deletions tracked                                        │
└─────────────────────────────────────────────────────────────────┘
```

### What You Still Need

The new Guix model provides infrastructure, but **does not verify authenticity**. You still need:

1. **cargo-vet** - Human audit attestations
2. **Software Heritage** - Independent verification
3. **Provenance tracking** - Your own audit trail

---

## Trust Anchors

### 1. cargo-vet (Primary Trust Anchor)

cargo-vet records human attestations that crates have been reviewed.

```bash
# Initialize
cargo vet init

# Import trusted audits
cargo vet trust --all mozilla
cargo vet trust --all google
cargo vet trust --all bytecode-alliance

# Check status
cargo vet

# After reviewing, certify
cargo vet certify CRATE VERSION safe-to-deploy

# Or exempt with rationale
cargo vet add-exemption CRATE VERSION --notes "Rationale"
```

This creates `supply-chain/` directory:
- `config.toml` - Whose audits to trust
- `audits.toml` - Your attestations
- `imports.lock` - Imported audit versions

### 2. Software Heritage (Independent Verification)

Cross-check crates against Software Heritage archives:

```python
def check_software_heritage(sha256: str) -> bool:
    """Verify crate exists in Software Heritage."""
    url = f"https://archive.softwareheritage.org/api/1/content/sha256:{sha256}/"
    try:
        response = urlopen(url, timeout=30)
        return response.status == 200
    except:
        return False
```

### 3. Guix Content-Addressed Storage

Guix verifies hashes on every fetch:

```scheme
(source
 (origin
   (method url-fetch)
   (uri (crate-uri "serde" "1.0.193"))
   ;; This hash is verified by Guix
   (sha256 (base32 "1hyr7k1z24i3approhx60spsg44d0m2vg7zn8lgxy5ya458x5qhx7"))))
```

---

## Implementation with the New Model

### Project Structure

```
xous-core/
├── Cargo.toml                    # Workspace manifest
├── Cargo.lock                    # Locked dependencies (COMMIT THIS)
├── guix/
│   ├── xous-core.scm             # Main package definition
│   ├── rust-sources.scm          # Complex crate definitions (if needed)
│   └── channels.scm              # Pinned Guix channels
├── supply-chain/                 # cargo-vet data (COMMIT THIS)
│   ├── config.toml
│   ├── audits.toml
│   └── imports.lock
├── .provenance/                  # Additional verification (optional)
│   └── swh-verification.json
└── TRUST_POLICY.md               # Document trust decisions
```

### Step 1: Set Up cargo-vet

```bash
cd xous-core
cargo vet init
cargo vet trust --all mozilla google bytecode-alliance
```

### Step 2: Import Dependencies to Guix

```bash
# Import all dependencies from Cargo.lock
guix import crate --lockfile=Cargo.lock xous-core \
     --insert=gnu/packages/rust-crates.scm
```

This populates `rust-crates.scm` with entries like:

```scheme
(define rust-serde-1.0.193
  (crate-source "serde" "1.0.193"
                "1hyr7k1z24i3approhx60spsg44d0m2vg7zn8lgxy5ya458x5qhx7"))
```

### Step 3: Handle Complex Dependencies

For git dependencies or those requiring modifications, add to `rust-sources.scm`:

```scheme
;;; xous-core rust-sources.scm

(define-module (xous packages rust-sources)
  #:use-module (guix packages)
  #:use-module (guix git-download)
  #:use-module (guix build-system cargo))

;; Git dependency example
(define-public rust-some-git-dep
  (let ((commit "abc123def456")
        (revision "0"))
    (package
      (name "rust-some-git-dep")
      (version (git-version "0.1.0" revision commit))
      (source
       (origin
         (method git-fetch)
         (uri (git-reference
               (url "https://github.com/org/repo")
               (commit commit)))
         (file-name (git-file-name name version))
         (sha256 (base32 "..."))))
      (build-system cargo-build-system)
      (arguments '(#:skip-build? #t))
      (home-page "...")
      (synopsis "...")
      (description "...")
      (license license:expat))))
```

### Step 4: Verify Dependencies

```bash
# Check cargo-vet coverage
cargo vet

# See what needs auditing
cargo vet suggest

# Verify against Software Heritage (custom script)
./scripts/verify-swh.py
```

---

## Guix Integration

### Main Package Definition

```scheme
;;; guix/xous-core.scm

(define-module (xous packages xous-core)
  #:use-module (guix packages)
  #:use-module (guix gexp)
  #:use-module (guix git-download)
  #:use-module (guix build-system cargo)
  #:use-module (gnu packages rust))

(define %commit "YOUR_PINNED_COMMIT")
(define %version "0.9.x")

(define-public xous-core
  (package
    (name "xous-core")
    (version %version)
    (source
     (origin
       (method git-fetch)
       (uri (git-reference
             (url "https://github.com/sbellem/xous-core")
             (commit %commit)))
       (file-name (git-file-name name version))
       (sha256 (base32 "SOURCE_HASH_HERE"))))
    
    (build-system cargo-build-system)
    
    ;; NEW MODEL: Use cargo-inputs procedure
    (inputs (cargo-inputs 'xous-core))
    
    ;; Non-Rust inputs
    (native-inputs
     (list pkg-config))
    
    (arguments
     (list
      ;; Custom target for xous
      #:cargo-build-flags
      #~'("--target" "riscv32imac-unknown-xous-elf")
      
      #:phases
      #~(modify-phases %standard-phases
          ;; Verify cargo-vet status (optional but recommended)
          (add-before 'build 'check-audit-status
            (lambda _
              (when (file-exists? "supply-chain/audits.toml")
                (display "cargo-vet audit data present\n"))))
          
          ;; Custom build for xous (uses xtask)
          (replace 'build
            (lambda _
              (invoke "cargo" "xtask" "app-image"
                      "--offline" "--locked")))
          
          ;; Tests require emulation
          (delete 'check)
          
          (replace 'install
            (lambda* (#:key outputs #:allow-other-keys)
              (let* ((out (assoc-ref outputs "out"))
                     (share (string-append out "/share/xous")))
                (mkdir-p share)
                (for-each
                 (lambda (f) (install-file f share))
                 (find-files "target" "\\.(img|bin)$"))))))))
    
    (synopsis "Xous microkernel operating system")
    (description
     "Xous is a microkernel operating system written in Rust,
designed for high-assurance embedded applications.")
    (home-page "https://github.com/betrusted-io/xous-core")
    (license license:asl2.0)))
```

### Development Shell

```scheme
;;; guix/manifest.scm - For development

(use-modules (guix import crate))

(packages->manifest
 (list
  ;; Import Rust toolchain
  rust
  rust-analyzer
  
  ;; Your project with deps from Cargo.lock
  (package
    (name "xous-dev")
    (version "0.0.0")
    (source #f)
    (build-system cargo-build-system)
    (inputs (cargo-inputs-from-lockfile "../Cargo.lock"))
    (synopsis "")
    (description "")
    (license #f)
    (home-page ""))))
```

### Channel Configuration

```scheme
;;; guix/channels.scm - Pin Guix version

(list
 (channel
  (name 'guix)
  (url "https://git.savannah.gnu.org/git/guix.git")
  ;; Pin to specific commit for reproducibility
  (commit "GUIX_COMMIT_HASH")))
```

---

## Verification Procedures

### Pre-Import Verification Script

```bash
#!/bin/bash
# verify-before-import.sh
# Run before guix import to verify dependencies

set -euo pipefail

echo "=== Pre-Import Verification ==="

# 1. Check Cargo.lock exists and is committed
echo "[1/4] Checking Cargo.lock..."
if [[ ! -f Cargo.lock ]]; then
    echo "ERROR: Cargo.lock not found"
    exit 1
fi
if ! git ls-files --error-unmatch Cargo.lock &>/dev/null; then
    echo "WARNING: Cargo.lock not committed"
fi
echo "  ✓ Cargo.lock present"

# 2. Check cargo-vet status
echo "[2/4] Checking cargo-vet..."
if command -v cargo-vet &>/dev/null; then
    if cargo vet --locked 2>/dev/null; then
        echo "  ✓ All dependencies audited or exempted"
    else
        echo "  ⚠ Some dependencies not audited"
        cargo vet suggest 2>/dev/null | head -20
    fi
else
    echo "  ⚠ cargo-vet not installed"
fi

# 3. Count dependencies
echo "[3/4] Counting dependencies..."
dep_count=$(grep -c '^\[\[package\]\]' Cargo.lock || echo "0")
echo "  Total packages in Cargo.lock: $dep_count"

# 4. Check for git dependencies
echo "[4/4] Checking for git dependencies..."
git_deps=$(grep -c 'source = "git+' Cargo.lock || echo "0")
if [[ "$git_deps" -gt 0 ]]; then
    echo "  ⚠ Found $git_deps git dependencies (may need rust-sources.scm entries)"
    grep 'source = "git+' Cargo.lock | head -10
else
    echo "  ✓ No git dependencies"
fi

echo ""
echo "=== Verification complete ==="
```

### Software Heritage Verification Script

```python
#!/usr/bin/env python3
"""verify-swh.py - Verify crates against Software Heritage"""

import hashlib
import json
import tomllib
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import HTTPError

def get_crate_hash(name: str, version: str) -> str:
    """Fetch crate and compute SHA256."""
    url = f"https://static.crates.io/crates/{name}/{name}-{version}.crate"
    with urlopen(url, timeout=60) as resp:
        return hashlib.sha256(resp.read()).hexdigest()

def check_swh(sha256: str) -> bool:
    """Check if Software Heritage knows this hash."""
    url = f"https://archive.softwareheritage.org/api/1/content/sha256:{sha256}/"
    try:
        with urlopen(url, timeout=30) as resp:
            return resp.status == 200
    except HTTPError as e:
        if e.code == 404:
            return False
        raise

def main():
    # Parse Cargo.lock
    with open("Cargo.lock", "rb") as f:
        lock = tomllib.load(f)
    
    results = {"verified": [], "not_found": [], "errors": []}
    
    for pkg in lock.get("package", []):
        name = pkg["name"]
        version = pkg["version"]
        source = pkg.get("source", "")
        
        # Skip non-crates.io sources
        if not source.startswith("registry+"):
            continue
        
        print(f"Checking {name}-{version}...", end=" ")
        
        try:
            sha256 = get_crate_hash(name, version)
            if check_swh(sha256):
                print("✓ verified")
                results["verified"].append(f"{name}-{version}")
            else:
                print("⚠ not in SWH")
                results["not_found"].append(f"{name}-{version}")
        except Exception as e:
            print(f"✗ error: {e}")
            results["errors"].append(f"{name}-{version}: {e}")
    
    # Summary
    print("\n=== Summary ===")
    print(f"Verified in SWH: {len(results['verified'])}")
    print(f"Not found in SWH: {len(results['not_found'])}")
    print(f"Errors: {len(results['errors'])}")
    
    # Save results
    with open(".provenance/swh-verification.json", "w") as f:
        json.dump(results, f, indent=2)

if __name__ == "__main__":
    main()
```

### CI/CD Integration

```yaml
# .github/workflows/verify-deps.yml
name: Verify Dependencies

on:
  pull_request:
    paths:
      - 'Cargo.lock'
      - 'supply-chain/**'

jobs:
  cargo-vet:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install cargo-vet
        run: cargo install cargo-vet
      
      - name: Check audits
        run: cargo vet --locked
      
      - name: Suggest missing
        if: failure()
        run: cargo vet suggest

  guix-import-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install Guix
        uses: PromyLOPh/guix-install-action@v1
      
      - name: Test import
        run: |
          guix import crate --lockfile=Cargo.lock xous-core \
               > /tmp/imported.scm
          echo "Import successful, $(wc -l < /tmp/imported.scm) lines"
```

---

## Workflow

### Initial Setup

```bash
# 1. Clone repository
git clone https://github.com/sbellem/xous-core
cd xous-core

# 2. Initialize cargo-vet
cargo vet init
cargo vet trust --all mozilla google bytecode-alliance

# 3. Run initial audit check
cargo vet

# 4. Address unaudited crates
cargo vet suggest
# Then either audit or exempt each one

# 5. Create trust policy document
cat > TRUST_POLICY.md << 'EOF'
# Trust Policy for xous-core

## Trusted Audit Sources
- Mozilla, Google, Bytecode Alliance

## Local Audit Requirements  
- All unsafe code must be reviewed
- All build.rs scripts must be reviewed
- All proc-macros must be reviewed

## Known Trust Gaps
- Rust compiler not yet fully bootstrapped in Guix
EOF

# 6. Import to Guix
guix import crate --lockfile=Cargo.lock xous-core \
     --insert=gnu/packages/rust-crates.scm

# 7. Commit everything
git add Cargo.lock supply-chain/ TRUST_POLICY.md
git commit -m "Initialize supply chain security"
```

### Updating Dependencies

```bash
# 1. Update Cargo.lock
cargo update

# 2. Check cargo-vet
cargo vet
cargo vet suggest  # Address any new unaudited deps

# 3. Re-import to Guix
guix import crate --lockfile=Cargo.lock xous-core \
     --insert=gnu/packages/rust-crates.scm

# 4. Commit
git add Cargo.lock supply-chain/ gnu/packages/rust-crates.scm
git commit -m "Update dependencies"
```

### Building

```bash
# Standard Guix build
guix build -f guix/xous-core.scm

# With verbosity
guix build -f guix/xous-core.scm -v2

# Check reproducibility
guix build -f guix/xous-core.scm --check

# Development shell
guix shell -m guix/manifest.scm
```

---

## Path to Fully Bootstrapped Rust

### The Bootstrap Problem

Rust is written in Rust, creating a circular dependency:

```
rustc 1.75 needs rustc 1.74 to compile
rustc 1.74 needs rustc 1.73 to compile
...
```

### The Solution: mrustc

[mrustc](https://github.com/thepowersgang/mrustc) is a Rust compiler written in C++ that can compile specific rustc versions.

```
┌─────────────────────────────────────────────────────────────────┐
│                 BOOTSTRAP CHAIN (Goal)                           │
│                                                                  │
│   GNU Mes (Scheme) → mescc → TinyCC → GCC 4.6 → Modern GCC      │
│                                                                  │
│                              ↓                                   │
│                                                                  │
│                          mrustc (C++)                            │
│                              ↓                                   │
│                       rustc 1.54 (first)                        │
│                              ↓                                   │
│                 rustc 1.55 → 1.56 → ... → current               │
└─────────────────────────────────────────────────────────────────┘
```

### Current Status in Guix

As of 2025:
- **Complete:** Mes → TinyCC → GCC bootstrap chain
- **In Progress:** mrustc integration, Rust version stepping
- **Workaround:** Guix currently uses pre-built rustc binaries

### What This Means for xous-core

```
┌─────────────────────────────────────────────────────────────────┐
│              TRUST CHAIN FOR XOUS-CORE                           │
│                                                                  │
│   VERIFIED BY GUIX:                                             │
│   ✓ All crate sources (hash-checked)                            │
│   ✓ Build isolation (no network)                                │
│   ✓ Reproducible builds                                         │
│                                                                  │
│   VERIFIED BY YOU:                                              │
│   ✓ cargo-vet audits                                            │
│   ✓ Software Heritage cross-check                               │
│   ✓ Provenance documentation                                    │
│                                                                  │
│   TRUSTED (NOT YET VERIFIED):                                   │
│   ! Rust compiler (rustc bootstrap binaries)                    │
│   ! LLVM backend                                                │
│                                                                  │
│   Document this gap in TRUST_POLICY.md                          │
└─────────────────────────────────────────────────────────────────┘
```

### Tracking Progress

```bash
# See Rust package build graph
guix graph rust | dot -Tpng > rust-graph.png

# Check for bootstrap status
guix graph --type=bag rust | grep bootstrap
```

---

## Limitations and Known Gaps

### What's Protected

| Threat | Protection | Mechanism |
|--------|------------|-----------|
| Compromised crate maintainer | ✓ Yes | cargo-vet audits |
| crates.io service compromise | ✓ Yes | SWH cross-verification |
| Index poisoning | ✓ Yes | Guix hash verification |
| Typosquatting | ✓ Yes | Cargo.lock + audits |
| Network MITM at build | ✓ Yes | Guix offline builds |
| Binary substitution | ✓ Yes | Reproducible builds |

### What's NOT Protected

| Threat | Gap | Mitigation |
|--------|-----|------------|
| **Rust toolchain** | Not fully bootstrapped | Document; await Guix progress |
| **Malicious build.rs** | Executes during build | Audit in cargo-vet review |
| **Proc-macro attacks** | Executes at compile | Audit proc-macros carefully |
| **0-day in audited crate** | Audits aren't perfect | Defense in depth |

### Honest Trust Statement

```markdown
## Known Trust Gaps (for TRUST_POLICY.md)

### Rust Compiler Bootstrap
Guix does not yet have a fully bootstrapped Rust compiler.
The `rust` package uses pre-built bootstrap binaries from
static.rust-lang.org.

**Risk:** We trust Rust project's release infrastructure.

**Mitigations:**
- Pin exact Guix commit for builds
- Pin exact Rust version
- Verify reproducibility with `guix build --check`
- Will adopt bootstrapped Rust when Guix completes it

**Tracking:** https://issues.guix.gnu.org (search "rust bootstrap")
```

---

## Appendix: Tools and Scripts

### A. Guix Import with Verification

```bash
#!/bin/bash
# secure-import.sh - Import with pre/post verification

set -euo pipefail

LOCKFILE="${1:-Cargo.lock}"
PACKAGE="${2:-$(basename $(pwd))}"

echo "=== Secure Import Workflow ==="

# Pre-import checks
echo "[1/4] Running cargo-vet..."
cargo vet --locked

echo "[2/4] Importing from $LOCKFILE..."
guix import crate --lockfile="$LOCKFILE" "$PACKAGE" \
     > /tmp/new-crates.scm

echo "[3/4] Checking import..."
lines=$(wc -l < /tmp/new-crates.scm)
echo "  Generated $lines lines"

echo "[4/4] Done!"
echo ""
echo "Review /tmp/new-crates.scm then merge into rust-crates.scm"
```

### B. Audit Helper Script

```bash
#!/bin/bash
# audit-new-deps.sh - Help audit new dependencies

# Get list of unaudited crates
unaudited=$(cargo vet suggest 2>/dev/null | grep -oP 'cargo vet certify \K[^ ]+' || true)

if [[ -z "$unaudited" ]]; then
    echo "All dependencies are audited or exempted!"
    exit 0
fi

echo "Unaudited crates:"
echo "$unaudited"
echo ""

for crate in $unaudited; do
    name=$(echo "$crate" | cut -d: -f1)
    version=$(echo "$crate" | cut -d: -f2)
    
    echo "=== $name $version ==="
    echo "Inspect: cargo vet inspect $name $version"
    echo "Diff:    cargo vet diff $name PREV_VERSION $version"
    echo "Certify: cargo vet certify $name $version safe-to-deploy"
    echo "Exempt:  cargo vet add-exemption $name $version"
    echo ""
done
```

### C. Channel Lock File

```scheme
;;; guix/channels-lock.scm
;;; Generated by: guix time-machine --commit=COMMIT -- describe -f channels

(list
 (channel
  (name 'guix)
  (url "https://git.savannah.gnu.org/git/guix.git")
  (branch "master")
  (commit "EXACT_COMMIT_HASH")
  (introduction
   (make-channel-introduction
    "9edb3f66fd807b096b48283debdcddccfea34bad"
    (openpgp-fingerprint
     "BBB0 2DDF 2CEA F6A8 0D1D  E643 A2A0 6DF2 A33A 54FA")))))
```

### D. Complete Package Template

```scheme
;;; Template for high-assurance Rust package

(define-module (my packages my-rust-app)
  #:use-module (guix packages)
  #:use-module (guix gexp)
  #:use-module (guix git-download)
  #:use-module (guix build-system cargo)
  #:use-module ((guix licenses) #:prefix license:))

;; Pin versions explicitly
(define %version "1.0.0")
(define %commit "abc123...")
(define %cargo-inputs-hash
  (base32 "..."))  ; Optional: hash of rust-crates.scm content

(define-public my-rust-app
  (package
    (name "my-rust-app")
    (version %version)
    (source
     (origin
       (method git-fetch)
       (uri (git-reference
             (url "https://github.com/org/my-rust-app")
             (commit %commit)))
       (file-name (git-file-name name version))
       (sha256 (base32 "..."))))
    
    (build-system cargo-build-system)
    
    ;; New model: cargo-inputs procedure
    (inputs (cargo-inputs 'my-rust-app))
    
    (arguments
     (list
      #:tests? #t
      #:cargo-build-flags #~'("--release")
      #:phases
      #~(modify-phases %standard-phases
          (add-after 'unpack 'verify-lockfile
            (lambda _
              (unless (file-exists? "Cargo.lock")
                (error "Cargo.lock missing - required for reproducibility"))))
          (add-after 'install 'install-docs
            (lambda* (#:key outputs #:allow-other-keys)
              (let ((doc (string-append (assoc-ref outputs "out")
                                        "/share/doc/my-rust-app")))
                (mkdir-p doc)
                (copy-file "README.md" (string-append doc "/README.md"))))))))
    
    (home-page "https://example.com/my-rust-app")
    (synopsis "Short description")
    (description "Longer description.")
    (license license:asl2.0)))
```

---

## References

- [A New Rust Packaging Model (Guix Blog, June 2025)](https://guix.gnu.org/en/blog/2025/a-new-rust-packaging-model/)
- [Guix Rust Packaging PR #387](https://codeberg.org/guix/guix/pulls/387)
- [cargo-vet Documentation](https://mozilla.github.io/cargo-vet/)
- [Software Heritage](https://www.softwareheritage.org/)
- [Guix Manual - Build Systems](https://guix.gnu.org/manual/en/html_node/Build-Systems.html)
- [mrustc - Rust compiler in C++](https://github.com/thepowersgang/mrustc)
- [SLSA Framework](https://slsa.dev/)
- [Reproducible Builds](https://reproducible-builds.org/)

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 2.0 | 2025-XX | Updated for new Guix Rust model (merged) |
| 1.0 | 2024-XX | Initial version (deprecated `#:cargo-inputs` approach) |

---

*This document is part of the xous-core project's security documentation.*
