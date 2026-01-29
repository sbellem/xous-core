# Guix vs Nix: Cargo Dependencies Handling Comparison

## Executive Summary

Both Guix and Nix face the same fundamental challenge: Cargo wants to own the entire build process, but functional package managers need deterministic, pure builds with explicit dependency graphs. The two ecosystems have evolved different solutions with different trade-offs.

| Aspect | Guix | Nix (various tools) |
|--------|------|---------------------|
| **Philosophy** | Each crate = first-class package | Multiple strategies available |
| **Granularity** | Per-crate derivations | Ranges from 1 to many derivations |
| **Code Generation** | `guix import crate` | cargo2nix, crate2nix generate .nix |
| **Git Dependencies** | Manual package + patch Cargo.toml | outputHashes or automatic (crane) |
| **Workspace Support** | Aliases + `#:cargo-package-crates` | Varies by tool |
| **Caching** | Per-crate substitutes | Per-derivation (granularity varies) |

---

## Nix Ecosystem: Multiple Approaches

### 1. buildRustPackage (nixpkgs built-in)

The simplest approach - vendors all dependencies into a single tarball.

```nix
rustPlatform.buildRustPackage {
  pname = "my-app";
  version = "1.0.0";
  src = ./.;
  
  # Single hash for ALL vendored dependencies
  cargoHash = "sha256-...";
  
  # For git dependencies, use cargoLock instead:
  cargoLock = {
    lockFile = ./Cargo.lock;
    outputHashes = {
      "some-git-dep-0.1.0" = "sha256-...";
    };
  };
}
```

**Characteristics:**
- **Derivations:** 1 (everything compiled together)
- **Git deps:** Manual `outputHashes` for each git dependency
- **Caching:** All-or-nothing (any dep change rebuilds everything)
- **Simplicity:** High (just need one hash)

---

### 2. Crane (Modern, Popular)

Splits build into dependencies-only + project derivations.

```nix
{
  inputs = {
    crane.url = "github:ipetkov/crane";
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };
  
  outputs = { self, nixpkgs, crane, ... }:
    let
      craneLib = crane.lib.x86_64-linux;
      src = ./.;
      
      # Build ONLY dependencies (cached separately)
      cargoArtifacts = craneLib.buildDepsOnly { inherit src; };
      
      # Build project using cached deps
      my-app = craneLib.buildPackage {
        inherit src cargoArtifacts;
      };
    in {
      packages.default = my-app;
    };
}
```

**Characteristics:**
- **Derivations:** 2 (deps + project)
- **Git deps:** Automatic support (no manual hashes needed!)
- **Caching:** Dependencies cached separately from project code
- **Composability:** Can add clippy, tests, docs as separate derivations

**How it works:**
1. Transforms source to build only deps (strips your code, keeps Cargo.toml/lock)
2. Runs `cargo build` to compile all dependencies
3. Packages `target/` directory as artifact
4. Second derivation uses real source + cached artifacts

---

### 3. Naersk (Predecessor to Crane)

Similar 2-derivation approach, slightly older.

```nix
naersk.buildPackage {
  src = ./.;
  # Automatic dependency handling
  # No manual hashes needed for crates.io deps
}
```

**Characteristics:**
- **Derivations:** 2
- **Git deps:** Supported but can be finicky
- **Caching:** Good (deps separate from project)

---

### 4. cargo2nix (Per-Crate Granularity)

Generates `Cargo.nix` with one derivation per crate.

```bash
# Generate Cargo.nix from Cargo.lock
cargo2nix
```

```nix
# Generated Cargo.nix contains individual crate definitions
rustPkgs = pkgs.rustBuilder.makePackageSet {
  packageFun = import ./Cargo.nix;
};

# Access specific crates
rustPkgs.workspace.my-app {}
rustPkgs.registry.serde."1.0.130" {}
```

**Characteristics:**
- **Derivations:** Many (one per crate)
- **Code generation:** Yes (`Cargo.nix` committed to repo)
- **Git deps:** Supported in generated code
- **Caching:** Maximum granularity (change one dep, rebuild only that)
- **Cross-project sharing:** Theoretically possible (same crate versions share builds)

---

### 5. crate2nix (Similar to cargo2nix)

Also generates per-crate Nix expressions.

```bash
crate2nix generate
```

**Characteristics:**
- **Derivations:** Many (one per crate)
- **Build tool:** Invokes `rustc` directly (no Cargo at build time)
- **Code generation:** Yes

---

### Nix Tools Comparison Table

| Tool | Derivations | Code Gen | Git Deps | Complexity |
|------|-------------|----------|----------|------------|
| buildRustPackage | 1 | No | Manual hashes | Low |
| crane | 2 | No | Automatic | Low-Medium |
| naersk | 2 | No | Semi-auto | Low-Medium |
| cargo2nix | Many | Yes | In generated | Medium-High |
| crate2nix | Many | Yes | In generated | Medium-High |

---

## Guix Approach

Guix takes a single, consistent approach: **every crate is a first-class package**.

> **Note:** The old `#:cargo-inputs` argument is **deprecated** and will be removed by end of 2025. The new approach uses a lookup table with `(inputs (cargo-inputs 'name))`.

### New Architecture (Current Best Practice)

The modern Guix Rust packaging uses two files:

**1. `rust-crates.scm`** - Dependency lookup table + crate source packages

```scheme
;;; Lookup table mapping package identifiers to their dependencies
(define lookup-cargo-inputs
  `((rust-serde-1.0.135 . ,(list
      rust-serde-derive-1.0.135))
    (rust-serde-derive-1.0.135 . ,(list
      rust-proc-macro2-1.0.36
      rust-quote-1.0.15
      rust-syn-1.0.86))
    (rust-tokio-1.25.0 . ,(list
      rust-bytes-1.4.0
      rust-mio-0.8.6
      rust-pin-project-lite-0.2.9))
    ;; ... hundreds more entries
    ))

;;; Helper function to retrieve inputs
(define (cargo-inputs name)
  (or (assoc-ref lookup-cargo-inputs name)
      (error "Unknown cargo inputs for" name)))

;;; Crate source definitions (just sources, no build)
(define rust-serde-1.0.135
  (origin
    (method url-fetch)
    (uri (crate-uri "serde" "1.0.135"))
    (file-name "rust-serde-1.0.135.tar.gz")
    (sha256 (base32 "..."))))
```

**2. `rust-sources.scm`** - Actual package definitions

```scheme
(define-public rust-serde-1
  (package
    (name "rust-serde")
    (version "1.0.135")
    (source rust-serde-1.0.135)  ; Reference from rust-crates.scm
    (build-system cargo-build-system)
    (arguments
     (list #:skip-build? #t))     ; Skip build for library crates
    (inputs (cargo-inputs 'rust-serde-1.0.135))  ; NEW WAY
    (home-page "https://serde.rs")
    (synopsis "Serialization framework")
    (description "...")
    (license (list license:expat license:asl2.0))))
```

### Importing Crates

```bash
# Import from a lockfile (generates both files)
guix import crate --lockfile=Cargo.lock my-project \
  --insert=rust-crates.scm

# Or import a single crate recursively
guix import crate serde
```

### Handling Git Dependencies

Git dependencies require:
1. Creating a manual package definition for the git source
2. Patching Cargo.toml to replace git refs with version wildcards
3. Adding to the lookup table with a commit-based identifier

```scheme
;;; In rust-crates.scm

;; Git-sourced crate with commit in identifier
(define rust-my-fork-1.0.0.abc123
  (origin
    (method git-fetch)
    (uri (git-reference
          (url "https://github.com/user/my-fork")
          (commit "abc123def456...")))
    (file-name "rust-my-fork-1.0.0-abc123.tar.gz")
    (sha256 (base32 "..."))))

;; Add to lookup table
(define lookup-cargo-inputs
  `(...
    (rust-my-fork-1.0.0.abc123 . ,(list
      rust-some-dep-1.0.0))
    ...))
```

```scheme
;;; In rust-sources.scm

(define-public rust-my-fork-1
  (package
    (name "rust-my-fork")
    (version (git-version "1.0.0" "0" "abc123"))
    (source rust-my-fork-1.0.0.abc123)
    (build-system cargo-build-system)
    (arguments
     (list #:skip-build? #t))
    (inputs (cargo-inputs 'rust-my-fork-1.0.0.abc123))
    ...))
```

For the consuming package, patch Cargo.toml:
```scheme
(arguments
 (list
  #:phases
  #~(modify-phases %standard-phases
      (add-after 'unpack 'patch-cargo-toml
        (lambda _
          (substitute* "Cargo.toml"
            (("git = \"https://github.com/user/my-fork\"") "")
            (("rev = \"abc123\"") "version = \"*\"")))))))
```

### Workspace Handling

```scheme
;;; In rust-crates.scm

;; Workspace dependencies (shared by all members)
(define lookup-cargo-inputs
  `(...
    (rust-curve25519-dalek-workspace.abc123 . ,(list
      rust-cfg-if-1.0.0
      rust-subtle-2.5.0
      rust-zeroize-1.5.0))
    ...))

;;; In rust-sources.scm

;; Workspace package with multiple crates
(define-public rust-curve25519-dalek-workspace
  (let ((commit "abc123"))
    (package
      (name "rust-curve25519-dalek-workspace")
      (version (git-version "4.1.2" "0" commit))
      (source (origin
                (method git-fetch)
                (uri (git-reference
                      (url "https://github.com/betrusted-io/curve25519-dalek")
                      (commit commit)))
                (sha256 (base32 "..."))))
      (build-system cargo-build-system)
      (arguments
       (list #:skip-build? #t
             #:cargo-package-crates
             ''("curve25519-dalek" 
                "curve25519-dalek-derive"
                "ed25519-dalek" 
                "x25519-dalek")))
      (inputs (cargo-inputs 'rust-curve25519-dalek-workspace.abc123))
      ...)))

;; Aliases for each workspace member (all point to same package)
(define rust-curve25519-dalek rust-curve25519-dalek-workspace)
(define rust-curve25519-dalek-derive rust-curve25519-dalek-workspace)
(define rust-ed25519-dalek rust-curve25519-dalek-workspace)
(define rust-x25519-dalek rust-curve25519-dalek-workspace)
```

### Why the New Approach?

The old `#:cargo-inputs` had issues:
- Mixed source fetching with dependency declaration
- Harder to generate programmatically
- Less efficient for the build system

The new approach:
- **Separation of concerns**: Sources in one place, deps in lookup table
- **Machine-friendly**: Easy for `guix import crate` to generate
- **Cacheable**: Source tarballs are separate derivations
- **Inspectable**: Clear dependency graph in lookup table

---

## Side-by-Side Comparison

### Simple crates.io Project

**Nix (crane):**
```nix
craneLib.buildPackage {
  src = ./.;
  # That's it! Deps handled automatically
}
```

**Guix (new approach):**
```bash
# Generate rust-crates.scm with lookup table + sources
guix import crate --lockfile=Cargo.lock my-project \
  --insert=rust-crates.scm

# Then define the package in rust-sources.scm
```

```scheme
;; rust-sources.scm
(define-public rust-my-project
  (package
    (name "rust-my-project")
    (version "1.0.0")
    (source (local-file "." "my-project"))
    (build-system cargo-build-system)
    (inputs (cargo-inputs 'rust-my-project-1.0.0))
    ...))
```

**Winner:** Nix/Crane (much less boilerplate)

---

### Project with Git Dependencies

**Nix (buildRustPackage):**
```nix
rustPlatform.buildRustPackage {
  src = ./.;
  cargoLock = {
    lockFile = ./Cargo.lock;
    outputHashes = {
      "git-dep-1-0.1.0" = "sha256-aaa...";
      "git-dep-2-0.2.0" = "sha256-bbb...";
      # Manual hash for EACH git dep
    };
  };
}
```

**Nix (crane):**
```nix
craneLib.buildPackage {
  src = ./.;
  # Git deps handled automatically!
}
```

**Guix (new approach):**
```scheme
;;; rust-crates.scm

;; Define git source with commit in identifier
(define rust-git-dep-1-0.1.0.abc123
  (origin
    (method git-fetch)
    (uri (git-reference
          (url "https://github.com/user/git-dep-1")
          (commit "abc123")))
    (sha256 (base32 "..."))))

;; Add to lookup table
(define lookup-cargo-inputs
  `((rust-git-dep-1-0.1.0.abc123 . ,(list ...))
    (rust-my-project-1.0.0 . ,(list
      rust-git-dep-1-0.1.0.abc123
      rust-git-dep-2-0.2.0.def456))
    ...))
```

```scheme
;;; rust-sources.scm

(define-public rust-git-dep-1
  (package
    (name "rust-git-dep-1")
    (version (git-version "0.1.0" "0" "abc123"))
    (source rust-git-dep-1-0.1.0.abc123)
    (inputs (cargo-inputs 'rust-git-dep-1-0.1.0.abc123))
    ...))

;; Main package patches Cargo.toml
(define-public rust-my-project
  (package
    ...
    (arguments
     (list
      #:phases
      #~(modify-phases %standard-phases
          (add-after 'unpack 'patch-cargo-toml
            (lambda _
              (substitute* "Cargo.toml"
                (("git = .*") "")
                (("rev = .*") "version = \"*\"")))))))
    (inputs (cargo-inputs 'rust-my-project-1.0.0))
    ...))
```

**Winner:** Nix/Crane (automatic git dep handling)

---

### Workspace with Multiple Crates

**Nix (crane):**
```nix
# Just works - builds entire workspace
craneLib.buildPackage { src = ./.; }

# Or build specific member
craneLib.buildPackage {
  src = ./.;
  cargoExtraArgs = "-p specific-crate";
}
```

**Guix (new approach):**
```scheme
;;; rust-crates.scm
(define lookup-cargo-inputs
  `((rust-workspace.abc123 . ,(list
      rust-dep-1
      rust-dep-2))
    ...))

;;; rust-sources.scm

;; Single package definition builds all members
(define-public rust-workspace
  (package
    (name "rust-workspace")
    (source ...)
    (arguments
     (list #:skip-build? #t
           #:cargo-package-crates
           ''("crate1" "crate2" "crate3")))
    (inputs (cargo-inputs 'rust-workspace.abc123))
    ...))

;; Aliases for each member
(define rust-crate1 rust-workspace)
(define rust-crate2 rust-workspace)
(define rust-crate3 rust-workspace)
```

**Winner:** Tie (both handle it, different approaches)

---

### Caching & Rebuilds

**Nix (crane/naersk):**
- Dependencies cached as single artifact
- Change any dep → rebuild all deps
- Change project code → only rebuild project

**Nix (cargo2nix/crate2nix):**
- Each crate cached individually
- Change one dep → rebuild only that crate + dependents
- Maximum cache reuse

**Guix:**
- Each crate is a substitutable package
- Change one dep → rebuild only that + dependents
- Cross-project sharing (same rust-serde used everywhere)

**Winner:** Guix & cargo2nix/crate2nix (finest granularity)

---

### Reproducibility

**Nix:**
- Hash-based verification at various levels
- Flakes provide lockfile for Nix inputs
- Cargo.lock provides Rust dep pinning

**Guix:**
- Every package has explicit hash
- Full dependency graph in Scheme code
- Time-machine feature for historical builds
- Bootstrappable (can rebuild entire toolchain from source)

**Winner:** Guix (slightly, due to bootstrappability philosophy)

---

## Key Philosophical Differences

### Nix: "Make it Work Easily"
- Multiple tools for different needs
- Pragmatic: crane/naersk let Cargo do the heavy lifting
- Flexibility in granularity choice
- Lower barrier to entry for simple cases

### Guix: "Every Crate is a Package"
- Single consistent model
- More upfront work, but maximum transparency
- Every dependency is inspectable and overridable
- Fits Guix's "packages all the way down" philosophy

---

## Practical Recommendations

### Use Nix/Crane when:
- You want minimal setup for a Rust project
- You have many git dependencies
- You're packaging your own project (not for a distro)
- CI/CD speed is critical

### Use Nix/cargo2nix when:
- You want per-crate caching
- You're building for nixpkgs distribution
- You need fine-grained control over each crate

### Use Guix when:
- You're contributing to Guix proper
- You need the full transparency/auditability
- You want cross-project crate sharing
- Bootstrappability matters to you
- You're building for GuixSD/Guix distribution

---

## The Git Dependencies Problem: A Deeper Look

Both systems struggle with git dependencies because:

1. **No content hash in Cargo.lock** - Git deps only have commit SHA, not content hash
2. **Network required** - Must fetch to compute hash
3. **Workspace complexity** - Git dep might be a workspace with multiple crates

### Nix Solutions:
- **buildRustPackage:** Manual `outputHashes` (tedious but explicit)
- **crane:** Automatic fetching during eval (convenient but impure-ish)
- **cargo2nix:** Bakes hashes into generated Cargo.nix

### Guix Solution:
- Always manual: define package with `git-fetch` origin
- Patch Cargo.toml to remove git refs
- Most explicit, most work

---

## Conclusion

| If you value... | Choose... |
|-----------------|-----------|
| Ease of use | Nix + Crane |
| Maximum caching granularity | Guix or Nix + cargo2nix |
| Automatic git dep handling | Nix + Crane |
| Transparency & auditability | Guix |
| Distribution packaging | Guix (for Guix) or cargo2nix (for Nix) |
| Quick prototyping | Nix + Crane |
| Bootstrappability | Guix |

Both ecosystems are actively evolving. Guix's recent workspace support and development snapshots pattern show it's addressing pain points. Nix's crane has become the de facto standard for its ergonomics. The "best" choice depends entirely on your priorities and context.
