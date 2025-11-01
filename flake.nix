{
  description = "Xous development environment with custom riscv32imac-unknown-xous-elf target";

  inputs = {
    nixpkgs.url = "https://flakehub.com/f/NixOS/nixpkgs/0.2511.905687";
    rust-overlay.url = "https://flakehub.com/f/oxalica/rust-overlay/0.1.2040";
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
    }:
    let
      # Rust version must match available sysroot from betrusted-io/rust releases
      rustVersion = "1.92.0";
      xousSysrootUrl = "https://github.com/betrusted-io/rust/releases/download/${rustVersion}.1/riscv32imac-unknown-xous_${rustVersion}.zip";

      overlays = [
        (import rust-overlay)
        (final: prev: {
          # Use specific Rust version matching the Xous sysroot
          rustToolchain = prev.rust-bin.stable.${rustVersion}.default.override {
            targets = [ "riscv32imac-unknown-none-elf" ];
          };
        })
      ];

      # Systems supported
      allSystems = [
        "x86_64-linux" # 64-bit Intel/AMD Linux
        "aarch64-linux" # 64-bit ARM Linux
        "x86_64-darwin" # 64-bit Intel macOS
        "aarch64-darwin" # 64-bit ARM macOS
      ];

      forAllSystems =
        f:
        nixpkgs.lib.genAttrs allSystems (
          system:
          f {
            pkgs = import nixpkgs { inherit overlays system; };
          }
        );
    in
    {
      devShells = forAllSystems (
        { pkgs }:
        let
          # Download and prepare the Xous sysroot
          xousSysroot = pkgs.stdenv.mkDerivation {
            name = "xous-sysroot-${rustVersion}";
            src = pkgs.fetchurl {
              url = xousSysrootUrl;
              sha256 = "sha256-/H5yEERO4zyWlWxAFe6v6WpYjBLWg4WtdjpNHzxuyBE=";
            };
            nativeBuildInputs = [ pkgs.unzip ];
            unpackPhase = "unzip $src -d $out";
            postUnpack = ''
              echo "${rustVersion}" > $out/lib/rustlib/riscv32imac-unknown-xous-elf/RUST_VERSION
            '';
            dontInstall = true;
            dontBuild = true;
          };

          # Create a merged sysroot directory that combines the Rust toolchain with Xous target
          mergedSysroot = pkgs.runCommand "merged-sysroot-${rustVersion}" {} ''
            mkdir -p $out/lib/rustlib
            
            # Symlink everything from the original sysroot
            for item in ${pkgs.rustToolchain}/lib/rustlib/*; do
              ln -s "$item" "$out/lib/rustlib/$(basename $item)"
            done
            
            # Add the Xous target
            ln -s ${xousSysroot}/lib/rustlib/riscv32imac-unknown-xous-elf $out/lib/rustlib/
          '';

          # Create a wrapped Rust toolchain where rustc --print sysroot returns mergedSysroot
          wrappedRustToolchain = pkgs.symlinkJoin {
            name = "rust-toolchain-wrapped-${rustVersion}";
            paths = [ pkgs.rustToolchain ];
            buildInputs = [ pkgs.makeWrapper ];
            postBuild = ''
              # Wrap rustc to use merged sysroot
              rm $out/bin/rustc
              makeWrapper ${pkgs.rustToolchain}/bin/rustc $out/bin/rustc \
                --add-flags "--sysroot ${mergedSysroot}"
            '';
          };

          # Wrapper script for cargo that sets the sysroot for xous target
          cargoXous = pkgs.writeShellScriptBin "cargo-xous" ''
            # When building for riscv32imac-unknown-xous-elf, use the merged sysroot
            if [[ "$*" == *"riscv32imac-unknown-xous-elf"* ]]; then
              export RUSTFLAGS="--sysroot ${mergedSysroot} ''${RUSTFLAGS:-}"
            fi
            exec cargo "$@"
          '';

          # Create a .cargo/config.toml snippet for the user
          cargoConfigSnippet = pkgs.writeText "cargo-config-xous.toml" ''
            [target.riscv32imac-unknown-xous-elf]
            rustflags = ["--sysroot", "${mergedSysroot}"]
          '';
        in
        {
          default = pkgs.mkShell {
            packages =
              (with pkgs; [
                # Wrapped Rust toolchain with merged sysroot (includes Xous target)
                wrappedRustToolchain
                pkg-config
                openssl
                unzip
              ])
              ++ pkgs.lib.optionals pkgs.stdenv.isDarwin (with pkgs; [ libiconv ])
              ++ pkgs.lib.optionals pkgs.stdenv.isLinux (with pkgs; [ systemd.dev ]);

            # Set environment variables for Xous target builds
            XOUS_SYSROOT = "${mergedSysroot}";

            shellHook = ''
              # Set CARGO_HOME if not already set (needed by xtask verifier)
              if [ -z "$CARGO_HOME" ]; then
                export CARGO_HOME="$HOME/.cargo"
              fi

              echo "Xous development environment (Rust ${rustVersion})"
              echo ""
              echo "Available targets:"
              echo "  - riscv32imac-unknown-none-elf (kernel/loader)"
              echo "  - riscv32imac-unknown-xous-elf (apps/services)"
              echo ""
              echo "✓ Xous sysroot: $(rustc --print sysroot)"
              echo "✓ CARGO_HOME: $CARGO_HOME"
              echo ""
              echo "Build example:"
              echo "  cargo xtask dabao helloworld"
            '';
          };
        }
      );
    };
}
