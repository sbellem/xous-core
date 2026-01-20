{
  description = "Xous development environment";

  inputs = {
    nixpkgs.url = "https://flakehub.com/f/NixOS/nixpkgs/0.2511.905687";
    rust-xous.url = "github:sbellem/rust-xous-flake?rev=7afb9744e6393493a9357d1a64ec108780880bd0";
    rust-overlay.url = "https://flakehub.com/f/oxalica/rust-overlay/0.1.2040";
    crane.url = "github:ipetkov/crane/0bda7e7d005ccb5522a76d11ccfbf562b71953ca";
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-xous,
      rust-overlay,
      crane,
    }:
    let
      # git describe --abbrev=0
      gitTag = "0.9.16";
      # git rev-list --count $(git describe --abbrev=0)
      gitTagRevCount = 7276;

      gitHash = if self ? rev
        then builtins.substring 0 9 self.rev
        else "000000000";

      sinceTagRevCount = if self ? revCount
        then toString (self.revCount - gitTagRevCount)
        else "0";

      xousVersion = "v${gitTag}-${sinceTagRevCount}-g${gitHash}";

      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      forAllSystems =
        f:
        nixpkgs.lib.genAttrs systems (
          system:
          f {
            pkgs = import nixpkgs {
              inherit system;
              overlays = [ (import rust-overlay) ];
            };
            rustToolchain = rust-xous.packages.${system}.rustToolchain;
            craneLib = (crane.mkLib nixpkgs.legacyPackages.${system}).overrideToolchain
              rust-xous.packages.${system}.rustToolchain;
          }
        );
    in
    {
      packages = forAllSystems (
        { pkgs, rustToolchain, craneLib }:
        let
          # Clean source to only include cargo-relevant files
          src = craneLib.cleanCargoSource self;

          # Vendor all dependencies (including git deps) - this runs in a FOD with network access
          vendoredDeps = craneLib.vendorCargoDeps {
            inherit src;
          };

          # Common postPatch to replace SemVer::from_git() with hardcoded version
          patchSemver = ''
            substituteInPlace tools/src/sign_image.rs \
              --replace-fail 'SemVer::from_git()?.into()' '"${xousVersion}".parse::<SemVer>().unwrap().into()'
          '';

          # Patch versioning.rs to use XOUS_VERSION env var instead of git describe
          patchVersioning = ''
            substituteInPlace xtask/src/versioning.rs \
              --replace-fail 'let gitver = output.stdout;' \
                             'let gitver = std::env::var("XOUS_VERSION").map(|s| s.into_bytes()).unwrap_or(output.stdout);'
          '';

          # Configure cargo to use vendored deps
          configureVendoring = ''
            mkdir -p .cargo
            # Append vendoring config to existing config
            cat ${vendoredDeps}/config.toml >> .cargo/config.toml
          '';

          # Common environment for reproducible Rust builds
          reproducibleRustEnv = ''
            export HOME=$PWD
            export CARGO_HOME=$PWD/.cargo
            mkdir -p $CARGO_HOME
            export XOUS_VERSION="${xousVersion}"
            # Reproducibility flags
            export CARGO_INCREMENTAL=0
            export RUSTFLAGS="-C codegen-units=1 --remap-path-prefix=$PWD=/build"
            # Fixed timestamp for reproducibility
            export SOURCE_DATE_EPOCH=1
          '';

          # Helper to create build derivations
          mkXousBuild = { pname, xtaskCmd, targetDir ? "riscv32imac-unknown-none-elf" }:
            pkgs.stdenv.mkDerivation {
              inherit pname;
              version = "0.1.0";
              src = self;  # Use full source for xtask builds
              nativeBuildInputs = [ rustToolchain ];

              postPatch = patchSemver + patchVersioning;

              configurePhase = configureVendoring;

              buildPhase = ''
                ${reproducibleRustEnv}
                cargo xtask ${xtaskCmd} --offline --no-verify
              '';

              installPhase = ''
                mkdir -p $out
                cp target/${targetDir}/release/*.uf2 $out/ || true
                cp target/${targetDir}/release/*.img $out/ || true
                cp target/${targetDir}/release/*.bin $out/ || true
              '';
            };

          dabao-helloworld = mkXousBuild {
            pname = "dabao-helloworld";
            xtaskCmd = "dabao helloworld";
            targetDir = "riscv32imac-unknown-xous-elf";
          };

          bao1x-boot0 = mkXousBuild {
            pname = "bao1x-boot0";
            xtaskCmd = "bao1x-boot0";
          };

          bao1x-alt-boot1 = mkXousBuild {
            pname = "bao1x-alt-boot1";
            xtaskCmd = "bao1x-alt-boot1";
          };

          bao1x-boot1 = mkXousBuild {
            pname = "bao1x-boot1";
            xtaskCmd = "bao1x-boot1";
          };
        in
        {
          # Main packages
          inherit dabao-helloworld bao1x-boot0 bao1x-alt-boot1 bao1x-boot1;

          # bootloader stage 1
          boot1 = pkgs.runCommand "boot1" {} ''
            mkdir -p $out
            cp -r ${bao1x-boot1}/* ${bao1x-alt-boot1}/* $out
          '';

          # Combined bootloader package (boot0 + boot1)
          bootloader = pkgs.runCommand "bootloader" {} ''
            mkdir -p $out
            cp -r ${bao1x-boot0}/* ${bao1x-boot1}/* ${bao1x-alt-boot1}/* $out
          '';

          # CI dependency caching - bundles shared dependencies
          ci-deps = pkgs.symlinkJoin {
            name = "xous-ci-deps";
            paths = [
              rustToolchain
              vendoredDeps
            ];
          };

          # Aliases
          dabao = dabao-helloworld;

          default = dabao-helloworld;
        }
      );

      devShells = forAllSystems (
        { pkgs, rustToolchain, craneLib }:
        let
          nightlyRustToolchain = pkgs.rust-bin.selectLatestNightlyWith (toolchain:
            toolchain.default.override {
              extensions = [ "rustfmt" ];
            }
          );
        in
        {
          default = pkgs.mkShell {
            packages = [ rustToolchain ];
            shellHook = ''
              echo "──────────────────────────────────────────────────────────────"
              echo "Xous development environment"
              echo "  $(rustc --version)"
              echo "  xous-core ${xousVersion}"
              echo ""
              echo "Installed Rust targets:"
              ls "$(rustc --print sysroot)/lib/rustlib" | grep -v -E '^(etc|src)$' | sed 's/^/  • /'
              echo ""
              echo "Build commands:"
              echo "  • nix build .#dabao-helloworld"
              echo "  • nix build .#bootloader"
              echo "  • nix build .#bao1x-boot0"
              echo "  • nix build .#bao1x-boot1"
              echo "  • nix build .#bao1x-alt-boot1"
              echo ""
              echo "Aliases:"
              echo "  • nix build .#dabao"
              echo "  • nix build .#boot1"
              echo ""
              echo "For formatting checks, use: nix develop .#nightly"
              echo "──────────────────────────────────────────────────────────────"
            '';
          };

          nightly = pkgs.mkShell {
            packages = [ nightlyRustToolchain ];
            shellHook = ''
              echo "──────────────────────────────────────────────────────────────"
              echo "Xous nightly development environment"
              echo "  $(rustc --version)"
              echo "  $(cargo --version)"
              echo "  xous-core ${xousVersion}"
              echo ""
              echo "Formatting commands:"
              echo "  • cargo fmt --check"
              echo "  • cargo fmt"
              echo "──────────────────────────────────────────────────────────────"
            '';
          };
        }
      );
    };
}
