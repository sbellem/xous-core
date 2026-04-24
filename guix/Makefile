# Makefile for xous-core Guix development environment
#
# Run from guix/ directory, or from repo root via: make -C guix <target>
#
# Usage:
#   make shell               # Enter dev shell
#   make boot0               # Build bao1x-boot0
#   make dabao               # Build dabao firmware
#   make firmware             # Build all firmware
#   make all-dry              # Dry-run all packages
#
#   make boot0 SUBS=baobit ROOT=boot0
#   make boot0 CHECK=1

CHANNELS ?= ../channels.scm
DRY ?=
ROOT ?=
CHECK ?=

# Substitute URL definitions
SUBS_OFFICIAL   := https://ci.guix.gnu.org https://bordeaux.guix.gnu.org
SUBS_BAOBIT     := https://guix.baobit.one
SUBS_COMMUNITY  := https://ci.guix.moe
SUBS_ALL        := $(SUBS_BAOBIT) $(SUBS_COMMUNITY) $(SUBS_OFFICIAL)

# Default: use all substitutes
SUBS ?= all

# Resolve preset names to URLs
ifeq ($(SUBS),all)
  _SUBS := $(SUBS_ALL)
else ifeq ($(SUBS),official)
  _SUBS := $(SUBS_OFFICIAL)
else ifeq ($(SUBS),baobit)
  _SUBS := $(SUBS_BAOBIT)
else ifeq ($(SUBS),community)
  _SUBS := $(SUBS_COMMUNITY)
else ifeq ($(SUBS),none)
  _SUBS :=
else
  # Raw URL passthrough for custom values
  _SUBS := $(SUBS)
endif

# Build command base
TM := guix time-machine --channels=$(CHANNELS) -- build -L .
ifdef DRY
  TM += --dry-run
endif
ifneq ($(_SUBS),)
  TM += --substitute-urls="$(_SUBS)"
endif
ifdef ROOT
  TM += --root=$(ROOT)
endif
ifdef CHECK
  TM += --check --keep-failed
endif

# Substitute flags for shell (same resolution, different base command)
_SHELL_SUBS := $(if $(_SUBS),--substitute-urls="$(_SUBS)")

# Vendor setup
VENDOR_GCROOT   := ../.cargo/vendor.gcroot
VENDOR_CFG      := ../.cargo/vendor-config.toml

.PHONY: help shell \
        rv32imac-none rv32imac-xous toolchain \
        boot0 boot1 alt-boot1 bootloader baremetal-dabao \
        dabao dabao-helloworld dabao-ethapp baosec firmware ethcli \
        rustfilt boot0-elf-analysis boot1-elf-analysis \
        alt-boot1-elf-analysis baremetal-dabao-elf-analysis \
        dabao-elf-analysis baosec-elf-analysis \
        all-dry dry-toolchain \
        vendor-setup vendor-clean

help:
	@echo "Targets:"
	@echo "  Dev shell:"
	@echo "    shell              - enter reproducible dev shell"
	@echo "  Sysroots & toolchain (from baobit channel):"
	@echo "    rv32imac-none      - bare-metal sysroot"
	@echo "    rv32imac-xous      - xous sysroot"
	@echo "    toolchain          - rust-xous-toolchain (both sysroots)"
	@echo "  Firmware:"
	@echo "    boot0 boot1 alt-boot1 baremetal-dabao"
	@echo "    dabao dabao-helloworld dabao-ethapp baosec"
	@echo "  Host tools:"
	@echo "    ethcli             - Ethereum wallet CLI (host binary)"
	@echo "    bootloader         - all bootloaders (boot0 + boot1 + alt-boot1)"
	@echo "    firmware           - all firmware (via manifest)"
	@echo "  Offline development:"
	@echo "    vendor-setup       - vendor deps for offline cargo xtask"
	@echo "    vendor-clean       - remove vendored deps and restore config"
	@echo "  ELF analysis (for debugging panics):"
	@echo "    rustfilt                       - build rustfilt demangler"
	@echo "    boot0-elf-analysis             - assembly listing for boot0"
	@echo "    boot1-elf-analysis             - assembly listing for boot1"
	@echo "    alt-boot1-elf-analysis         - assembly listing for alt-boot1"
	@echo "    baremetal-dabao-elf-analysis    - assembly listing for baremetal-dabao"
	@echo "    dabao-elf-analysis             - assembly listing for dabao"
	@echo "    baosec-elf-analysis            - assembly listing for baosec"
	@echo ""
	@echo "Options:"
	@echo "  CHANNELS=file.scm    - use different channels file"
	@echo "  DRY=1                - dry-run only"
	@echo "  SUBS=all             - all substitutes (default)"
	@echo "  SUBS=official        - official Guix substitutes only"
	@echo "  SUBS=baobit          - baobit substitute only"
	@echo "  SUBS=community       - community substitute (ci.guix.moe) only"
	@echo "  SUBS=none            - build from source"
	@echo "  SUBS='url ...'       - custom substitute URLs"
	@echo "  ROOT=name            - create GC root"
	@echo "  CHECK=1              - verify reproducibility"

# Dev shell (starts in repo root)
shell:
	cd .. && guix time-machine --channels=channels.scm -- shell -m manifest.scm $(_SHELL_SUBS)

# Sysroots & toolchain (from baobit channel)
rv32imac-none:
	$(TM) -e '(@ (embedded) rust-sysroot-riscv32imac-none-elf)'

rv32imac-xous:
	$(TM) -e '(@ (rust-xous-toolchain) rust-sysroot-riscv32imac-xous-elf)'

toolchain:
	$(TM) -e '(@ (rust-xous-toolchain) rust-xous-toolchain)'

# Firmware
boot0:
	$(TM) -e '(@ (bao) bao1x-boot0)'

boot1:
	$(TM) -e '(@ (bao) bao1x-boot1)'

alt-boot1:
	$(TM) -e '(@ (bao) bao1x-alt-boot1)'

bootloader: boot0 boot1 alt-boot1

baremetal-dabao:
	$(TM) -e '(@ (bao) bao1x-baremetal-dabao)'

dabao:
	$(TM) -e '(@ (bao) dabao)'

dabao-helloworld:
	$(TM) -e '(@ (bao) dabao-helloworld)'

dabao-ethapp:
	$(TM) -e '(@ (bao) dabao-ethapp)'

ethcli:
	$(TM) -e '(@ (ethcli) ethcli)'

baosec:
	$(TM) -e '(@ (bao) baosec)'

firmware:
	guix time-machine --channels=$(CHANNELS) -- build -L . -m firmware-manifest.scm $(if $(DRY),--dry-run) $(if $(_SUBS),--substitute-urls="$(_SUBS)") $(if $(ROOT),--root=$(ROOT)) $(if $(CHECK),--check --keep-failed)

# ELF analysis (tools from baobit channel)
rustfilt:
	$(TM) -e '(@ (tools) rustfilt)'

boot0-elf-analysis:
	$(TM) -e '((@ (tools) elf-analyzer) (@ (bao) bao1x-boot0))'

boot1-elf-analysis:
	$(TM) -e '((@ (tools) elf-analyzer) (@ (bao) bao1x-boot1))'

alt-boot1-elf-analysis:
	$(TM) -e '((@ (tools) elf-analyzer) (@ (bao) bao1x-alt-boot1))'

baremetal-dabao-elf-analysis:
	$(TM) -e '((@ (tools) elf-analyzer) (@ (bao) bao1x-baremetal-dabao))'

dabao-elf-analysis:
	$(TM) -e '((@ (tools) elf-analyzer) (@ (bao) dabao))'

baosec-elf-analysis:
	$(TM) -e '((@ (tools) elf-analyzer) (@ (bao) baosec))'

# Shortcuts
all-dry:
	$(MAKE) DRY=1 rv32imac-none rv32imac-xous toolchain boot0

dry-toolchain:
	$(MAKE) DRY=1 toolchain

# Offline vendor setup
vendor-setup:
	guix time-machine --channels=$(CHANNELS) -- build -L . \
	    $(if $(_SUBS),--substitute-urls="$(_SUBS)") \
	    --root=$(VENDOR_GCROOT) \
	    -e '(@ (bao-vendor) xous-vendor-deps)'
	cp $$(readlink -f $(VENDOR_GCROOT))/vendor-config.toml $(VENDOR_CFG)
	@echo "Vendor setup complete."
	@echo "Use: cargo xtask <target> --config .cargo/vendor-config.toml --no-verify"

vendor-clean:
	rm -f $(VENDOR_GCROOT) $(VENDOR_CFG)
	@echo "Vendor removed."
