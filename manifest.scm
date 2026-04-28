(use-modules (rust-xous-toolchain)
             (bao-vendor)
             (gnu packages version-control)
             (gnu packages base)
             (gnu packages bash)
             (gnu packages commencement)
             (gnu packages linux)
             (gnu packages nss)
             (gnu packages pkg-config)
             (gnu packages tls)
             (gnu packages compression))

(packages->manifest
 (list rust-xous-toolchain
       xous-vendor-setup
       xous-build
       git
       tar
       gzip
       bash
       nss-certs
       openssl
       coreutils
       grep
       findutils
       sed
       diffutils
       which
       ;; Needed for host-side C compilation (zstd-sys, ring, etc.)
       gcc-toolchain
       ;; Needed for crates that link against system libraries (e.g. libudev-sys)
       pkg-config
       eudev))
