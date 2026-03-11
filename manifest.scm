(use-modules (rust-xous-toolchain)
             (gnu packages version-control)
             (gnu packages base)
             (gnu packages bash)
             (gnu packages nss)
             (gnu packages compression))

(packages->manifest
 (list rust-xous-toolchain
       git
       tar
       gzip
       bash
       nss-certs
       coreutils
       grep
       findutils
       sed
       diffutils
       which))
