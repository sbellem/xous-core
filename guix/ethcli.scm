;;; GNU Guix package definition for ethcli
;;;
;;; ethcli is the host-side CLI for the Baochip-1x Ethereum hardware wallet.
;;; It communicates with the device over USB CDC-ACM serial.
;;;
;;; Build:
;;;   make -C guix ethcli
;;;
;;; Or manually:
;;;   guix time-machine -C channels.scm -- build -L guix -e '(@ (ethcli) ethcli)'

(define-module (ethcli)
  #:use-module (guix packages)
  #:use-module (guix gexp)
  #:use-module (guix build-system cargo)
  #:use-module ((guix licenses)
                #:prefix license:)
  #:use-module (gnu packages crates-io)
  #:use-module (gnu packages linux)         ; eudev (libudev)
  #:use-module (gnu packages pkg-config)
  #:use-module (bao-config))

;;; TODO: The cargo-build-system requires all transitive Rust crate deps
;;; declared as #:cargo-inputs.  Generate them with:
;;;
;;;   cd services/ethapp/tools/ethcli
;;;   guix import crate -r clap@4 serialport@4 ureq@2 serde_json@1 hex@0.4 anyhow@1
;;;
;;; Then paste the resulting (package ...) definitions here or into a
;;; separate ethcli-crates.scm, and reference them in #:cargo-inputs below.
;;;
;;; For now, this package definition uses gnu-build-system with cargo
;;; invoked manually, which avoids needing every transitive crate declared
;;; but requires network access (or a pre-populated cargo registry).

(define-public ethcli
  (package
    (name "ethcli")
    (version %xous-git-describe)
    (source
     (local-file (string-append (dirname (current-source-directory))
                                "/services/ethapp/tools/ethcli")
                 #:recursive? #t
                 #:select? (lambda (file stat)
                             (not (string-contains file "/target/")))))
    (build-system cargo-build-system)
    (arguments
     (list
      ;; TODO: populate with transitive crate deps from `guix import crate`
      #:cargo-inputs '()
      #:phases
      #~(modify-phases %standard-phases
          (add-after 'unpack 'set-version
            (lambda _
              ;; Inject version for build.rs (no git in build sandbox)
              (setenv "ETHCLI_VERSION" #$version))))))
    (native-inputs (list pkg-config))
    (inputs (list eudev))                   ; libudev for serialport USB enumeration
    (home-page "https://github.com/betrusted-io/xous-core")
    (synopsis "Host CLI for the Baochip-1x Ethereum hardware wallet")
    (description
     "ethcli is the host-side companion tool for the Baochip-1x Ethereum
hardware wallet.  It communicates with the device over USB CDC-ACM serial
to manage keys, sign transactions, query chain state, and broadcast
signed transactions.  Supports air-gapped workflows via separate
build-tx / sign-tx / publish commands.")
    (license (list license:asl2.0 license:expat))))

ethcli
