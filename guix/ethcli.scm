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
  #:use-module (gnu packages linux)         ; eudev (libudev)
  #:use-module (gnu packages pkg-config)
  #:use-module (bao-config)
  #:use-module (ethcli-crates))

(define-public ethcli
  (package
    (name "ethcli")
    (version %xous-git-describe)
    (source
     (local-file (string-append %repo-root
                                "/services/ethapp/tools/ethcli")
                 #:recursive? #t
                 #:select? (lambda (file stat)
                             (not (string-contains file "/target/")))))
    (build-system cargo-build-system)
    (arguments
     (list
      #:cargo-inputs %ethcli-crate-inputs
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
