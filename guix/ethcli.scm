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
  #:use-module (guix build-system gnu)
  #:use-module ((guix licenses)
                #:prefix license:)
  #:use-module (gnu packages base)           ; coreutils
  #:use-module (gnu packages compression)   ; tar, gzip
  #:use-module (gnu packages linux)         ; eudev (libudev)
  #:use-module (gnu packages pkg-config)
  #:use-module (rust-xous-toolchain)        ; provides cargo/rustc
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
    (build-system gnu-build-system)
    (arguments
     (list
      #:phases
      #~(modify-phases %standard-phases
          (delete 'configure)
          (delete 'check)

          ;; Set up crates.io vendor directory from declared inputs
          (add-after 'unpack 'setup-vendor
            (lambda* (#:key inputs #:allow-other-keys)
              (use-modules (ice-9 popen)
                           (ice-9 rdelim))
              (let ((vendor-dir (string-append (getcwd) "/vendor")))
                (mkdir-p vendor-dir)
                (for-each
                 (lambda (input)
                   (let* ((name (car input))
                          (path (cdr input)))
                     (when (string-prefix? "crate-" name)
                       (let* ((file-name (basename path))
                              ;; Strip "rust-" prefix and ".tar.gz" suffix
                              (crate-name (substring file-name 5
                                                     (- (string-length
                                                         file-name) 7)))
                              (crate-dir (string-append vendor-dir
                                                        "/" crate-name))
                              (port (open-pipe* OPEN_READ
                                                "sha256sum" path))
                              (checksum-line (read-line port))
                              (_ (close-pipe port))
                              (checksum (car (string-split
                                              checksum-line #\space))))
                         (mkdir-p crate-dir)
                         (invoke "tar" "xzf" path
                                 "-C" crate-dir
                                 "--strip-components=1")
                         (call-with-output-file
                             (string-append crate-dir
                                            "/.cargo-checksum.json")
                           (lambda (port)
                             (format port
                                     "{\"files\":{},\"package\":\"~a\"}"
                                     checksum)))))))
                 inputs))))

          ;; Configure cargo for offline vendored builds
          (add-after 'setup-vendor 'setup-cargo
            (lambda* (#:key inputs #:allow-other-keys)
              (let ((vendor-dir (string-append (getcwd) "/vendor"))
                    (rust (assoc-ref inputs "rust")))
                (setenv "HOME" (getcwd))
                (setenv "CARGO_HOME"
                        (string-append (getcwd) "/.cargo"))
                (mkdir-p (getenv "CARGO_HOME"))
                (setenv "PATH"
                        (string-append rust "/bin:" (getenv "PATH")))
                (call-with-output-file ".cargo/config.toml"
                  (lambda (port)
                    (display
                     (string-append
                      "[source.crates-io]\n"
                      "replace-with = \"vendored-sources\"\n\n"
                      "[source.vendored-sources]\n"
                      "directory = \"" vendor-dir "\"\n\n"
                      "[net]\n"
                      "offline = true\n")
                     port))))))

          ;; Build with cargo
          (replace 'build
            (lambda _
              (setenv "ETHCLI_VERSION" #$version)
              (invoke "cargo" "build" "--release" "--offline")))

          ;; Install the binary
          (replace 'install
            (lambda* (#:key outputs #:allow-other-keys)
              (let ((bin (string-append (assoc-ref outputs "out")
                                        "/bin")))
                (mkdir-p bin)
                (install-file "target/release/ethcli" bin)))))))
    (native-inputs
     `(("rust" ,rust-xous-toolchain)
       ("pkg-config" ,pkg-config)
       ("tar" ,tar)
       ("gzip" ,gzip)
       ("coreutils" ,coreutils)
       ;; All crate tarballs as inputs
       ,@(map (lambda (crate)
                `(,(string-append "crate-"
                                  (origin-file-name crate)) ,crate))
              %ethcli-crate-inputs)))
    (inputs (list eudev))
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
