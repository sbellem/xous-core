;;; Vendored dependency tree for offline xous-core development.
;;;
;;; Produces a store path with vendor/crates-io/ and vendor/git/ subdirectories
;;; containing all dependencies needed by `cargo xtask`.
;;;
;;; Usage:
;;;   guix time-machine -C channels.scm -- build -L guix -e '(@ (bao-vendor) xous-vendor-deps)'
;;;   make vendor-setup   (builds + symlinks + generates .cargo/vendor-config.toml)

(define-module (bao-vendor)
  #:use-module (guix packages)
  #:use-module (guix build-system trivial)
  #:use-module (guix gexp)
  #:use-module (guix utils)
  #:use-module ((guix licenses)
                #:prefix license:)
  #:use-module (gnu packages base)
  #:use-module (gnu packages bash)
  #:use-module (gnu packages compression)
  #:use-module (bao)
  #:use-module (bao-crates)
  #:use-module (bao-config))

(define-public xous-vendor-deps
  (package
    (name "xous-vendor-deps")
    (version %xous-git-describe)
    (source #f)
    (build-system trivial-build-system)
    (arguments
     (list
      #:modules '((guix build utils)
                  (ice-9 popen)
                  (ice-9 rdelim)
                  (ice-9 textual-ports)
                  (ice-9 regex)
                  (srfi srfi-1))
      #:builder
      #~(begin
          (use-modules (guix build utils)
                       (ice-9 popen)
                       (ice-9 rdelim)
                       (ice-9 textual-ports)
                       (ice-9 regex)
                       (srfi srfi-1))
          (let* ((out (assoc-ref %outputs "out"))
                 (tar (string-append (assoc-ref %build-inputs "tar") "/bin/tar"))
                 (coreutils (assoc-ref %build-inputs "coreutils"))
                 (gzip (assoc-ref %build-inputs "gzip"))
                 (crates-io-dir (string-append out "/vendor/crates-io"))
                 (git-dir (string-append out "/vendor/git"))
                 (mappings '#$%git-vendor-mappings)
                 (source-keys '#$%git-source-keys))

            ;; tar needs gzip on PATH; sha256sum needs coreutils
            (setenv "PATH" (string-append gzip "/bin:" coreutils "/bin"))

            (mkdir-p crates-io-dir)
            (mkdir-p git-dir)

            ;; Phase A: Extract crate tarballs into vendor/crates-io/
            ;; Package checksum is the sha256 of the .crate tarball —
            ;; Cargo uses it to verify vendored crates match Cargo.lock.
            (for-each
             (lambda (input)
               (let* ((name (car input))
                      (path (cdr input)))
                 (when (string-prefix? "crate-" name)
                   (let* ((file-name (basename path))
                          ;; Strip "rust-" prefix (5 chars) and ".tar.gz" suffix
                          (crate-name (substring file-name 5
                                                 (- (string-length file-name) 7)))
                          (crate-dir (string-append crates-io-dir "/" crate-name))
                          (port (open-pipe* OPEN_READ "sha256sum" path))
                          (checksum-line (read-line port))
                          (_ (close-pipe port))
                          (checksum (car (string-split checksum-line #\space))))
                     (mkdir-p crate-dir)
                     (invoke tar "xzf" path "-C" crate-dir
                             "--strip-components=1")
                     (call-with-output-file
                         (string-append crate-dir "/.cargo-checksum.json")
                       (lambda (port)
                         (format port
                                 "{\"files\":{},\"package\":\"~a\"}"
                                 checksum)))))))
             %build-inputs)

            ;; Phase B: Copy git dependency crate subdirs into vendor/git/
            (for-each
             (lambda (input)
               (let* ((name (car input))
                      (path (cdr input)))
                 (when (string-prefix? "git-" name)
                   (let ((mapping (assoc name mappings string=?)))
                     (when mapping
                       (for-each
                        (lambda (crate-entry)
                          (let* ((crate-name (car crate-entry))
                                 (subdir (cdr crate-entry))
                                 (src (if (string=? subdir ".")
                                          path
                                          (string-append path "/" subdir)))
                                 (dest (string-append git-dir "/" crate-name)))
                            (copy-recursively src dest)
                            ;; Fix permissions (store paths are read-only)
                            (for-each (lambda (f) (chmod f #o755))
                                      (find-files dest ".*" #:directories? #t))
                            ;; Clean Cargo.toml: strip [workspace], members,
                            ;; exclude, and [dev-dependencies] sections
                            (for-each
                             (lambda (cargo-toml)
                               (let ((content (call-with-input-file cargo-toml
                                                get-string-all)))
                                 (when (or (string-contains content "[workspace]")
                                           (string-contains content
                                                            "[dev-dependencies]"))
                                   (call-with-output-file cargo-toml
                                     (lambda (port)
                                       (let* ((modified content)
                                              (modified
                                               (regexp-substitute/global
                                                #f "\\[workspace\\]\n?"
                                                modified 'pre 'post))
                                              (modified
                                               (regexp-substitute/global
                                                #f
                                                "members *= *\\[([^]]|\n)*\\]\n?"
                                                modified 'pre 'post))
                                              (modified
                                               (regexp-substitute/global
                                                #f
                                                "exclude *= *\\[([^]]|\n)*\\]\n?"
                                                modified 'pre 'post)))
                                         (let* ((lines (string-split modified
                                                                     #\newline))
                                                (in-dev-deps #f)
                                                (filtered
                                                 (filter
                                                  (lambda (line)
                                                    (cond
                                                     ((string-prefix?
                                                       "[dev-dependencies]"
                                                       (string-trim line))
                                                      (set! in-dev-deps #t) #f)
                                                     ((and in-dev-deps
                                                           (string-prefix?
                                                            "["
                                                            (string-trim line)))
                                                      (set! in-dev-deps #f) #t)
                                                     (in-dev-deps #f)
                                                     (else #t)))
                                                  lines)))
                                           (display (string-join filtered "\n")
                                                    port))))))))
                             (find-files dest "^Cargo\\.toml$"))
                            ;; Stub checksum (same as crates-io)
                            (call-with-output-file
                                (string-append dest "/.cargo-checksum.json")
                              (lambda (port)
                                (display "{\"files\":{}}" port)))))
                        (cdr mapping)))))))
             %build-inputs)

            ;; Phase C: Generate vendor-config.toml
            (call-with-output-file (string-append out "/vendor-config.toml")
              (lambda (port)
                (display "[source.crates-io]\n" port)
                (display "replace-with = \"vendored-crates-io\"\n\n" port)
                ;; Per-git-source entries
                (for-each
                 (lambda (entry)
                   (let ((url (car entry))
                         (param-type (cadr entry))
                         (param-value (caddr entry)))
                     (format port "[source.\"~a?~a=~a\"]\n"
                             url param-type param-value)
                     (format port "git = \"~a\"\n" url)
                     (format port "~a = \"~a\"\n" param-type param-value)
                     (display "replace-with = \"vendored-git\"\n\n" port)))
                 source-keys)
                ;; Vendored source directories
                (display "[source.vendored-crates-io]\n" port)
                (format port "directory = \"~a\"\n\n" crates-io-dir)
                (display "[source.vendored-git]\n" port)
                (format port "directory = \"~a\"\n\n" git-dir)
                (display "[net]\noffline = true\n" port)))))))
    (inputs
     (append
      ;; All crate tarballs
      (map (lambda (crate)
             `(,(string-append "crate-" (origin-file-name crate)) ,crate))
           %bao-crate-inputs)
      ;; All git dependency origins
      %git-dependency-inputs))
    (native-inputs `(("tar" ,tar)
                     ("gzip" ,gzip)
                     ("coreutils" ,coreutils)))
    (home-page "https://github.com/betrusted-io/xous-core")
    (synopsis "Vendored cargo dependencies for offline xous-core development")
    (description
     "Unified vendor tree providing all crates.io and git dependencies needed \
to run @code{cargo xtask} in the xous-core development shell without network \
access.  Contains vendor/crates-io/ (registry crates) and vendor/git/ (git \
dependency crate subdirectories).")
    (license license:asl2.0)))

;;; Shell script that copies vendor-config.toml into the working tree.
;;; Include this in the dev shell manifest alongside xous-vendor-deps.
(define-public xous-vendor-setup
  (package
    (name "xous-vendor-setup")
    (version %xous-git-describe)
    (source #f)
    (build-system trivial-build-system)
    (arguments
     (list
      #:modules '((guix build utils))
      #:builder
      #~(begin
          (use-modules (guix build utils))
          (let ((bin (string-append #$output "/bin"))
                (vendor-deps #$(this-package-input "xous-vendor-deps"))
                (bash #$(this-package-input "bash-minimal")))
            (mkdir-p bin)
            (call-with-output-file (string-append bin "/xous-vendor-setup")
              (lambda (port)
                (format port "#!~a/bin/bash
if [ ! -f Cargo.toml ]; then
  echo \"Error: not in xous-core project root\" >&2
  exit 1
fi
mkdir -p .cargo
cp ~a/vendor-config.toml .cargo/vendor-config.toml
echo \"Wrote .cargo/vendor-config.toml\"
echo \"Use: cargo xtask <target> --config .cargo/vendor-config.toml --no-verify\"
" bash vendor-deps)))
            (chmod (string-append bin "/xous-vendor-setup") #o755)))))
    (inputs `(("xous-vendor-deps" ,xous-vendor-deps)
              ("bash-minimal" ,bash-minimal)))
    (home-page "https://github.com/betrusted-io/xous-core")
    (synopsis "Setup script for offline xous-core cargo builds")
    (description
     "Copies the vendored cargo configuration into the working tree, \
enabling offline @code{cargo xtask} builds.")
    (license license:asl2.0)))

;;; Wrapper script that invokes cargo xtask with vendor config and version info.
;;; Mirrors the Nix flake's xous-build script.
(define-public xous-build
  (package
    (name "xous-build")
    (version %xous-git-describe)
    (source #f)
    (build-system trivial-build-system)
    (arguments
     (list
      #:modules '((guix build utils))
      #:builder
      #~(begin
          (use-modules (guix build utils))
          (let ((bin (string-append #$output "/bin"))
                (bash #$(this-package-input "bash-minimal")))
            (mkdir-p bin)
            (call-with-output-file (string-append bin "/xous-build")
              (lambda (port)
                (format port "#!~a/bin/bash
exec cargo --config .cargo/vendor-config.toml \\
  xtask \"$@\" \\
  --config .cargo/vendor-config.toml \\
  --git-describe ~a \\
  --git-rev ~a
" bash #$%xous-git-describe #$%xous-commit)))
            (chmod (string-append bin "/xous-build") #o755)))))
    (inputs `(("bash-minimal" ,bash-minimal)))
    (home-page "https://github.com/betrusted-io/xous-core")
    (synopsis "Cargo xtask wrapper with vendor config and version info")
    (description
     "Wraps @code{cargo xtask} with @code{--config .cargo/vendor-config.toml} \
and @code{--git-describe}/@code{--git-rev} flags for offline builds in \
containers and CI.")
    (license license:asl2.0)))
