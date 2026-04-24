;;; Development build configuration for bao.scm
;;;
;;; Provides source via local-file from the working tree.
;;; Version and commit are computed from git at evaluation time.

(define-module (bao-config)
  #:use-module (guix packages)
  #:use-module (guix gexp)
  #:use-module (guix utils)
  #:use-module (ice-9 popen)
  #:use-module (ice-9 rdelim)
  #:export (%xous-source %xous-git-describe %xous-commit %repo-root))

;;; Determine the directory containing this module (guix/).
;;; Falls back to searching %load-path when current-source-directory is
;;; unavailable (e.g., inside guix time-machine).
(define %source-dir
  (or (current-source-directory)
      (and=> (search-path %load-path "bao-config.scm")
             (lambda (f) (dirname (canonicalize-path f))))))

;;; Repository root (parent of guix/)
(define %repo-root
  (and=> %source-dir dirname))

;;; Helper to run git command at evaluation time
(define (git-command . args)
  "Run a git command in the repo directory and return output, or #f on failure."
  (and %repo-root
       (false-if-exception
        (let* ((port (apply open-pipe* OPEN_READ "git" "-C" %repo-root args))
               (output (read-line port))
               (status (close-pipe port)))
          (and (zero? (status:exit-val status))
               (string? output)
               output)))))

;;; Git revision (full 40-char hash) - detected at evaluation time
;;; Falls back to zeros if not in git repo
(define %xous-commit
  (or (git-command "rev-parse" "HEAD")
      "0000000000000000000000000000000000000000"))

;;; Version string from git describe (e.g., "v0.9.16-123-gabcdef01")
(define %xous-git-describe
  (or (git-command "describe" "--tags")
      "v0.0.0-unknown"))

;;; Local source from current repository
(define %xous-source
  (local-file %repo-root
              #:recursive? #t
              #:select? (lambda (file stat)
                          (not (or (string-contains file "/target/")
                                   (string-contains file "/.git/"))))))
