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
  #:use-module (ice-9 textual-ports)
  #:export (%xous-source %xous-git-describe %xous-commit))

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

;;; Version configuration
(define %xous-git-tag "0.9.16")
(define %xous-git-tag-rev-count 7276)

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

;;; Helper to check git command exit status only
(define (git-status-zero? . args)
  "Run a git command and return #t if exit status is 0, #f otherwise."
  (and %repo-root
       (false-if-exception
        (let* ((port (apply open-pipe* OPEN_READ "git" "-C" %repo-root args))
               (_ (get-string-all port))
               (status (close-pipe port)))
          (zero? (status:exit-val status))))))

;;; Git revision (full 40-char hash) - detected at evaluation time
;;; Falls back to zeros if not in git repo or working tree is dirty
(define %xous-commit
  (or (and (git-status-zero? "diff" "--quiet")
           (git-command "rev-parse" "HEAD"))
      "0000000000000000000000000000000000000000"))

;;; Count of commits since tag (0 if not in git repo)
(define %since-tag-rev-count
  (or (false-if-exception
       (let ((total (git-command "rev-list" "--count" "HEAD")))
         (and total (- (string->number total) %xous-git-tag-rev-count))))
      0))

;;; Computed version string: v{tag}-{count-since-tag}-g{hash}
(define %xous-git-describe
  (string-append "v" %xous-git-tag "-"
                 (number->string %since-tag-rev-count) "-g"
                 (substring %xous-commit 0 8)))

;;; Local source from current repository
(define %xous-source
  (local-file %repo-root
              #:recursive? #t
              #:select? (lambda (file stat)
                          (not (or (string-contains file "/target/")
                                   (string-contains file "/.git/"))))))
