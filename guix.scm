;;; Guix development environment for baochip
;;;
;;; Preferred usage (reproducible, pinned channels):
;;;   guix time-machine -C channels.scm -- shell -m manifest.scm
;;;
;;; Quick usage (requires baobit channel configured):
;;;   guix shell -m manifest.scm

(use-modules (bao))

;; Default package for `guix build -f guix.scm`
dabao-helloworld
