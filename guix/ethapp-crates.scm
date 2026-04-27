;;; Crate sources for ethapp (device firmware)
;;;
;;; Dependencies needed by services/ethapp that are not already in
;;; bao-crates.scm (bip32, k256, secp256k1, and their transitive deps).
;;;
;;; Generated from Cargo.lock.
;;; Hashes are SHA256 of .crate tarballs, nix-base32 encoded.

(define-module (ethapp-crates)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (bao-crates)
  #:export (%ethapp-crate-inputs))

(define rust-base16ct-0.2.0
  (crate-source "base16ct" "0.2.0"
                "1kylrjhdzk7qpknrvlphw8ywdnvvg39dizw9622w3wk5xba04zsc"))

(define rust-bip32-0.5.3
  (crate-source "bip32" "0.5.3"
                "0saw83qxz1i9knn0f5nf27dv186al0pn8i68g0fh6kmbpvgx6h6v"))

(define rust-bs58-0.5.1
  (crate-source "bs58" "0.5.1"
                "1x3v51n5n2s3l0rgrsn142akdf331n2qsa75pscw71fi848vm25z"))

(define rust-crypto-bigint-0.5.5
  (crate-source "crypto-bigint" "0.5.5"
                "0xmbdff3g6ii5sbxjxc31xfkv9lrmyril4arh3dzckd4gjsjzj8d"))

(define rust-ecdsa-0.16.9
  (crate-source "ecdsa" "0.16.9"
                "1jhb0bcbkaz4001sdmfyv8ajrv8a1cg7z7aa5myrd4jjbhmz69zf"))

(define rust-elliptic-curve-0.13.8
  (crate-source "elliptic-curve" "0.13.8"
                "0ixx4brgnzi61z29r3g1606nh2za88hzyz8c5r3p6ydzhqq09rmm"))

(define rust-k256-0.13.4
  (crate-source "k256" "0.13.4"
                "06s1lxjp49zgmbxnfdy2kajyklbkl4s3jvdvy0amg552padr3qzn"))

(define rust-rfc6979-0.4.0
  (crate-source "rfc6979" "0.4.0"
                "1chw95jgcfrysyzsq6a10b1j5qb7bagkx8h0wda4lv25in02mpgq"))

(define rust-ripemd-0.1.3
  (crate-source "ripemd" "0.1.3"
                "17xh5yl9wjjj2v18rh3m8ajlmdjg1yj13l6r9rj3mnbss4i444mx"))

(define rust-sec1-0.7.3
  (crate-source "sec1" "0.7.3"
                "1p273j8c87pid6a1iyyc7vxbvifrw55wbxgr0dh3l8vnbxb7msfk"))

(define rust-secp256k1-0.27.0
  (crate-source "secp256k1" "0.27.0"
                "13wwv91qnx8lsyn891q16a6x6h46zz7m5w086pnmfyia5616p695"))

(define rust-secp256k1-sys-0.8.2
  (crate-source "secp256k1-sys" "0.8.2"
                "16gxc3zccx0942yjgngj5ip19wvd33qrw5v86vpb8xzcfwsh2ws4"))

(define %ethapp-crate-inputs
  (list rust-base16ct-0.2.0
        rust-bip32-0.5.3
        rust-bs58-0.5.1
        rust-crypto-bigint-0.5.5
        rust-ecdsa-0.16.9
        rust-elliptic-curve-0.13.8
        rust-k256-0.13.4
        rust-rfc6979-0.4.0
        rust-ripemd-0.1.3
        rust-sec1-0.7.3
        rust-secp256k1-0.27.0
        rust-secp256k1-sys-0.8.2))
