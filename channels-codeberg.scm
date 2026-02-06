;; Channels configuration for xous-core firmware builds (Codeberg mirror)
;; Fallback when Savannah is unavailable

(list
 (channel
  (name 'guix)
  (url "https://codeberg.org/guix/guix.git")
  (branch "rust-team")
  (commit "71f6e64afaa580a99aaea67ffd39bd4a40a8293d")
  (introduction
    (make-channel-introduction
      "9edb3f66fd807b096b48283debdcddccfea34bad"
      (openpgp-fingerprint
        "BBB0 2DDF 2CEA F6A8 0D1D  E643 A2A0 6DF2 A33A 54FA"))))
 (channel
  (name 'baochan)
  (url "https://github.com/sbellem/baochan")
  (branch "ci")
  (commit "c60a16b4712ae9dbb04dadd2a6c8c3ee239999e0")
  (introduction
    (make-channel-introduction
      "06e8707cac44731b16bfc46b3fb5c34427fc5efe"
      (openpgp-fingerprint
        "E39D 2B3D 0564 BA43 7BD9  2756 C38A E0EC CAB7 D5C8")))))
