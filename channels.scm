(list (channel
        (name 'guix)
        (url "https://codeberg.org/guix/guix.git")
        (branch "master")
        (commit "7e7487166b02aa41d42e96a1dfccaceda7fefc12")
        (introduction
         (make-channel-introduction "9edb3f66fd807b096b48283debdcddccfea34bad"
          (openpgp-fingerprint
           "BBB0 2DDF 2CEA F6A8 0D1D  E643 A2A0 6DF2 A33A 54FA"))))
      (channel
        (name 'baobit)
        (url "https://github.com/sbellem/baobit")
        (commit "04a104cb35d3b26b28c3088678a45611a49054b9")
        (introduction
         (make-channel-introduction
          "06e8707cac44731b16bfc46b3fb5c34427fc5efe"
          (openpgp-fingerprint
           "E39D 2B3D 0564 BA43 7BD9  2756 C38A E0EC CAB7 D5C8")))))
