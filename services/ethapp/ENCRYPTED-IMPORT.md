# Encrypted Mnemonic Import Protocol

Specification for securely transferring a BIP39 mnemonic from a trusted
source device to a Baochip running ethapp, without exposing the
mnemonic to the untrusted host computer.

## Overview

```
SOURCE DEVICE              HOST (untrusted)         BAOCHIP
(e.g., Precursor)          (transports opaque       (decrypts + imports)
                            ciphertext only)

1. Get Baochip pubkey  ←── QR / hex / file ───────  ethcli get-import-key
                                                     → 0x02abc... (33 bytes)

2. Generate mnemonic
   from hardware TRNG

3. Encrypt mnemonic
   to Baochip pubkey
   using ECIES

4. Output ciphertext   ─── QR / hex / file ───────→ ethcli import-encrypted
                                                     (or raw serial opcode 0x67)

5.                                                   Decrypt → validate →
                                                     derive seed → store
```

The host never sees the plaintext mnemonic. It only passes opaque bytes.

## Setup (one-time)

The Baochip must have an import keypair initialized:

```bash
ethcli init-import-key
ethcli get-import-key
# → 0x02abc...def  (33-byte compressed secp256k1 public key)
```

Transfer this public key to the source device. Methods:
- Scan a QR code (`ethcli qr --address` with the pubkey)
- Copy the hex string manually
- Transfer via file on USB stick

## Wire format

```
[e_pub: 33 bytes] [ciphertext + tag: N + 16 bytes]
```

| Field | Size | Description |
|---|---|---|
| `e_pub` | 33 bytes | Compressed secp256k1 ephemeral public key |
| `ciphertext` | N bytes | Encrypted mnemonic (UTF-8, space-separated BIP39 words) |
| `tag` | 16 bytes | Poly1305 authentication tag (appended by ChaCha20-Poly1305) |

For a 24-word mnemonic (~240 bytes plaintext), total payload is ~289
bytes. Maximum supported: 65534 bytes (serial frame limit).

## ECIES construction

The encryption scheme is ECIES (Elliptic Curve Integrated Encryption
Scheme) using:

- **Key agreement**: secp256k1 ECDH
- **Key derivation**: HKDF-SHA256
- **Symmetric cipher**: ChaCha20-Poly1305 (AEAD)

### Encryption (source device)

```
Inputs:
  recipient_pubkey  : 33-byte compressed secp256k1 public key (Baochip's import key)
  mnemonic          : UTF-8 string of space-separated BIP39 words

Steps:
  1. Generate ephemeral secp256k1 keypair:
       e_priv = random_scalar()
       e_pub  = e_priv * G                    (compressed, 33 bytes)

  2. ECDH shared secret:
       shared = ecdh(e_priv, recipient_pubkey) (32 bytes, x-coordinate only)

  3. Derive symmetric key via HKDF-SHA256:
       key = HKDF-Expand(
               HKDF-Extract(salt = "ethapp-import-v1", ikm = shared),
               info = "",
               len  = 32
             )

  4. Derive nonce from ephemeral public key:
       nonce = SHA-256(e_pub_bytes)[0..12]     (first 12 bytes)

  5. Encrypt with ChaCha20-Poly1305:
       ciphertext || tag = ChaCha20Poly1305_Encrypt(key, nonce, mnemonic_bytes)

  6. Assemble payload:
       output = e_pub || ciphertext || tag

  7. Zeroize: e_priv, shared, key, mnemonic_bytes
```

### Decryption (Baochip)

```
Inputs:
  import_priv : 32-byte secp256k1 private key (from PDDB)
  payload     : the encrypted payload bytes

Steps:
  1. Parse:
       e_pub           = payload[0..33]        (compressed secp256k1 pubkey)
       ciphertext_tag  = payload[33..]         (ciphertext + 16-byte Poly1305 tag)

  2. ECDH shared secret:
       shared = ecdh(import_priv, e_pub)       (32 bytes, x-coordinate)

  3. Derive key and nonce:
       key   = HKDF-SHA256(salt = "ethapp-import-v1", ikm = shared, info = "", len = 32)
       nonce = SHA-256(e_pub_bytes)[0..12]

  4. Decrypt and verify:
       mnemonic_bytes = ChaCha20Poly1305_Decrypt(key, nonce, ciphertext_tag)
       (fails if tag verification fails → DecryptionFailed error)

  5. Validate plaintext:
       - Must be valid UTF-8
       - Must contain exactly 12 or 24 whitespace-separated words

  6. Derive seed:
       seed = PBKDF2-HMAC-SHA512(password = mnemonic, salt = "mnemonic", rounds = 2048)

  7. Zeroize: shared, key, mnemonic_bytes
```

## Constants

| Name | Value | Purpose |
|---|---|---|
| HKDF salt | `"ethapp-import-v1"` (UTF-8, 18 bytes) | Domain separation |
| HKDF info | `""` (empty) | No additional context |
| HKDF output length | 32 bytes | ChaCha20-Poly1305 key size |
| Nonce derivation | SHA-256(e_pub)[0..12] | Deterministic, unique per ephemeral key |
| Curve | secp256k1 | Same as Ethereum transaction signing |
| ECDH output | 32 bytes (x-coordinate) | Raw shared secret before KDF |

## Serial protocol

The encrypted payload is sent to the Baochip via the 0xE7-framed
serial protocol:

```
Request:  [0xE7] [length: u16 LE] [0x67] [e_pub:33] [ciphertext+tag]
Response: [0xE7] [length: u16 LE] [status: u8]
```

Status codes:
- `0x00` — success (mnemonic imported)
- `0x09` — import key not initialized (run init-import-key first)
- `0x0A` — decryption failed (wrong key, corrupted, or tampered)

Other opcodes:
- `0x65` — InitImportKey (generate import keypair)
- `0x66` — GetImportKey (return 33-byte compressed pubkey)

## Implementing on Precursor

Precursor has all the necessary primitives:

| Primitive | Precursor source |
|---|---|
| secp256k1 keypair generation | k256 crate (via ethapp or vault) |
| secp256k1 ECDH | k256 with `ecdh` feature |
| HKDF-SHA256 | `apps/vault/libraries/crypto/src/hkdf.rs` |
| ChaCha20-Poly1305 | chacha20poly1305 crate (add to deps) |
| SHA-256 | sha2 crate (already available) |
| BIP39 mnemonic generation | `libs/bip39-utils/src/lib.rs` |
| QR code display | `libs/ux-api/src/service/gfx.rs::render_qr()` |
| Hardware TRNG | `services/trng/` |

### Suggested Precursor flow

1. Prompt user for Baochip import pubkey (manual hex entry or QR scan)
2. Generate 256 bits of entropy from hardware TRNG
3. Convert to 24 BIP39 words using `bip39_utils::bytes_to_bip39()`
4. Display words on Precursor's screen for user to write down
5. Encrypt the word string to Baochip's pubkey using the ECIES protocol above
6. Display the encrypted payload as a QR code (or hex)
7. User scans/pastes the payload into `ethcli import-encrypted` on the host
8. Zeroize all key material

The mnemonic is shown on Precursor's trusted display and encrypted
before leaving the device. The host computer never sees it.

## Security properties

| Property | Guarantee |
|---|---|
| Confidentiality | Only the Baochip with the import private key can decrypt |
| Integrity | Poly1305 tag detects any tampering with the ciphertext |
| Forward secrecy | Each encryption uses a fresh ephemeral key; compromising the import key later doesn't reveal past mnemonics (assuming ephemeral keys were properly zeroized) |
| Replay protection | Not built-in; the same ciphertext can be re-imported. Acceptable since importing the same mnemonic twice is idempotent. |

## Limitations

- If the host is compromised and the user types the mnemonic into
  `ethcli import-encrypted`, the host sees it before encryption.
  The encrypted path only helps when the **source device** does the
  encryption (e.g., Precursor encrypts and outputs a QR code).
- The import private key is stored in PDDB. In dev-mode, custom
  firmware could extract it (see ATTESTATION.md for the trust model).
