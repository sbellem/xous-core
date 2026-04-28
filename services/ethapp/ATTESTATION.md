# Device Attestation

How the ethapp hardware wallet proves a transaction was signed on a
specific device, and the trust assumptions involved.

## Problem

An ECDSA signature from a hardware wallet is identical to one from
software with the same key. To prove a transaction was signed on
Baochip hardware, the device needs a separate **attestation identity**
that co-signs transactions.

## Current implementation (proof-of-concept)

The device generates a secp256k1 attestation keypair from its hardware
TRNG, stored in PDDB independently of the wallet seed. When signing a
transaction, the device produces both the transaction signature and an
attestation co-signature:

```
attest_sig = sign(keccak256(tx_sign_hash || v || r || s))
```

This binds the attestation to the exact transaction signature.

### Commands

| Command | Purpose |
|---|---|
| `ethcli init-attestation` | Generate attestation keypair (one-time) |
| `ethcli get-attestation-key` | Export the 33-byte compressed public key |
| `ethcli attest-sign-tx <rlp>` | Sign tx + produce attestation co-signature |
| `ethcli verify-attestation ...` | Offline verification (no device needed) |

### Verifier setup

Bob must obtain Alice's attestation public key and trust it. Three
options, from strongest to weakest:

1. **Witnessed setup** -- Bob is present when Alice generates the key
2. **Published key (TOFU)** -- Alice publishes the key (on-chain, ENS,
   website); Bob trusts her initial publication
3. **Manufacturer certificate (not yet implemented)** -- Baobit signs
   the device's attestation pubkey; Bob verifies against Baobit's
   public root key

## Trust chain

```
IFR-fused signing pubkey (burned into silicon at manufacturing)
  -> Boot0 (immutable ROM, validates Boot1)
    -> Boot1 (validates firmware signature)
      -> Verified firmware (guards the attestation key)
        -> Attestation signature
```

### What each layer provides

| Layer | Guarantee |
|---|---|
| Fused IFR key | Only firmware signed by the corresponding private key can run |
| Boot0 -> Boot1 -> firmware | Firmware integrity (can't be replaced without the signing key) |
| Firmware -> attestation key | Only verified firmware can use the attestation key to sign |

### Developer mode limitation

The developer signing key is well-known (anyone can sign firmware).
This means:

- Alice can build custom firmware that exports the attestation private
  key from PDDB
- Alice can build custom firmware that produces fake attestation
  signatures
- The attestation is only as trustworthy as the initial key exchange
  with Bob (witnessed setup or TOFU)

With a **production signing key** (secret, held by Baobit), neither
attack is possible -- only Baobit-approved firmware runs on the device.

## Hardware key isolation

Baochip-1x has RRAM data slots with hardware ACLs (read/write disable
bits enforced by hardware), but no **hardware signing oracle** -- any
key that firmware can sign with, firmware can also read. The protection
comes from controlling which firmware runs (secure boot), not from
hardware key isolation.

### Comparison with a secure element (e.g., TROPIC01)

A dedicated secure element like TROPIC01 provides hardware key
isolation: the private key is generated inside the chip and never
appears on any bus. The host sends a hash, the secure element returns
a signature. Even fully compromised host firmware cannot extract the
key.

| | Baochip-1x alone | Baochip + TROPIC01 |
|---|---|---|
| Key extraction by firmware | Possible (key in RRAM/RAM) | Impossible (key inside SE) |
| Fake attestation with custom firmware | Possible (dev key is public) | Possible (SE signs any hash it receives) |
| Full attestation guarantee | Requires production signing key | Requires production signing key AND SE |

**TROPIC01 solves key extraction. Secure boot solves firmware
authenticity. You need both.**

With only one:
- Secure boot alone (production key, no SE): firmware can't be
  replaced, but the key is extractable via hardware attacks (probing,
  glitching)
- SE alone (TROPIC01, dev signing key): key can't be extracted, but
  custom firmware can ask the SE to sign anything

The full trust chain requires:
1. TROPIC01 for key isolation (private key never leaves silicon)
2. Production signing key for firmware integrity (only approved code
   runs)
3. Both verified by Bob: attestation signature chains to the SE,
   firmware signature chains to the manufacturer root

## Roadmap

- **Today (dev mode)**: Attestation works end-to-end with TOFU or
  witnessed setup trust model. Suitable for testing and development.
- **Production signing key**: Swap developer key for secret bao1/bao2
  key. No architecture changes needed. Closes the firmware tampering
  gap.
- **TROPIC01 integration**: Move attestation key (and optionally
  wallet seed) into the secure element. Closes the key extraction gap.
- **Manufacturer certificates**: Baobit signs each device's
  attestation pubkey at provisioning. Bob can verify without trusting
  Alice.
