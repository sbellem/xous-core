# Baochip Signature Verification Tool

This tool verifies Ed25519 signatures from Baochip firmware attestation data. It supports two signature modes used by different boot stages.

## Background

Baochip uses a chain-of-trust boot sequence: `boot0` → `boot1` → `loader` → `kernel` → `apps`. Each stage's firmware is signed, and the signature can be verified externally to ensure authenticity.

### Signature Modes

| Stage | Mode | Description |
|-------|------|-------------|
| boot0 | FIDO2 | Signed with hardware security key (aad_len > 0) |
| boot1 | Ed25519ph | Prehashed Ed25519 per RFC 8032 (aad_len = 0) |
| loader | Ed25519ph | Prehashed Ed25519 per RFC 8032 (aad_len = 0) |

**Ed25519ph** (prehashed): `signature = Ed25519.sign(dom2(1,"") || SHA-512(image))`

**FIDO2**: `signature = Ed25519.sign(aad || SHA-256(SHA-512(image)))`
- `aad` is FIDO2 authenticator data (37 bytes typical)
- Stored in the signature block, not reconstructed

### Known Public Keys

From `libs/bao1x-api/src/pubkeys/`:

| Slot | Name | Purpose |
|------|------|---------|
| 0 | bao1 | Production key 1 |
| 1 | bao2 | Production key 2 |
| 2 | beta | Beta testing key |
| 3 | developer | Open developer key (private key is public) |

## Installation

```bash
# Enter guix development shell
guix shell -L guix -D xous-dev-shell

# Build the verifier (RUSTFLAGS embeds library path in binary)
cd scripts/verify_ed25519ph
RUSTFLAGS="-C link-args=-Wl,-rpath,$(dirname $(gcc -print-file-name=libgcc_s.so.1))" cargo build --release

# Verify it works
./target/release/verify_ed25519ph --help
```

## Usage

### Verify from Audit Output (Recommended)

The easiest way is to pipe the `audit` command output directly:

```bash
# On device, run: audit
# Save output to file, then:
./target/release/verify_ed25519ph < audit.txt

# Or for a specific stage:
./target/release/verify_ed25519ph --name boot1 < audit.txt
```

### Manual Verification

```bash
# Ed25519ph mode (boot1, loader)
./target/release/verify_ed25519ph -p developer -H <sha512_hash> -s <signature> -n boot1

# FIDO2 mode (boot0) - requires AAD
./target/release/verify_ed25519ph -p beta -H <sha512_hash> -s <signature> -a <aad_hex> -n boot0
```

### Options

```
-p, --pubkey <KEY>   Public key name (bao1, bao2, beta, dev) or hex
-H, --hash <HEX>     SHA-512 hash of signed region (64 bytes)
-s, --sig <HEX>      Signature (64 bytes)
-a, --aad <HEX>      AAD for FIDO2 mode (optional, read from audit if piped)
-n, --name <STAGE>   Stage name: boot0, boot1, loader, or "all"
```

## Verification Flow for Alice

Alice receives a Baochip device and wants to verify the firmware is authentic:

### Step 1: Get Attestation Data from Device

Connect to the device's serial console and run:
```
audit
```

Save the output. Key fields:
```
boot0.sig:<signature_hex>
boot0.aad_len:<number>
boot0.aad:<aad_hex>           # Only if aad_len > 0
boot0.hash:<sha512_hash>
Boot0: key 2/2 (beta) -> ...  # Shows which key signed it
```

### Step 2: Verify Signatures

```bash
./target/release/verify_ed25519ph < audit.txt
```

Expected output:
```
=== Verifying boot0 ===
Mode:       FIDO2
Public key: beta
✓ PASSED

=== Verifying boot1 ===
Mode:       Ed25519ph
Public key: developer
✓ PASSED

=== Summary ===
boot0: ✓ VERIFIED
boot1: ✓ VERIFIED
loader: ✓ VERIFIED
```

### Step 3: Verify Hash Matches Reproducible Build (Optional)

For full verification, Alice can rebuild the firmware herself and compare hashes:

```bash
# Build with Guix reproducible toolchain
guix build -L guix bao1x-boot1

# Compare boot1.hash from device with hash of built image
```

If hashes match, Alice knows:
1. The firmware on device is identical to what she built
2. The signature is valid for that firmware
3. The signing key is one of the known Baochip keys

## Technical Details

### Signature Block Structure (`SignatureInFlash`)

```
Offset  Size   Field
0       4      JAL instruction (jump over header)
4       64     Signature
68      4      aad_len (0 = Ed25519ph, >0 = FIDO2)
72      60     aad (FIDO2 authenticator data)
132     var    sealed_data (SealedFields struct)
```

### What is Signed

The signature covers `sealed_data || code`:
- `sealed_data`: Version, magic, signed_len, function_code, anti_rollback, pubkeys
- `code`: The actual executable code

### Hash Computation

```
hash = SHA-512(sealed_data || code)
```

For Ed25519ph: signature is verified against this hash directly (with RFC 8032 domain separator).

For FIDO2: signature is verified against `aad || SHA-256(hash)`.

### AAD (Additional Authenticated Data)

The AAD field contains FIDO2/WebAuthn authenticator data from the hardware security key used to sign boot0. It's stored in the firmware image itself - Alice reads it from the device, she doesn't need to reconstruct it.

Typical AAD structure (37 bytes):
- RP ID hash (32 bytes)
- Flags (1 byte)
- Sign count (4 bytes)

## Security Considerations

- **Developer key**: The private key is publicly known. Images signed with it are for development only. Production devices should have the developer key revoked.
- **Trust anchor**: Alice must trust the public keys embedded in source code. These are the reference keys burned into boot0 ROM.
- **Reproducible builds**: Hash comparison only works if Alice uses the exact same Guix toolchain version.

## Troubleshooting

### "libgcc_s.so.1 not found"

Rebuild with RUSTFLAGS to embed the library path:
```bash
RUSTFLAGS="-C link-args=-Wl,-rpath,$(dirname $(gcc -print-file-name=libgcc_s.so.1))" cargo build --release
```

### "Unknown key tag"

The audit output may have trailing spaces in tags (e.g., "dev " vs "devl"). The tool handles common variants.

### Verification fails for boot0

Ensure you're using the full audit output (with aad field) so FIDO2 mode is detected. Manual CLI without `--aad` defaults to Ed25519ph which will fail for boot0.
