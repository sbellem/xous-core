# ethapp - Ethereum Hardware Wallet for Xous

Ethereum signing service for Baochip-1x running Xous OS, paired with
`ethcli`, a host-side CLI that communicates over USB serial.

**Status:** Developer preview. See [STATUS.md](STATUS.md) for security
assessment and production gaps.

## Architecture

```
HOST (untrusted)                    DEVICE (trusted)
+--------------------------+       +------------------------+
| ethcli (Rust CLI)        |       | ethapp (Xous service)  |
|  - builds unsigned txs   |       |  - secp256k1 signing   |
|  - JSON-RPC queries      | USB   |  - BIP32/BIP44 derive  |
|  - broadcasts signed txs |<----->|  - tx parsing          |
|                          | serial|  - user confirmation   |
+--------------------------+       +------------------------+
```

The device holds the seed and signs; the host builds transactions and
talks to the chain. Keys never leave the device.

## ethcli - Host CLI

### Building

```bash
# Via Nix (recommended, reproducible):
nix build .#ethcli

# Via Cargo (needs network + libudev on Linux):
cd services/ethapp/tools/ethcli
cargo build --release
```

### Device connection

ethcli auto-detects the Baochip-1x USB serial port. Override with
`--port /dev/ttyACM0` if needed.

### Commands

#### Wallet management

```bash
# Health check
ethcli ping

# Device info (version, protocol, feature flags)
ethcli config

# Generate a new 24-word mnemonic on device
ethcli generate-mnemonic

# Import an existing mnemonic (interactive prompt, avoids shell history)
ethcli import-mnemonic

# Wipe the master seed from device memory and storage
ethcli clear-seed
```

#### Addresses

```bash
# Get address at default index (m/44'/60'/0'/0/0)
ethcli address

# Get address at specific index
ethcli address --index 3

# List first 10 addresses
ethcli accounts --count 10
```

#### Balances

```bash
# ETH balance (device address)
ethcli balance --rpc-url https://ethereum-sepolia-rpc.publicnode.com

# ETH balance (arbitrary address, no device needed)
ethcli balance --rpc-url https://... --address 0x1234...

# ERC-20 token balance
ethcli token-balance --token 0xA0b8...USDC --rpc-url https://... \
  --decimals 6 --symbol USDC

# Token balance for arbitrary address (no device needed)
ethcli token-balance --token 0xA0b8... --rpc-url https://... \
  --address 0x1234... --decimals 6 --symbol USDC
```

#### Sending ETH

Three workflows are supported:

**1. Online all-in-one** (simplest):

```bash
# Fetch chain state (nonce, gas, fees, balance)
ethcli tx-info --rpc-url https://... --to 0xRecipient --value 1000000000000000000

# Build, sign, and get raw tx hex (legacy EIP-155)
ethcli gen-tx 0xRecipient 1000000000000000000 \
  --nonce 0 --chain-id 11155111 --gas-price 1000000000 --gas-limit 21000

# Broadcast
ethcli publish 0xRawSignedHex --rpc-url https://... --wait
```

**2. Air-gapped** (most secure):

```bash
# On online machine: build unsigned tx
ethcli build-tx 0xRecipient 1000000000000000000 \
  --nonce 0 --chain-id 11155111 --gas-price 1000000000 --gas-limit 21000

# Transfer the unsigned hex to a device-connected machine

# On device-connected machine: sign
ethcli sign-tx 0xUnsignedHex --index 0

# Transfer signed hex back, then broadcast
ethcli publish 0xSignedHex --rpc-url https://...
```

**3. Manual**: build the RLP externally, pass to `sign-tx`.

#### Sending ERC-20 tokens

```bash
# Send 100 USDC (6 decimals, so 100000000 smallest units)
# Uses EIP-1559 by default, auto-fetches nonce/gas/fees
ethcli send-token --token 0xA0b8...USDC 0xRecipient 100000000 \
  --rpc-url https://... --index 0

# Send and broadcast in one step
ethcli send-token --token 0xA0b8... 0xRecipient 100000000 \
  --rpc-url https://... --broadcast

# Force legacy transaction
ethcli send-token --token 0xA0b8... 0xRecipient 100000000 \
  --rpc-url https://... --legacy

# Override gas/nonce
ethcli send-token --token 0xA0b8... 0xRecipient 100000000 \
  --rpc-url https://... --nonce 5 --gas-limit 80000
```

The `amount` argument is always in the token's smallest unit (e.g.,
for USDC with 6 decimals: 1000000 = 1 USDC, 100000000 = 100 USDC).

#### Message signing

```bash
# Sign an EIP-191 personal message
ethcli sign-message "Hello Ethereum" --index 0

# Sign a raw RLP-encoded transaction (any type: legacy, EIP-2930, EIP-1559)
ethcli sign-tx 0xRlpHex --index 0
```

#### Dangerous mode

On displayless dev boards (dabao), mainnet signing is blocked by default
to prevent accidental fund loss. To override for a single session:

```bash
ethcli dangerous-mode  # alias: ethcli yolo
# Type "I ACCEPT THE RISK" when prompted. Resets on reboot.
```

### Command reference

| Command | Device | RPC | Purpose |
|---|---|---|---|
| `ping` | yes | no | Health check |
| `config` | yes | no | Device info |
| `address` | yes | no | Derive address |
| `accounts` | yes | no | List addresses |
| `generate-mnemonic` | yes | no | New wallet |
| `import-mnemonic` | yes | no | Restore wallet |
| `clear-seed` | yes | no | Wipe wallet |
| `dangerous-mode` | yes | no | Enable mainnet on dev boards |
| `sign-message` | yes | no | EIP-191 sign |
| `sign-tx` | yes | no | Sign any RLP tx |
| `balance` | opt | yes | ETH balance |
| `token-balance` | opt | yes | ERC-20 balance |
| `tx-info` | yes | yes | Chain state for tx building |
| `gen-tx` | yes | no | Build + sign legacy tx |
| `build-tx` | no | no | Offline unsigned RLP |
| `send-token` | yes | yes | Build + sign + broadcast ERC-20 transfer |
| `publish` | no | yes | Broadcast signed tx |

## ethapp - Device Service

### Features

- **Key derivation**: BIP32/BIP44 hierarchical (`m/44'/60'/account'/change/index`)
- **Seed management**: generate mnemonic, import mnemonic, import raw seed, wipe
- **Transaction signing**: Legacy (EIP-155), EIP-2930, EIP-1559
- **Message signing**: EIP-191 personal messages, EIP-712 typed data
- **Clear signing**: ERC-20 `transfer()` and `approve()` decoded for display
- **Token metadata**: Cached token info (ticker, decimals) for clear-signed display
- **Persistent storage**: Optional PDDB integration (encrypted at rest)

### Cargo features

| Feature | Purpose | Security |
|---|---|---|
| `dev-mode` | Ephemeral test seed, mnemonic over serial | INSECURE |
| `autoapprove` | Skip user confirmation | INSECURE |
| `blind-signing` | Allow pre-hashed EIP-712 | Reduces visibility |
| `board-dabao` | Dabao dev board target | - |
| `hosted-dabao` | Host-emulated dabao | - |

### Building firmware

```bash
# Dabao dev board with ethapp test suite
xous-build dabao ethapp-test --no-verify

# Via Nix
nix build .#dabao-ethapp
```

### Transaction types

The device parses and signs all three Ethereum transaction types:

| Type | Byte | Description |
|---|---|---|
| Legacy | (none) | Pre-EIP-2718, `v = chainId * 2 + 35 + recoveryId` |
| EIP-2930 | `0x01` | Access list, `v = recoveryId` |
| EIP-1559 | `0x02` | Fee market (maxFee/priorityFee), `v = recoveryId` |

### Clear signing

When the device receives a transaction whose calldata matches a known
ERC-20 method (`transfer` or `approve`), it decodes the calldata and
displays a human-readable summary:

```
Type:      ERC-20 Transfer
Chain ID:  1
Token:     0xA0b8...3c4d
To:        0xRecipient...
Amount:    100 [UNVERIFIED] USDC
Gas Limit: 65000
Gas Price: 12.5 Gwei
```

If token metadata (ticker, decimals) has been provided via the
`ProvideErc20TokenInfo` opcode, the amount is formatted with the
correct decimals and ticker. Otherwise it shows raw values with `???`.

**Warning**: Token metadata is currently accepted without signature
verification (CRITICAL-04). The ticker is prefixed with `[UNVERIFIED]`
to indicate this. See STATUS.md for details.

## Wire protocol

Communication over USB CDC-ACM serial at 115200 baud.

```
Request:  [0xE7] [length: u16 LE] [opcode: u8] [payload...]
Response: [0xE7] [length: u16 LE] [status: u8] [payload...]
```

The `0xE7` magic byte allows ethcli frames to coexist with the text
console — non-`0xE7` bytes flow to the keyboard injection path, so
`tio` and `ethcli` work simultaneously.

## Security considerations

This is a developer preview. Key gaps before production use:

1. **No trusted display on hardware** (C1) - the single biggest gap
2. **Token metadata unverified** (C2) - attacker can spoof tickers
3. **No firmware attestation** (C3)
4. **No PIN protection** (C4)

See [STATUS.md](STATUS.md) for the full assessment and roadmap.
