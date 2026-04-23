//! ethcli - Host-side CLI for the Baochip-1x Ethereum hardware wallet.
//!
//! Communicates with the ethapp service over USB CDC-ACM serial,
//! replacing the need for `tio /dev/ttyACM0`.

mod rpc;
mod transport;

use std::io::{self, BufRead, Write};

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use transport::{Transport, STATUS_OK};

// Opcodes matching EthAppOp values
const OP_PING: u8 = 0xFF;
const OP_GET_CONFIG: u8 = 0x01;
const OP_GET_ADDRESS: u8 = 0x51;
const OP_GENERATE_MNEMONIC: u8 = 0x62;
const OP_IMPORT_MNEMONIC: u8 = 0x61;
const OP_CLEAR_SEED: u8 = 0x63;
const OP_ENABLE_DANGEROUS_MAINNET: u8 = 0x64;
const OP_SIGN_PERSONAL_MESSAGE: u8 = 0x20;
const OP_SIGN_TRANSACTION: u8 = 0x10;

#[derive(Parser)]
#[command(name = "ethcli", about = "Baochip-1x Ethereum hardware wallet CLI")]
struct Cli {
    /// Serial port path (auto-detected if not specified)
    #[arg(long, short)]
    port: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Health check
    Ping,

    /// Get device configuration
    Config,

    /// Get Ethereum address at BIP44 path
    Address {
        /// Account index (m/44'/60'/0'/0/<index>)
        #[arg(long, default_value = "0")]
        index: u32,
    },

    /// List first N account addresses
    Accounts {
        /// Number of accounts to list
        #[arg(long, default_value = "5")]
        count: u32,
    },

    /// Generate a new 24-word mnemonic on device
    GenerateMnemonic,

    /// Import a BIP39 mnemonic (interactive prompt)
    ImportMnemonic,

    /// Wipe the master seed
    ClearSeed,

    /// DANGEROUS: enable mainnet signing on a displayless device.
    /// Session-only (resets on reboot). You assume all risk.
    #[command(alias = "yolo")]
    DangerousMode,

    /// Sign an EIP-191 personal message
    SignMessage {
        /// The message to sign
        message: String,

        /// Account index
        #[arg(long, default_value = "0")]
        index: u32,
    },

    /// Sign a raw RLP-encoded transaction
    SignTx {
        /// Hex-encoded RLP transaction (with or without 0x prefix)
        rlp_hex: String,

        /// Account index
        #[arg(long, default_value = "0")]
        index: u32,
    },

    /// Fetch chain state needed to build a transaction: chain ID, nonce,
    /// gas price, EIP-1559 fee suggestion, balance, and gas limit estimate.
    /// Uses the device's address at the given index.
    TxInfo {
        /// JSON-RPC URL (e.g. https://ethereum-sepolia-rpc.publicnode.com)
        #[arg(long)]
        rpc_url: String,

        /// Account index — uses device address at this index for queries
        #[arg(long, default_value = "0")]
        index: u32,

        /// Recipient address for gas estimation context (else assumes 21000)
        #[arg(long)]
        to: Option<String>,

        /// Value in wei for gas estimation context
        #[arg(long, default_value = "0")]
        value: u128,

        /// Calldata hex for contract-call gas estimation
        #[arg(long)]
        data: Option<String>,
    },

    /// Broadcast a pre-signed transaction (eth_sendRawTransaction).
    /// Equivalent to foundry's `cast publish`. Does NOT touch the device.
    #[command(alias = "broadcast")]
    Publish {
        /// Hex-encoded signed transaction (with or without 0x prefix)
        signed_tx_hex: String,

        /// JSON-RPC URL
        #[arg(long)]
        rpc_url: String,

        /// Poll until the tx is mined and print the receipt
        #[arg(long)]
        wait: bool,

        /// How long to poll before giving up (seconds)
        #[arg(long, default_value = "120")]
        wait_timeout: u64,
    },

    /// Build (only) the unsigned RLP for a legacy EIP-155 transaction.
    /// Does NOT touch the device — useful for offline workflows where you
    /// build the tx on one machine and sign it elsewhere with `sign-tx`.
    BuildTx {
        /// Recipient address (hex, with or without 0x prefix, 20 bytes)
        to: String,

        /// Value to send in wei
        value: u128,

        /// Account nonce
        #[arg(long, default_value = "0")]
        nonce: u64,

        /// Chain ID (1=mainnet, 11155111=sepolia, 17000=holesky, ...)
        #[arg(long, default_value = "11155111")]
        chain_id: u64,

        /// Gas price in wei
        #[arg(long, default_value = "1000000000")]
        gas_price: u64,

        /// Gas limit
        #[arg(long, default_value = "21000")]
        gas_limit: u64,

        /// Optional hex-encoded calldata (for contract calls)
        #[arg(long)]
        data: Option<String>,
    },

    /// Build, sign, and emit a legacy (EIP-155) ETH transfer transaction.
    /// Output is the raw signed tx hex ready to broadcast via eth_sendRawTransaction.
    GenTx {
        /// Recipient address (hex, with or without 0x prefix, 20 bytes)
        to: String,

        /// Value to send in wei
        value: u128,

        /// Account nonce
        #[arg(long, default_value = "0")]
        nonce: u64,

        /// Chain ID (1=mainnet, 11155111=sepolia, 17000=holesky, ...)
        #[arg(long, default_value = "11155111")]
        chain_id: u64,

        /// Gas price in wei
        #[arg(long, default_value = "1000000000")]
        gas_price: u64,

        /// Gas limit
        #[arg(long, default_value = "21000")]
        gas_limit: u64,

        /// Account index for signing
        #[arg(long, default_value = "0")]
        index: u32,

        /// Optional hex-encoded calldata (for contract calls)
        #[arg(long)]
        data: Option<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Offline commands: handle before opening the device.
    match &cli.command {
        Commands::BuildTx {
            to, value, nonce, chain_id, gas_price, gas_limit, data,
        } => {
            return cmd_build_tx(
                to, *value, *nonce, *chain_id, *gas_price, *gas_limit, data.as_deref(),
            );
        }
        Commands::Publish { signed_tx_hex, rpc_url, wait, wait_timeout } => {
            return cmd_publish(signed_tx_hex, rpc_url, *wait, *wait_timeout);
        }
        _ => {}
    }

    let mut transport = Transport::open(cli.port.as_deref())?;

    match cli.command {
        Commands::Ping => cmd_ping(&mut transport),
        Commands::Config => cmd_config(&mut transport),
        Commands::Address { index } => cmd_address(&mut transport, index),
        Commands::Accounts { count } => cmd_accounts(&mut transport, count),
        Commands::GenerateMnemonic => cmd_generate_mnemonic(&mut transport),
        Commands::ImportMnemonic => cmd_import_mnemonic(&mut transport),
        Commands::ClearSeed => cmd_clear_seed(&mut transport),
        Commands::DangerousMode => cmd_dangerous_mode(&mut transport),
        Commands::SignMessage { message, index } => cmd_sign_message(&mut transport, &message, index),
        Commands::SignTx { rlp_hex, index } => cmd_sign_tx(&mut transport, &rlp_hex, index),
        Commands::GenTx {
            to, value, nonce, chain_id, gas_price, gas_limit, index, data,
        } => cmd_gen_tx(
            &mut transport, &to, value, nonce, chain_id, gas_price, gas_limit, index,
            data.as_deref(),
        ),
        Commands::TxInfo { rpc_url, index, to, value, data } => cmd_tx_info(
            &mut transport, &rpc_url, index, to.as_deref(), value, data.as_deref(),
        ),
        Commands::BuildTx { .. } | Commands::Publish { .. } => unreachable!("handled above"),
    }
}

fn cmd_ping(t: &mut Transport) -> Result<()> {
    let (status, _) = t.command(OP_PING, &[])?;
    if status == STATUS_OK {
        println!("pong");
    } else {
        bail!("ping failed (status: 0x{:02x})", status);
    }
    Ok(())
}

fn cmd_config(t: &mut Transport) -> Result<()> {
    let (status, payload) = t.command(OP_GET_CONFIG, &[])?;
    if status != STATUS_OK {
        bail!("config failed (status: 0x{:02x})", status);
    }
    // Parse config response: [major, minor, patch, protocol, flags]
    if payload.len() >= 5 {
        let blind_signing = payload[4] & 0x01 != 0;
        let eth2 = payload[4] & 0x02 != 0;
        println!(
            "v{}.{}.{} protocol={} blind_signing={} eth2={}",
            payload[0], payload[1], payload[2], payload[3], blind_signing, eth2
        );
    } else {
        println!("config response: {}", hex::encode(&payload));
    }
    Ok(())
}

fn cmd_address(t: &mut Transport, index: u32) -> Result<()> {
    // Payload: BIP44 path components [purpose, coin_type, account, change, index]
    // Each as u32 BE, with hardened bit set on first three
    let path = bip44_payload(0, 0, index);
    let (status, payload) = t.command(OP_GET_ADDRESS, &path)?;
    if status != STATUS_OK {
        bail!("address failed (status: 0x{:02x})", status);
    }
    if payload.len() >= 20 {
        println!("m/44'/60'/0'/0/{} -> 0x{}", index, hex::encode(&payload[..20]));
    } else {
        bail!("unexpected response length: {}", payload.len());
    }
    Ok(())
}

fn cmd_accounts(t: &mut Transport, count: u32) -> Result<()> {
    for i in 0..count {
        let path = bip44_payload(0, 0, i);
        let (status, payload) = t.command(OP_GET_ADDRESS, &path)?;
        if status != STATUS_OK {
            eprintln!("[{}] error (status: 0x{:02x})", i, status);
            break;
        }
        if payload.len() >= 20 {
            println!("[{}] 0x{}", i, hex::encode(&payload[..20]));
        }
    }
    Ok(())
}

fn cmd_generate_mnemonic(t: &mut Transport) -> Result<()> {
    println!("Generating new mnemonic on device...");
    let (status, payload) = t.command(OP_GENERATE_MNEMONIC, &[])?;
    if status != STATUS_OK {
        bail!("generate-mnemonic failed (status: 0x{:02x})", status);
    }

    if !payload.is_empty() {
        // Dev-mode: device returned the mnemonic words for backup.
        let mnemonic = String::from_utf8_lossy(&payload);
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        println!();
        println!("╔══════════════════════════════════════════════════════════════╗");
        println!("║  DEVELOPER MODE — RECOVERY PHRASE SHOWN ON HOST             ║");
        println!("║  This is INSECURE. On production hardware, the phrase       ║");
        println!("║  is shown only on the device's secure display.              ║");
        println!("║                                                              ║");
        println!("║  Write these words down on paper. Store securely.           ║");
        println!("║  This is the ONLY way to recover your wallet.               ║");
        println!("╚══════════════════════════════════════════════════════════════╝");
        println!();
        for (i, word) in words.iter().enumerate() {
            print!("  {:>2}. {:<12}", i + 1, word);
            if (i + 1) % 4 == 0 {
                println!();
            }
        }
        if words.len() % 4 != 0 {
            println!();
        }
        println!();
        println!("Wallet created successfully.");
    } else {
        // Production: words shown on device screen only.
        println!("Check the device screen for your 24-word recovery phrase.");
        println!("Wallet created successfully.");
    }

    Ok(())
}

fn cmd_import_mnemonic(t: &mut Transport) -> Result<()> {
    // Read mnemonic from stdin interactively to avoid shell history
    print!("Enter your BIP39 mnemonic (12 or 24 words): ");
    io::stdout().flush()?;

    let stdin = io::stdin();
    let line = stdin.lock().lines().next()
        .ok_or_else(|| anyhow::anyhow!("No input"))??;

    let words: Vec<&str> = line.split_whitespace().collect();
    if words.len() != 12 && words.len() != 24 {
        bail!("Expected 12 or 24 words, got {}", words.len());
    }

    let mnemonic = words.join(" ");
    let (status, _) = t.command(OP_IMPORT_MNEMONIC, mnemonic.as_bytes())?;
    if status == STATUS_OK {
        println!("Mnemonic imported.");
        // Show derived address
        let path = bip44_payload(0, 0, 0);
        if let Ok((s, payload)) = t.command(OP_GET_ADDRESS, &path) {
            if s == STATUS_OK && payload.len() >= 20 {
                println!("address[0]: 0x{}", hex::encode(&payload[..20]));
            }
        }
    } else {
        bail!("import-mnemonic failed (status: 0x{:02x})", status);
    }
    Ok(())
}

fn cmd_clear_seed(t: &mut Transport) -> Result<()> {
    println!("This will wipe the master seed. Confirm on device.");
    let (status, _) = t.command(OP_CLEAR_SEED, &[])?;
    if status == STATUS_OK {
        println!("Seed cleared.");
    } else {
        bail!("clear-seed failed (status: 0x{:02x})", status);
    }
    Ok(())
}

fn cmd_dangerous_mode(t: &mut Transport) -> Result<()> {
    eprintln!("╔══════════════════════════════════════════════════════════════╗");
    eprintln!("║  WARNING: ENABLING DANGEROUS MAINNET MODE                   ║");
    eprintln!("║                                                              ║");
    eprintln!("║  This device has NO trusted display.                         ║");
    eprintln!("║  You CANNOT verify what you are signing on the device.       ║");
    eprintln!("║  A compromised host can steal ALL your funds.                ║");
    eprintln!("║                                                              ║");
    eprintln!("║  By proceeding you accept FULL responsibility for losses.    ║");
    eprintln!("║  This mode resets on device reboot.                          ║");
    eprintln!("╚══════════════════════════════════════════════════════════════╝");
    eprint!("Type 'I ACCEPT THE RISK' to continue: ");
    io::stderr().flush()?;

    let stdin = io::stdin();
    let line = stdin.lock().lines().next()
        .ok_or_else(|| anyhow::anyhow!("No input"))??;
    if line.trim() != "I ACCEPT THE RISK" {
        bail!("Aborted. You must type exactly: I ACCEPT THE RISK");
    }

    let (status, _) = t.command(OP_ENABLE_DANGEROUS_MAINNET, &[])?;
    if status == STATUS_OK {
        eprintln!("Dangerous mainnet mode ENABLED for this session.");
    } else {
        bail!("failed (status: 0x{:02x})", status);
    }
    Ok(())
}

fn cmd_sign_message(t: &mut Transport, message: &str, index: u32) -> Result<()> {
    let mut payload = bip44_payload(0, 0, index);
    payload.extend_from_slice(message.as_bytes());

    let (status, resp) = t.command(OP_SIGN_PERSONAL_MESSAGE, &payload)?;
    if status != STATUS_OK {
        bail!("sign-message failed (status: 0x{:02x})", status);
    }
    print_signature(&resp);
    Ok(())
}

fn cmd_sign_tx(t: &mut Transport, rlp_hex: &str, index: u32) -> Result<()> {
    let hex_str = rlp_hex.strip_prefix("0x").unwrap_or(rlp_hex);
    let tx_data = hex::decode(hex_str)?;

    // Detect tx type. EIP-2718 typed txs start with a type byte < 0x80.
    // Legacy txs start with the RLP list prefix (0xc0..=0xff).
    let tx_type = if !tx_data.is_empty() && tx_data[0] < 0x80 {
        Some(tx_data[0])
    } else {
        None
    };

    let mut payload = bip44_payload(0, 0, index);
    payload.extend_from_slice(&tx_data);

    let (status, resp) = t.command(OP_SIGN_TRANSACTION, &payload)?;
    if status != STATUS_OK {
        bail!("sign-tx failed (status: 0x{:02x})", status);
    }
    if resp.len() < 72 {
        print_signature(&resp);
        return Ok(());
    }
    let v = u64::from_le_bytes(resp[0..8].try_into().unwrap());
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&resp[8..40]);
    s.copy_from_slice(&resp[40..72]);

    println!("v={}", v);
    println!("r={}", hex::encode(&r));
    println!("s={}", hex::encode(&s));

    // Assemble the broadcastable signed RLP.
    match assemble_signed_tx(&tx_data, tx_type, v, &r, &s) {
        Ok(signed) => println!("raw: 0x{}", hex::encode(&signed)),
        Err(e) => eprintln!(
            "warning: could not assemble signed RLP ({}); pass an *unsigned* tx to get a broadcastable result",
            e
        ),
    }

    Ok(())
}

/// Combine an unsigned tx with the signature returned by the device into a
/// broadcastable signed RLP. Supports legacy EIP-155, EIP-2930, and EIP-1559.
fn assemble_signed_tx(
    tx_data: &[u8],
    tx_type: Option<u8>,
    v: u64,
    r: &[u8; 32],
    s: &[u8; 32],
) -> Result<Vec<u8>> {
    match tx_type {
        // Legacy EIP-155: unsigned has 9 items [n, gp, gl, to, value, data, chainId, 0, 0].
        // Replace last 3 with [v, r, s] to form the signed form.
        None => {
            let items = decode_top_level_items(tx_data)?;
            if items.len() != 9 {
                bail!("expected 9 RLP items in legacy tx, got {}", items.len());
            }
            // Sanity: items[7] and items[8] of an unsigned EIP-155 tx are the empty bytes (0).
            // If they aren't, the input is likely already signed.
            if items[7] != [0x80] || items[8] != [0x80] {
                bail!("input looks already signed (items 7,8 not zero)");
            }
            let mut payload = Vec::new();
            for item in items.iter().take(6) {
                payload.extend_from_slice(item);
            }
            payload.extend_from_slice(&rlp_encode_u64(v));
            payload.extend_from_slice(&rlp_encode_bytes(trim_leading_zeros(r)));
            payload.extend_from_slice(&rlp_encode_bytes(trim_leading_zeros(s)));
            Ok(rlp_encode_list(&payload))
        }
        // EIP-2930 (type 0x01): unsigned has 8 items [chainId, n, gp, gl, to, value, data, accessList].
        // Append [yParity, r, s] to form the signed body, then prepend type byte.
        Some(0x01) => {
            let items = decode_top_level_items(&tx_data[1..])?;
            if items.len() != 8 {
                bail!("expected 8 RLP items in EIP-2930 tx, got {}", items.len());
            }
            let mut payload = Vec::new();
            for item in &items {
                payload.extend_from_slice(item);
            }
            payload.extend_from_slice(&rlp_encode_u64(v));
            payload.extend_from_slice(&rlp_encode_bytes(trim_leading_zeros(r)));
            payload.extend_from_slice(&rlp_encode_bytes(trim_leading_zeros(s)));
            let mut out = vec![0x01];
            out.extend_from_slice(&rlp_encode_list(&payload));
            Ok(out)
        }
        // EIP-1559 (type 0x02): unsigned has 9 items
        // [chainId, n, maxPriorityFeePerGas, maxFeePerGas, gl, to, value, data, accessList].
        Some(0x02) => {
            let items = decode_top_level_items(&tx_data[1..])?;
            if items.len() != 9 {
                bail!("expected 9 RLP items in EIP-1559 tx, got {}", items.len());
            }
            let mut payload = Vec::new();
            for item in &items {
                payload.extend_from_slice(item);
            }
            payload.extend_from_slice(&rlp_encode_u64(v));
            payload.extend_from_slice(&rlp_encode_bytes(trim_leading_zeros(r)));
            payload.extend_from_slice(&rlp_encode_bytes(trim_leading_zeros(s)));
            let mut out = vec![0x02];
            out.extend_from_slice(&rlp_encode_list(&payload));
            Ok(out)
        }
        Some(t) => bail!("unsupported tx type byte: 0x{:02x}", t),
    }
}

/// Decode a top-level RLP list into its constituent items, returning each
/// item in its original encoded form (so we can splice without re-encoding
/// nested structures like accessList).
fn decode_top_level_items(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    if data.is_empty() {
        bail!("empty RLP");
    }
    let (header_len, payload_len, is_list) = parse_rlp_header(data)?;
    if !is_list {
        bail!("expected RLP list, got string");
    }
    let payload = &data[header_len..header_len + payload_len];
    let mut items = Vec::new();
    let mut offset = 0;
    while offset < payload.len() {
        let item_len = item_total_len(&payload[offset..])?;
        items.push(payload[offset..offset + item_len].to_vec());
        offset += item_len;
    }
    Ok(items)
}

/// Returns (header_len, payload_len, is_list).
fn parse_rlp_header(data: &[u8]) -> Result<(usize, usize, bool)> {
    if data.is_empty() {
        bail!("empty RLP");
    }
    let first = data[0];
    match first {
        0x00..=0x7f => Ok((0, 1, false)), // single-byte string, "header" is implicit
        0x80..=0xb7 => Ok((1, (first - 0x80) as usize, false)),
        0xb8..=0xbf => {
            let lb = (first - 0xb7) as usize;
            if data.len() < 1 + lb {
                bail!("truncated long string length");
            }
            let mut len = 0usize;
            for i in 0..lb {
                len = (len << 8) | data[1 + i] as usize;
            }
            Ok((1 + lb, len, false))
        }
        0xc0..=0xf7 => Ok((1, (first - 0xc0) as usize, true)),
        0xf8..=0xff => {
            let lb = (first - 0xf7) as usize;
            if data.len() < 1 + lb {
                bail!("truncated long list length");
            }
            let mut len = 0usize;
            for i in 0..lb {
                len = (len << 8) | data[1 + i] as usize;
            }
            Ok((1 + lb, len, true))
        }
    }
}

fn item_total_len(data: &[u8]) -> Result<usize> {
    let (header_len, payload_len, _) = parse_rlp_header(data)?;
    if header_len == 0 {
        // single-byte string in 0x00..=0x7f: data[0] IS the value
        Ok(1)
    } else {
        Ok(header_len + payload_len)
    }
}

/// Encode a BIP44 Ethereum path as bytes for the wire protocol.
///
/// Path: m/44'/60'/account'/change/index
/// Each component is u32 BE; hardened components have bit 31 set.
fn bip44_payload(account: u32, change: u32, index: u32) -> Vec<u8> {
    let components = [
        44 | 0x80000000,       // purpose (hardened)
        60 | 0x80000000,       // coin_type (hardened)
        account | 0x80000000,  // account (hardened)
        change,                // change
        index,                 // address_index
    ];
    let mut buf = Vec::with_capacity(1 + 5 * 4);
    buf.push(5); // path length
    for c in &components {
        buf.extend_from_slice(&c.to_be_bytes());
    }
    buf
}

fn print_signature(data: &[u8]) {
    // Expected: v (8 bytes u64 LE) + r (32 bytes) + s (32 bytes) = 72 bytes
    if data.len() >= 72 {
        let v = u64::from_le_bytes(data[0..8].try_into().unwrap());
        let r = &data[8..40];
        let s = &data[40..72];
        println!("v={}", v);
        println!("r={}", hex::encode(r));
        println!("s={}", hex::encode(s));
    } else {
        println!("signature: {}", hex::encode(data));
    }
}

// =============================================================================
// tx-info: fetch chain state for transaction construction
// =============================================================================

fn cmd_tx_info(
    t: &mut Transport,
    rpc_url: &str,
    index: u32,
    to: Option<&str>,
    value: u128,
    data_hex: Option<&str>,
) -> Result<()> {
    // 1. Get our address from the device
    let path = bip44_payload(0, 0, index);
    let (status, payload) = t.command(OP_GET_ADDRESS, &path)?;
    if status != STATUS_OK || payload.len() < 20 {
        bail!("failed to get address from device (status: 0x{:02x})", status);
    }
    let addr_hex = format!("0x{}", hex::encode(&payload[..20]));

    println!("address[{}]   {}", index, addr_hex);

    // 2. Query the RPC
    let mut rpc = rpc::RpcClient::new(rpc_url);

    let chain_id = rpc.chain_id()?;
    println!("chain id     {} ({})", chain_id, chain_name(chain_id));

    let balance = rpc.balance(&addr_hex)?;
    println!("balance      {} wei  ({})", balance, format_eth(balance));

    let nonce = rpc.nonce(&addr_hex)?;
    println!("nonce        {}  (pending)", nonce);

    let gas_price = rpc.gas_price()?;
    println!("gas price    {} wei  ({})", gas_price, format_gwei(gas_price));

    match rpc.fee_suggestion() {
        Ok(Some(fees)) => {
            println!("EIP-1559:");
            println!(
                "  next base fee       {} wei  ({})",
                fees.next_base_fee, format_gwei(fees.next_base_fee)
            );
            println!(
                "  priority fee (p50)  {} wei  ({})",
                fees.priority_fee_per_gas, format_gwei(fees.priority_fee_per_gas)
            );
            let max_fee = fees.max_fee_per_gas();
            println!(
                "  suggested max fee   {} wei  ({})",
                max_fee, format_gwei(max_fee)
            );
        }
        Ok(None) => println!("EIP-1559:    not supported by this RPC"),
        Err(e) => println!("EIP-1559:    error fetching feeHistory: {}", e),
    }

    // 3. Gas estimate
    let calldata: Vec<u8> = match data_hex {
        Some(h) => hex::decode(h.strip_prefix("0x").unwrap_or(h))?,
        None => Vec::new(),
    };
    let gas_limit = match to {
        Some(to_addr) => {
            let to_clean = to_addr.strip_prefix("0x").unwrap_or(to_addr);
            let to_full = format!("0x{}", to_clean);
            match rpc.estimate_gas(&addr_hex, &to_full, value, &calldata) {
                Ok(g) => {
                    println!("gas limit    {} (estimated for the given --to/--value/--data)", g);
                    g
                }
                Err(e) => {
                    eprintln!("gas estimate failed: {}", e);
                    21_000
                }
            }
        }
        None => {
            println!("gas limit    21000 (default; pass --to to estimate against a target)");
            21_000
        }
    };

    // 4. Convenience: print a ready-to-use gen-tx invocation
    if let Some(to_addr) = to {
        println!();
        println!("Ready-to-use gen-tx command:");
        let calldata_arg = if data_hex.is_some() {
            format!(" --data {}", data_hex.unwrap())
        } else {
            String::new()
        };
        println!(
            "  ethcli gen-tx {} {} \\\n    --nonce {} --chain-id {} \\\n    --gas-price {} --gas-limit {} --index {}{}",
            to_addr, value, nonce, chain_id, gas_price, gas_limit, index, calldata_arg
        );
    }

    Ok(())
}

fn format_eth(wei: u128) -> String {
    let eth = wei as f64 / 1e18;
    if eth >= 0.0001 {
        format!("{:.6} ETH", eth)
    } else {
        format!("{:.9} ETH", eth)
    }
}

fn format_gwei(wei: u128) -> String {
    format!("{:.3} gwei", wei as f64 / 1e9)
}

// =============================================================================
// publish: broadcast a signed tx via eth_sendRawTransaction
// =============================================================================

fn cmd_publish(signed_tx_hex: &str, rpc_url: &str, wait: bool, wait_timeout: u64) -> Result<()> {
    let hex_str = signed_tx_hex.strip_prefix("0x").unwrap_or(signed_tx_hex);
    let signed = hex::decode(hex_str)?;
    if signed.is_empty() {
        bail!("empty signed tx");
    }

    let mut rpc = rpc::RpcClient::new(rpc_url);
    let tx_hash = rpc.send_raw_transaction(&signed)?;
    println!("tx hash: {}", tx_hash);

    if !wait {
        return Ok(());
    }

    println!("waiting for inclusion (timeout: {}s)...", wait_timeout);
    let start = std::time::Instant::now();
    let poll_interval = std::time::Duration::from_secs(3);
    loop {
        if start.elapsed().as_secs() > wait_timeout {
            bail!("timeout waiting for tx receipt");
        }
        match rpc.get_transaction_receipt(&tx_hash)? {
            Some(receipt) => {
                let block = receipt.get("blockNumber")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                let status = receipt.get("status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                let gas_used = receipt.get("gasUsed")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                let status_label = match status {
                    "0x1" => "success",
                    "0x0" => "REVERTED",
                    _ => status,
                };
                println!("included in block {}", block);
                println!("status:    {}", status_label);
                println!("gas used:  {}", gas_used);
                return Ok(());
            }
            None => {
                std::thread::sleep(poll_interval);
            }
        }
    }
}

// =============================================================================
// build-tx: produce the unsigned RLP without touching the device
// =============================================================================

#[allow(clippy::too_many_arguments)]
fn cmd_build_tx(
    to: &str,
    value: u128,
    nonce: u64,
    chain_id: u64,
    gas_price: u64,
    gas_limit: u64,
    data_hex: Option<&str>,
) -> Result<()> {
    let to_clean = to.strip_prefix("0x").unwrap_or(to);
    let to_addr = hex::decode(to_clean)?;
    if to_addr.len() != 20 {
        bail!("invalid address: need 20 bytes, got {}", to_addr.len());
    }

    let calldata: Vec<u8> = match data_hex {
        Some(h) => hex::decode(h.strip_prefix("0x").unwrap_or(h))?,
        None => Vec::new(),
    };

    let params = TxParams { nonce, gas_price, gas_limit, chain_id };
    let unsigned = rlp_encode_legacy_unsigned(&to_addr, value, &calldata, &params);

    println!("chain:    {} ({})", chain_id, chain_name(chain_id));
    println!("to:       0x{}", to_clean);
    println!("value:    {} wei", value);
    println!("nonce:    {}  gas: {}  gasPrice: {} wei", nonce, gas_limit, gas_price);
    if !calldata.is_empty() {
        println!("data:     0x{}", hex::encode(&calldata));
    }
    println!("unsigned: 0x{}", hex::encode(&unsigned));
    println!();
    println!("To sign and broadcast: ethcli sign-tx 0x{}", hex::encode(&unsigned));
    Ok(())
}

// =============================================================================
// gen-tx: build, sign, and emit a legacy EIP-155 transaction
// =============================================================================

#[allow(clippy::too_many_arguments)]
fn cmd_gen_tx(
    t: &mut Transport,
    to: &str,
    value: u128,
    nonce: u64,
    chain_id: u64,
    gas_price: u64,
    gas_limit: u64,
    index: u32,
    data_hex: Option<&str>,
) -> Result<()> {
    let to_clean = to.strip_prefix("0x").unwrap_or(to);
    let to_addr = hex::decode(to_clean)?;
    if to_addr.len() != 20 {
        bail!("invalid address: need 20 bytes, got {}", to_addr.len());
    }

    let calldata: Vec<u8> = match data_hex {
        Some(h) => {
            let h = h.strip_prefix("0x").unwrap_or(h);
            hex::decode(h)?
        }
        None => Vec::new(),
    };

    let params = TxParams { nonce, gas_price, gas_limit, chain_id };
    let unsigned = rlp_encode_legacy_unsigned(&to_addr, value, &calldata, &params);

    // Build payload: [path_bytes...][rlp_unsigned_tx_bytes...]
    let mut payload = bip44_payload(0, 0, index);
    payload.extend_from_slice(&unsigned);

    let (status, resp) = t.command(OP_SIGN_TRANSACTION, &payload)?;
    if status != STATUS_OK {
        bail!("sign failed (status: 0x{:02x})", status);
    }
    if resp.len() < 72 {
        bail!("unexpected signature response length: {}", resp.len());
    }

    let v = u64::from_le_bytes(resp[0..8].try_into().unwrap());
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&resp[8..40]);
    s.copy_from_slice(&resp[40..72]);

    let signed = rlp_encode_legacy_signed(&to_addr, value, &calldata, &params, v, &r, &s);

    println!("chain: {} ({})", chain_id, chain_name(chain_id));
    println!("to:    0x{}", to_clean);
    println!("value: {} wei", value);
    println!("nonce: {}  gas: {}  gasPrice: {} wei", nonce, gas_limit, gas_price);
    if !calldata.is_empty() {
        println!("data:  0x{}", hex::encode(&calldata));
    }
    println!("v={}", v);
    println!("r={}", hex::encode(&r));
    println!("s={}", hex::encode(&s));
    println!("raw:   0x{}", hex::encode(&signed));
    Ok(())
}

struct TxParams {
    nonce: u64,
    gas_price: u64,
    gas_limit: u64,
    chain_id: u64,
}

/// RLP-encode an unsigned legacy EIP-155 transaction:
/// [nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0]
fn rlp_encode_legacy_unsigned(to: &[u8], value: u128, data: &[u8], p: &TxParams) -> Vec<u8> {
    let mut items = Vec::new();
    items.extend_from_slice(&rlp_encode_u64(p.nonce));
    items.extend_from_slice(&rlp_encode_u64(p.gas_price));
    items.extend_from_slice(&rlp_encode_u64(p.gas_limit));
    items.extend_from_slice(&rlp_encode_bytes(to));
    items.extend_from_slice(&rlp_encode_u128(value));
    items.extend_from_slice(&rlp_encode_bytes(data));
    items.extend_from_slice(&rlp_encode_u64(p.chain_id));
    items.extend_from_slice(&rlp_encode_u64(0));
    items.extend_from_slice(&rlp_encode_u64(0));
    rlp_encode_list(&items)
}

/// RLP-encode a signed legacy transaction:
/// [nonce, gasPrice, gasLimit, to, value, data, v, r, s]
fn rlp_encode_legacy_signed(
    to: &[u8], value: u128, data: &[u8], p: &TxParams,
    v: u64, r: &[u8; 32], s: &[u8; 32],
) -> Vec<u8> {
    let mut items = Vec::new();
    items.extend_from_slice(&rlp_encode_u64(p.nonce));
    items.extend_from_slice(&rlp_encode_u64(p.gas_price));
    items.extend_from_slice(&rlp_encode_u64(p.gas_limit));
    items.extend_from_slice(&rlp_encode_bytes(to));
    items.extend_from_slice(&rlp_encode_u128(value));
    items.extend_from_slice(&rlp_encode_bytes(data));
    items.extend_from_slice(&rlp_encode_u64(v));
    items.extend_from_slice(&rlp_encode_bytes(trim_leading_zeros(r)));
    items.extend_from_slice(&rlp_encode_bytes(trim_leading_zeros(s)));
    rlp_encode_list(&items)
}

fn trim_leading_zeros(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    &bytes[start..]
}

fn rlp_encode_u64(value: u64) -> Vec<u8> {
    if value == 0 {
        return vec![0x80];
    }
    let bytes = value.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(8);
    rlp_encode_bytes(&bytes[start..])
}

fn rlp_encode_u128(value: u128) -> Vec<u8> {
    if value == 0 {
        return vec![0x80];
    }
    let bytes = value.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(16);
    rlp_encode_bytes(&bytes[start..])
}

fn rlp_encode_bytes(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return vec![0x80];
    }
    if data.len() == 1 && data[0] < 0x80 {
        return data.to_vec();
    }
    if data.len() <= 55 {
        let mut result = vec![0x80 + data.len() as u8];
        result.extend_from_slice(data);
        return result;
    }
    let len_bytes = (data.len() as u64).to_be_bytes();
    let start = len_bytes.iter().position(|&b| b != 0).unwrap_or(8);
    let len_bytes = &len_bytes[start..];
    let mut result = vec![0xb7 + len_bytes.len() as u8];
    result.extend_from_slice(len_bytes);
    result.extend_from_slice(data);
    result
}

fn rlp_encode_list(items: &[u8]) -> Vec<u8> {
    if items.len() <= 55 {
        let mut result = vec![0xc0 + items.len() as u8];
        result.extend_from_slice(items);
        return result;
    }
    let len_bytes = (items.len() as u64).to_be_bytes();
    let start = len_bytes.iter().position(|&b| b != 0).unwrap_or(8);
    let len_bytes = &len_bytes[start..];
    let mut result = vec![0xf7 + len_bytes.len() as u8];
    result.extend_from_slice(len_bytes);
    result.extend_from_slice(items);
    result
}

fn chain_name(id: u64) -> &'static str {
    match id {
        1 => "mainnet",
        5 => "goerli",
        10 => "optimism",
        56 => "bsc",
        137 => "polygon",
        17000 => "holesky",
        42161 => "arbitrum",
        11155111 => "sepolia",
        _ => "unknown",
    }
}
