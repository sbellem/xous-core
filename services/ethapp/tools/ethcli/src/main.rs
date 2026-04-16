//! ethcli - Host-side CLI for the Baochip-1x Ethereum hardware wallet.
//!
//! Communicates with the ethapp service over USB CDC-ACM serial,
//! replacing the need for `tio /dev/ttyACM0`.

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
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut transport = Transport::open(cli.port.as_deref())?;

    match cli.command {
        Commands::Ping => cmd_ping(&mut transport),
        Commands::Config => cmd_config(&mut transport),
        Commands::Address { index } => cmd_address(&mut transport, index),
        Commands::Accounts { count } => cmd_accounts(&mut transport, count),
        Commands::GenerateMnemonic => cmd_generate_mnemonic(&mut transport),
        Commands::ImportMnemonic => cmd_import_mnemonic(&mut transport),
        Commands::ClearSeed => cmd_clear_seed(&mut transport),
        Commands::SignMessage { message, index } => cmd_sign_message(&mut transport, &message, index),
        Commands::SignTx { rlp_hex, index } => cmd_sign_tx(&mut transport, &rlp_hex, index),
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
    println!("Check the device screen for your 24-word recovery phrase.");
    let (status, _) = t.command(OP_GENERATE_MNEMONIC, &[])?;
    if status == STATUS_OK {
        println!("Wallet created successfully.");
    } else {
        bail!("generate-mnemonic failed (status: 0x{:02x})", status);
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

    let mut payload = bip44_payload(0, 0, index);
    payload.extend_from_slice(&tx_data);

    let (status, resp) = t.command(OP_SIGN_TRANSACTION, &payload)?;
    if status != STATUS_OK {
        bail!("sign-tx failed (status: 0x{:02x})", status);
    }
    print_signature(&resp);
    Ok(())
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
