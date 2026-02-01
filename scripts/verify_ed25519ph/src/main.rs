//! Ed25519ph signature verification tool for Baochip attestation
//!
//! This tool verifies Ed25519ph (prehashed) signatures from Baochip audit output.
//! Ed25519ph uses SHA-512 as the prehash function per RFC 8032.
//!
//! Usage:
//!   # Parse audit output from stdin
//!   cat audit.txt | verify_ed25519ph
//!   verify_ed25519ph < audit.txt
//!
//!   # Or specify values directly
//!   verify_ed25519ph --pubkey developer --hash <hex> --sig <hex> --name boot1

use clap::Parser;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::digest::{FixedOutput, HashMarker, Output, OutputSizeUser, Reset, Update};
use std::collections::HashMap;
use std::io::{self, BufRead};

/// Known public keys from libs/bao1x-api/src/pubkeys/
/// Key slots: 0=bao1, 1=bao2, 2=beta, 3=developer
const PUBKEYS: &[(&str, &str)] = &[
    (
        "bao1",
        "a87a5f98daabfb512fc3c2e5749b3beb192388d20160a7dd5888fb9da409523a",
    ),
    (
        "bao2",
        "79135dc667aff4f7d352b90328788ebf92c7867821388b77370b15194e312888",
    ),
    (
        "beta",
        "80979929edd04e40124b52cae9ae54b24bdff72a7b8a004c41065bd1402078a7",
    ),
    (
        "developer",
        "1c9beae32aeac87507c18094387eff1c74614282affd8152d871352edf3f58bb",
    ),
    // Aliases
    (
        "dev",
        "1c9beae32aeac87507c18094387eff1c74614282affd8152d871352edf3f58bb",
    ),
];

/// Tag to key name mapping (from audit output)
/// Tags are 4 bytes in the signature block, may have trailing spaces
const TAG_TO_KEY: &[(&str, &str)] = &[
    ("bao1", "bao1"),
    ("bao2", "bao2"),
    ("beta", "beta"),
    ("devl", "developer"),
    ("dev", "developer"),  // may appear as "dev " with trailing space
];

#[derive(Parser)]
#[command(name = "verify_ed25519ph")]
#[command(about = "Verify Ed25519ph signatures from Baochip attestation")]
#[command(
    long_about = "Verify Ed25519ph signatures from Baochip attestation.\n\n\
    Can parse audit output from stdin or accept explicit values.\n\n\
    Examples:\n  \
    cat audit.txt | verify_ed25519ph\n  \
    verify_ed25519ph --pubkey developer --hash <hex> --sig <hex>"
)]
struct Args {
    /// Public key in hex (32 bytes) or key name (bao1, bao2, beta, developer)
    #[arg(short, long)]
    pubkey: Option<String>,

    /// SHA-512 hash of signed data in hex (64 bytes)
    #[arg(short = 'H', long)]
    hash: Option<String>,

    /// Signature in hex (64 bytes)
    #[arg(short, long)]
    sig: Option<String>,

    /// AAD (Additional Authenticated Data) in hex - if provided, uses FIDO2 mode
    #[arg(short, long)]
    aad: Option<String>,

    /// Name/stage to verify (boot0, boot1, loader) - used when parsing audit output
    #[arg(short, long, default_value = "all")]
    name: String,
}

/// A wrapper struct that implements Digest but returns a precomputed hash.
/// This allows us to use ed25519-dalek's verify_prehashed with an already-finalized hash.
struct PrecomputedHash {
    hash: [u8; 64],
}

impl OutputSizeUser for PrecomputedHash {
    type OutputSize = sha2::digest::typenum::U64;
}

impl FixedOutput for PrecomputedHash {
    fn finalize_into(self, out: &mut Output<Self>) {
        out.copy_from_slice(&self.hash);
    }
}

impl Default for PrecomputedHash {
    fn default() -> Self {
        Self { hash: [0u8; 64] }
    }
}

impl HashMarker for PrecomputedHash {}

impl Update for PrecomputedHash {
    fn update(&mut self, _data: &[u8]) {
        // No-op: we already have the finalized hash
    }
}

impl Reset for PrecomputedHash {
    fn reset(&mut self) {
        // No-op
    }
}

fn resolve_pubkey(input: &str) -> Result<[u8; 32], String> {
    // Check if it's a known key name
    for (name, pk_hex) in PUBKEYS {
        if input.eq_ignore_ascii_case(name) {
            let bytes = hex::decode(pk_hex).map_err(|e| format!("Invalid built-in key: {}", e))?;
            return bytes
                .try_into()
                .map_err(|_| "Built-in key has wrong length".to_string());
        }
    }

    // Otherwise treat as hex
    let bytes = hex::decode(input).map_err(|e| format!("Invalid hex: {}", e))?;
    bytes
        .try_into()
        .map_err(|_| format!("Public key must be 32 bytes, got {}", input.len() / 2))
}

fn identify_key(pubkey_bytes: &[u8; 32]) -> Option<&'static str> {
    let pubkey_hex = hex::encode(pubkey_bytes);
    for (name, pk) in PUBKEYS {
        if pubkey_hex.eq_ignore_ascii_case(pk) {
            return Some(name);
        }
    }
    None
}

fn tag_to_key_name(tag: &str) -> Option<&'static str> {
    let tag = tag.trim();  // Handle trailing spaces in 4-byte tags
    for (t, name) in TAG_TO_KEY {
        if tag.eq_ignore_ascii_case(t) {
            return Some(name);
        }
    }
    None
}

/// Parsed attestation data for a single stage
#[derive(Default, Debug)]
struct StageData {
    sig: Option<String>,
    hash: Option<String>,
    key_slot: Option<u32>,
    key_tag: Option<String>,
    aad_len: Option<u32>,
    aad: Option<String>,
}

/// Parse audit output and extract attestation data
fn parse_audit_output(input: &str) -> HashMap<String, StageData> {
    let mut stages: HashMap<String, StageData> = HashMap::new();

    for line in input.lines() {
        let line = line.trim();

        // Parse: boot0.sig:<hex>, boot0.hash:<hex>, boot0.aad_len:<num>, boot0.aad:<hex>
        for stage in &["boot0", "boot1", "loader"] {
            if let Some(rest) = line.strip_prefix(&format!("{}.sig:", stage)) {
                stages.entry(stage.to_string()).or_default().sig = Some(rest.trim().to_string());
            }
            if let Some(rest) = line.strip_prefix(&format!("{}.hash:", stage)) {
                stages.entry(stage.to_string()).or_default().hash = Some(rest.trim().to_string());
            }
            if let Some(rest) = line.strip_prefix(&format!("{}.aad_len:", stage)) {
                if let Ok(len) = rest.trim().parse::<u32>() {
                    stages.entry(stage.to_string()).or_default().aad_len = Some(len);
                }
            }
            if let Some(rest) = line.strip_prefix(&format!("{}.aad:", stage)) {
                stages.entry(stage.to_string()).or_default().aad = Some(rest.trim().to_string());
            }
        }

        // Parse: "Boot0: key 2/true (beta) -> ..."
        if let Some(caps) = parse_key_line(line, "Boot0:") {
            let entry = stages.entry("boot0".to_string()).or_default();
            entry.key_slot = Some(caps.0);
            entry.key_tag = Some(caps.1);
        }
        if let Some(caps) = parse_key_line(line, "Boot1:") {
            let entry = stages.entry("boot1".to_string()).or_default();
            entry.key_slot = Some(caps.0);
            entry.key_tag = Some(caps.1);
        }
        if let Some(caps) = parse_key_line(line, "Next stage:") {
            let entry = stages.entry("loader".to_string()).or_default();
            entry.key_slot = Some(caps.0);
            entry.key_tag = Some(caps.1);
        }
    }

    stages
}

/// Parse a line like "Boot0: key 2/true (beta) -> ..." and extract (slot, tag)
fn parse_key_line(line: &str, prefix: &str) -> Option<(u32, String)> {
    if !line.starts_with(prefix) {
        return None;
    }

    // Find "key N" pattern
    let key_idx = line.find("key ")?;
    let after_key = &line[key_idx + 4..];

    // Parse the number
    let slot_end = after_key.find(|c: char| !c.is_ascii_digit())?;
    let slot: u32 = after_key[..slot_end].parse().ok()?;

    // Find tag in parentheses
    let paren_start = line.find('(')?;
    let paren_end = line.find(')')?;
    let tag = line[paren_start + 1..paren_end].to_string();

    Some((slot, tag))
}

/// Verify a signature - supports both Ed25519ph and FIDO2 modes
///
/// - If aad is None or empty: Ed25519ph mode (verify_prehashed)
/// - If aad is Some with data: FIDO2 mode (standard Ed25519 over aad || SHA256(hash))
fn verify_single(
    pubkey_hex: &str,
    hash_hex: &str,
    sig_hex: &str,
    aad_hex: Option<&str>,
    name: &str,
) -> Result<(), String> {
    use ed25519_dalek::Verifier;
    use sha2::{Sha256, Digest};

    // Parse public key
    let pubkey_bytes = resolve_pubkey(pubkey_hex)?;

    // Parse hash (SHA-512 of signed region)
    let hash_bytes: [u8; 64] = hex::decode(hash_hex)
        .map_err(|e| format!("Invalid hash hex: {}", e))?
        .try_into()
        .map_err(|_| format!("Hash must be 64 bytes, got {}", hash_hex.len() / 2))?;

    // Parse signature
    let sig_bytes: [u8; 64] = hex::decode(sig_hex)
        .map_err(|e| format!("Invalid signature hex: {}", e))?
        .try_into()
        .map_err(|_| format!("Signature must be 64 bytes, got {}", sig_hex.len() / 2))?;

    // Parse AAD if provided
    let aad_bytes: Option<Vec<u8>> = match aad_hex {
        Some(hex) if !hex.is_empty() => {
            Some(hex::decode(hex).map_err(|e| format!("Invalid AAD hex: {}", e))?)
        }
        _ => None,
    };

    // Determine verification mode
    let is_fido2 = aad_bytes.is_some();

    // Display verification info
    println!("=== Verifying {} ===", name);
    println!("Mode:       {}", if is_fido2 { "FIDO2" } else { "Ed25519ph" });

    if let Some(key_name) = identify_key(&pubkey_bytes) {
        println!("Public key: {}", key_name);
    } else {
        println!(
            "Public key: {}...{}",
            &pubkey_hex[..16.min(pubkey_hex.len())],
            &pubkey_hex[pubkey_hex.len().saturating_sub(16)..]
        );
    }

    println!(
        "Hash:       {}...{}",
        &hash_hex[..16.min(hash_hex.len())],
        &hash_hex[hash_hex.len().saturating_sub(16)..]
    );
    println!(
        "Signature:  {}...{}",
        &sig_hex[..16.min(sig_hex.len())],
        &sig_hex[sig_hex.len().saturating_sub(16)..]
    );
    if let Some(ref aad) = aad_bytes {
        println!("AAD:        {} bytes", aad.len());
    }

    // Create verification key
    let verifying_key =
        VerifyingKey::from_bytes(&pubkey_bytes).map_err(|e| format!("Invalid public key: {}", e))?;

    // Create signature
    let signature = Signature::from_bytes(&sig_bytes);

    let result = if is_fido2 {
        // FIDO2 mode: verify standard Ed25519 over (aad || SHA256(SHA512_hash))
        // 1. hash_bytes is already SHA-512 of the signed region
        // 2. Compute SHA-256 of that
        let mut sha256 = Sha256::new();
        Digest::update(&mut sha256, &hash_bytes);
        let hashed_hash = sha256.finalize();

        // 3. Concatenate: aad || SHA256(SHA512(image))
        let mut msg = Vec::new();
        msg.extend_from_slice(aad_bytes.as_ref().unwrap());
        msg.extend_from_slice(&hashed_hash);

        // 4. Standard Ed25519 verify
        verifying_key.verify(&msg, &signature)
    } else {
        // Ed25519ph mode: verify_prehashed with the SHA-512 hash
        let prehash = PrecomputedHash { hash: hash_bytes };
        verifying_key.verify_prehashed(prehash, None, &signature)
    };

    match result {
        Ok(()) => {
            println!("✓ PASSED\n");
            Ok(())
        }
        Err(e) => {
            println!("✗ FAILED: {}\n", e);
            Err(format!("{} verification failed", name))
        }
    }
}

fn main() {
    let args = Args::parse();

    // If explicit values provided, verify directly
    if args.pubkey.is_some() && args.hash.is_some() && args.sig.is_some() {
        let result = verify_single(
            args.pubkey.as_ref().unwrap(),
            args.hash.as_ref().unwrap(),
            args.sig.as_ref().unwrap(),
            args.aad.as_deref(),  // Use AAD if provided for FIDO2 mode
            &args.name,
        );
        match &result {
            Ok(_) => {}
            Err(e) => eprintln!("Error: {}", e),
        }
        std::process::exit(if result.is_ok() { 0 } else { 1 });
    }

    // Otherwise, read audit output from stdin
    let stdin = io::stdin();
    let input: String = stdin.lock().lines().filter_map(|l| l.ok()).collect::<Vec<_>>().join("\n");

    if input.is_empty() {
        eprintln!("No input provided.");
        eprintln!("Usage: cat audit.txt | verify_ed25519ph");
        eprintln!("   or: verify_ed25519ph --pubkey <key> --hash <hex> --sig <hex>");
        std::process::exit(1);
    }

    let stages = parse_audit_output(&input);

    if stages.is_empty() {
        eprintln!("No attestation data found in input.");
        eprintln!("Expected format: boot0.sig:<hex>, boot0.hash:<hex>, etc.");
        std::process::exit(1);
    }

    // Determine which stages to verify
    let stages_to_verify: Vec<&str> = if args.name == "all" {
        vec!["boot0", "boot1", "loader"]
    } else {
        vec![args.name.as_str()]
    };

    println!("Found attestation data for: {:?}\n", stages.keys().collect::<Vec<_>>());

    let mut results: Vec<(&str, bool)> = Vec::new();

    for stage_name in stages_to_verify {
        if let Some(stage) = stages.get(stage_name) {
            let (sig, hash) = match (&stage.sig, &stage.hash) {
                (Some(s), Some(h)) => (s, h),
                _ => {
                    println!("Incomplete data for {} (missing sig or hash)\n", stage_name);
                    continue;
                }
            };

            // Determine which key to use
            let pubkey = if let Some(ref tag) = stage.key_tag {
                if let Some(key_name) = tag_to_key_name(tag) {
                    key_name.to_string()
                } else {
                    eprintln!("Unknown key tag '{}' for {}", tag, stage_name);
                    continue;
                }
            } else if let Some(slot) = stage.key_slot {
                match slot {
                    0 => "bao1".to_string(),
                    1 => "bao2".to_string(),
                    2 => "beta".to_string(),
                    3 => "developer".to_string(),
                    _ => {
                        eprintln!("Unknown key slot {} for {}", slot, stage_name);
                        continue;
                    }
                }
            } else {
                // Default to developer key
                eprintln!("No key info for {}, using developer key", stage_name);
                "developer".to_string()
            };

            // Get AAD if present (for FIDO2 mode)
            let aad = stage.aad.as_deref();

            let result = verify_single(&pubkey, hash, sig, aad, stage_name);
            results.push((stage_name, result.is_ok()));
        }
    }

    // Print summary
    println!("=== Summary ===");
    let mut all_passed = true;
    for (stage, passed) in &results {
        let status = if *passed { "✓ VERIFIED" } else { "✗ FAILED" };
        println!("{}: {}", stage, status);
        if !passed {
            all_passed = false;
        }
    }

    std::process::exit(if all_passed { 0 } else { 1 });
}
