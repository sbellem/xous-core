//! Integration test app for the ethapp Ethereum signing service.
//!
//! Exercises the ethapp service via IPC to verify:
//! - Service connectivity (ping)
//! - App configuration retrieval
//! - Public key derivation (BIP44 Ethereum paths)
//! - Personal message signing (EIP-191)
//! - Transaction signing (legacy EIP-155)
//! - EIP-712 hashed signing
//! - Metadata caching
//!
//! Requires the ethapp service to be running with `dev-mode` and `autoapprove`
//! features for unattended testing.
//!
//! Run with: cargo xtask dabao-emu ethapp-test

use std::string::String;
use std::vec::Vec;

use ethapp_api::EthAppClient;
use ethapp_common::{
    rlp, Bip32Path, Hash256, ProvideTokenInfoRequest, SignEip712HashedRequest,
    SignPersonalMessageRequest, SignTransactionRequest, TokenInfo,
};

// =============================================================================
// Test runner
// =============================================================================

struct TestRunner {
    passed: u32,
    failed: u32,
    skipped: u32,
}

impl TestRunner {
    fn new() -> Self {
        Self {
            passed: 0,
            failed: 0,
            skipped: 0,
        }
    }

    fn pass(&mut self, name: &str) {
        self.passed += 1;
        log::info!("[PASS] {}", name);
    }

    fn fail(&mut self, name: &str, reason: &str) {
        self.failed += 1;
        log::error!("[FAIL] {}: {}", name, reason);
    }

    fn skip(&mut self, name: &str, reason: &str) {
        self.skipped += 1;
        log::warn!("[SKIP] {}: {}", name, reason);
    }

    fn summary(&self) {
        let total = self.passed + self.failed + self.skipped;
        log::info!("========================================");
        log::info!(
            "Results: {} passed, {} failed, {} skipped (of {} total)",
            self.passed,
            self.failed,
            self.skipped,
            total
        );
        if self.failed == 0 {
            log::info!("ALL TESTS PASSED");
        } else {
            log::error!("{} TEST(S) FAILED", self.failed);
        }
        log::info!("========================================");
    }
}

// =============================================================================
// Tests
// =============================================================================

fn test_ping(client: &EthAppClient, runner: &mut TestRunner) {
    match client.ping() {
        Ok(()) => runner.pass("ping"),
        Err(e) => runner.fail("ping", &format!("{:?}", e)),
    }
}

fn test_get_app_configuration(client: &EthAppClient, runner: &mut TestRunner) {
    match client.get_app_configuration() {
        Ok(config) => {
            log::info!(
                "  config: v{}.{}.{}, protocol={}, blind_signing={}, eth2={}",
                config.version_major,
                config.version_minor,
                config.version_patch,
                config.protocol_version,
                config.blind_signing_enabled,
                config.eth2_supported,
            );
            if config.protocol_version == 1 {
                runner.pass("get_app_configuration");
            } else {
                runner.fail(
                    "get_app_configuration",
                    &format!("unexpected protocol version: {}", config.protocol_version),
                );
            }
        }
        Err(e) => runner.fail("get_app_configuration", &format!("{:?}", e)),
    }
}

fn test_get_public_key(client: &EthAppClient, runner: &mut TestRunner) {
    // Standard Ethereum path: m/44'/60'/0'/0/0
    let path = Bip32Path::ethereum(0, 0, 0);

    match client.get_public_key(&path) {
        Ok(response) => {
            let addr_hex = hex::encode(response.address);
            let pubkey_hex = hex::encode(response.pubkey);
            log::info!("  address: 0x{}", addr_hex);
            log::info!("  pubkey:  {}", pubkey_hex);

            // Basic sanity: pubkey should start with 0x02 or 0x03 (compressed)
            if response.pubkey[0] == 0x02 || response.pubkey[0] == 0x03 {
                runner.pass("get_public_key");
            } else {
                runner.fail(
                    "get_public_key",
                    &format!("unexpected pubkey prefix: 0x{:02x}", response.pubkey[0]),
                );
            }
        }
        Err(e) => runner.fail("get_public_key", &format!("{:?}", e)),
    }
}

fn test_get_address(client: &EthAppClient, runner: &mut TestRunner) {
    let path = Bip32Path::ethereum(0, 0, 0);

    match client.get_address(&path) {
        Ok(address) => {
            let addr_hex = hex::encode(address);
            log::info!("  address: 0x{}", addr_hex);

            // Address should not be all zeros
            if address.iter().any(|&b| b != 0) {
                runner.pass("get_address");
            } else {
                runner.fail("get_address", "address is all zeros");
            }
        }
        Err(e) => runner.fail("get_address", &format!("{:?}", e)),
    }
}

fn test_get_public_key_consistency(client: &EthAppClient, runner: &mut TestRunner) {
    // Verify that get_public_key and get_address return the same address
    let path = Bip32Path::ethereum(0, 0, 0);

    let pk_result = client.get_public_key(&path);
    let addr_result = client.get_address(&path);

    match (pk_result, addr_result) {
        (Ok(pk_resp), Ok(addr)) => {
            if pk_resp.address == addr {
                runner.pass("public_key_address_consistency");
            } else {
                runner.fail(
                    "public_key_address_consistency",
                    &format!(
                        "mismatch: pk.address=0x{} vs address=0x{}",
                        hex::encode(pk_resp.address),
                        hex::encode(addr)
                    ),
                );
            }
        }
        (Err(e), _) => runner.fail("public_key_address_consistency", &format!("pk: {:?}", e)),
        (_, Err(e)) => runner.fail("public_key_address_consistency", &format!("addr: {:?}", e)),
    }
}

fn test_different_derivation_paths(client: &EthAppClient, runner: &mut TestRunner) {
    // Different accounts should produce different addresses
    let path0 = Bip32Path::ethereum(0, 0, 0);
    let path1 = Bip32Path::ethereum(0, 0, 1);

    let addr0 = client.get_address(&path0);
    let addr1 = client.get_address(&path1);

    match (addr0, addr1) {
        (Ok(a0), Ok(a1)) => {
            if a0 != a1 {
                log::info!("  index 0: 0x{}", hex::encode(a0));
                log::info!("  index 1: 0x{}", hex::encode(a1));
                runner.pass("different_derivation_paths");
            } else {
                runner.fail(
                    "different_derivation_paths",
                    "same address for different paths",
                );
            }
        }
        (Err(e), _) | (_, Err(e)) => {
            runner.fail("different_derivation_paths", &format!("{:?}", e))
        }
    }
}

fn test_sign_personal_message(client: &EthAppClient, runner: &mut TestRunner) {
    let request = SignPersonalMessageRequest {
        path: Bip32Path::ethereum(0, 0, 0),
        message: b"Hello from ethapp-test!".to_vec(),
    };

    match client.sign_personal_message(&request) {
        Ok(sig) => {
            log::info!("  v={}, r={}..., s={}...",
                sig.v,
                hex::encode(&sig.r[..4]),
                hex::encode(&sig.s[..4]),
            );
            // v should be 27 or 28 for personal messages
            if sig.v == 27 || sig.v == 28 {
                runner.pass("sign_personal_message");
            } else {
                runner.fail(
                    "sign_personal_message",
                    &format!("unexpected v value: {}", sig.v),
                );
            }
        }
        Err(e) => runner.fail("sign_personal_message", &format!("{:?}", e)),
    }
}

fn test_sign_transaction(client: &EthAppClient, runner: &mut TestRunner) {
    // Build a minimal unsigned EIP-155 legacy transaction (chain 1)
    let to_addr: [u8; 20] = [0xde; 20];
    let mut fields = Vec::new();
    fields.extend_from_slice(&rlp::encode_u64(0)); // nonce
    fields.extend_from_slice(&rlp::encode_u64(20_000_000_000)); // gasPrice 20 gwei
    fields.extend_from_slice(&rlp::encode_u64(21000)); // gasLimit
    fields.extend_from_slice(&rlp::encode_bytes(&to_addr)); // to
    fields.extend_from_slice(&rlp::encode_u64(1_000_000_000_000_000)); // 0.001 ETH
    fields.extend_from_slice(&rlp::encode_bytes(&[])); // data
    fields.extend_from_slice(&rlp::encode_u64(1)); // chainId (mainnet)
    fields.extend_from_slice(&rlp::encode_u64(0)); // r = 0
    fields.extend_from_slice(&rlp::encode_u64(0)); // s = 0
    let tx_data = rlp::encode_list(&fields);

    let request = SignTransactionRequest {
        path: Bip32Path::ethereum(0, 0, 0),
        tx_data,
    };

    match client.sign_transaction(&request) {
        Ok(sig) => {
            // EIP-155 mainnet: v = 1*2+35+recid = 37 or 38
            log::info!("  v={}, r={}..., s={}...",
                sig.v,
                hex::encode(&sig.r[..4]),
                hex::encode(&sig.s[..4]),
            );
            if sig.v == 37 || sig.v == 38 {
                runner.pass("sign_transaction_eip155");
            } else {
                runner.fail(
                    "sign_transaction_eip155",
                    &format!("unexpected v value: {} (expected 37 or 38)", sig.v),
                );
            }
        }
        Err(e) => runner.fail("sign_transaction_eip155", &format!("{:?}", e)),
    }
}

fn test_sign_eip712_hashed(client: &EthAppClient, runner: &mut TestRunner) {
    let domain_hash: Hash256 = [0xAA; 32];
    let message_hash: Hash256 = [0xBB; 32];

    let request = SignEip712HashedRequest {
        path: Bip32Path::ethereum(0, 0, 0),
        domain_hash,
        message_hash,
    };

    match client.sign_eip712_hashed(&request) {
        Ok(sig) => {
            // EIP-712: v = 27 or 28
            if sig.v == 27 || sig.v == 28 {
                runner.pass("sign_eip712_hashed");
            } else {
                runner.fail(
                    "sign_eip712_hashed",
                    &format!("unexpected v: {}", sig.v),
                );
            }
        }
        Err(e) => {
            // Blind signing may be disabled
            if let Some(ethapp_common::EthAppError::BlindSigningDisabled) =
                e.service_error()
            {
                runner.skip("sign_eip712_hashed", "blind signing disabled");
            } else {
                runner.fail("sign_eip712_hashed", &format!("{:?}", e));
            }
        }
    }
}

fn test_provide_token_info(client: &EthAppClient, runner: &mut TestRunner) {
    let request = ProvideTokenInfoRequest {
        info: TokenInfo {
            chain_id: 1,
            address: [0xA0; 20], // fake USDC address
            ticker: String::from("USDC"),
            decimals: 6,
        },
        signature: vec![],
    };

    match client.provide_token_info(&request) {
        Ok(accepted) => {
            log::info!("  token info accepted: {}", accepted);
            runner.pass("provide_token_info");
        }
        Err(e) => runner.fail("provide_token_info", &format!("{:?}", e)),
    }
}

fn test_clear_metadata_cache(client: &EthAppClient, runner: &mut TestRunner) {
    match client.clear_metadata_cache() {
        Ok(()) => runner.pass("clear_metadata_cache"),
        Err(e) => runner.fail("clear_metadata_cache", &format!("{:?}", e)),
    }
}

fn test_invalid_path_rejected(client: &EthAppClient, runner: &mut TestRunner) {
    // Empty path should be rejected
    let path = Bip32Path::new();
    match client.get_public_key(&path) {
        Err(e) => {
            log::info!("  correctly rejected: {:?}", e);
            runner.pass("invalid_path_rejected");
        }
        Ok(_) => runner.fail("invalid_path_rejected", "empty path was accepted"),
    }
}

fn test_signature_determinism(client: &EthAppClient, runner: &mut TestRunner) {
    // Same message + path should produce the same signature (deterministic ECDSA)
    let request = SignPersonalMessageRequest {
        path: Bip32Path::ethereum(0, 0, 0),
        message: b"determinism test".to_vec(),
    };

    let sig1 = client.sign_personal_message(&request);
    let sig2 = client.sign_personal_message(&request);

    match (sig1, sig2) {
        (Ok(s1), Ok(s2)) => {
            if s1 == s2 {
                runner.pass("signature_determinism");
            } else {
                runner.fail("signature_determinism", "signatures differ for same input");
            }
        }
        (Err(e), _) | (_, Err(e)) => {
            runner.fail("signature_determinism", &format!("{:?}", e))
        }
    }
}

// =============================================================================
// Main
// =============================================================================

fn main() -> ! {
    run_tests();
    xous::terminate_process(0)
}

fn run_tests() {
    log_server::init_wait().unwrap();
    log::set_max_level(log::LevelFilter::Info);

    log::info!("========================================");
    log::info!("ethapp-test: Ethereum signing service integration tests");
    log::info!("========================================");

    // Brief pause for console attachment
    #[cfg(target_os = "xous")]
    {
        let tt = ticktimer_server::Ticktimer::new().unwrap();
        tt.sleep_ms(2000).unwrap();
    }

    // Connect to ethapp service
    log::info!("Connecting to ethapp service...");
    let client = match EthAppClient::new() {
        Ok(c) => {
            log::info!("Connected to ethapp service");
            c
        }
        Err(e) => {
            log::error!("Failed to connect to ethapp: {:?}", e);
            log::error!("Is the ethapp service running with dev-mode + autoapprove?");
            return;
        }
    };

    let mut runner = TestRunner::new();

    // Connectivity
    test_ping(&client, &mut runner);
    test_get_app_configuration(&client, &mut runner);

    // Key derivation
    test_get_public_key(&client, &mut runner);
    test_get_address(&client, &mut runner);
    test_get_public_key_consistency(&client, &mut runner);
    test_different_derivation_paths(&client, &mut runner);
    test_invalid_path_rejected(&client, &mut runner);

    // Signing
    test_sign_personal_message(&client, &mut runner);
    test_sign_transaction(&client, &mut runner);
    test_sign_eip712_hashed(&client, &mut runner);
    test_signature_determinism(&client, &mut runner);

    // Metadata
    test_provide_token_info(&client, &mut runner);
    test_clear_metadata_cache(&client, &mut runner);

    // Summary
    runner.summary();
}
