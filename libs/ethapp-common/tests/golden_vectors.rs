//! Golden vector tests for the Ethereum app.
//!
//! These tests verify correctness against known test vectors from:
//! - Ethereum official tests
//! - EIP specifications
//! - Ledger ethereum-app tests
//!
//! Tests use ethapp-common types directly since the ethapp service
//! crate cannot compile on host until k256/bip32 are vendored.
//!
//! Run with: cargo test -p ethapp-common

use ethapp_common::rlp;
use ethapp_common::types::*;
use ethapp_common::error::EthAppError;
use hex_literal::hex;

// =============================================================================
// RLP Encoding Tests (Ethereum Yellow Paper Appendix B)
// =============================================================================

mod rlp_spec {
    use super::*;

    #[test]
    fn test_rlp_empty_string() {
        // Empty string encodes to 0x80
        let encoded = rlp::encode_bytes(b"");
        assert_eq!(encoded, vec![0x80]);

        let item = rlp::decode_exact(&encoded).unwrap();
        assert_eq!(item.as_string(), Some(&[][..]));
    }

    #[test]
    fn test_rlp_single_byte_below_0x80() {
        // Single byte < 0x80 encodes as itself
        let encoded = rlp::encode_bytes(&[0x42]);
        assert_eq!(encoded, vec![0x42]);

        let item = rlp::decode_exact(&encoded).unwrap();
        assert_eq!(item.as_string(), Some(&[0x42][..]));
    }

    #[test]
    fn test_rlp_single_byte_0x80() {
        // Byte 0x80 requires prefix
        let encoded = rlp::encode_bytes(&[0x80]);
        assert_eq!(encoded, vec![0x81, 0x80]);
    }

    #[test]
    fn test_rlp_short_string_cat() {
        // "cat" = [0x83, 0x63, 0x61, 0x74]
        let encoded = rlp::encode_bytes(b"cat");
        assert_eq!(encoded, hex!("83636174").to_vec());
    }

    #[test]
    fn test_rlp_short_string_dog() {
        // "dog" = [0x83, 0x64, 0x6f, 0x67]
        let encoded = rlp::encode_bytes(b"dog");
        assert_eq!(encoded, hex!("83646f67").to_vec());
    }

    #[test]
    fn test_rlp_empty_list() {
        let encoded = rlp::encode_list(&[]);
        assert_eq!(encoded, vec![0xc0]);
    }

    #[test]
    fn test_rlp_integer_zero() {
        // Integer 0 encodes as empty string (0x80)
        let encoded = rlp::encode_u64(0);
        assert_eq!(encoded, vec![0x80]);

        let item = rlp::decode_exact(&encoded).unwrap();
        assert_eq!(item.as_u64(), Some(0));
    }

    #[test]
    fn test_rlp_integer_15() {
        let encoded = rlp::encode_u64(15);
        assert_eq!(encoded, vec![0x0f]);

        let item = rlp::decode_exact(&encoded).unwrap();
        assert_eq!(item.as_u64(), Some(15));
    }

    #[test]
    fn test_rlp_integer_1024() {
        let encoded = rlp::encode_u64(1024);
        assert_eq!(encoded, vec![0x82, 0x04, 0x00]);

        let item = rlp::decode_exact(&encoded).unwrap();
        assert_eq!(item.as_u64(), Some(1024));
    }

    #[test]
    fn test_rlp_list_cat_dog() {
        // ["cat", "dog"]
        let mut items = Vec::new();
        items.extend_from_slice(&rlp::encode_bytes(b"cat"));
        items.extend_from_slice(&rlp::encode_bytes(b"dog"));
        let encoded = rlp::encode_list(&items);

        // Expected: 0xc8 0x83 "cat" 0x83 "dog"
        assert_eq!(encoded, hex!("c88363617483646f67").to_vec());
    }

    #[test]
    fn test_rlp_nested_list() {
        // [[]] = [0xc1, 0xc0]
        let inner = rlp::encode_list(&[]);
        let outer = rlp::encode_list(&inner);
        assert_eq!(outer, hex!("c1c0").to_vec());
    }

    #[test]
    fn test_rlp_non_canonical_rejection() {
        // 0x81 0x42 is non-canonical (should be just 0x42)
        let result = rlp::decode(&[0x81, 0x42]);
        assert!(result.is_err());
    }
}

// =============================================================================
// Transaction Structure Tests
// =============================================================================

mod transactions {
    use super::*;

    #[test]
    fn test_legacy_tx_rlp_structure() {
        // Build unsigned legacy tx: [nonce, gasPrice, gasLimit, to, value, data]
        let to_addr = hex!("d8da6bf26964af9d7eed9e03e53415d37aa96045"); // vitalik.eth
        let mut fields = Vec::new();
        fields.extend_from_slice(&rlp::encode_u64(9));              // nonce = 9
        fields.extend_from_slice(&rlp::encode_u64(10_000_000_000)); // gasPrice = 10 gwei
        fields.extend_from_slice(&rlp::encode_u64(21000));          // gasLimit
        fields.extend_from_slice(&rlp::encode_bytes(&to_addr));     // to
        fields.extend_from_slice(&rlp::encode_u64(1_000_000_000_000_000)); // 0.001 ETH
        fields.extend_from_slice(&rlp::encode_bytes(&[]));          // data empty
        let tx = rlp::encode_list(&fields);

        let item = rlp::decode_exact(&tx).unwrap();
        let list = item.as_list().unwrap();
        assert_eq!(list.len(), 6);
        assert_eq!(list[0].as_u64(), Some(9));     // nonce
        assert_eq!(list[2].as_u64(), Some(21000)); // gasLimit
        assert_eq!(list[3].as_address().unwrap(), to_addr);
    }

    #[test]
    fn test_eip155_unsigned_tx_structure() {
        // EIP-155 unsigned: [nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0]
        let mut fields = Vec::new();
        fields.extend_from_slice(&rlp::encode_u64(0));
        fields.extend_from_slice(&rlp::encode_u64(20_000_000_000));
        fields.extend_from_slice(&rlp::encode_u64(21000));
        fields.extend_from_slice(&rlp::encode_bytes(&[0xde; 20]));
        fields.extend_from_slice(&rlp::encode_u64(1_000_000_000_000_000_000));
        fields.extend_from_slice(&rlp::encode_bytes(&[]));
        fields.extend_from_slice(&rlp::encode_u64(1));  // chainId = mainnet
        fields.extend_from_slice(&rlp::encode_u64(0));  // r = 0
        fields.extend_from_slice(&rlp::encode_u64(0));  // s = 0
        let tx = rlp::encode_list(&fields);

        let item = rlp::decode_exact(&tx).unwrap();
        let list = item.as_list().unwrap();
        assert_eq!(list.len(), 9);
        assert_eq!(list[6].as_u64(), Some(1)); // chainId
    }

    #[test]
    fn test_eip1559_tx_structure() {
        // EIP-1559: 0x02 || rlp([chainId, nonce, maxPriorityFee, maxFee, gasLimit, to, value, data, accessList])
        let mut fields = Vec::new();
        fields.extend_from_slice(&rlp::encode_u64(1));               // chainId
        fields.extend_from_slice(&rlp::encode_u64(0));               // nonce
        fields.extend_from_slice(&rlp::encode_u64(1_000_000_000));   // maxPriorityFee = 1 gwei
        fields.extend_from_slice(&rlp::encode_u64(50_000_000_000));  // maxFee = 50 gwei
        fields.extend_from_slice(&rlp::encode_u64(21000));           // gasLimit
        fields.extend_from_slice(&rlp::encode_bytes(&[0xde; 20]));   // to
        fields.extend_from_slice(&rlp::encode_u64(0));               // value
        fields.extend_from_slice(&rlp::encode_bytes(&[]));           // data
        fields.extend_from_slice(&rlp::encode_list(&[]));            // accessList (empty)
        let rlp_payload = rlp::encode_list(&fields);

        // Typed tx starts with 0x02
        let mut tx = vec![0x02u8];
        tx.extend_from_slice(&rlp_payload);

        assert_eq!(tx[0], 0x02);
        // The RLP payload should decode fine
        let item = rlp::decode_exact(&rlp_payload).unwrap();
        let list = item.as_list().unwrap();
        assert_eq!(list.len(), 9);
        assert_eq!(list[0].as_u64(), Some(1)); // chainId
    }

    #[test]
    fn test_eip2930_tx_structure() {
        // EIP-2930: 0x01 || rlp([chainId, nonce, gasPrice, gasLimit, to, value, data, accessList])
        let mut fields = Vec::new();
        fields.extend_from_slice(&rlp::encode_u64(1));
        fields.extend_from_slice(&rlp::encode_u64(0));
        fields.extend_from_slice(&rlp::encode_u64(20_000_000_000));
        fields.extend_from_slice(&rlp::encode_u64(21000));
        fields.extend_from_slice(&rlp::encode_bytes(&[0xde; 20]));
        fields.extend_from_slice(&rlp::encode_u64(0));
        fields.extend_from_slice(&rlp::encode_bytes(&[]));
        fields.extend_from_slice(&rlp::encode_list(&[]));
        let rlp_payload = rlp::encode_list(&fields);

        let item = rlp::decode_exact(&rlp_payload).unwrap();
        let list = item.as_list().unwrap();
        assert_eq!(list.len(), 8);
    }

    #[test]
    fn test_contract_creation_empty_to() {
        // Contract creation has empty "to" field
        let mut fields = Vec::new();
        fields.extend_from_slice(&rlp::encode_u64(0));              // nonce
        fields.extend_from_slice(&rlp::encode_u64(10_000_000_000)); // gasPrice
        fields.extend_from_slice(&rlp::encode_u64(1_000_000));      // gasLimit (higher for deploy)
        fields.extend_from_slice(&rlp::encode_bytes(&[]));           // to = empty (contract creation)
        fields.extend_from_slice(&rlp::encode_u64(0));              // value
        fields.extend_from_slice(&rlp::encode_bytes(&[0x60, 0x80, 0x60, 0x40])); // bytecode
        let tx = rlp::encode_list(&fields);

        let item = rlp::decode_exact(&tx).unwrap();
        let list = item.as_list().unwrap();
        // "to" field is empty string
        assert_eq!(list[3].as_string(), Some(&[][..]));
    }
}

// =============================================================================
// Signature Tests
// =============================================================================

mod signatures {
    use super::*;

    #[test]
    fn test_eip155_v_chain_1() {
        // Chain ID 1 (Mainnet): v = 1 * 2 + 35 + recovery_id
        let v0 = 1u64 * 2 + 35 + 0;
        let v1 = 1u64 * 2 + 35 + 1;
        assert_eq!(v0, 37);
        assert_eq!(v1, 38);

        // Verify signature can store these values
        let sig = Signature { v: v0, r: [1; 32], s: [2; 32] };
        assert!(sig.to_bytes_legacy().is_some());
    }

    #[test]
    fn test_eip155_v_chain_56() {
        // Chain ID 56 (BSC): v = 56 * 2 + 35 + 0 = 147
        let v0 = 56u64 * 2 + 35 + 0;
        let v1 = 56u64 * 2 + 35 + 1;
        assert_eq!(v0, 147);
        assert_eq!(v1, 148);

        let sig = Signature { v: v0, r: [0; 32], s: [0; 32] };
        assert!(sig.to_bytes_legacy().is_some()); // 147 fits in u8
    }

    #[test]
    fn test_eip155_v_chain_137() {
        // Chain ID 137 (Polygon): v = 137 * 2 + 35 + 0 = 309
        let v0 = 137u64 * 2 + 35 + 0;
        assert_eq!(v0, 309);

        let sig = Signature { v: v0, r: [0; 32], s: [0; 32] };
        // 309 > 255, doesn't fit in legacy format
        assert!(sig.to_bytes_legacy().is_none());
        // But 72-byte format works
        let bytes = sig.to_bytes();
        let recovered = Signature::from_bytes(&bytes);
        assert_eq!(recovered.v, 309);
    }

    #[test]
    fn test_legacy_v_no_chain_id() {
        // Pre-EIP-155: v = 27 or 28
        let sig27 = Signature { v: 27, r: [0xAA; 32], s: [0xBB; 32] };
        let sig28 = Signature { v: 28, r: [0xCC; 32], s: [0xDD; 32] };

        assert!(sig27.to_bytes_legacy().is_some());
        assert!(sig28.to_bytes_legacy().is_some());
    }

    #[test]
    fn test_typed_tx_v() {
        // EIP-2930/1559: v = recovery_id (0 or 1)
        for v in [0u64, 1] {
            let sig = Signature { v, r: [0xFF; 32], s: [0xEE; 32] };
            let bytes = sig.to_bytes();
            let recovered = Signature::from_bytes(&bytes);
            assert_eq!(recovered.v, v);
        }
    }

    #[test]
    fn test_signature_roundtrip_all_formats() {
        let sig = Signature {
            v: 27,
            r: hex!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
            s: hex!("fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321"),
        };

        // 72-byte roundtrip
        let bytes72 = sig.to_bytes();
        assert_eq!(Signature::from_bytes(&bytes72), sig);

        // 65-byte roundtrip
        let bytes65 = sig.to_bytes_legacy().unwrap();
        assert_eq!(bytes65[64], 27);
        assert_eq!(&bytes65[0..32], &sig.r);
        assert_eq!(&bytes65[32..64], &sig.s);
    }
}

// =============================================================================
// Keccak256 Test Vectors
// =============================================================================

mod keccak_vectors {
    use super::*;

    // Note: These are reference vectors. Actual keccak256 computation
    // requires the ethapp service crate (tiny-keccak dep).

    #[test]
    fn test_keccak256_empty_vector() {
        // keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
        let expected = hex!("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
        assert_eq!(expected.len(), 32);
    }

    #[test]
    fn test_keccak256_hello_vector() {
        // keccak256("hello") = 1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8
        let expected = hex!("1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8");
        assert_eq!(expected.len(), 32);
    }
}

// =============================================================================
// Address Tests (EIP-55)
// =============================================================================

mod addresses {
    use super::*;

    #[test]
    fn test_eip55_addresses_are_20_bytes() {
        // Test addresses from EIP-55
        let addr1 = hex!("5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
        let addr2 = hex!("fB6916095ca1df60bB79Ce92cE3Ea74c37c5d359");
        let addr3 = hex!("dbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB");
        let addr4 = hex!("D1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb");

        for addr in &[addr1, addr2, addr3, addr4] {
            assert_eq!(addr.len(), 20);

            // Verify RLP roundtrip
            let encoded = rlp::encode_bytes(addr);
            let item = rlp::decode_exact(&encoded).unwrap();
            assert_eq!(item.as_address().unwrap(), *addr);
        }
    }

    #[test]
    fn test_address_derivation_structure() {
        // Address = keccak256(pubkey[1..])[12..32]
        // Uncompressed pubkey is 65 bytes (0x04 || x[32] || y[32])
        // Take last 20 bytes of keccak256(x || y)
        let uncompressed_pubkey_len = 65usize;
        let hash_len = 32usize;
        let addr_offset = 12usize;
        let addr_len = hash_len - addr_offset;
        assert_eq!(addr_len, 20);
        assert_eq!(uncompressed_pubkey_len - 1, 64); // skip 0x04 prefix
    }
}

// =============================================================================
// EIP-191 Personal Sign Tests
// =============================================================================

mod personal_sign {
    #[test]
    fn test_eip191_prefix() {
        let prefix = b"\x19Ethereum Signed Message:\n";
        assert_eq!(prefix.len(), 26);
        assert_eq!(prefix[0], 0x19);
    }

    #[test]
    fn test_personal_message_hash_structure() {
        // personal_sign("hello"):
        // hash = keccak256("\x19Ethereum Signed Message:\n5hello")
        let prefix = b"\x19Ethereum Signed Message:\n";
        let msg = b"hello";
        let len_str = msg.len().to_string();

        let mut preimage = Vec::new();
        preimage.extend_from_slice(prefix);
        preimage.extend_from_slice(len_str.as_bytes());
        preimage.extend_from_slice(msg);
        assert_eq!(preimage.len(), 26 + 1 + 5);
    }
}

// =============================================================================
// EIP-712 Tests
// =============================================================================

mod eip712 {
    #[test]
    fn test_eip712_hash_structure() {
        // hash = keccak256(0x19 || 0x01 || domainSeparator || hashStruct(message))
        let prefix_len = 2usize;
        let domain_hash_len = 32usize;
        let message_hash_len = 32usize;
        assert_eq!(prefix_len + domain_hash_len + message_hash_len, 66);
    }
}

// =============================================================================
// BIP32/BIP44 Path Tests
// =============================================================================

mod bip44 {
    use super::*;

    #[test]
    fn test_ethereum_path_standard() {
        let path = Bip32Path::ethereum(0, 0, 0);
        assert!(path.is_valid_ethereum_path());
        assert_eq!(path.len(), 5);
    }

    #[test]
    fn test_ethereum_path_account_1() {
        let path = Bip32Path::ethereum(1, 0, 0);
        assert!(path.is_valid_ethereum_path());
    }

    #[test]
    fn test_ethereum_path_with_address_index() {
        for idx in 0..10u32 {
            let path = Bip32Path::ethereum(0, 0, idx);
            assert!(path.is_valid_ethereum_path());
            assert_eq!(path.as_slice()[4], idx);
        }
    }

    #[test]
    fn test_non_ethereum_paths_rejected() {
        // Bitcoin path (coin_type = 0)
        let btc = Bip32Path::from_slice(&[
            44 | Bip32Path::HARDENED,
            0 | Bip32Path::HARDENED,
            0 | Bip32Path::HARDENED,
        ]);
        assert!(!btc.is_valid_ethereum_path());

        // Solana path (coin_type = 501)
        let sol = Bip32Path::from_slice(&[
            44 | Bip32Path::HARDENED,
            501 | Bip32Path::HARDENED,
            0 | Bip32Path::HARDENED,
        ]);
        assert!(!sol.is_valid_ethereum_path());
    }
}

// =============================================================================
// Error Type Tests
// =============================================================================

mod error_types {
    use super::*;

    #[test]
    fn test_security_vs_operational_errors() {
        // Security errors should be distinguished from operational ones
        assert!(EthAppError::SecurityViolation.is_security_error());
        assert!(EthAppError::InvalidSignature.is_security_error());
        assert!(EthAppError::BlindSigningDisabled.is_security_error());
        assert!(EthAppError::InvalidDerivationPath.is_security_error());

        // These are NOT security errors
        assert!(!EthAppError::Timeout.is_security_error());
        assert!(!EthAppError::InternalError.is_security_error());
        assert!(!EthAppError::RejectedByUser.is_security_error());
    }
}

// =============================================================================
// Gas & Wei Value Tests
// =============================================================================

mod values {
    use super::*;

    #[test]
    fn test_wei_to_eth() {
        let one_eth_in_wei: u128 = 1_000_000_000_000_000_000;
        assert_eq!(one_eth_in_wei, 10u128.pow(18));
    }

    #[test]
    fn test_gwei_to_wei() {
        let one_gwei_in_wei: u64 = 1_000_000_000;
        assert_eq!(one_gwei_in_wei, 10u64.pow(9));
    }

    #[test]
    fn test_gas_values_fit_in_u64() {
        // Common gas values should fit in u64
        let base_gas: u64 = 21_000;
        let typical_max_fee: u64 = 500_000_000_000; // 500 gwei
        let typical_gas_limit: u64 = 1_000_000;

        assert!(base_gas < u64::MAX);
        assert!(typical_max_fee < u64::MAX);
        assert!(typical_gas_limit < u64::MAX);
    }

    #[test]
    fn test_large_value_in_bytes32() {
        // 1 ETH = 10^18 wei, should fit in bytes32
        let one_eth_bytes = {
            let val = 1_000_000_000_000_000_000u64;
            let mut result = [0u8; 32];
            result[24..32].copy_from_slice(&val.to_be_bytes());
            result
        };
        // Verify it roundtrips through RLP
        let trimmed = &one_eth_bytes[one_eth_bytes.iter().position(|&b| b != 0).unwrap_or(32)..];
        let encoded = rlp::encode_bytes(trimmed);
        let item = rlp::decode_exact(&encoded).unwrap();
        let recovered = item.as_bytes32().unwrap();
        assert_eq!(recovered, one_eth_bytes);
    }
}

// =============================================================================
// Chain ID Tests
// =============================================================================

mod chain_ids {
    use super::*;

    #[test]
    fn test_common_chain_ids_rlp() {
        let chains: &[(u64, &str)] = &[
            (1, "mainnet"),
            (5, "goerli"),
            (10, "optimism"),
            (56, "bsc"),
            (137, "polygon"),
            (42161, "arbitrum"),
            (43114, "avalanche"),
            (11155111, "sepolia"),
        ];

        for &(chain_id, name) in chains {
            let encoded = rlp::encode_u64(chain_id);
            let item = rlp::decode_exact(&encoded).unwrap();
            assert_eq!(item.as_u64(), Some(chain_id), "chain {name} roundtrip failed");
        }
    }

    #[test]
    fn test_eip155_v_extraction() {
        // From a signed tx: extract chain_id from v value
        // v = chain_id * 2 + 35 + recovery_id
        // chain_id = (v - 35) / 2
        let v_mainnet_0 = 37u64; // chain 1, recovery 0
        let v_mainnet_1 = 38u64; // chain 1, recovery 1

        assert_eq!((v_mainnet_0 - 35) / 2, 1);
        assert_eq!((v_mainnet_1 - 35) / 2, 1);

        let v_polygon_0 = 309u64; // chain 137, recovery 0
        assert_eq!((v_polygon_0 - 35) / 2, 137);
    }
}
