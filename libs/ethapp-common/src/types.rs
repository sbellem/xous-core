//! Core types for the Xous Ethereum App.
//!
//! These types are shared between the service and client, serialized
//! via rkyv for efficient Xous IPC. All validation happens in the
//! service after deserialization.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use rkyv::{Archive, Deserialize, Serialize};
use zeroize::Zeroize;

/// Maximum BIP32 derivation path depth.
pub const MAX_BIP32_PATH_DEPTH: usize = 10;

/// Maximum transaction size (64KB).
pub const MAX_TX_SIZE: usize = 65536;

/// Maximum message size for personal_sign (64KB).
pub const MAX_MESSAGE_SIZE: usize = 65536;

/// Maximum typed data size (64KB).
pub const MAX_TYPED_DATA_SIZE: usize = 65536;

/// Ethereum address (20 bytes).
pub type EthAddress = [u8; 20];

/// Keccak256 hash (32 bytes).
pub type Hash256 = [u8; 32];

/// Function selector (4 bytes).
pub type Selector = [u8; 4];

// =============================================================================
// BIP32 Path
// =============================================================================

/// BIP32 derivation path.
///
/// The path is stored as a vector of u32 values where hardened indices
/// have the 0x80000000 bit set. Maximum depth is 10 elements.
#[derive(Debug, Clone, Default, PartialEq, Eq, Archive, Serialize, Deserialize, Zeroize)]
pub struct Bip32Path {
    /// Path components (hardened indices have bit 31 set).
    pub components: Vec<u32>,
}

impl Bip32Path {
    /// Hardened index marker (bit 31).
    pub const HARDENED: u32 = 0x80000000;

    /// Creates a new empty path.
    pub fn new() -> Self {
        Self {
            components: Vec::new(),
        }
    }

    /// Creates a path from a slice.
    pub fn from_slice(path: &[u32]) -> Self {
        Self {
            components: path.to_vec(),
        }
    }

    /// Creates a standard Ethereum path: m/44'/60'/account'/change/index
    pub fn ethereum(account: u32, change: u32, index: u32) -> Self {
        Self {
            components: vec![
                44 | Self::HARDENED,  // purpose
                60 | Self::HARDENED,  // coin type (Ethereum)
                account | Self::HARDENED,
                change,
                index,
            ],
        }
    }

    /// Returns the path length.
    #[inline]
    pub fn len(&self) -> usize {
        self.components.len()
    }

    /// Returns true if the path is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.components.is_empty()
    }

    /// Returns the path as a slice.
    #[inline]
    pub fn as_slice(&self) -> &[u32] {
        &self.components
    }

    /// Validates the path for Ethereum (BIP44 m/44'/60'/account'/change/index).
    ///
    /// Returns true if the path follows standard Ethereum derivation.
    pub fn is_valid_ethereum_path(&self) -> bool {
        if self.components.len() < 3 || self.components.len() > MAX_BIP32_PATH_DEPTH {
            return false;
        }

        // Check purpose: must be 44' (hardened)
        if self.components[0] != (44 | Self::HARDENED) {
            return false;
        }

        // Check coin type: must be 60' (Ethereum) - hardened
        if self.components[1] != (60 | Self::HARDENED) {
            return false;
        }

        // Account index must be hardened
        if self.components[2] & Self::HARDENED == 0 {
            return false;
        }

        // Change and address index should not be hardened (if present)
        for &idx in &self.components[3..] {
            if idx & Self::HARDENED != 0 {
                return false;
            }
        }

        true
    }
}

// =============================================================================
// Signature
// =============================================================================

/// ECDSA signature components (v, r, s).
///
/// For transactions, v follows EIP-155: v = chain_id * 2 + 35 + recovery_id
/// For messages, v = 27 + recovery_id
///
/// The `v` field is u64 to support EIP-155 with large chain IDs
/// (chain_id > 110 would overflow u8 with the formula chain_id * 2 + 35 + recid).
#[derive(Debug, Clone, Default, PartialEq, Eq, Archive, Serialize, Deserialize, Zeroize)]
pub struct Signature {
    /// Recovery identifier (27/28 for legacy, EIP-155 for transactions).
    /// u64 to accommodate EIP-155 v values for chains with large IDs.
    pub v: u64,
    /// R component (32 bytes, big-endian).
    pub r: [u8; 32],
    /// S component (32 bytes, big-endian, low-S normalized).
    pub s: [u8; 32],
}

impl Signature {
    /// Returns the signature as a 72-byte array (r[32] || s[32] || v[8] big-endian).
    ///
    /// The v field is serialized as 8 bytes big-endian to support large chain IDs.
    pub fn to_bytes(&self) -> [u8; 72] {
        let mut bytes = [0u8; 72];
        bytes[0..32].copy_from_slice(&self.r);
        bytes[32..64].copy_from_slice(&self.s);
        bytes[64..72].copy_from_slice(&self.v.to_be_bytes());
        bytes
    }

    /// Creates a signature from a 72-byte array (r[32] || s[32] || v[8] big-endian).
    pub fn from_bytes(bytes: &[u8; 72]) -> Self {
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&bytes[0..32]);
        s.copy_from_slice(&bytes[32..64]);
        let mut v_bytes = [0u8; 8];
        v_bytes.copy_from_slice(&bytes[64..72]);
        Self {
            v: u64::from_be_bytes(v_bytes),
            r,
            s,
        }
    }

    /// Returns the signature in legacy 65-byte format (r || s || v_byte).
    ///
    /// Only valid when v fits in a single byte (v <= 255).
    /// Returns None if v exceeds u8 range.
    pub fn to_bytes_legacy(&self) -> Option<[u8; 65]> {
        if self.v > 255 {
            return None;
        }
        let mut bytes = [0u8; 65];
        bytes[0..32].copy_from_slice(&self.r);
        bytes[32..64].copy_from_slice(&self.s);
        bytes[64] = self.v as u8;
        Some(bytes)
    }
}

// =============================================================================
// App Configuration
// =============================================================================

/// App configuration returned by GetAppConfiguration.
#[derive(Debug, Clone, Default, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct AppConfiguration {
    /// Major version.
    pub version_major: u8,
    /// Minor version.
    pub version_minor: u8,
    /// Patch version.
    pub version_patch: u8,
    /// Whether blind signing is enabled.
    pub blind_signing_enabled: bool,
    /// Whether EIP-712 filtering is enabled.
    pub eip712_filtering_enabled: bool,
    /// Whether Eth2/BLS operations are supported.
    pub eth2_supported: bool,
    /// Protocol version for compatibility.
    pub protocol_version: u32,
}

// =============================================================================
// Transaction Types
// =============================================================================

/// Transaction type for EIP-2718 typed transactions.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Archive, Serialize, Deserialize)]
#[repr(u8)]
pub enum TransactionType {
    /// Legacy transaction (pre-EIP-2718).
    #[default]
    Legacy = 0x00,
    /// EIP-2930 access list transaction.
    AccessList = 0x01,
    /// EIP-1559 fee market transaction.
    FeeMarket = 0x02,
}

impl TryFrom<u8> for TransactionType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(TransactionType::Legacy),
            0x01 => Ok(TransactionType::AccessList),
            0x02 => Ok(TransactionType::FeeMarket),
            _ => Err(()),
        }
    }
}

// =============================================================================
// Metadata Types
// =============================================================================

/// ERC-20 token information for display purposes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct TokenInfo {
    /// Chain ID where the token is deployed.
    pub chain_id: u64,
    /// Token contract address.
    pub address: EthAddress,
    /// Token ticker symbol (e.g., "USDC").
    pub ticker: String,
    /// Token decimals (e.g., 6 for USDC, 18 for most tokens).
    pub decimals: u8,
}

/// NFT collection information for display purposes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct NftInfo {
    /// Chain ID where the NFT is deployed.
    pub chain_id: u64,
    /// NFT contract address.
    pub address: EthAddress,
    /// Collection name.
    pub name: String,
}

/// Domain name resolution information.
#[derive(Debug, Clone, Default, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct DomainInfo {
    /// Resolved address.
    pub address: EthAddress,
    /// Domain name (e.g., "vitalik.eth").
    pub domain: String,
}

/// Contract method information for clear signing.
#[derive(Debug, Clone, Default, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct MethodInfo {
    /// Chain ID.
    pub chain_id: u64,
    /// Contract address.
    pub address: EthAddress,
    /// Function selector (4 bytes).
    pub selector: Selector,
    /// Method name (e.g., "transfer").
    pub name: String,
    /// ABI-encoded parameter definitions.
    pub abi: Vec<u8>,
}

// =============================================================================
// Request/Response Types
// =============================================================================

/// Request to sign a transaction.
#[derive(Debug, Clone, Default, Archive, Serialize, Deserialize)]
pub struct SignTransactionRequest {
    /// BIP32 derivation path.
    pub path: Bip32Path,
    /// RLP-encoded transaction data.
    pub tx_data: Vec<u8>,
}

/// Request to sign a transaction with clear signing.
#[derive(Debug, Clone, Default, Archive, Serialize, Deserialize)]
pub struct ClearSignTransactionRequest {
    /// BIP32 derivation path.
    pub path: Bip32Path,
    /// RLP-encoded transaction data.
    pub tx_data: Vec<u8>,
    /// Additional context for clear signing.
    pub context: Vec<u8>,
}

/// Request to sign a personal message.
#[derive(Debug, Clone, Default, Archive, Serialize, Deserialize)]
pub struct SignPersonalMessageRequest {
    /// BIP32 derivation path.
    pub path: Bip32Path,
    /// Message bytes to sign.
    pub message: Vec<u8>,
}

/// Request to sign pre-hashed EIP-712 data.
#[derive(Debug, Clone, Default, Archive, Serialize, Deserialize)]
pub struct SignEip712HashedRequest {
    /// BIP32 derivation path.
    pub path: Bip32Path,
    /// EIP-712 domain separator hash.
    pub domain_hash: Hash256,
    /// EIP-712 message hash.
    pub message_hash: Hash256,
}

/// Request to sign full EIP-712 typed data.
#[derive(Debug, Clone, Default, Archive, Serialize, Deserialize)]
pub struct SignEip712MessageRequest {
    /// BIP32 derivation path.
    pub path: Bip32Path,
    /// Binary-encoded typed data (not JSON).
    pub typed_data: Vec<u8>,
}

/// Request to provide token info.
#[derive(Debug, Clone, Default, Archive, Serialize, Deserialize)]
pub struct ProvideTokenInfoRequest {
    /// Token information.
    pub info: TokenInfo,
    /// Signature over the info (for verification).
    pub signature: Vec<u8>,
}

/// Request to provide NFT info.
#[derive(Debug, Clone, Default, Archive, Serialize, Deserialize)]
pub struct ProvideNftInfoRequest {
    /// NFT collection information.
    pub info: NftInfo,
    /// Signature over the info.
    pub signature: Vec<u8>,
}

/// Request to provide domain name resolution.
#[derive(Debug, Clone, Default, Archive, Serialize, Deserialize)]
pub struct ProvideDomainNameRequest {
    /// Domain resolution information.
    pub info: DomainInfo,
    /// Signature from domain authority.
    pub signature: Vec<u8>,
}

/// Request to provide contract method info.
#[derive(Debug, Clone, Default, Archive, Serialize, Deserialize)]
pub struct ProvideMethodInfoRequest {
    /// Method information.
    pub info: MethodInfo,
    /// Signature over the info.
    pub signature: Vec<u8>,
}

/// Response with public key and address.
#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct PublicKeyResponse {
    /// Compressed public key (33 bytes).
    pub pubkey: [u8; 33],
    /// Ethereum address (20 bytes).
    pub address: EthAddress,
}

impl Default for PublicKeyResponse {
    fn default() -> Self {
        Self {
            pubkey: [0u8; 33],
            address: [0u8; 20],
        }
    }
}

// =============================================================================
// Attestation
// =============================================================================

/// Request to initialize device attestation identity.
#[derive(Debug, Clone, Default, Archive, Serialize, Deserialize)]
pub struct InitAttestationRequest {
    /// If true, overwrite an existing attestation key.
    pub overwrite: bool,
}

/// Response containing the device's attestation public key.
#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct AttestationKeyResponse {
    /// Compressed secp256k1 public key (33 bytes).
    pub pubkey: [u8; 33],
}

impl Default for AttestationKeyResponse {
    fn default() -> Self {
        Self { pubkey: [0u8; 33] }
    }
}

/// Combined transaction signature + attestation co-signature.
///
/// The attestation signature is over `keccak256(tx_sign_hash || v || r || s)`,
/// binding the attestation to the specific transaction signature.
#[derive(Debug, Clone, Default, PartialEq, Eq, Archive, Serialize, Deserialize, Zeroize)]
pub struct AttestedSignature {
    /// The transaction signature (v, r, s).
    pub tx_sig: Signature,
    /// The attestation co-signature (v = 27 + recovery_id).
    pub attest_sig: Signature,
}

// =============================================================================
// Encrypted Import (ECIES)
// =============================================================================

/// Request to initialize the import keypair.
#[derive(Debug, Clone, Default, Archive, Serialize, Deserialize)]
pub struct InitImportKeyRequest {
    /// If true, overwrite an existing import key.
    pub overwrite: bool,
}

/// Response containing the device's import public key.
#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct ImportKeyResponse {
    /// Compressed secp256k1 public key (33 bytes).
    pub pubkey: [u8; 33],
}

impl Default for ImportKeyResponse {
    fn default() -> Self {
        Self { pubkey: [0u8; 33] }
    }
}

/// Encrypted mnemonic import payload (ECIES with ChaCha20-Poly1305).
///
/// Wire format: `[e_pub: 33 bytes compressed][ciphertext + poly1305 tag: N+16 bytes]`
#[derive(Debug, Clone, Archive, Serialize, Deserialize)]
pub struct EncryptedMnemonicImport {
    /// Total payload length in bytes.
    pub len: u32,
    /// Payload: [e_pub:33][ciphertext+tag].
    pub data: [u8; 512],
}

impl Default for EncryptedMnemonicImport {
    fn default() -> Self {
        Self {
            len: 0,
            data: [0u8; 512],
        }
    }
}

// =============================================================================
// Chunked Transfer
// =============================================================================

/// Context binding for metadata lookups.
///
/// Sent by the client to associate a chain ID and contract address with
/// a subsequent signing operation.
#[derive(Debug, Clone, Copy, Default, Archive, Serialize, Deserialize)]
pub struct MetadataContext {
    /// Chain ID for the context.
    pub chain_id: u64,
    /// Contract address for the context.
    pub address: EthAddress,
}

// =============================================================================

/// Header for chunked data transfer.
///
/// Used when data exceeds single Xous page size (4096 bytes).
#[derive(Debug, Clone, Default, Archive, Serialize, Deserialize)]
pub struct ChunkHeader {
    /// Total size of the complete data.
    pub total_size: u32,
    /// Offset of this chunk in the complete data.
    pub offset: u32,
    /// Size of this chunk's payload.
    pub chunk_size: u32,
    /// Chunk flags (first/last/continue).
    pub flags: u8,
    /// Sequence number for ordering.
    pub sequence: u16,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bip32_path_validation() {
        // Valid standard Ethereum path: m/44'/60'/0'/0/0
        let valid = Bip32Path::ethereum(0, 0, 0);
        assert!(valid.is_valid_ethereum_path());

        // Invalid: wrong purpose
        let invalid_purpose = Bip32Path::from_slice(&[
            49 | Bip32Path::HARDENED,
            60 | Bip32Path::HARDENED,
            Bip32Path::HARDENED,
        ]);
        assert!(!invalid_purpose.is_valid_ethereum_path());

        // Invalid: wrong coin type
        let invalid_coin = Bip32Path::from_slice(&[
            44 | Bip32Path::HARDENED,
            0 | Bip32Path::HARDENED,
            Bip32Path::HARDENED,
        ]);
        assert!(!invalid_coin.is_valid_ethereum_path());

        // Invalid: too short
        let too_short = Bip32Path::from_slice(&[
            44 | Bip32Path::HARDENED,
            60 | Bip32Path::HARDENED,
        ]);
        assert!(!too_short.is_valid_ethereum_path());
    }

    #[test]
    fn test_signature_bytes_roundtrip() {
        let sig = Signature {
            v: 27,
            r: [1u8; 32],
            s: [2u8; 32],
        };
        let bytes = sig.to_bytes();
        let recovered = Signature::from_bytes(&bytes);
        assert_eq!(sig, recovered);
    }

    #[test]
    fn test_signature_large_chain_id() {
        // EIP-155 with chain_id = 56 (BSC): v = 56 * 2 + 35 + 0 = 147
        let sig = Signature {
            v: 147,
            r: [1u8; 32],
            s: [2u8; 32],
        };
        let bytes = sig.to_bytes();
        let recovered = Signature::from_bytes(&bytes);
        assert_eq!(sig, recovered);

        // Legacy format should work for small v
        assert!(sig.to_bytes_legacy().is_some());

        // EIP-155 with large chain_id = 999999: v = 999999*2+35 = 2000033
        let large_sig = Signature {
            v: 2_000_033,
            r: [3u8; 32],
            s: [4u8; 32],
        };
        let large_bytes = large_sig.to_bytes();
        let large_recovered = Signature::from_bytes(&large_bytes);
        assert_eq!(large_sig, large_recovered);

        // Legacy format should return None for large v
        assert!(large_sig.to_bytes_legacy().is_none());
    }

    #[test]
    fn test_transaction_type_conversion() {
        assert_eq!(TransactionType::try_from(0x00).unwrap(), TransactionType::Legacy);
        assert_eq!(TransactionType::try_from(0x01).unwrap(), TransactionType::AccessList);
        assert_eq!(TransactionType::try_from(0x02).unwrap(), TransactionType::FeeMarket);
        assert!(TransactionType::try_from(0x03).is_err());
    }

    // =========================================================================
    // BIP32 path tests
    // =========================================================================

    #[test]
    fn test_bip32_ethereum_constructor() {
        let path = Bip32Path::ethereum(0, 0, 0);
        assert_eq!(path.len(), 5);
        assert_eq!(path.as_slice()[0], 44 | Bip32Path::HARDENED);
        assert_eq!(path.as_slice()[1], 60 | Bip32Path::HARDENED);
        assert_eq!(path.as_slice()[2], 0 | Bip32Path::HARDENED);
        assert_eq!(path.as_slice()[3], 0);
        assert_eq!(path.as_slice()[4], 0);
    }

    #[test]
    fn test_bip32_different_accounts() {
        for account in 0..5u32 {
            let path = Bip32Path::ethereum(account, 0, 0);
            assert!(path.is_valid_ethereum_path());
            assert_eq!(path.as_slice()[2], account | Bip32Path::HARDENED);
        }
    }

    #[test]
    fn test_bip32_valid_3_component_path() {
        // Minimum valid: m/44'/60'/0'
        let path = Bip32Path::from_slice(&[
            44 | Bip32Path::HARDENED,
            60 | Bip32Path::HARDENED,
            0 | Bip32Path::HARDENED,
        ]);
        assert!(path.is_valid_ethereum_path());
    }

    #[test]
    fn test_bip32_invalid_hardened_change() {
        // change index should NOT be hardened
        let path = Bip32Path::from_slice(&[
            44 | Bip32Path::HARDENED,
            60 | Bip32Path::HARDENED,
            0 | Bip32Path::HARDENED,
            0 | Bip32Path::HARDENED, // invalid: hardened change
        ]);
        assert!(!path.is_valid_ethereum_path());
    }

    #[test]
    fn test_bip32_invalid_unhardened_account() {
        // account must be hardened
        let path = Bip32Path::from_slice(&[
            44 | Bip32Path::HARDENED,
            60 | Bip32Path::HARDENED,
            0, // invalid: not hardened
        ]);
        assert!(!path.is_valid_ethereum_path());
    }

    #[test]
    fn test_bip32_too_long() {
        // More than MAX_BIP32_PATH_DEPTH components
        let mut components = vec![
            44 | Bip32Path::HARDENED,
            60 | Bip32Path::HARDENED,
            0 | Bip32Path::HARDENED,
        ];
        for i in 0..(MAX_BIP32_PATH_DEPTH - 2) {
            components.push(i as u32);
        }
        assert!(components.len() > MAX_BIP32_PATH_DEPTH);
        let path = Bip32Path::from_slice(&components);
        assert!(!path.is_valid_ethereum_path());
    }

    #[test]
    fn test_bip32_empty_path() {
        let path = Bip32Path::new();
        assert!(path.is_empty());
        assert_eq!(path.len(), 0);
        assert!(!path.is_valid_ethereum_path());
    }

    // =========================================================================
    // Signature tests
    // =========================================================================

    #[test]
    fn test_signature_default() {
        let sig = Signature::default();
        assert_eq!(sig.v, 0);
        assert_eq!(sig.r, [0u8; 32]);
        assert_eq!(sig.s, [0u8; 32]);
    }

    #[test]
    fn test_signature_72_byte_format() {
        let sig = Signature {
            v: 0x1234567890ABCDEF,
            r: [0xAA; 32],
            s: [0xBB; 32],
        };
        let bytes = sig.to_bytes();
        assert_eq!(bytes.len(), 72);
        // r is first 32 bytes
        assert_eq!(&bytes[0..32], &[0xAA; 32]);
        // s is next 32 bytes
        assert_eq!(&bytes[32..64], &[0xBB; 32]);
        // v is last 8 bytes big-endian
        assert_eq!(&bytes[64..72], &0x1234567890ABCDEFu64.to_be_bytes());
    }

    #[test]
    fn test_signature_legacy_format_v27() {
        let sig = Signature {
            v: 27,
            r: [1u8; 32],
            s: [2u8; 32],
        };
        let legacy = sig.to_bytes_legacy().unwrap();
        assert_eq!(legacy.len(), 65);
        assert_eq!(&legacy[0..32], &[1u8; 32]);
        assert_eq!(&legacy[32..64], &[2u8; 32]);
        assert_eq!(legacy[64], 27);
    }

    #[test]
    fn test_signature_legacy_format_v28() {
        let sig = Signature {
            v: 28,
            r: [0xFF; 32],
            s: [0xEE; 32],
        };
        let legacy = sig.to_bytes_legacy().unwrap();
        assert_eq!(legacy[64], 28);
    }

    #[test]
    fn test_signature_legacy_max_u8() {
        // v = 255 should still fit in legacy format
        let sig = Signature { v: 255, r: [0; 32], s: [0; 32] };
        assert!(sig.to_bytes_legacy().is_some());
    }

    #[test]
    fn test_signature_legacy_overflow_256() {
        // v = 256 should NOT fit
        let sig = Signature { v: 256, r: [0; 32], s: [0; 32] };
        assert!(sig.to_bytes_legacy().is_none());
    }

    #[test]
    fn test_signature_eip155_mainnet() {
        // EIP-155 mainnet: v = 1 * 2 + 35 + 0 = 37
        let sig = Signature { v: 37, r: [1; 32], s: [2; 32] };
        let bytes = sig.to_bytes();
        let recovered = Signature::from_bytes(&bytes);
        assert_eq!(recovered.v, 37);
        assert!(sig.to_bytes_legacy().is_some()); // 37 fits in u8
    }

    #[test]
    fn test_signature_eip155_large_chain_id() {
        // Chain ID = 100_000: v = 100_000 * 2 + 35 = 200_035
        let sig = Signature { v: 200_035, r: [0; 32], s: [0; 32] };
        assert!(sig.to_bytes_legacy().is_none()); // doesn't fit in u8
        let bytes = sig.to_bytes();
        let recovered = Signature::from_bytes(&bytes);
        assert_eq!(recovered.v, 200_035);
    }

    // =========================================================================
    // Transaction type tests
    // =========================================================================

    #[test]
    fn test_transaction_type_default() {
        assert_eq!(TransactionType::default(), TransactionType::Legacy);
    }

    #[test]
    fn test_transaction_type_all_invalid() {
        for byte in 3..=255u8 {
            assert!(TransactionType::try_from(byte).is_err());
        }
    }

    // =========================================================================
    // PublicKeyResponse tests
    // =========================================================================

    #[test]
    fn test_public_key_response_default() {
        let resp = PublicKeyResponse::default();
        assert_eq!(resp.pubkey, [0u8; 33]);
        assert_eq!(resp.address, [0u8; 20]);
    }
}

// =============================================================================
// Mnemonic Import
// =============================================================================

/// Fixed-size container for transmitting a mnemonic string via IPC.
#[derive(Clone, Archive, Serialize, Deserialize)]
pub struct MnemonicImport {
    /// Length of the mnemonic string in bytes.
    pub len: u32,
    /// Mnemonic bytes (zero-padded).
    pub data: [u8; 256],
}

impl MnemonicImport {
    /// Create from a mnemonic string. Returns None if too long.
    pub fn from_str(s: &str) -> Option<Self> {
        let bytes = s.as_bytes();
        if bytes.len() > 256 {
            return None;
        }
        let mut data = [0u8; 256];
        data[..bytes.len()].copy_from_slice(bytes);
        Some(Self {
            len: bytes.len() as u32,
            data,
        })
    }

    /// Get the mnemonic as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len as usize]
    }
}

// =============================================================================
// Serial Frame Transport
// =============================================================================

/// Maximum serial frame payload size (fits in one Xous page with header).
pub const SERIAL_FRAME_MAX: usize = 4000;

/// Serial frame data for IPC between USB service and ethapp.
///
/// Used for both request and response:
/// - Request: data = [opcode, payload...]
/// - Response: data = [status, payload...]
#[derive(Debug, Clone, Archive, Serialize, Deserialize)]
pub struct SerialFrameData {
    pub data: Vec<u8>,
}
