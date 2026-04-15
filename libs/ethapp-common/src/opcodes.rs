//! Message opcodes for the Ethereum App Xous service.
//!
//! Each opcode corresponds to a specific operation that can be
//! requested from the ethapp service.

use num_derive::{FromPrimitive, ToPrimitive};

/// Operation codes for ethapp service messages.
///
/// These map to the Vanadium Ethereum app commands but are adapted
/// for Xous message-passing patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive, ToPrimitive)]
#[repr(u32)]
pub enum EthAppOp {
    // === Configuration Commands (0x01-0x0F) ===

    /// Get application configuration and version.
    /// Returns: AppConfiguration via memory message.
    GetAppConfiguration = 0x01,

    /// Get a 32-byte random challenge for anti-phishing.
    /// Returns: 32 bytes via memory message.
    GetChallenge = 0x02,

    /// Graceful shutdown (testing only).
    Exit = 0x0F,

    // === Transaction Signing (0x10-0x1F) ===

    /// Sign a legacy or EIP-2718 typed transaction.
    /// Input: SignTransactionRequest via memory message.
    /// Returns: Signature via memory message.
    SignTransaction = 0x10,

    /// Sign transaction with full metadata display (clear signing).
    /// Input: ClearSignTransactionRequest via memory message.
    /// Returns: Signature via memory message.
    ClearSignTransaction = 0x11,

    // === Message Signing (0x20-0x2F) ===

    /// Sign an EIP-191 personal message.
    /// Input: SignPersonalMessageRequest via memory message.
    /// Returns: Signature via memory message.
    SignPersonalMessage = 0x20,

    /// Sign pre-hashed EIP-712 typed data (blind signing).
    /// Input: SignEip712HashedRequest via memory message.
    /// Returns: Signature via memory message.
    SignEip712Hashed = 0x21,

    /// Sign full EIP-712 typed data with parsing.
    /// Input: SignEip712MessageRequest via memory message.
    /// Returns: Signature via memory message.
    SignEip712Message = 0x22,

    // === Metadata Provision (0x30-0x3F) ===

    /// Provide verified ERC-20 token metadata.
    /// Input: ProvideTokenInfoRequest via memory message.
    /// Returns: bool (accepted) via scalar.
    ProvideErc20TokenInfo = 0x30,

    /// Provide verified NFT collection metadata.
    /// Input: ProvideNftInfoRequest via memory message.
    /// Returns: bool (accepted) via scalar.
    ProvideNftInfo = 0x31,

    /// Provide verified domain name resolution.
    /// Input: ProvideDomainNameRequest via memory message.
    /// Returns: bool (accepted) via scalar.
    ProvideDomainName = 0x32,

    /// Provide verified contract method ABI info.
    /// Input: ProvideMethodInfoRequest via memory message.
    /// Returns: bool (accepted) via scalar.
    LoadContractMethodInfo = 0x33,

    /// Set context for metadata lookup (chain + address).
    /// Input: chain_id (u64) and address (20 bytes) via scalar/memory.
    /// Returns: bool (bound) via scalar.
    ByContractAddressAndChain = 0x34,

    // === Eth2 Staking (0x40-0x4F) ===

    /// Get BLS public key for validator.
    /// Input: Bip32Path via memory message.
    /// Returns: 48-byte BLS pubkey or UnsupportedOperation error.
    Eth2GetPublicKey = 0x40,

    /// Set withdrawal credential index.
    /// Input: u32 index via scalar.
    /// Returns: Success or error.
    Eth2SetWithdrawalIndex = 0x41,

    // === Key Management (0x50-0x5F) ===

    /// Get public key and address for a derivation path.
    /// Input: Bip32Path via memory message.
    /// Returns: PublicKeyResponse (pubkey + address).
    GetPublicKey = 0x50,

    /// Get address only for a derivation path.
    /// Input: Bip32Path via memory message.
    /// Returns: 20-byte address.
    GetAddress = 0x51,

    // === Seed Management (0x60-0x6F) ===

    /// Import a 64-byte seed for key derivation.
    /// Input: 64 bytes via memory message.
    /// Returns: success or error.
    SetSeed = 0x60,

    /// Import a BIP39 mnemonic and derive the seed via PBKDF2.
    /// Input: mnemonic string via memory message.
    /// Returns: success or error.
    ImportMnemonic = 0x61,

    // === Internal/Debug (0xF0-0xFF) ===

    /// Clear all cached metadata.
    ClearMetadataCache = 0xF0,

    /// Get service statistics (debug).
    GetStats = 0xF1,

    /// Ping for health check.
    /// Returns immediately with scalar response.
    Ping = 0xFF,
}

/// Chunk flags for streaming large payloads.
///
/// When data exceeds a single Xous page (4096 bytes), it must be
/// sent in chunks with appropriate flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive, ToPrimitive)]
#[repr(u8)]
pub enum ChunkFlags {
    /// Continuation chunk (neither first nor last).
    Continue = 0x00,
    /// First chunk of a multi-part message.
    First = 0x01,
    /// Last chunk of a multi-part message.
    Last = 0x02,
    /// Single chunk (both first and last).
    Single = 0x03,
}

impl ChunkFlags {
    /// Returns true if this is the first chunk.
    #[inline]
    pub fn is_first(self) -> bool {
        matches!(self, ChunkFlags::First | ChunkFlags::Single)
    }

    /// Returns true if this is the last chunk.
    #[inline]
    pub fn is_last(self) -> bool {
        matches!(self, ChunkFlags::Last | ChunkFlags::Single)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::{FromPrimitive, ToPrimitive};

    #[test]
    fn test_opcode_roundtrip() {
        let op = EthAppOp::SignTransaction;
        let val = op.to_u32().unwrap();
        let back = EthAppOp::from_u32(val).unwrap();
        assert_eq!(op, back);
    }

    #[test]
    fn test_chunk_flags() {
        assert!(ChunkFlags::First.is_first());
        assert!(!ChunkFlags::First.is_last());
        assert!(ChunkFlags::Single.is_first());
        assert!(ChunkFlags::Single.is_last());
    }

    #[test]
    fn test_chunk_flags_continue() {
        assert!(!ChunkFlags::Continue.is_first());
        assert!(!ChunkFlags::Continue.is_last());
    }

    #[test]
    fn test_chunk_flags_last() {
        assert!(!ChunkFlags::Last.is_first());
        assert!(ChunkFlags::Last.is_last());
    }

    #[test]
    fn test_opcode_ranges() {
        // Config commands: 0x01-0x0F
        assert_eq!(EthAppOp::GetAppConfiguration.to_u32().unwrap(), 0x01);
        assert_eq!(EthAppOp::Exit.to_u32().unwrap(), 0x0F);

        // Transaction signing: 0x10-0x1F
        assert_eq!(EthAppOp::SignTransaction.to_u32().unwrap(), 0x10);
        assert_eq!(EthAppOp::ClearSignTransaction.to_u32().unwrap(), 0x11);

        // Message signing: 0x20-0x2F
        assert_eq!(EthAppOp::SignPersonalMessage.to_u32().unwrap(), 0x20);
        assert_eq!(EthAppOp::SignEip712Hashed.to_u32().unwrap(), 0x21);
        assert_eq!(EthAppOp::SignEip712Message.to_u32().unwrap(), 0x22);

        // Metadata: 0x30-0x3F
        assert_eq!(EthAppOp::ProvideErc20TokenInfo.to_u32().unwrap(), 0x30);
        assert_eq!(EthAppOp::ByContractAddressAndChain.to_u32().unwrap(), 0x34);

        // Key management: 0x50-0x5F
        assert_eq!(EthAppOp::GetPublicKey.to_u32().unwrap(), 0x50);
        assert_eq!(EthAppOp::GetAddress.to_u32().unwrap(), 0x51);

        // Ping: 0xFF
        assert_eq!(EthAppOp::Ping.to_u32().unwrap(), 0xFF);
    }

    #[test]
    fn test_opcode_roundtrip_all() {
        let ops = [
            EthAppOp::GetAppConfiguration, EthAppOp::GetChallenge, EthAppOp::Exit,
            EthAppOp::SignTransaction, EthAppOp::ClearSignTransaction,
            EthAppOp::SignPersonalMessage, EthAppOp::SignEip712Hashed,
            EthAppOp::SignEip712Message,
            EthAppOp::ProvideErc20TokenInfo, EthAppOp::ProvideNftInfo,
            EthAppOp::ProvideDomainName, EthAppOp::LoadContractMethodInfo,
            EthAppOp::ByContractAddressAndChain,
            EthAppOp::Eth2GetPublicKey, EthAppOp::Eth2SetWithdrawalIndex,
            EthAppOp::GetPublicKey, EthAppOp::GetAddress,
            EthAppOp::SetSeed, EthAppOp::ImportMnemonic,
            EthAppOp::ClearMetadataCache, EthAppOp::GetStats, EthAppOp::Ping,
        ];
        for op in &ops {
            let val = op.to_u32().unwrap();
            let back = EthAppOp::from_u32(val).unwrap();
            assert_eq!(*op, back, "roundtrip failed for {op:?}");
        }
    }

    #[test]
    fn test_invalid_opcode_values() {
        // Values that are not valid opcodes
        assert!(EthAppOp::from_u32(0x00).is_none());
        assert!(EthAppOp::from_u32(0x03).is_none());
        assert!(EthAppOp::from_u32(0x12).is_none());
        assert!(EthAppOp::from_u32(0x99).is_none());
    }
}
