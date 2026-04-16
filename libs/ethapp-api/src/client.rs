//! EthApp client implementation for Xous IPC.
//!
//! This module provides the main client type that handles connection
//! management and message serialization for all ethapp operations.

use alloc::vec::Vec;

#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
use alloc::string::ToString;

#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
use alloc::format;

use ethapp_common::{
    AppConfiguration, Bip32Path, ClearSignTransactionRequest, EthAddress, EthAppError,
    EthAppOp, Hash256, MetadataContext, ProvideDomainNameRequest, ProvideMethodInfoRequest,
    ProvideNftInfoRequest, ProvideTokenInfoRequest, PublicKeyResponse, SignEip712HashedRequest,
    SignEip712MessageRequest, SignPersonalMessageRequest, SignTransactionRequest, Signature,
};

#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
use ethapp_common::SERVER_NAME;

#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
use num_traits::{FromPrimitive, ToPrimitive};

use crate::error::ApiError;

/// Client for interacting with the ethapp Xous service.
///
/// This client manages the connection to the ethapp server and provides
/// type-safe methods for all supported operations.
///
/// # Thread Safety
///
/// This client is NOT `Send`/`Sync`. Each thread should create its own instance.
///
/// # Example
///
/// ```ignore
/// let client = EthAppClient::new()?;
/// let config = client.get_app_configuration()?;
/// println!("EthApp version: {}.{}.{}", config.version_major, config.version_minor, config.version_patch);
/// ```
pub struct EthAppClient {
    /// Connection ID to the ethapp server.
    #[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
    conn: xous::CID,

    /// Phantom for non-Xous builds.
    #[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
    _phantom: core::marker::PhantomData<()>,
}

impl EthAppClient {
    /// Creates a new client and connects to the ethapp service.
    ///
    /// # Errors
    ///
    /// Returns `ApiError::ConnectionFailed` if the service is not available.
    #[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
    pub fn new() -> Result<Self, ApiError> {
        let xns = xous_names::XousNames::new()
            .map_err(|_| ApiError::ConnectionFailed("Failed to connect to xous-names".to_string()))?;

        let conn = xns
            .request_connection_blocking(SERVER_NAME)
            .map_err(|_| ApiError::ConnectionFailed("ethapp service not found".to_string()))?;

        Ok(Self { conn })
    }

    /// Creates a mock client for host testing.
    #[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
    pub fn new() -> Result<Self, ApiError> {
        Ok(Self {
            _phantom: core::marker::PhantomData,
        })
    }

    // =========================================================================
    // Configuration
    // =========================================================================

    /// Gets the application configuration and version.
    ///
    /// Returns version info, feature flags, and protocol version.
    pub fn get_app_configuration(&self) -> Result<AppConfiguration, ApiError> {
        self.send_receive_memory::<(), AppConfiguration>(EthAppOp::GetAppConfiguration, &())
    }

    /// Gets a 32-byte random challenge for anti-phishing.
    ///
    /// The challenge can be displayed to the user to verify they are
    /// communicating with the genuine device.
    pub fn get_challenge(&self) -> Result<Hash256, ApiError> {
        self.send_receive_memory::<(), Hash256>(EthAppOp::GetChallenge, &())
    }

    /// Pings the service for health check.
    ///
    /// Returns `Ok(())` if the service is responsive.
    pub fn ping(&self) -> Result<(), ApiError> {
        self.send_scalar(EthAppOp::Ping)?;
        Ok(())
    }

    // =========================================================================
    // Seed Management
    // =========================================================================

    /// Import a 64-byte seed for key derivation.
    ///
    /// The seed is stored in memory only (lost on reboot).
    /// Takes priority over the dev seed and PDDB seed.
    pub fn set_seed(&self, seed: &[u8; 64]) -> Result<(), ApiError> {
        self.send_memory(EthAppOp::SetSeed, seed)
    }

    /// Import a BIP39 mnemonic and derive the seed via PBKDF2.
    ///
    /// The service performs PBKDF2-HMAC-SHA512 (2048 rounds) to derive
    /// the 64-byte seed from the mnemonic. The seed is persisted to PDDB.
    pub fn import_mnemonic(&self, mnemonic: &str) -> Result<(), ApiError> {
        use ethapp_common::MnemonicImport;
        let import = MnemonicImport::from_str(mnemonic)
            .ok_or_else(|| ApiError::SerializationFailed("mnemonic too long (max 256 bytes)".into()))?;
        self.send_memory(EthAppOp::ImportMnemonic, &import)
    }

    /// Generate a new 24-word BIP39 mnemonic from device TRNG entropy.
    ///
    /// The mnemonic words are displayed on the device screen only and
    /// are never transmitted over IPC or USB. The derived seed is
    /// persisted to PDDB.
    ///
    /// This is a blocking call — it waits for the user to confirm on device.
    pub fn generate_mnemonic(&self) -> Result<(), ApiError> {
        self.send_blocking_scalar(EthAppOp::GenerateMnemonic)
    }

    /// Wipe the master seed from memory and persistent storage.
    ///
    /// Requires on-device user confirmation. After clearing, all
    /// signing operations will fail until a new seed is imported
    /// or generated.
    pub fn clear_seed(&self) -> Result<(), ApiError> {
        self.send_blocking_scalar(EthAppOp::ClearSeed)
    }

    // =========================================================================
    // Key Management
    // =========================================================================

    /// Gets the public key and address for a derivation path.
    ///
    /// # Arguments
    /// * `path` - BIP32 derivation path (must be valid Ethereum path)
    ///
    /// # Returns
    /// Public key (33 bytes compressed) and Ethereum address (20 bytes).
    pub fn get_public_key(&self, path: &Bip32Path) -> Result<PublicKeyResponse, ApiError> {
        self.send_receive_memory(EthAppOp::GetPublicKey, path)
    }

    /// Gets only the Ethereum address for a derivation path.
    ///
    /// This is more efficient than `get_public_key` if you only need the address.
    pub fn get_address(&self, path: &Bip32Path) -> Result<EthAddress, ApiError> {
        self.send_receive_memory(EthAppOp::GetAddress, path)
    }

    // =========================================================================
    // Transaction Signing
    // =========================================================================

    /// Signs an Ethereum transaction.
    ///
    /// Supports legacy, EIP-2930 (access list), and EIP-1559 (fee market) transactions.
    /// User will be prompted to confirm on the device display.
    ///
    /// # Arguments
    /// * `request` - Contains derivation path and RLP-encoded transaction
    ///
    /// # Returns
    /// ECDSA signature with EIP-155 v value for replay protection.
    ///
    /// # Errors
    /// - `RejectedByUser` - User declined to sign
    /// - `InvalidTransaction` - Transaction parsing failed
    /// - `InvalidDerivationPath` - Path is not valid Ethereum BIP44
    pub fn sign_transaction(&self, request: &SignTransactionRequest) -> Result<Signature, ApiError> {
        self.send_receive_memory(EthAppOp::SignTransaction, request)
    }

    /// Signs a transaction with clear signing (full metadata display).
    ///
    /// Similar to `sign_transaction` but uses provided metadata to show
    /// human-readable information (token names, ENS names, method names).
    ///
    /// # Note
    /// Metadata must be provided first via the `provide_*` methods.
    pub fn clear_sign_transaction(
        &self,
        request: &ClearSignTransactionRequest,
    ) -> Result<Signature, ApiError> {
        self.send_receive_memory(EthAppOp::ClearSignTransaction, request)
    }

    // =========================================================================
    // Message Signing
    // =========================================================================

    /// Signs an EIP-191 personal message.
    ///
    /// The message is prefixed with "\x19Ethereum Signed Message:\n{length}"
    /// before hashing with Keccak256.
    ///
    /// # Arguments
    /// * `request` - Contains derivation path and message bytes
    ///
    /// # Returns
    /// ECDSA signature with v = 27 or 28.
    pub fn sign_personal_message(
        &self,
        request: &SignPersonalMessageRequest,
    ) -> Result<Signature, ApiError> {
        self.send_receive_memory(EthAppOp::SignPersonalMessage, request)
    }

    /// Signs pre-hashed EIP-712 typed data (blind signing).
    ///
    /// Use this when you have already computed the domain separator and
    /// message hashes. This is "blind signing" because the service cannot
    /// display the original typed data.
    ///
    /// # Security Warning
    /// Blind signing should only be used when necessary. Prefer `sign_eip712_message`
    /// for better user experience.
    pub fn sign_eip712_hashed(
        &self,
        request: &SignEip712HashedRequest,
    ) -> Result<Signature, ApiError> {
        self.send_receive_memory(EthAppOp::SignEip712Hashed, request)
    }

    /// Signs full EIP-712 typed data with parsing.
    ///
    /// The service will parse and display the typed data structure to the user.
    /// This provides better security than blind signing.
    pub fn sign_eip712_message(
        &self,
        request: &SignEip712MessageRequest,
    ) -> Result<Signature, ApiError> {
        self.send_receive_memory(EthAppOp::SignEip712Message, request)
    }

    // =========================================================================
    // Metadata Provision
    // =========================================================================

    /// Provides ERC-20 token information for display.
    ///
    /// Token info is cached by the service and used to display human-readable
    /// token amounts in transactions (e.g., "100 USDC" instead of raw value).
    ///
    /// # Arguments
    /// * `request` - Token info and signature (for verification)
    ///
    /// # Returns
    /// `true` if the token info was accepted and cached.
    pub fn provide_token_info(&self, request: &ProvideTokenInfoRequest) -> Result<bool, ApiError> {
        let result = self.send_receive_memory::<_, u8>(EthAppOp::ProvideErc20TokenInfo, request)?;
        Ok(result != 0)
    }

    /// Provides NFT collection information for display.
    pub fn provide_nft_info(&self, request: &ProvideNftInfoRequest) -> Result<bool, ApiError> {
        let result = self.send_receive_memory::<_, u8>(EthAppOp::ProvideNftInfo, request)?;
        Ok(result != 0)
    }

    /// Provides domain name resolution information.
    ///
    /// Used to display ENS names instead of raw addresses.
    pub fn provide_domain_name(&self, request: &ProvideDomainNameRequest) -> Result<bool, ApiError> {
        let result = self.send_receive_memory::<_, u8>(EthAppOp::ProvideDomainName, request)?;
        Ok(result != 0)
    }

    /// Provides contract method ABI information for clear signing.
    ///
    /// Allows the service to decode and display contract call parameters.
    pub fn provide_method_info(&self, request: &ProvideMethodInfoRequest) -> Result<bool, ApiError> {
        let result = self.send_receive_memory::<_, u8>(EthAppOp::LoadContractMethodInfo, request)?;
        Ok(result != 0)
    }

    /// Sets the context for subsequent metadata lookups.
    ///
    /// Binds the next signing operation to a specific chain and contract address.
    pub fn set_metadata_context(&self, chain_id: u64, address: &EthAddress) -> Result<bool, ApiError> {
        // Pack chain_id and address into a context structure
        let context = MetadataContext {
            chain_id,
            address: *address,
        };
        let result =
            self.send_receive_memory::<_, u8>(EthAppOp::ByContractAddressAndChain, &context)?;
        Ok(result != 0)
    }

    /// Clears all cached metadata.
    ///
    /// Useful for testing or when switching between applications.
    pub fn clear_metadata_cache(&self) -> Result<(), ApiError> {
        self.send_scalar(EthAppOp::ClearMetadataCache)?;
        Ok(())
    }

    // =========================================================================
    // Eth2 Staking (optional feature)
    // =========================================================================

    /// Gets the BLS public key for Eth2 validator operations.
    ///
    /// # Returns
    /// 48-byte BLS12-381 public key, or `UnsupportedOperation` if Eth2 is disabled.
    #[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
    pub fn eth2_get_public_key(&self, path: &Bip32Path) -> Result<Vec<u8>, ApiError> {
        self.send_receive_memory(EthAppOp::Eth2GetPublicKey, path)
    }

    /// Gets the BLS public key for Eth2 validator operations (mock for host).
    #[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
    pub fn eth2_get_public_key(&self, _path: &Bip32Path) -> Result<Vec<u8>, ApiError> {
        Ok(Vec::new())
    }

    /// Sets the withdrawal credential index for Eth2 operations.
    pub fn eth2_set_withdrawal_index(&self, index: u32) -> Result<(), ApiError> {
        self.send_scalar_with_arg(EthAppOp::Eth2SetWithdrawalIndex, index as usize)?;
        Ok(())
    }

    // =========================================================================
    // Internal Methods
    // =========================================================================

    /// Sends a scalar message (no payload).
    #[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
    fn send_scalar(&self, op: EthAppOp) -> Result<(), ApiError> {
        let opcode = op.to_u32().ok_or_else(|| {
            ApiError::SerializationFailed("Invalid opcode".to_string())
        })?;

        xous::send_message(
            self.conn,
            xous::Message::new_scalar(opcode as usize, 0, 0, 0, 0),
        )
        .map_err(|e| ApiError::IpcFailed(format!("{:?}", e)))?;

        Ok(())
    }

    /// Sends a blocking scalar message (waits for server to return).
    #[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
    fn send_blocking_scalar(&self, op: EthAppOp) -> Result<(), ApiError> {
        let opcode = op.to_u32().ok_or_else(|| {
            ApiError::SerializationFailed("Invalid opcode".to_string())
        })?;

        xous::send_message(
            self.conn,
            xous::Message::new_blocking_scalar(opcode as usize, 0, 0, 0, 0),
        )
        .map_err(|e| ApiError::IpcFailed(format!("{:?}", e)))?;

        Ok(())
    }

    #[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
    fn send_blocking_scalar(&self, _op: EthAppOp) -> Result<(), ApiError> {
        Ok(())
    }

    /// Sends a scalar message with one argument.
    #[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
    fn send_scalar_with_arg(&self, op: EthAppOp, arg: usize) -> Result<(), ApiError> {
        let opcode = op.to_u32().ok_or_else(|| {
            ApiError::SerializationFailed("Invalid opcode".to_string())
        })?;

        xous::send_message(
            self.conn,
            xous::Message::new_scalar(opcode as usize, arg, 0, 0, 0),
        )
        .map_err(|e| ApiError::IpcFailed(format!("{:?}", e)))?;

        Ok(())
    }

    /// Sends a memory message (fire-and-forget, no typed response).
    #[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
    fn send_memory<T>(&self, op: EthAppOp, request: &T) -> Result<(), ApiError>
    where
        T: Clone
            + for<'b, 'a> rkyv::Serialize<
                rkyv::rancor::Strategy<
                    rkyv::ser::Serializer<
                        rkyv::ser::writer::Buffer<'b>,
                        rkyv::ser::allocator::SubAllocator<'a>,
                        (),
                    >,
                    rkyv::rancor::Failure,
                >,
            >,
    {
        let opcode = op.to_u32().ok_or_else(|| {
            ApiError::SerializationFailed("Invalid opcode".to_string())
        })?;

        let mut buf = xous_ipc::Buffer::new(4096);
        buf.replace(request.clone())
            .map_err(|_| ApiError::SerializationFailed("Buffer serialization failed".to_string()))?;

        buf.lend_mut(self.conn, opcode as u32)
            .map_err(|e| ApiError::IpcFailed(format!("{:?}", e)))?;

        Ok(())
    }

    #[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
    fn send_memory<T>(&self, _op: EthAppOp, _request: &T) -> Result<(), ApiError> {
        Ok(())
    }

    /// Sends a memory message and receives a response via xous-ipc Buffer.
    ///
    /// Serializes `request` using rkyv's low-level serializer (matching
    /// `xous_ipc::Buffer::into_buf`) and deserializes the response with
    /// `Buffer::to_original`. Both sides must use the same rkyv version.
    #[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
    fn send_receive_memory<T, R>(&self, op: EthAppOp, request: &T) -> Result<R, ApiError>
    where
        T: Clone
            + for<'b, 'a> rkyv::Serialize<
                rkyv::rancor::Strategy<
                    rkyv::ser::Serializer<
                        rkyv::ser::writer::Buffer<'b>,
                        rkyv::ser::allocator::SubAllocator<'a>,
                        (),
                    >,
                    rkyv::rancor::Failure,
                >,
            >,
        R: rkyv::Archive,
        R::Archived: rkyv::Portable
            + rkyv::Deserialize<
                R,
                rkyv::rancor::Strategy<rkyv::de::Pool, rkyv::rancor::Error>,
            >,
    {
        let opcode = op.to_u32().ok_or_else(|| {
            ApiError::SerializationFailed("Invalid opcode".to_string())
        })?;

        // Always allocate at least one page so MemorySize::new() succeeds even
        // for zero-sized request types like `()`. The extra space also ensures
        // the buffer is large enough to hold the server's response.
        let mut buf = xous_ipc::Buffer::new(4096);
        buf.replace(request.clone())
            .map_err(|_| ApiError::SerializationFailed("Buffer serialization failed".to_string()))?;

        buf.lend_mut(self.conn, opcode as u32)
            .map_err(|e| ApiError::IpcFailed(format!("{:?}", e)))?;

        // A 4-byte response is an error code written by write_error_response().
        // Normal responses are either 1 byte (u8 bool) or >= 20 bytes (addresses,
        // signatures, AppConfiguration, etc.), so 4 bytes is unambiguous.
        if buf.used() == 4 {
            if let Ok(code) = buf.to_original::<u32, _>() {
                if let Some(err) = EthAppError::from_u32(code) {
                    return Err(ApiError::ServiceError(err));
                }
            }
        }

        buf.to_original::<R, _>()
            .map_err(|_| ApiError::DeserializationFailed("Response deserialization failed".to_string()))
    }

    // Mock implementations for non-Xous builds
    #[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
    fn send_scalar(&self, _op: EthAppOp) -> Result<(), ApiError> {
        Ok(())
    }

    #[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
    fn send_scalar_with_arg(&self, _op: EthAppOp, _arg: usize) -> Result<(), ApiError> {
        Ok(())
    }

    #[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
    fn send_receive_memory<T, R>(&self, _op: EthAppOp, _request: &T) -> Result<R, ApiError>
    where
        R: Default,
    {
        // Return default value for host testing
        Ok(R::default())
    }
}

impl Drop for EthAppClient {
    fn drop(&mut self) {
        #[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
        {
            // Disconnect from the server
            let _ = xous::send_message(
                self.conn,
                xous::Message::new_blocking_scalar(0, 0, 0, 0, 0),
            );
        }
    }
}

// MetadataContext is defined in ethapp-common and re-exported from there.

// ============================================================================
// Convenience Builders
// ============================================================================

/// Builder for creating sign transaction requests.
pub struct SignTransactionBuilder {
    path: Bip32Path,
    tx_data: Vec<u8>,
}

impl SignTransactionBuilder {
    /// Creates a new builder with the given derivation path.
    pub fn new(path: Bip32Path) -> Self {
        Self {
            path,
            tx_data: Vec::new(),
        }
    }

    /// Sets the RLP-encoded transaction data.
    pub fn tx_data(mut self, data: Vec<u8>) -> Self {
        self.tx_data = data;
        self
    }

    /// Builds the request.
    pub fn build(self) -> SignTransactionRequest {
        SignTransactionRequest {
            path: self.path,
            tx_data: self.tx_data,
        }
    }
}

/// Builder for creating personal message sign requests.
pub struct SignPersonalMessageBuilder {
    path: Bip32Path,
    message: Vec<u8>,
}

impl SignPersonalMessageBuilder {
    /// Creates a new builder with the given derivation path.
    pub fn new(path: Bip32Path) -> Self {
        Self {
            path,
            message: Vec::new(),
        }
    }

    /// Sets the message as bytes.
    pub fn message_bytes(mut self, msg: Vec<u8>) -> Self {
        self.message = msg;
        self
    }

    /// Sets the message as a string.
    pub fn message_str(mut self, msg: &str) -> Self {
        self.message = msg.as_bytes().to_vec();
        self
    }

    /// Builds the request.
    pub fn build(self) -> SignPersonalMessageRequest {
        SignPersonalMessageRequest {
            path: self.path,
            message: self.message,
        }
    }
}

/// Builder for EIP-712 hashed sign requests.
pub struct SignEip712HashedBuilder {
    path: Bip32Path,
    domain_hash: Hash256,
    message_hash: Hash256,
}

impl SignEip712HashedBuilder {
    /// Creates a new builder with the given derivation path.
    pub fn new(path: Bip32Path) -> Self {
        Self {
            path,
            domain_hash: [0u8; 32],
            message_hash: [0u8; 32],
        }
    }

    /// Sets the domain separator hash.
    pub fn domain_hash(mut self, hash: Hash256) -> Self {
        self.domain_hash = hash;
        self
    }

    /// Sets the message hash.
    pub fn message_hash(mut self, hash: Hash256) -> Self {
        self.message_hash = hash;
        self
    }

    /// Builds the request.
    pub fn build(self) -> SignEip712HashedRequest {
        SignEip712HashedRequest {
            path: self.path,
            domain_hash: self.domain_hash,
            message_hash: self.message_hash,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_sign_transaction_builder() {
        let path = Bip32Path::ethereum(0, 0, 0);
        let tx_data = vec![0xf8, 0x6c]; // RLP prefix

        let request = SignTransactionBuilder::new(path.clone())
            .tx_data(tx_data.clone())
            .build();

        assert_eq!(request.path, path);
        assert_eq!(request.tx_data, tx_data);
    }

    #[test]
    fn test_sign_personal_message_builder() {
        let path = Bip32Path::ethereum(0, 0, 0);
        let msg = "Hello, Ethereum!";

        let request = SignPersonalMessageBuilder::new(path.clone())
            .message_str(msg)
            .build();

        assert_eq!(request.path, path);
        assert_eq!(request.message, msg.as_bytes());
    }

    #[test]
    fn test_sign_eip712_hashed_builder() {
        let path = Bip32Path::ethereum(0, 0, 0);
        let domain = [1u8; 32];
        let message = [2u8; 32];

        let request = SignEip712HashedBuilder::new(path.clone())
            .domain_hash(domain)
            .message_hash(message)
            .build();

        assert_eq!(request.path, path);
        assert_eq!(request.domain_hash, domain);
        assert_eq!(request.message_hash, message);
    }

    #[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
    #[test]
    fn test_client_creation() {
        let client = EthAppClient::new();
        assert!(client.is_ok());
    }
}
