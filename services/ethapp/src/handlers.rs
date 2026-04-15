//! Message handlers for the ethapp service.
//!
//! Each handler processes a specific opcode and returns a response.
//! Handlers are responsible for:
//! - Deserializing request data
//! - Validating parameters
//! - Performing the operation
//! - Serializing and returning the response

use std::string::String;

use ethapp_common::{
    Bip32Path, EthAppError, MetadataContext, ProvideTokenInfoRequest,
    PublicKeyResponse, Signature, SignEip712HashedRequest, SignEip712MessageRequest,
    SignPersonalMessageRequest, SignTransactionRequest,
};

use crate::crypto::{
    derive_private_key, get_compressed_pubkey,
    public_key_to_address, sign_eth, sign_eip712, sign_personal_message, get_public_key,
};
use crate::parsing::TransactionParser;
use crate::platform::Platform;
use crate::state::ServiceState;
use crate::ui;

// =============================================================================
// Helper Functions
// =============================================================================

/// Returns a success scalar response.
#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
pub fn return_success(msg: xous::MessageEnvelope) -> Result<(), EthAppError> {
    xous::return_scalar(msg.sender, 0)
        .map_err(|_| EthAppError::InternalError)
}

#[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
pub fn return_success(_msg: ()) -> Result<(), EthAppError> {
    Ok(())
}

/// Returns an error scalar response.
#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
pub fn return_error(msg: xous::MessageEnvelope, error: EthAppError) -> Result<(), EthAppError> {
    xous::return_scalar(msg.sender, error.code() as usize)
        .map_err(|_| EthAppError::InternalError)
}

#[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
pub fn return_error(_msg: (), error: EthAppError) -> Result<(), EthAppError> {
    Err(error)
}

/// Write an error code into the response buffer so the client can detect it.
///
/// Encodes `error.code()` as a `u32` (4 bytes).  The client distinguishes
/// this from normal responses by checking `buf.used() == 4`: valid responses
/// are either 1 byte (u8 bool) or ≥ 20 bytes (addresses, signatures, etc.).
/// Error codes are 0x00–0x1A, so a 4-byte response is unambiguously an error.
#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
fn write_error_response(buffer: &mut xous_ipc::Buffer, error: EthAppError) {
    let _ = buffer.replace(error.code() as u32);
}


/// Get the seed for key derivation.
///
/// Both dev-mode and production paths return the same type to prevent
/// compilation errors where callers use `?` for one cfg but not the other.
///
/// Get the seed for key derivation.
///
/// Priority: imported seed (runtime) > dev seed (dev-mode) > error.
fn get_seed(state: &ServiceState) -> Result<crate::crypto::Seed, EthAppError> {
    // Check for runtime-imported seed first
    if let Some(seed) = &state.imported_seed {
        return Ok(seed.clone());
    }

    // Fall back to dev seed or error
    #[cfg(feature = "dev-mode")]
    {
        return Ok(crate::crypto::get_dev_seed());
    }

    #[cfg(not(feature = "dev-mode"))]
    {
        // TODO(baochip): Load from PDDB when available
        Err(EthAppError::UnsupportedOperation)
    }
}

// =============================================================================
// Configuration Handlers
// =============================================================================

/// Handle GetAppConfiguration request.
#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
pub fn handle_get_app_configuration(
    state: &mut ServiceState,
    mut msg: xous::MessageEnvelope,
) -> Result<(), EthAppError> {
    use xous_ipc::Buffer;

    let mut buffer = unsafe {
        Buffer::from_memory_message_mut(
            msg.body.memory_message_mut().ok_or(EthAppError::InvalidData)?,
        )
    };

    let config = state.config.clone();
    buffer.replace(config).map_err(|_| EthAppError::InternalError)?;
    Ok(())
}

#[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
pub fn handle_get_app_configuration(
    state: &mut ServiceState,
    _msg: (),
) -> Result<AppConfiguration, EthAppError> {
    Ok(state.config.clone())
}

/// Handle GetChallenge request.
#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
pub fn handle_get_challenge(
    state: &mut ServiceState,
    mut msg: xous::MessageEnvelope,
) -> Result<(), EthAppError> {
    use xous_ipc::Buffer;

    let mut buffer = unsafe {
        Buffer::from_memory_message_mut(
            msg.body.memory_message_mut().ok_or(EthAppError::InvalidData)?,
        )
    };

    let mut challenge = [0u8; 32];
    state.platform.rng_fill_bytes(&mut challenge)?;
    buffer.replace(challenge).map_err(|_| EthAppError::InternalError)?;
    Ok(())
}

#[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
pub fn handle_get_challenge(
    state: &mut ServiceState,
    _msg: (),
) -> Result<[u8; 32], EthAppError> {
    let mut challenge = [0u8; 32];
    state.platform.rng_fill_bytes(&mut challenge)?;
    Ok(challenge)
}

// =============================================================================
// Transaction Signing Handlers
// =============================================================================

/// Handle SignTransaction request.
#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
pub fn handle_sign_transaction(
    state: &mut ServiceState,
    mut msg: xous::MessageEnvelope,
) -> Result<(), EthAppError> {
    use xous_ipc::Buffer;

    let mut buffer = unsafe {
        Buffer::from_memory_message_mut(
            msg.body.memory_message_mut().ok_or(EthAppError::InvalidData)?,
        )
    };

    let request: SignTransactionRequest = buffer
        .to_original()
        .map_err(|_| EthAppError::SerializationError)?;

    match process_sign_transaction(state, &request) {
        Ok(signature) => {
            buffer.replace(signature).map_err(|_| EthAppError::InternalError)?;
            state.record_sign_success();
        }
        Err(e) => write_error_response(&mut buffer, e),
    }
    Ok(())
}

#[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
pub fn handle_sign_transaction(
    state: &mut ServiceState,
    request: &SignTransactionRequest,
) -> Result<Signature, EthAppError> {
    let signature = process_sign_transaction(state, request)?;
    state.record_sign_success();
    Ok(signature)
}

/// Process a sign transaction request.
fn process_sign_transaction(
    state: &mut ServiceState,
    request: &SignTransactionRequest,
) -> Result<Signature, EthAppError> {
    // Validate path
    if !request.path.is_valid_ethereum_path() {
        return Err(EthAppError::InvalidDerivationPath);
    }

    // Parse transaction
    let tx = TransactionParser::parse(&request.tx_data)
        .map_err(|_| EthAppError::InvalidTransaction)?;

    // Display transaction for user confirmation
    if !ui::display_transaction(&state.platform, &tx, false)? {
        state.record_sign_rejected();
        return Err(EthAppError::RejectedByUser);
    }

    // Get seed and derive key; sign in a tight scope so the signing key
    // is dropped (and zeroized via k256's ZeroizeOnDrop) immediately after use.
    let signature = {
        let seed = get_seed(state)?;
        let signing_key = derive_private_key(&seed, &request.path)?;
        // seed is Zeroize+Drop, signing_key has ZeroizeOnDrop
        sign_eth(&signing_key, &tx.sign_hash, tx.chain_id, tx.tx_type)?
        // signing_key and seed dropped here, secret material zeroized
    };

    state.platform.show_info(true, "Transaction signed");

    Ok(signature)
}

/// Handle ClearSignTransaction request.
#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
pub fn handle_clear_sign_transaction(
    state: &mut ServiceState,
    mut msg: xous::MessageEnvelope,
) -> Result<(), EthAppError> {
    // For now, delegate to regular sign transaction
    // Full implementation would use cached metadata
    handle_sign_transaction(state, msg)
}

#[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
pub fn handle_clear_sign_transaction(
    state: &mut ServiceState,
    request: &SignTransactionRequest,
) -> Result<Signature, EthAppError> {
    handle_sign_transaction(state, request)
}

// =============================================================================
// Message Signing Handlers
// =============================================================================

/// Handle SignPersonalMessage request.
#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
pub fn handle_sign_personal_message(
    state: &mut ServiceState,
    mut msg: xous::MessageEnvelope,
) -> Result<(), EthAppError> {
    use xous_ipc::Buffer;

    let mut buffer = unsafe {
        Buffer::from_memory_message_mut(
            msg.body.memory_message_mut().ok_or(EthAppError::InvalidData)?,
        )
    };

    let request: SignPersonalMessageRequest = buffer
        .to_original()
        .map_err(|_| EthAppError::SerializationError)?;

    match process_sign_personal_message(state, &request) {
        Ok(signature) => {
            buffer.replace(signature).map_err(|_| EthAppError::InternalError)?;
            state.record_sign_success();
        }
        Err(e) => write_error_response(&mut buffer, e),
    }
    Ok(())
}

#[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
pub fn handle_sign_personal_message(
    state: &mut ServiceState,
    request: &SignPersonalMessageRequest,
) -> Result<Signature, EthAppError> {
    let signature = process_sign_personal_message(state, request)?;
    state.record_sign_success();
    Ok(signature)
}

fn process_sign_personal_message(
    state: &mut ServiceState,
    request: &SignPersonalMessageRequest,
) -> Result<Signature, EthAppError> {
    // Validate path
    if !request.path.is_valid_ethereum_path() {
        return Err(EthAppError::InvalidDerivationPath);
    }

    // Validate message size
    if request.message.is_empty() || request.message.len() > 65536 {
        return Err(EthAppError::InvalidMessage);
    }

    // Display message for confirmation
    if !ui::display_personal_message(&state.platform, &request.message)? {
        state.record_sign_rejected();
        return Err(EthAppError::RejectedByUser);
    }

    // Get seed and derive key; sign in a tight scope so the signing key
    // is dropped (and zeroized via k256's ZeroizeOnDrop) immediately after use.
    let signature = {
        let seed = get_seed(state)?;
        let signing_key = derive_private_key(&seed, &request.path)?;
        sign_personal_message(&signing_key, &request.message)?
        // signing_key and seed dropped here, secret material zeroized
    };

    state.platform.show_info(true, "Message signed");

    Ok(signature)
}

/// Handle SignEip712Hashed request.
#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
pub fn handle_sign_eip712_hashed(
    state: &mut ServiceState,
    mut msg: xous::MessageEnvelope,
) -> Result<(), EthAppError> {
    use xous_ipc::Buffer;

    // Create buffer first so we can write an error code back to the client.
    let mut buffer = unsafe {
        Buffer::from_memory_message_mut(
            msg.body.memory_message_mut().ok_or(EthAppError::InvalidData)?,
        )
    };

    if !state.config.blind_signing_enabled {
        write_error_response(&mut buffer, EthAppError::BlindSigningDisabled);
        return Ok(());
    }

    let request: SignEip712HashedRequest = buffer
        .to_original()
        .map_err(|_| EthAppError::SerializationError)?;

    match process_sign_eip712_hashed(state, &request) {
        Ok(signature) => {
            buffer.replace(signature).map_err(|_| EthAppError::InternalError)?;
            state.record_sign_success();
        }
        Err(e) => write_error_response(&mut buffer, e),
    }
    Ok(())
}

#[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
pub fn handle_sign_eip712_hashed(
    state: &mut ServiceState,
    request: &SignEip712HashedRequest,
) -> Result<Signature, EthAppError> {
    if !state.config.blind_signing_enabled {
        return Err(EthAppError::BlindSigningDisabled);
    }
    let signature = process_sign_eip712_hashed(state, request)?;
    state.record_sign_success();
    Ok(signature)
}

fn process_sign_eip712_hashed(
    state: &mut ServiceState,
    request: &SignEip712HashedRequest,
) -> Result<Signature, EthAppError> {
    // Validate path
    if !request.path.is_valid_ethereum_path() {
        return Err(EthAppError::InvalidDerivationPath);
    }

    // Display for confirmation (blind signing warning)
    if !ui::display_eip712_hashed(&state.platform, &request.domain_hash, &request.message_hash)? {
        state.record_sign_rejected();
        return Err(EthAppError::RejectedByUser);
    }

    // Get seed and derive key; sign in a tight scope so the signing key
    // is dropped (and zeroized via k256's ZeroizeOnDrop) immediately after use.
    let signature = {
        let seed = get_seed(state)?;
        let signing_key = derive_private_key(&seed, &request.path)?;
        sign_eip712(&signing_key, &request.domain_hash, &request.message_hash)?
        // signing_key and seed dropped here, secret material zeroized
    };

    state.platform.show_info(true, "Typed data signed");

    Ok(signature)
}

/// Handle SignEip712Message request.
#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
pub fn handle_sign_eip712_message(
    state: &mut ServiceState,
    mut msg: xous::MessageEnvelope,
) -> Result<(), EthAppError> {
    use xous_ipc::Buffer;

    let mut buffer = unsafe {
        Buffer::from_memory_message_mut(
            msg.body.memory_message_mut().ok_or(EthAppError::InvalidData)?,
        )
    };

    let request: SignEip712MessageRequest = buffer
        .to_original()
        .map_err(|_| EthAppError::SerializationError)?;

    match process_sign_eip712_message(state, &request) {
        Ok(signature) => {
            buffer.replace(signature).map_err(|_| EthAppError::InternalError)?;
            state.record_sign_success();
        }
        Err(e) => write_error_response(&mut buffer, e),
    }
    Ok(())
}

#[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
pub fn handle_sign_eip712_message(
    state: &mut ServiceState,
    request: &SignEip712MessageRequest,
) -> Result<Signature, EthAppError> {
    let signature = process_sign_eip712_message(state, request)?;
    state.record_sign_success();
    Ok(signature)
}

fn process_sign_eip712_message(
    state: &mut ServiceState,
    request: &SignEip712MessageRequest,
) -> Result<Signature, EthAppError> {
    // Validate path
    if !request.path.is_valid_ethereum_path() {
        return Err(EthAppError::InvalidDerivationPath);
    }

    // Validate typed data size
    if request.typed_data.is_empty() || request.typed_data.len() > 65536 {
        return Err(EthAppError::InvalidTypedData);
    }

    // Parse typed data - minimal implementation expects pre-computed hashes
    if request.typed_data.len() < 64 {
        return Err(EthAppError::InvalidTypedData);
    }

    let mut domain_hash = [0u8; 32];
    let mut message_hash = [0u8; 32];
    domain_hash.copy_from_slice(&request.typed_data[..32]);
    message_hash.copy_from_slice(&request.typed_data[32..64]);

    // Display for confirmation
    if !ui::display_eip712_message(&state.platform, &domain_hash, &message_hash)? {
        state.record_sign_rejected();
        return Err(EthAppError::RejectedByUser);
    }

    // Get seed and derive key; sign in a tight scope so the signing key
    // is dropped (and zeroized via k256's ZeroizeOnDrop) immediately after use.
    let signature = {
        let seed = get_seed(state)?;
        let signing_key = derive_private_key(&seed, &request.path)?;
        sign_eip712(&signing_key, &domain_hash, &message_hash)?
        // signing_key and seed dropped here, secret material zeroized
    };

    state.platform.show_info(true, "Typed data signed");

    Ok(signature)
}

// =============================================================================
// Metadata Handlers
// =============================================================================

/// Handle ProvideErc20TokenInfo request.
#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
pub fn handle_provide_erc20_token_info(
    state: &mut ServiceState,
    mut msg: xous::MessageEnvelope,
) -> Result<(), EthAppError> {
    use xous_ipc::Buffer;

    let mut buffer = unsafe {
        Buffer::from_memory_message_mut(
            msg.body.memory_message_mut().ok_or(EthAppError::InvalidData)?,
        )
    };

    let request: ProvideTokenInfoRequest = buffer
        .to_original()
        .map_err(|_| EthAppError::SerializationError)?;

    // Validate basic constraints
    if request.info.ticker.is_empty() || request.info.ticker.len() > 12 {
        return Err(EthAppError::InvalidParameter);
    }

    if request.info.decimals > 36 {
        return Err(EthAppError::InvalidParameter);
    }

    // SECURITY WARNING (CRITICAL-04): Metadata signature is NOT verified.
    // An attacker can provide arbitrary token info (fake ticker, wrong decimals)
    // which will be displayed to the user during transaction signing.
    // This can trick users into signing transactions that transfer different
    // amounts or different tokens than displayed.
    //
    // TODO: Implement signature verification against a trusted Ledger/provider
    // public key before accepting metadata. Until then, all cached metadata
    // is marked as unverified and displayed with an "[UNVERIFIED]" prefix.
    //
    // The `request.signature` field is present but currently ignored.
    // Verification should check: ECDSA(sha256(chain_id || address || ticker || decimals))
    // against a known trusted public key embedded at build time.

    log::warn!(
        "ethapp: Accepted UNVERIFIED token info for chain={}, ticker={}",
        request.info.chain_id,
        request.info.ticker
    );

    // Prefix ticker with [UNVERIFIED] to warn the user during display
    let mut unverified_info = request.info;
    let mut unverified_ticker = String::from("[UNVERIFIED] ");
    unverified_ticker.push_str(&unverified_info.ticker);
    unverified_info.ticker = unverified_ticker;

    state.cache_token_info(unverified_info);

    buffer.replace(1u8).map_err(|_| EthAppError::InternalError)?;
    Ok(())
}

#[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
pub fn handle_provide_erc20_token_info(
    state: &mut ServiceState,
    request: &ProvideTokenInfoRequest,
) -> Result<bool, EthAppError> {
    if request.info.ticker.is_empty() || request.info.ticker.len() > 12 {
        return Err(EthAppError::InvalidParameter);
    }
    if request.info.decimals > 36 {
        return Err(EthAppError::InvalidParameter);
    }

    // SECURITY WARNING (CRITICAL-04): Metadata signature NOT verified.
    // See Xous-target handler for full explanation.
    let mut unverified_info = request.info.clone();
    let mut unverified_ticker = String::from("[UNVERIFIED] ");
    unverified_ticker.push_str(&unverified_info.ticker);
    unverified_info.ticker = unverified_ticker;

    state.cache_token_info(unverified_info);
    Ok(true)
}

// Stub handlers for other metadata operations.
// These validate the incoming message format but return UnsupportedOperation
// since the actual metadata processing is not yet implemented.

#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
pub fn handle_provide_nft_info(
    _state: &mut ServiceState,
    mut msg: xous::MessageEnvelope,
) -> Result<(), EthAppError> {
    use ethapp_common::ProvideNftInfoRequest;
    use xous_ipc::Buffer;

    let mut buffer = unsafe {
        Buffer::from_memory_message_mut(
            msg.body.memory_message_mut().ok_or(EthAppError::InvalidData)?,
        )
    };

    let _request: ProvideNftInfoRequest = buffer
        .to_original()
        .map_err(|_| EthAppError::SerializationError)?;

    log::warn!("ethapp: handle_provide_nft_info called but not yet implemented");
    buffer.replace(0u8).map_err(|_| EthAppError::InternalError)?;
    Ok(())
}

#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
pub fn handle_provide_domain_name(
    _state: &mut ServiceState,
    mut msg: xous::MessageEnvelope,
) -> Result<(), EthAppError> {
    use ethapp_common::ProvideDomainNameRequest;
    use xous_ipc::Buffer;

    let mut buffer = unsafe {
        Buffer::from_memory_message_mut(
            msg.body.memory_message_mut().ok_or(EthAppError::InvalidData)?,
        )
    };

    let _request: ProvideDomainNameRequest = buffer
        .to_original()
        .map_err(|_| EthAppError::SerializationError)?;

    log::warn!("ethapp: handle_provide_domain_name called but not yet implemented");
    buffer.replace(0u8).map_err(|_| EthAppError::InternalError)?;
    Ok(())
}

#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
pub fn handle_load_contract_method_info(
    _state: &mut ServiceState,
    mut msg: xous::MessageEnvelope,
) -> Result<(), EthAppError> {
    use ethapp_common::ProvideMethodInfoRequest;
    use xous_ipc::Buffer;

    let mut buffer = unsafe {
        Buffer::from_memory_message_mut(
            msg.body.memory_message_mut().ok_or(EthAppError::InvalidData)?,
        )
    };

    let _request: ProvideMethodInfoRequest = buffer
        .to_original()
        .map_err(|_| EthAppError::SerializationError)?;

    log::warn!("ethapp: handle_load_contract_method_info called but not yet implemented");
    buffer.replace(0u8).map_err(|_| EthAppError::InternalError)?;
    Ok(())
}

/// Handle ByContractAddressAndChain request.
///
/// Receives a `MetadataContext` (chain_id + address) via memory message and
/// stores it as the current context for subsequent signing operations.
#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
pub fn handle_by_contract_address_and_chain(
    state: &mut ServiceState,
    mut msg: xous::MessageEnvelope,
) -> Result<(), EthAppError> {
    use xous_ipc::Buffer;

    let mut buffer = unsafe {
        Buffer::from_memory_message_mut(
            msg.body.memory_message_mut().ok_or(EthAppError::InvalidData)?,
        )
    };

    let context: MetadataContext = buffer
        .to_original()
        .map_err(|_| EthAppError::SerializationError)?;

    state.set_context(context.chain_id, context.address);
    buffer.replace(1u8).map_err(|_| EthAppError::InternalError)?;
    Ok(())
}

// =============================================================================
// Key Operation Handlers
// =============================================================================

/// Handle GetPublicKey request.
#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
pub fn handle_get_public_key(
    state: &mut ServiceState,
    mut msg: xous::MessageEnvelope,
) -> Result<(), EthAppError> {
    use xous_ipc::Buffer;

    let mut buffer = unsafe {
        Buffer::from_memory_message_mut(
            msg.body.memory_message_mut().ok_or(EthAppError::InvalidData)?,
        )
    };

    let path: Bip32Path = buffer
        .to_original()
        .map_err(|_| EthAppError::SerializationError)?;

    match process_get_public_key(state, &path) {
        Ok(response) => buffer.replace(response).map_err(|_| EthAppError::InternalError)?,
        Err(e) => write_error_response(&mut buffer, e),
    }
    Ok(())
}

#[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
pub fn handle_get_public_key(
    state: &mut ServiceState,
    path: &Bip32Path,
) -> Result<PublicKeyResponse, EthAppError> {
    process_get_public_key(state, path)
}

fn process_get_public_key(state: &ServiceState, path: &Bip32Path) -> Result<PublicKeyResponse, EthAppError> {
    if !path.is_valid_ethereum_path() {
        return Err(EthAppError::InvalidDerivationPath);
    }

    // Derive key in a scope to ensure prompt zeroization of secret material.
    let (pubkey, address) = {
        let seed = get_seed(state)?;
        let signing_key = derive_private_key(&seed, path)?;
        let pk = get_compressed_pubkey(&signing_key);
        let addr = public_key_to_address(&get_public_key(&signing_key));
        (pk, addr)
        // signing_key and seed dropped here, secret material zeroized
    };

    Ok(PublicKeyResponse { pubkey, address })
}

/// Handle GetAddress request.
#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
pub fn handle_get_address(
    state: &mut ServiceState,
    mut msg: xous::MessageEnvelope,
) -> Result<(), EthAppError> {
    use xous_ipc::Buffer;

    let mut buffer = unsafe {
        Buffer::from_memory_message_mut(
            msg.body.memory_message_mut().ok_or(EthAppError::InvalidData)?,
        )
    };

    let path: Bip32Path = buffer
        .to_original()
        .map_err(|_| EthAppError::SerializationError)?;

    match process_get_public_key(state, &path) {
        Ok(response) => buffer.replace(response.address).map_err(|_| EthAppError::InternalError)?,
        Err(e) => write_error_response(&mut buffer, e),
    }
    Ok(())
}

#[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
pub fn handle_get_address(
    state: &mut ServiceState,
    path: &Bip32Path,
) -> Result<[u8; 20], EthAppError> {
    let response = process_get_public_key(state, path)?;
    Ok(response.address)
}

// =============================================================================
// Statistics Handler
// =============================================================================

#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
pub fn handle_get_stats(
    state: &mut ServiceState,
    mut msg: xous::MessageEnvelope,
) -> Result<(), EthAppError> {
    let stats = state.get_stats();

    // Return stats as scalar values
    xous::return_scalar2(
        msg.sender,
        stats.signs_completed as usize,
        stats.signs_rejected as usize,
    ).map_err(|_| EthAppError::InternalError)
}

#[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
pub fn handle_get_stats(
    state: &mut ServiceState,
    _msg: (),
) -> Result<(u64, u64, u64), EthAppError> {
    let stats = state.get_stats();
    Ok((stats.signs_completed, stats.signs_rejected, stats.errors))
}

// =============================================================================
// Seed Management Handlers
// =============================================================================

/// Handle SetSeed request — import a 64-byte seed at runtime.
#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
pub fn handle_set_seed(
    state: &mut ServiceState,
    mut msg: xous::MessageEnvelope,
) -> Result<(), EthAppError> {
    use xous_ipc::Buffer;

    let buffer = unsafe {
        Buffer::from_memory_message_mut(
            msg.body.memory_message_mut().ok_or(EthAppError::InvalidData)?,
        )
    };

    let seed_bytes: [u8; 64] = buffer
        .to_original()
        .map_err(|_| EthAppError::SerializationError)?;

    state.imported_seed = Some(crate::crypto::Seed::from_bytes(&seed_bytes));
    log::info!("ethapp: Seed imported (64 bytes)");

    Ok(())
}

#[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
pub fn handle_set_seed(
    state: &mut ServiceState,
    seed_bytes: &[u8; 64],
) -> Result<(), EthAppError> {
    state.imported_seed = Some(crate::crypto::Seed::from_bytes(seed_bytes));
    Ok(())
}

/// Handle ImportMnemonic request — derive seed from BIP39 mnemonic via PBKDF2.
#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
pub fn handle_import_mnemonic(
    state: &mut ServiceState,
    mut msg: xous::MessageEnvelope,
) -> Result<(), EthAppError> {
    use xous_ipc::Buffer;
    use ethapp_common::MnemonicImport;

    let buffer = unsafe {
        Buffer::from_memory_message_mut(
            msg.body.memory_message_mut().ok_or(EthAppError::InvalidData)?,
        )
    };

    let import: MnemonicImport = buffer
        .to_original()
        .map_err(|_| EthAppError::SerializationError)?;

    let mnemonic_bytes = import.as_bytes();
    if mnemonic_bytes.is_empty() {
        return Err(EthAppError::InvalidData);
    }

    let seed = crate::crypto::seed_from_mnemonic(mnemonic_bytes);
    state.imported_seed = Some(seed);
    log::info!("ethapp: Seed derived from mnemonic ({} bytes)", mnemonic_bytes.len());

    Ok(())
}

#[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
pub fn handle_import_mnemonic(
    state: &mut ServiceState,
    mnemonic: &str,
) -> Result<(), EthAppError> {
    let seed = crate::crypto::seed_from_mnemonic(mnemonic.as_bytes());
    state.imported_seed = Some(seed);
    Ok(())
}
