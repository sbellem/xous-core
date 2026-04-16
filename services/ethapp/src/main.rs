//! Xous Native Ethereum App Service
//!
//! This service provides secure Ethereum transaction and message signing
//! for Baochip-1x hardware running Xous OS.
//!
//! # Architecture
//!
//! The service runs as a standard Xous server:
//! 1. Registers with xous-names as "ethapp.ethereum"
//! 2. Receives messages via `xous::receive_message()`
//! 3. Dispatches to handlers based on opcode
//! 4. Returns responses via scalar or memory messages
//!
//! # Security Model
//!
//! - All cryptographic operations use constant-time implementations
//! - Private keys never leave service memory
//! - User confirmation required for all signing operations
//! - Fail closed on any validation error
//!
//! # Docs consulted
//!
//! - Xous Book: Server patterns, message passing
//! - Vanadium docs/security.md: Security invariants
//! - EIP-155, EIP-191, EIP-712: Ethereum standards

#[allow(dead_code)]
mod crypto;
#[allow(dead_code)]
mod handlers;
#[allow(dead_code)]
mod parsing;
#[allow(dead_code)]
mod platform;
#[allow(dead_code)]
mod state;
#[allow(dead_code)]
mod serial;
#[allow(dead_code)]
mod ui;

use ethapp_common::{EthAppError, EthAppOp, SERVER_NAME};
use num_traits::FromPrimitive;

fn main() -> ! {
    service_main();
    panic!("ethapp: service_main returned unexpectedly");
}

/// The actual service loop, shared between native and hosted builds.
fn service_main() {
    log_server::init_wait().unwrap();
    log::info!("ethapp: Starting Ethereum App service");

    let xns = xous_names::XousNames::new().expect("ethapp: Failed to connect to xous-names");

    let sid = xns
        .register_name(SERVER_NAME, None)
        .expect("ethapp: Failed to register server name");

    log::info!("ethapp: Registered as '{}'", SERVER_NAME);

    let mut state = state::ServiceState::new();

    if let Err(e) = state.init_platform() {
        log::error!("ethapp: Failed to initialize platform: {:?}", e);
    }

    log::info!("ethapp: Service initialized, entering message loop");

    loop {
        let msg = xous::receive_message(sid).expect("ethapp: Failed to receive message");

        let opcode = EthAppOp::from_usize(msg.body.id());

        match opcode {
            Some(op) => {
                let result = handle_message(&mut state, op, msg);
                if let Err(e) = result {
                    log::warn!("ethapp: Handler error for {:?}: {:?}", op, e);
                }
            }
            None => {
                log::warn!("ethapp: Unknown opcode: {}", msg.body.id());
            }
        }
    }
}

/// Dispatch a message to the appropriate handler.
fn handle_message(
    state: &mut state::ServiceState,
    op: EthAppOp,
    msg: xous::MessageEnvelope,
) -> Result<(), EthAppError> {
    use xous::Message;

    match op {
        // === Configuration Commands ===
        EthAppOp::GetAppConfiguration => {
            handlers::handle_get_app_configuration(state, msg)?;
        }
        EthAppOp::GetChallenge => {
            handlers::handle_get_challenge(state, msg)?;
        }
        EthAppOp::Ping => {
            if let Message::Scalar(s) = &msg.body {
                xous::return_scalar(msg.sender, s.arg1).ok();
            }
        }
        EthAppOp::Exit => {
            log::info!("ethapp: Received exit command");
            #[cfg(feature = "dev-mode")]
            {
                xous::terminate_process(0);
            }
        }

        // === Transaction Signing ===
        EthAppOp::SignTransaction => {
            handlers::handle_sign_transaction(state, msg)?;
        }
        EthAppOp::ClearSignTransaction => {
            handlers::handle_clear_sign_transaction(state, msg)?;
        }

        // === Message Signing ===
        EthAppOp::SignPersonalMessage => {
            handlers::handle_sign_personal_message(state, msg)?;
        }
        EthAppOp::SignEip712Hashed => {
            handlers::handle_sign_eip712_hashed(state, msg)?;
        }
        EthAppOp::SignEip712Message => {
            handlers::handle_sign_eip712_message(state, msg)?;
        }

        // === Metadata Provision ===
        EthAppOp::ProvideErc20TokenInfo => {
            handlers::handle_provide_erc20_token_info(state, msg)?;
        }
        EthAppOp::ProvideNftInfo => {
            handlers::handle_provide_nft_info(state, msg)?;
        }
        EthAppOp::ProvideDomainName => {
            handlers::handle_provide_domain_name(state, msg)?;
        }
        EthAppOp::LoadContractMethodInfo => {
            handlers::handle_load_contract_method_info(state, msg)?;
        }
        EthAppOp::ByContractAddressAndChain => {
            handlers::handle_by_contract_address_and_chain(state, msg)?;
        }

        // === Key Operations ===
        EthAppOp::GetPublicKey => {
            handlers::handle_get_public_key(state, msg)?;
        }
        EthAppOp::GetAddress => {
            handlers::handle_get_address(state, msg)?;
        }

        // === Seed Management ===
        EthAppOp::SetSeed => {
            handlers::handle_set_seed(state, msg)?;
        }
        EthAppOp::ImportMnemonic => {
            handlers::handle_import_mnemonic(state, msg)?;
        }
        EthAppOp::GenerateMnemonic => {
            handlers::handle_generate_mnemonic(state, msg)?;
        }
        EthAppOp::ClearSeed => {
            handlers::handle_clear_seed(state, msg)?;
        }

        // === Serial Transport ===
        EthAppOp::SerialFrame => {
            handlers::handle_serial_frame(state, msg)?;
        }

        // === Eth2 (placeholder) ===
        EthAppOp::Eth2GetPublicKey | EthAppOp::Eth2SetWithdrawalIndex => {
            handlers::return_error(msg, EthAppError::UnsupportedOperation)?;
        }

        // === Internal ===
        EthAppOp::ClearMetadataCache => {
            state.clear_metadata_cache();
            handlers::return_success(msg)?;
        }
        EthAppOp::GetStats => {
            handlers::handle_get_stats(state, msg)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opcode_parsing() {
        assert_eq!(EthAppOp::from_usize(0x01), Some(EthAppOp::GetAppConfiguration));
        assert_eq!(EthAppOp::from_usize(0x10), Some(EthAppOp::SignTransaction));
        assert_eq!(EthAppOp::from_usize(0xFF), Some(EthAppOp::Ping));
        assert_eq!(EthAppOp::from_usize(0x1234), None);
    }
}
