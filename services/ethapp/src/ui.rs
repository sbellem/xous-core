//! User interface functions for the ethapp service.
//!
//! This module provides UI primitives for:
//! - Transaction review screens
//! - Message signing confirmation
//! - EIP-712 typed data display
//! - Status notifications
//!
//! # Security
//!
//! All signing operations MUST show a confirmation screen.
//! The user MUST see what they are signing.

use std::string::String;
use std::vec::Vec;

use ethapp_common::{EthAddress, EthAppError, Hash256, TokenInfo, TransactionType};
use crate::crypto::format_address_checksummed;
use crate::parsing::ParsedTransaction;
use crate::platform::Platform;

// =============================================================================
// ERC-20 calldata decoding
// =============================================================================

/// ERC-20 transfer(address,uint256) selector.
const TRANSFER_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
/// ERC-20 approve(address,uint256) selector.
const APPROVE_SELECTOR: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3];

/// Decoded ERC-20 call information.
struct Erc20CallInfo {
    /// Method name for display.
    method: &'static str,
    /// Recipient (transfer) or spender (approve) address.
    target: EthAddress,
    /// Raw uint256 amount (32 bytes, big-endian).
    amount: [u8; 32],
}

/// Try to decode transaction data as an ERC-20 transfer() or approve() call.
///
/// Returns None if the data doesn't match the expected format:
/// - Exactly 68 bytes (4 selector + 32 address + 32 amount)
/// - Known selector
/// - Address argument has 12 zero-padding bytes
fn try_decode_erc20(data: &[u8]) -> Option<Erc20CallInfo> {
    if data.len() != 68 {
        return None;
    }

    let method = if data[..4] == TRANSFER_SELECTOR {
        "Transfer"
    } else if data[..4] == APPROVE_SELECTOR {
        "Approve"
    } else {
        return None;
    };

    // Validate that the address argument has 12 zero-padding bytes
    if data[4..16] != [0u8; 12] {
        return None;
    }

    let mut target = [0u8; 20];
    target.copy_from_slice(&data[16..36]);

    let mut amount = [0u8; 32];
    amount.copy_from_slice(&data[36..68]);

    Some(Erc20CallInfo { method, target, amount })
}

/// Display a transaction for user review.
///
/// Shows all relevant transaction fields and waits for user approval.
/// When `token_info` is provided and the calldata matches a known ERC-20
/// method, displays a human-readable clear-signed view.
///
/// # Arguments
/// * `platform` - Platform abstraction for UI
/// * `tx` - Parsed transaction to display
/// * `_clear_sign` - Whether this is a clear signing request
/// * `token_info` - Optional cached token metadata for display
///
/// # Returns
/// - `Ok(true)` if user approved
/// - `Ok(false)` if user rejected
/// - `Err` on UI error
pub fn display_transaction<P: Platform>(
    platform: &P,
    tx: &ParsedTransaction,
    _clear_sign: bool,
    token_info: Option<&TokenInfo>,
) -> Result<bool, EthAppError> {
    // Auto-approve for testing
    #[cfg(feature = "autoapprove")]
    {
        return Ok(true);
    }

    #[cfg(not(feature = "autoapprove"))]
    {
        let gas_str = format!("{}", tx.gas_limit);
        let gas_price_str = format_gas_price(&tx.gas_price);

        let chain_str = tx
            .chain_id
            .map(|c| format!("{}", c))
            .unwrap_or_else(|| String::from("(none)"));

        // Try clear signing for ERC-20 calls
        let mut fields: Vec<(&str, String)> = if let Some(erc20) = try_decode_erc20(&tx.data) {
            let (ticker, decimals) = match token_info {
                Some(ti) => (ti.ticker.as_str(), ti.decimals),
                None => ("???", 18),
            };

            let amount_str = format_token_amount(&erc20.amount, decimals, ticker);

            let target_checksummed = format_address_checksummed(&erc20.target);
            let target_str = String::from_utf8_lossy(&target_checksummed).into_owned();

            let contract_str = match &tx.to {
                Some(addr) => {
                    let checksummed = format_address_checksummed(addr);
                    String::from_utf8_lossy(&checksummed).into_owned()
                }
                None => String::from("(unknown)"),
            };

            let target_label = if erc20.method == "Transfer" { "To" } else { "Spender" };

            vec![
                ("Type", format!("ERC-20 {}", erc20.method)),
                ("Chain ID", chain_str),
                ("Token", contract_str),
                (target_label, target_str),
                ("Amount", amount_str),
                ("Gas Limit", gas_str),
                ("Gas Price", gas_price_str),
            ]
        } else {
            // Standard transaction display
            let tx_type_str = match tx.tx_type {
                TransactionType::Legacy => "Legacy",
                TransactionType::AccessList => "EIP-2930",
                TransactionType::FeeMarket => "EIP-1559",
            };

            let recipient = match &tx.to {
                Some(addr) => {
                    let checksummed = format_address_checksummed(addr);
                    String::from_utf8_lossy(&checksummed).into_owned()
                }
                None => String::from("Contract Creation"),
            };

            let value_str = format_eth_amount(&tx.value);

            let data_str = if tx.data.is_empty() {
                String::from("(none)")
            } else if tx.data.len() > 32 {
                format!("{} bytes", tx.data.len())
            } else {
                hex::encode(&tx.data)
            };

            vec![
                ("Type", tx_type_str.to_string()),
                ("Chain ID", chain_str),
                ("To", recipient),
                ("Value", value_str),
                ("Gas Limit", gas_str),
                ("Gas Price", gas_price_str),
                ("Data", data_str),
            ]
        };

        // Add max priority fee for EIP-1559
        if let Some(priority_fee) = &tx.max_priority_fee {
            fields.push(("Priority Fee", format_gas_price(priority_fee)));
        }

        let field_refs: Vec<(&str, &str)> = fields
            .iter()
            .map(|(k, v): &(&str, String)| (*k, v.as_str()))
            .collect();

        platform.show_transaction_review(&field_refs, "Sign transaction")
    }
}

/// Display a personal message for signing confirmation.
///
/// # Display Rules
/// - Printable ASCII: show as text
/// - Non-printable: show as hex with warning
/// - Long messages: truncate with "..."
pub fn display_personal_message<P: Platform>(
    platform: &P,
    message: &[u8],
) -> Result<bool, EthAppError> {
    #[cfg(feature = "autoapprove")]
    {
        return Ok(true);
    }

    #[cfg(not(feature = "autoapprove"))]
    {
        let (message_display, is_hex) = if is_printable_ascii(message) {
            let text = core::str::from_utf8(message).unwrap_or("<invalid UTF-8>");
            (truncate_for_display(text, 200), false)
        } else {
            let hex = hex::encode(message);
            (truncate_for_display(&hex, 200), true)
        };

        let title = if is_hex {
            "Sign message (hex data)"
        } else {
            "Sign message"
        };

        let length_str = format!("{} bytes", message.len());

        let fields = vec![
            ("Message", message_display.as_str()),
            ("Length", length_str.as_str()),
        ];

        platform.show_transaction_review(&fields, title)
    }
}

/// Display EIP-712 hashed data for signing (blind signing).
pub fn display_eip712_hashed<P: Platform>(
    platform: &P,
    domain_hash: &Hash256,
    message_hash: &Hash256,
) -> Result<bool, EthAppError> {
    #[cfg(feature = "autoapprove")]
    {
        return Ok(true);
    }

    #[cfg(not(feature = "autoapprove"))]
    {
        let domain_str = hex::encode(domain_hash);
        let message_str = hex::encode(message_hash);

        let fields = vec![
            ("Domain hash", domain_str.as_str()),
            ("Message hash", message_str.as_str()),
        ];

        platform.show_transaction_review(&fields, "Sign EIP-712 (blind signing)")
    }
}

/// Display EIP-712 message for signing.
pub fn display_eip712_message<P: Platform>(
    platform: &P,
    domain_hash: &Hash256,
    message_hash: &Hash256,
) -> Result<bool, EthAppError> {
    #[cfg(feature = "autoapprove")]
    {
        return Ok(true);
    }

    #[cfg(not(feature = "autoapprove"))]
    {
        // For minimal implementation, show abbreviated hashes
        let domain_str = format!("{}...", hex::encode(&domain_hash[..8]));
        let message_str = format!("{}...", hex::encode(&message_hash[..8]));

        let fields = vec![
            ("Domain", domain_str.as_str()),
            ("Message", message_str.as_str()),
        ];

        platform.show_transaction_review(&fields, "Sign EIP-712 typed data")
    }
}

// =============================================================================
// Formatting Helpers
// =============================================================================

/// Formats a 256-bit value as ETH with decimals.
fn format_eth_amount(value: &[u8; 32]) -> String {
    format_token_amount(value, 18, "ETH")
}

/// Formats gas price in Gwei.
fn format_gas_price(value: &[u8; 32]) -> String {
    format_token_amount(value, 9, "Gwei")
}

/// Formats a 256-bit value with token decimals.
fn format_token_amount(value: &[u8; 32], decimals: u8, ticker: &str) -> String {
    // Check if value fits in u128
    let mut is_small = true;
    for &byte in &value[..16] {
        if byte != 0 {
            is_small = false;
            break;
        }
    }

    if is_small {
        let mut n: u128 = 0;
        for &byte in &value[16..] {
            n = n << 8 | byte as u128;
        }

        let formatted = format_u128_with_decimals(n, decimals);
        format!("{} {}", formatted, ticker)
    } else {
        // Large value - show hex
        let hex = hex::encode(value);
        let trimmed = hex.trim_start_matches('0');
        if trimmed.is_empty() {
            format!("0 {}", ticker)
        } else {
            format!("0x{} {}", trimmed, ticker)
        }
    }
}

/// Formats a u128 value with decimal places.
fn format_u128_with_decimals(value: u128, decimals: u8) -> String {
    if decimals == 0 {
        return format!("{}", value);
    }

    let divisor = 10u128.pow(decimals as u32);
    let whole = value / divisor;
    let frac = value % divisor;

    if frac == 0 {
        format!("{}", whole)
    } else {
        let frac_str = format!("{:0width$}", frac, width = decimals as usize);
        let trimmed = frac_str.trim_end_matches('0');
        format!("{}.{}", whole, trimmed)
    }
}

/// Checks if a byte slice contains only printable ASCII.
fn is_printable_ascii(data: &[u8]) -> bool {
    data.iter().all(|&b| b >= 0x20 && b < 0x7F)
}

/// Truncates a string for display, adding ellipsis if needed.
fn truncate_for_display(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        return String::from(s);
    }

    let mut result = String::with_capacity(max_len + 3);
    result.push_str(&s[..max_len]);
    result.push_str("...");
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_eth_amount() {
        // 1 ETH = 10^18 wei
        let mut one_eth = [0u8; 32];
        one_eth[24..].copy_from_slice(&[0x0d, 0xe0, 0xb6, 0xb3, 0xa7, 0x64, 0x00, 0x00]);
        let formatted = format_eth_amount(&one_eth);
        assert_eq!(formatted, "1 ETH");

        // 0 ETH
        let zero = [0u8; 32];
        let formatted = format_eth_amount(&zero);
        assert_eq!(formatted, "0 ETH");
    }

    #[test]
    fn test_format_with_decimals() {
        // 1.5 with 6 decimals
        let result = format_u128_with_decimals(1_500_000, 6);
        assert_eq!(result, "1.5");

        // 1.0 with 18 decimals
        let result = format_u128_with_decimals(1_000_000_000_000_000_000, 18);
        assert_eq!(result, "1");

        // 0.001 with 18 decimals
        let result = format_u128_with_decimals(1_000_000_000_000_000, 18);
        assert_eq!(result, "0.001");
    }

    #[test]
    fn test_is_printable_ascii() {
        assert!(is_printable_ascii(b"Hello, World!"));
        assert!(!is_printable_ascii(b"Hello\x00World"));
        assert!(!is_printable_ascii(b"\xff\xfe"));
    }

    #[test]
    fn test_truncate_for_display() {
        assert_eq!(truncate_for_display("short", 10), "short");
        assert_eq!(truncate_for_display("this is a long string", 10), "this is a ...");
    }

    // =========================================================================
    // ERC-20 calldata decoding tests
    // =========================================================================

    #[test]
    fn test_decode_erc20_transfer() {
        let recipient = [0xde; 20];
        let mut data = Vec::new();
        data.extend_from_slice(&TRANSFER_SELECTOR);
        data.extend_from_slice(&[0u8; 12]); // padding
        data.extend_from_slice(&recipient);
        data.extend_from_slice(&[0u8; 16]); // upper amount
        data.extend_from_slice(&1_000_000u128.to_be_bytes()); // lower amount

        let info = try_decode_erc20(&data).unwrap();
        assert_eq!(info.method, "Transfer");
        assert_eq!(info.target, recipient);
    }

    #[test]
    fn test_decode_erc20_approve() {
        let spender = [0xab; 20];
        let mut data = Vec::new();
        data.extend_from_slice(&APPROVE_SELECTOR);
        data.extend_from_slice(&[0u8; 12]);
        data.extend_from_slice(&spender);
        data.extend_from_slice(&[0xff; 32]); // max approval

        let info = try_decode_erc20(&data).unwrap();
        assert_eq!(info.method, "Approve");
        assert_eq!(info.target, spender);
    }

    #[test]
    fn test_decode_erc20_wrong_length() {
        assert!(try_decode_erc20(&[0xa9, 0x05, 0x9c, 0xbb]).is_none());
        assert!(try_decode_erc20(&[0; 100]).is_none());
        assert!(try_decode_erc20(&[]).is_none());
    }

    #[test]
    fn test_decode_erc20_unknown_selector() {
        let mut data = [0u8; 68];
        data[0..4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        assert!(try_decode_erc20(&data).is_none());
    }

    #[test]
    fn test_decode_erc20_nonzero_padding() {
        let mut data = Vec::new();
        data.extend_from_slice(&TRANSFER_SELECTOR);
        data.extend_from_slice(&[0u8; 11]);
        data.push(0x01); // non-zero padding byte
        data.extend_from_slice(&[0xde; 20]);
        data.extend_from_slice(&[0u8; 32]);

        assert!(try_decode_erc20(&data).is_none());
    }
}
