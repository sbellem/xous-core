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

use ethapp_common::{EthAppError, Hash256, TransactionType};
use crate::crypto::format_address_checksummed;
use crate::parsing::ParsedTransaction;
use crate::platform::Platform;

/// Display a transaction for user review.
///
/// Shows all relevant transaction fields and waits for user approval.
///
/// # Arguments
/// * `platform` - Platform abstraction for UI
/// * `tx` - Parsed transaction to display
/// * `clear_sign` - Whether this is a clear signing request
///
/// # Returns
/// - `Ok(true)` if user approved
/// - `Ok(false)` if user rejected
/// - `Err` on UI error
pub fn display_transaction<P: Platform>(
    platform: &P,
    tx: &ParsedTransaction,
    _clear_sign: bool,
) -> Result<bool, EthAppError> {
    // Auto-approve for testing
    #[cfg(feature = "autoapprove")]
    {
        return Ok(true);
    }

    #[cfg(not(feature = "autoapprove"))]
    {
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
        let gas_str = format!("{}", tx.gas_limit);
        let gas_price_str = format_gas_price(&tx.gas_price);

        let data_str = if tx.data.is_empty() {
            String::from("(none)")
        } else if tx.data.len() > 32 {
            format!("{} bytes", tx.data.len())
        } else {
            hex::encode(&tx.data)
        };

        let chain_str = tx
            .chain_id
            .map(|c| format!("{}", c))
            .unwrap_or_else(|| String::from("(none)"));

        let mut fields: Vec<(&str, String)> = vec![
            ("Type", tx_type_str.to_string()),
            ("Chain ID", chain_str),
            ("To", recipient),
            ("Value", value_str),
            ("Gas Limit", gas_str),
            ("Gas Price", gas_price_str),
            ("Data", data_str),
        ];

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
}
