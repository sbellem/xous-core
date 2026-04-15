//! Transaction and message parsing for the Ethereum app.
//!
//! This module provides:
//! - RLP (Recursive Length Prefix) decoding (re-exported from ethapp-common)
//! - Transaction parsing (legacy, EIP-2930, EIP-1559)
//! - EIP-712 typed data parsing
//!
//! # Security
//!
//! All parsing happens on untrusted input. Parsers must:
//! - Validate all length fields before access
//! - Fail closed on any malformed data
//! - Avoid unbounded allocations

/// Re-export RLP module from ethapp-common.
pub use ethapp_common::rlp;

pub mod transaction;

pub use transaction::{ParsedTransaction, TransactionParser, TxParseError};
