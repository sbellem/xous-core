//! Common types for the Xous Ethereum App.
//!
//! This crate provides shared types used by both the ethapp service
//! and client libraries. All types are designed to be serializable
//! with rkyv for efficient Xous IPC.
//!
//! # Security Note
//!
//! These types cross trust boundaries. All validation must happen
//! in the ethapp service after deserialization.

#![no_std]

extern crate alloc;

pub mod error;
pub mod opcodes;
pub mod rlp;
pub mod types;

pub use error::EthAppError;
pub use opcodes::{ChunkFlags, EthAppOp};
pub use types::*;

/// Protocol version for compatibility checks.
pub const PROTOCOL_VERSION: u32 = 1;

/// Server name for Xous name registration.
pub const SERVER_NAME: &str = "ethapp.ethereum";

/// Maximum connections allowed to this service.
/// Set to None for unlimited, or Some(n) for restricted access.
pub const MAX_CONNECTIONS: Option<u32> = None;
