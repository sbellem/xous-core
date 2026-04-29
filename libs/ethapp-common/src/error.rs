//! Error types for the Xous Ethereum App.
//!
//! Error codes are kept minimal to avoid leaking security-relevant
//! information to potentially malicious callers.

use core::fmt;
use num_derive::{FromPrimitive, ToPrimitive};
use rkyv::{Archive, Deserialize, Serialize};

/// Error codes for the Ethereum App.
///
/// Each variant maps to a specific error condition.
/// Messages are intentionally terse to avoid information leakage.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Archive, Serialize, Deserialize, FromPrimitive, ToPrimitive,
)]
#[repr(u32)]
pub enum EthAppError {
    /// Operation completed successfully (not an error).
    Success = 0x00,

    /// User rejected the operation on the device.
    RejectedByUser = 0x01,

    /// Unknown or unsupported opcode.
    InvalidOpcode = 0x02,

    /// Invalid parameter in the request.
    InvalidParameter = 0x03,

    /// Malformed data in the request payload.
    InvalidData = 0x04,

    /// Signature verification failed.
    InvalidSignature = 0x05,

    /// Security policy violation.
    SecurityViolation = 0x06,

    /// Operation not supported by this build.
    UnsupportedOperation = 0x07,

    /// Internal error in the service.
    InternalError = 0x08,

    /// Operation timed out.
    Timeout = 0x09,

    /// Blind signing is disabled but required.
    BlindSigningDisabled = 0x0A,

    /// Required metadata not found in cache.
    MetadataNotFound = 0x0B,

    /// Invalid BIP32/44 derivation path.
    InvalidDerivationPath = 0x0C,

    /// Key derivation failed.
    KeyDerivationFailed = 0x0D,

    /// Signing operation failed.
    SigningFailed = 0x0E,

    /// Invalid transaction format.
    InvalidTransaction = 0x0F,

    /// Invalid RLP encoding.
    InvalidRlp = 0x10,

    /// Invalid message format.
    InvalidMessage = 0x11,

    /// Invalid EIP-712 typed data.
    InvalidTypedData = 0x12,

    /// Invalid state machine transition.
    InvalidState = 0x13,

    /// Chunked transfer error.
    ChunkError = 0x14,

    /// Buffer overflow or size limit exceeded.
    BufferOverflow = 0x15,

    /// Connection to required service failed.
    ServiceConnectionFailed = 0x16,

    /// IPC serialization/deserialization error.
    SerializationError = 0x17,

    /// Storage (PDDB) operation failed.
    StorageError = 0x18,

    /// UI/GAM operation failed.
    UiError = 0x19,

    /// Cryptographic operation failed.
    CryptoError = 0x1A,

    /// Attestation key already exists (use overwrite to replace).
    AttestationKeyExists = 0x1B,

    /// Attestation key not initialized.
    AttestationNotInitialized = 0x1C,

    /// Import key already exists (use overwrite to replace).
    ImportKeyExists = 0x1D,

    /// Import key not initialized.
    ImportKeyNotInitialized = 0x1E,

    /// Decryption or authentication tag verification failed.
    DecryptionFailed = 0x1F,
}

impl EthAppError {
    /// Returns the error code as a u32 for scalar responses.
    #[inline]
    pub fn code(self) -> u32 {
        self as u32
    }

    /// Returns true if this represents success.
    #[inline]
    pub fn is_success(self) -> bool {
        matches!(self, EthAppError::Success)
    }

    /// Returns true if this is a user-initiated rejection.
    #[inline]
    pub fn is_user_rejection(self) -> bool {
        matches!(self, EthAppError::RejectedByUser)
    }

    /// Returns true if this is a security-related error.
    #[inline]
    pub fn is_security_error(self) -> bool {
        matches!(
            self,
            EthAppError::InvalidSignature
                | EthAppError::SecurityViolation
                | EthAppError::BlindSigningDisabled
                | EthAppError::InvalidDerivationPath
        )
    }
}

impl Default for EthAppError {
    fn default() -> Self {
        EthAppError::Success
    }
}

impl fmt::Display for EthAppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Intentionally terse messages to avoid information leakage
        match self {
            EthAppError::Success => write!(f, "Success"),
            EthAppError::RejectedByUser => write!(f, "Rejected by user"),
            EthAppError::InvalidOpcode => write!(f, "Invalid opcode"),
            EthAppError::InvalidParameter => write!(f, "Invalid parameter"),
            EthAppError::InvalidData => write!(f, "Invalid data"),
            EthAppError::InvalidSignature => write!(f, "Invalid signature"),
            EthAppError::SecurityViolation => write!(f, "Security violation"),
            EthAppError::UnsupportedOperation => write!(f, "Unsupported operation"),
            EthAppError::InternalError => write!(f, "Internal error"),
            EthAppError::Timeout => write!(f, "Timeout"),
            EthAppError::BlindSigningDisabled => write!(f, "Blind signing disabled"),
            EthAppError::MetadataNotFound => write!(f, "Metadata not found"),
            EthAppError::InvalidDerivationPath => write!(f, "Invalid derivation path"),
            EthAppError::KeyDerivationFailed => write!(f, "Key derivation failed"),
            EthAppError::SigningFailed => write!(f, "Signing failed"),
            EthAppError::InvalidTransaction => write!(f, "Invalid transaction"),
            EthAppError::InvalidRlp => write!(f, "Invalid RLP"),
            EthAppError::InvalidMessage => write!(f, "Invalid message"),
            EthAppError::InvalidTypedData => write!(f, "Invalid typed data"),
            EthAppError::InvalidState => write!(f, "Invalid state"),
            EthAppError::ChunkError => write!(f, "Chunk error"),
            EthAppError::BufferOverflow => write!(f, "Buffer overflow"),
            EthAppError::ServiceConnectionFailed => write!(f, "Service connection failed"),
            EthAppError::SerializationError => write!(f, "Serialization error"),
            EthAppError::StorageError => write!(f, "Storage error"),
            EthAppError::UiError => write!(f, "UI error"),
            EthAppError::CryptoError => write!(f, "Crypto error"),
            EthAppError::AttestationKeyExists => write!(f, "Attestation key exists"),
            EthAppError::AttestationNotInitialized => write!(f, "Attestation not initialized"),
            EthAppError::ImportKeyExists => write!(f, "Import key exists"),
            EthAppError::ImportKeyNotInitialized => write!(f, "Import key not initialized"),
            EthAppError::DecryptionFailed => write!(f, "Decryption failed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_codes() {
        assert_eq!(EthAppError::Success.code(), 0x00);
        assert_eq!(EthAppError::RejectedByUser.code(), 0x01);
        assert_eq!(EthAppError::CryptoError.code(), 0x1A);
        assert_eq!(EthAppError::AttestationKeyExists.code(), 0x1B);
        assert_eq!(EthAppError::AttestationNotInitialized.code(), 0x1C);
        assert_eq!(EthAppError::ImportKeyExists.code(), 0x1D);
        assert_eq!(EthAppError::ImportKeyNotInitialized.code(), 0x1E);
        assert_eq!(EthAppError::DecryptionFailed.code(), 0x1F);
    }

    #[test]
    fn test_error_classification() {
        assert!(EthAppError::Success.is_success());
        assert!(!EthAppError::RejectedByUser.is_success());
        assert!(EthAppError::RejectedByUser.is_user_rejection());
        assert!(EthAppError::InvalidSignature.is_security_error());
    }

    #[test]
    fn test_all_security_errors() {
        let security_errors = [
            EthAppError::InvalidSignature,
            EthAppError::SecurityViolation,
            EthAppError::BlindSigningDisabled,
            EthAppError::InvalidDerivationPath,
        ];
        for err in &security_errors {
            assert!(err.is_security_error(), "{err} should be security error");
        }
    }

    #[test]
    fn test_non_security_errors() {
        let non_security = [
            EthAppError::Success,
            EthAppError::RejectedByUser,
            EthAppError::InvalidOpcode,
            EthAppError::InternalError,
            EthAppError::Timeout,
            EthAppError::CryptoError,
        ];
        for err in &non_security {
            assert!(!err.is_security_error(), "{err} should NOT be security error");
        }
    }

    #[test]
    fn test_error_codes_are_unique() {
        use alloc::vec::Vec;
        let errors = [
            EthAppError::Success, EthAppError::RejectedByUser, EthAppError::InvalidOpcode,
            EthAppError::InvalidParameter, EthAppError::InvalidData, EthAppError::InvalidSignature,
            EthAppError::SecurityViolation, EthAppError::UnsupportedOperation,
            EthAppError::InternalError, EthAppError::Timeout, EthAppError::BlindSigningDisabled,
            EthAppError::MetadataNotFound, EthAppError::InvalidDerivationPath,
            EthAppError::KeyDerivationFailed, EthAppError::SigningFailed,
            EthAppError::InvalidTransaction, EthAppError::InvalidRlp, EthAppError::InvalidMessage,
            EthAppError::InvalidTypedData, EthAppError::InvalidState, EthAppError::ChunkError,
            EthAppError::BufferOverflow, EthAppError::ServiceConnectionFailed,
            EthAppError::SerializationError, EthAppError::StorageError, EthAppError::UiError,
            EthAppError::CryptoError, EthAppError::AttestationKeyExists,
            EthAppError::AttestationNotInitialized, EthAppError::ImportKeyExists,
            EthAppError::ImportKeyNotInitialized, EthAppError::DecryptionFailed,
        ];
        let mut codes: Vec<u32> = errors.iter().map(|e| e.code()).collect();
        let len_before = codes.len();
        codes.sort();
        codes.dedup();
        assert_eq!(codes.len(), len_before, "duplicate error codes found");
    }

    #[test]
    fn test_error_display_non_empty() {
        use core::fmt::Write;
        let errors = [
            EthAppError::Success, EthAppError::RejectedByUser, EthAppError::CryptoError,
        ];
        for err in &errors {
            let mut buf = alloc::string::String::new();
            write!(buf, "{err}").unwrap();
            assert!(!buf.is_empty(), "display for {err:?} should not be empty");
        }
    }

    #[test]
    fn test_error_default_is_success() {
        assert_eq!(EthAppError::default(), EthAppError::Success);
    }

    #[test]
    fn test_error_code_contiguous() {
        // Error codes should be 0x00 through 0x1F contiguously
        assert_eq!(EthAppError::Success.code(), 0x00);
        assert_eq!(EthAppError::DecryptionFailed.code(), 0x1F);
    }
}
