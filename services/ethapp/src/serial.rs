//! Serial frame protocol handler for host CLI communication.
//!
//! This module implements the binary frame protocol used by `ethcli`
//! to communicate with ethapp over USB CDC-ACM serial.
//!
//! Wire protocol:
//!   Request:  [0xE7] [length: u16 LE] [opcode: u8] [payload...]
//!   Response: [0xE7] [length: u16 LE] [status: u8] [payload...]
//!
//! The magic byte 0xE7 distinguishes binary frames from ASCII console
//! input, allowing the serial handler to coexist with the text console.
//!
//! # Integration
//!
//! The console's serial input handler should check for 0xE7 as the first
//! byte. If found, route the remaining bytes to `SerialFrameHandler::process_byte()`.
//! Otherwise, handle as normal text input.

use std::vec::Vec;

use ethapp_common::EthAppError;

/// Magic byte for frame synchronization.
pub const FRAME_MAGIC: u8 = 0xE7;

/// Maximum payload size (64KB).
const MAX_FRAME_SIZE: usize = 65535;

/// Status codes for serial responses.
pub const STATUS_OK: u8 = 0x00;
pub const STATUS_ERR_INVALID_OPCODE: u8 = 0x01;
pub const STATUS_ERR_REJECTED: u8 = 0x02;
pub const STATUS_ERR_NO_SEED: u8 = 0x03;
pub const STATUS_ERR_INVALID_PATH: u8 = 0x04;
pub const STATUS_ERR_CRYPTO: u8 = 0x05;
pub const STATUS_ERR_ATTEST_EXISTS: u8 = 0x06;
pub const STATUS_ERR_NO_ATTEST: u8 = 0x07;
pub const STATUS_ERR_IMPORT_EXISTS: u8 = 0x08;
pub const STATUS_ERR_NO_IMPORT: u8 = 0x09;
pub const STATUS_ERR_DECRYPT: u8 = 0x0A;
pub const STATUS_ERR_INTERNAL: u8 = 0xFF;

/// State machine for parsing incoming serial frames.
#[derive(Debug)]
enum ParseState {
    /// Waiting for magic byte.
    WaitMagic,
    /// Got magic, reading length low byte.
    LengthLow,
    /// Got length low, reading length high byte.
    LengthHigh(u8),
    /// Reading payload bytes.
    Payload { expected: usize, buf: Vec<u8> },
}

/// Serial frame handler that accumulates bytes into complete frames.
pub struct SerialFrameHandler {
    state: ParseState,
}

/// A complete parsed frame.
pub struct Frame {
    pub opcode: u8,
    pub payload: Vec<u8>,
}

impl SerialFrameHandler {
    pub fn new() -> Self {
        Self {
            state: ParseState::WaitMagic,
        }
    }

    /// Feed a byte into the parser.
    ///
    /// Returns `Some(Frame)` when a complete frame has been received.
    pub fn process_byte(&mut self, byte: u8) -> Option<Frame> {
        match &mut self.state {
            ParseState::WaitMagic => {
                if byte == FRAME_MAGIC {
                    self.state = ParseState::LengthLow;
                }
                None
            }
            ParseState::LengthLow => {
                self.state = ParseState::LengthHigh(byte);
                None
            }
            ParseState::LengthHigh(low) => {
                let length = (*low as usize) | ((byte as usize) << 8);
                if length == 0 || length > MAX_FRAME_SIZE {
                    self.state = ParseState::WaitMagic;
                    return None;
                }
                self.state = ParseState::Payload {
                    expected: length,
                    buf: Vec::with_capacity(length),
                };
                None
            }
            ParseState::Payload { expected, buf } => {
                buf.push(byte);
                if buf.len() >= *expected {
                    let data = std::mem::take(buf);
                    self.state = ParseState::WaitMagic;
                    let opcode = data[0];
                    let payload = data[1..].to_vec();
                    Some(Frame { opcode, payload })
                } else {
                    None
                }
            }
        }
    }

    /// Reset the parser state.
    pub fn reset(&mut self) {
        self.state = ParseState::WaitMagic;
    }
}

/// Build a response frame.
pub fn build_response(status: u8, payload: &[u8]) -> Vec<u8> {
    let length = 1 + payload.len(); // status + payload
    let mut frame = Vec::with_capacity(3 + length);
    frame.push(FRAME_MAGIC);
    frame.extend_from_slice(&(length as u16).to_le_bytes());
    frame.push(status);
    frame.extend_from_slice(payload);
    frame
}

/// Map an EthAppError to a serial status code.
pub fn error_to_status(err: &EthAppError) -> u8 {
    match err {
        EthAppError::RejectedByUser => STATUS_ERR_REJECTED,
        EthAppError::UnsupportedOperation => STATUS_ERR_NO_SEED,
        EthAppError::InvalidDerivationPath => STATUS_ERR_INVALID_PATH,
        EthAppError::CryptoError => STATUS_ERR_CRYPTO,
        EthAppError::AttestationKeyExists => STATUS_ERR_ATTEST_EXISTS,
        EthAppError::AttestationNotInitialized => STATUS_ERR_NO_ATTEST,
        EthAppError::ImportKeyExists => STATUS_ERR_IMPORT_EXISTS,
        EthAppError::ImportKeyNotInitialized => STATUS_ERR_NO_IMPORT,
        EthAppError::DecryptionFailed => STATUS_ERR_DECRYPT,
        _ => STATUS_ERR_INTERNAL,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_complete_frame() {
        let mut handler = SerialFrameHandler::new();

        // Frame: magic=0xE7, length=3 (opcode + 2 payload bytes), opcode=0xFF, payload=[0x01, 0x02]
        let bytes = [0xE7, 0x03, 0x00, 0xFF, 0x01, 0x02];

        let mut result = None;
        for &b in &bytes {
            if let Some(frame) = handler.process_byte(b) {
                result = Some(frame);
            }
        }

        let frame = result.expect("should have parsed a frame");
        assert_eq!(frame.opcode, 0xFF);
        assert_eq!(frame.payload, vec![0x01, 0x02]);
    }

    #[test]
    fn test_parse_empty_payload() {
        let mut handler = SerialFrameHandler::new();

        // Frame: magic=0xE7, length=1 (opcode only), opcode=0xFF
        let bytes = [0xE7, 0x01, 0x00, 0xFF];

        let mut result = None;
        for &b in &bytes {
            if let Some(frame) = handler.process_byte(b) {
                result = Some(frame);
            }
        }

        let frame = result.expect("should have parsed a frame");
        assert_eq!(frame.opcode, 0xFF);
        assert_eq!(frame.payload, Vec::<u8>::new());
    }

    #[test]
    fn test_skip_garbage_before_magic() {
        let mut handler = SerialFrameHandler::new();

        // Garbage bytes followed by a valid frame
        let bytes = [0x00, 0x55, 0xAA, 0xE7, 0x01, 0x00, 0xFF];

        let mut result = None;
        for &b in &bytes {
            if let Some(frame) = handler.process_byte(b) {
                result = Some(frame);
            }
        }

        let frame = result.expect("should have parsed a frame");
        assert_eq!(frame.opcode, 0xFF);
    }

    #[test]
    fn test_build_response() {
        let resp = build_response(STATUS_OK, &[0x01, 0x02, 0x03]);
        assert_eq!(resp, vec![0xE7, 0x04, 0x00, STATUS_OK, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_zero_length_rejected() {
        let mut handler = SerialFrameHandler::new();
        // length=0 should be rejected
        let bytes = [0xE7, 0x00, 0x00];
        for &b in &bytes {
            assert!(handler.process_byte(b).is_none());
        }
    }
}
