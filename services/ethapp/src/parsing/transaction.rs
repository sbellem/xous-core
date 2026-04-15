//! Transaction parsing for Ethereum.
//!
//! Supports:
//! - Legacy transactions (pre-EIP-2718)
//! - EIP-2930 access list transactions (type 0x01)
//! - EIP-1559 fee market transactions (type 0x02)
//!
//! # Security
//!
//! All transaction data comes from untrusted sources.
//! Parser must:
//! - Validate all fields before returning
//! - Fail closed on any ambiguity
//! - Compute correct hash for signing

#[cfg(target_os = "xous")]
use alloc::vec::Vec;

#[cfg(not(target_os = "xous"))]
use std::vec::Vec;

use ethapp_common::{EthAddress, Hash256, TransactionType, MAX_TX_SIZE};

use ethapp_common::rlp::{self, RlpError, RlpItem};
use crate::crypto::keccak256;

/// Transaction parsing errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxParseError {
    /// RLP decoding failed.
    RlpError(RlpError),
    /// Transaction data is empty.
    EmptyTransaction,
    /// Transaction too large.
    TransactionTooLarge,
    /// Unknown transaction type.
    UnknownType,
    /// Invalid field count for transaction type.
    InvalidFieldCount,
    /// Missing required field.
    MissingField,
    /// Field value out of range.
    ValueOutOfRange,
    /// Invalid chain ID.
    InvalidChainId,
}

impl From<RlpError> for TxParseError {
    fn from(e: RlpError) -> Self {
        TxParseError::RlpError(e)
    }
}

/// Parsed transaction fields for display and signing.
#[derive(Debug, Clone)]
pub struct ParsedTransaction {
    /// Transaction type.
    pub tx_type: TransactionType,
    /// Chain ID (for EIP-155 and typed transactions).
    pub chain_id: Option<u64>,
    /// Nonce.
    pub nonce: u64,
    /// Recipient address (None for contract creation).
    pub to: Option<EthAddress>,
    /// Value in wei (32 bytes, big-endian).
    pub value: [u8; 32],
    /// Gas limit.
    pub gas_limit: u64,
    /// Gas price (legacy) or max fee per gas (EIP-1559).
    pub gas_price: [u8; 32],
    /// Max priority fee per gas (EIP-1559 only).
    pub max_priority_fee: Option<[u8; 32]>,
    /// Input data.
    pub data: Vec<u8>,
    /// Access list (EIP-2930/1559).
    pub access_list: Vec<(EthAddress, Vec<Hash256>)>,
    /// Hash to sign (keccak256 of RLP-encoded unsigned tx).
    pub sign_hash: Hash256,
    /// Original raw transaction data.
    pub raw_data: Vec<u8>,
}

impl ParsedTransaction {
    /// Returns true if this is a contract creation.
    pub fn is_contract_creation(&self) -> bool {
        self.to.is_none()
    }

    /// Returns the function selector (first 4 bytes of data) if present.
    pub fn selector(&self) -> Option<[u8; 4]> {
        if self.data.len() >= 4 {
            let mut sel = [0u8; 4];
            sel.copy_from_slice(&self.data[..4]);
            Some(sel)
        } else {
            None
        }
    }
}

/// Transaction parser.
pub struct TransactionParser;

impl TransactionParser {
    /// Parses a transaction from raw bytes.
    ///
    /// Supports legacy (untyped) and EIP-2718 typed transactions.
    pub fn parse(data: &[u8]) -> Result<ParsedTransaction, TxParseError> {
        if data.is_empty() {
            return Err(TxParseError::EmptyTransaction);
        }

        if data.len() > MAX_TX_SIZE {
            return Err(TxParseError::TransactionTooLarge);
        }

        // Check for typed transaction (EIP-2718)
        let first_byte = data[0];

        if first_byte < 0x80 {
            // Typed transaction: first byte is the type
            match first_byte {
                0x01 => Self::parse_eip2930(data),
                0x02 => Self::parse_eip1559(data),
                _ => Err(TxParseError::UnknownType),
            }
        } else {
            // Legacy transaction (first byte is RLP list prefix)
            Self::parse_legacy(data)
        }
    }

    /// Parses a legacy (pre-EIP-2718) transaction.
    fn parse_legacy(data: &[u8]) -> Result<ParsedTransaction, TxParseError> {
        let item = rlp::decode_exact(data)?;
        let fields = item.as_list().ok_or(TxParseError::InvalidFieldCount)?;

        // Legacy tx: [nonce, gasPrice, gasLimit, to, value, data, v, r, s]
        // For unsigned: [nonce, gasPrice, gasLimit, to, value, data] or
        // EIP-155 unsigned: [nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0]
        if fields.len() != 6 && fields.len() != 9 {
            return Err(TxParseError::InvalidFieldCount);
        }

        let nonce = fields[0].as_u64().ok_or(TxParseError::MissingField)?;
        let gas_price = fields[1].as_bytes32().ok_or(TxParseError::MissingField)?;
        let gas_limit = fields[2].as_u64().ok_or(TxParseError::MissingField)?;
        let to = parse_to_field(&fields[3])?;
        let value = fields[4].as_bytes32().ok_or(TxParseError::MissingField)?;
        let input_data = fields[5]
            .as_string()
            .ok_or(TxParseError::MissingField)?
            .to_vec();

        // Extract chain ID from v value or explicit fields
        let (chain_id, is_unsigned) = if fields.len() == 9 {
            let r_data = fields[7].as_string().ok_or(TxParseError::MissingField)?;
            let s_data = fields[8].as_string().ok_or(TxParseError::MissingField)?;

            let is_r_zero = r_data.is_empty() || r_data.iter().all(|&b| b == 0);
            let is_s_zero = s_data.is_empty() || s_data.iter().all(|&b| b == 0);

            if is_r_zero && is_s_zero {
                // Unsigned EIP-155: chainId is in field[6]
                let chain_id = fields[6].as_u64().ok_or(TxParseError::InvalidChainId)?;
                (Some(chain_id), true)
            } else {
                // Signed transaction - extract chain ID from v
                let v = fields[6].as_u64().ok_or(TxParseError::MissingField)?;
                if v >= 35 {
                    // EIP-155 signed: chain_id = (v - 35) / 2
                    (Some((v - 35) / 2), false)
                } else if v == 27 || v == 28 {
                    // Pre-EIP-155 signed: no chain ID
                    (None, false)
                } else {
                    return Err(TxParseError::ValueOutOfRange);
                }
            }
        } else {
            (None, false)
        };

        // Compute hash to sign
        let sign_hash = compute_legacy_sign_hash(data, chain_id, is_unsigned)?;

        Ok(ParsedTransaction {
            tx_type: TransactionType::Legacy,
            chain_id,
            nonce,
            to,
            value,
            gas_limit,
            gas_price,
            max_priority_fee: None,
            data: input_data,
            access_list: Vec::new(),
            sign_hash,
            raw_data: data.to_vec(),
        })
    }

    /// Parses an EIP-2930 (access list) transaction.
    fn parse_eip2930(data: &[u8]) -> Result<ParsedTransaction, TxParseError> {
        if data.is_empty() || data[0] != 0x01 {
            return Err(TxParseError::UnknownType);
        }

        let item = rlp::decode_exact(&data[1..])?;
        let fields = item.as_list().ok_or(TxParseError::InvalidFieldCount)?;

        // EIP-2930: 8 fields for unsigned, 11 for signed
        if fields.len() != 8 && fields.len() != 11 {
            return Err(TxParseError::InvalidFieldCount);
        }

        let chain_id = fields[0].as_u64().ok_or(TxParseError::InvalidChainId)?;
        let nonce = fields[1].as_u64().ok_or(TxParseError::MissingField)?;
        let gas_price = fields[2].as_bytes32().ok_or(TxParseError::MissingField)?;
        let gas_limit = fields[3].as_u64().ok_or(TxParseError::MissingField)?;
        let to = parse_to_field(&fields[4])?;
        let value = fields[5].as_bytes32().ok_or(TxParseError::MissingField)?;
        let input_data = fields[6]
            .as_string()
            .ok_or(TxParseError::MissingField)?
            .to_vec();
        let access_list = parse_access_list(&fields[7])?;

        // Compute hash: keccak256(0x01 || rlp([...]))
        let sign_hash = compute_typed_sign_hash(data)?;

        Ok(ParsedTransaction {
            tx_type: TransactionType::AccessList,
            chain_id: Some(chain_id),
            nonce,
            to,
            value,
            gas_limit,
            gas_price,
            max_priority_fee: None,
            data: input_data,
            access_list,
            sign_hash,
            raw_data: data.to_vec(),
        })
    }

    /// Parses an EIP-1559 (fee market) transaction.
    fn parse_eip1559(data: &[u8]) -> Result<ParsedTransaction, TxParseError> {
        if data.is_empty() || data[0] != 0x02 {
            return Err(TxParseError::UnknownType);
        }

        let item = rlp::decode_exact(&data[1..])?;
        let fields = item.as_list().ok_or(TxParseError::InvalidFieldCount)?;

        // EIP-1559: 9 fields for unsigned, 12 for signed
        if fields.len() != 9 && fields.len() != 12 {
            return Err(TxParseError::InvalidFieldCount);
        }

        let chain_id = fields[0].as_u64().ok_or(TxParseError::InvalidChainId)?;
        let nonce = fields[1].as_u64().ok_or(TxParseError::MissingField)?;
        let max_priority_fee = fields[2].as_bytes32().ok_or(TxParseError::MissingField)?;
        let max_fee = fields[3].as_bytes32().ok_or(TxParseError::MissingField)?;
        let gas_limit = fields[4].as_u64().ok_or(TxParseError::MissingField)?;
        let to = parse_to_field(&fields[5])?;
        let value = fields[6].as_bytes32().ok_or(TxParseError::MissingField)?;
        let input_data = fields[7]
            .as_string()
            .ok_or(TxParseError::MissingField)?
            .to_vec();
        let access_list = parse_access_list(&fields[8])?;

        // Compute hash
        let sign_hash = compute_typed_sign_hash(data)?;

        Ok(ParsedTransaction {
            tx_type: TransactionType::FeeMarket,
            chain_id: Some(chain_id),
            nonce,
            to,
            value,
            gas_limit,
            gas_price: max_fee,
            max_priority_fee: Some(max_priority_fee),
            data: input_data,
            access_list,
            sign_hash,
            raw_data: data.to_vec(),
        })
    }
}

/// Parses the "to" field (empty for contract creation).
fn parse_to_field(item: &RlpItem<'_>) -> Result<Option<EthAddress>, TxParseError> {
    let data = item.as_string().ok_or(TxParseError::MissingField)?;
    if data.is_empty() {
        Ok(None)
    } else if data.len() == 20 {
        let mut addr = [0u8; 20];
        addr.copy_from_slice(data);
        Ok(Some(addr))
    } else {
        Err(TxParseError::MissingField)
    }
}

/// Parses an access list.
fn parse_access_list(item: &RlpItem<'_>) -> Result<Vec<(EthAddress, Vec<Hash256>)>, TxParseError> {
    let list = item.as_list().ok_or(TxParseError::MissingField)?;
    let mut result = Vec::new();

    for entry in list {
        let entry_list = entry.as_list().ok_or(TxParseError::MissingField)?;
        if entry_list.len() != 2 {
            return Err(TxParseError::InvalidFieldCount);
        }

        let address = entry_list[0]
            .as_address()
            .ok_or(TxParseError::MissingField)?;

        let storage_keys_item = entry_list[1]
            .as_list()
            .ok_or(TxParseError::MissingField)?;
        let mut storage_keys = Vec::new();
        for key_item in storage_keys_item {
            let key = key_item.as_bytes32().ok_or(TxParseError::MissingField)?;
            storage_keys.push(key);
        }

        result.push((address, storage_keys));
    }

    Ok(result)
}

/// Computes the signing hash for a legacy transaction.
fn compute_legacy_sign_hash(
    data: &[u8],
    chain_id: Option<u64>,
    is_unsigned: bool,
) -> Result<Hash256, TxParseError> {
    let item = rlp::decode_exact(data)?;
    let fields = item.as_list().ok_or(TxParseError::InvalidFieldCount)?;

    if fields.len() == 6 {
        // 6-field unsigned transaction (pre-EIP-155)
        Ok(keccak256(data))
    } else if fields.len() == 9 {
        if is_unsigned {
            // Already in unsigned EIP-155 format
            Ok(keccak256(data))
        } else {
            // Signed transaction - reconstruct unsigned form
            let mut unsigned = Vec::new();
            for i in 0..6 {
                let field_data = fields[i].as_string().unwrap_or(&[]);
                unsigned.extend_from_slice(&rlp::encode_bytes(field_data));
            }

            if let Some(cid) = chain_id {
                // EIP-155: append [chainId, 0, 0]
                unsigned.extend_from_slice(&rlp::encode_u64(cid));
                unsigned.extend_from_slice(&rlp::encode_u64(0));
                unsigned.extend_from_slice(&rlp::encode_u64(0));
            }

            let encoded = rlp::encode_list(&unsigned);
            Ok(keccak256(&encoded))
        }
    } else {
        Err(TxParseError::InvalidFieldCount)
    }
}

/// Computes the signing hash for a typed transaction.
fn compute_typed_sign_hash(data: &[u8]) -> Result<Hash256, TxParseError> {
    // Hash is keccak256(type_byte || rlp(unsigned_fields))
    Ok(keccak256(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_empty_transaction() {
        let result = TransactionParser::parse(&[]);
        assert!(matches!(result, Err(TxParseError::EmptyTransaction)));
    }

    #[test]
    fn test_unknown_type() {
        // Type 0x03 is not supported
        let result = TransactionParser::parse(&[0x03, 0xc0]);
        assert!(matches!(result, Err(TxParseError::UnknownType)));
    }

    #[test]
    fn test_parse_to_field_empty() {
        let item = RlpItem::String(&[]);
        let result = parse_to_field(&item).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_to_field_address() {
        let addr = [0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let item = RlpItem::String(&addr);
        let result = parse_to_field(&item).unwrap();
        assert_eq!(result, Some(addr));
    }

    #[test]
    fn test_parse_unsigned_eip155() {
        // Construct an unsigned EIP-155 transaction with chainId=137
        let mut fields = Vec::new();
        fields.extend_from_slice(&rlp::encode_u64(0)); // nonce
        fields.extend_from_slice(&rlp::encode_u64(20_000_000_000)); // gasPrice
        fields.extend_from_slice(&rlp::encode_u64(21000)); // gasLimit
        fields.extend_from_slice(&rlp::encode_bytes(&[0xde; 20])); // to
        fields.extend_from_slice(&rlp::encode_u64(1_000_000_000_000_000_000)); // value
        fields.extend_from_slice(&rlp::encode_bytes(&[])); // data
        fields.extend_from_slice(&rlp::encode_u64(137)); // chainId
        fields.extend_from_slice(&rlp::encode_u64(0)); // r
        fields.extend_from_slice(&rlp::encode_u64(0)); // s

        let tx_data = rlp::encode_list(&fields);
        let parsed = TransactionParser::parse(&tx_data).unwrap();

        assert_eq!(parsed.chain_id, Some(137));
        assert_eq!(parsed.tx_type, TransactionType::Legacy);
    }

    #[test]
    fn test_parse_eip1559() {
        // Construct an unsigned EIP-1559 transaction
        let mut fields = Vec::new();
        fields.extend_from_slice(&rlp::encode_u64(1)); // chainId
        fields.extend_from_slice(&rlp::encode_u64(0)); // nonce
        fields.extend_from_slice(&rlp::encode_u64(1_000_000_000)); // maxPriorityFee
        fields.extend_from_slice(&rlp::encode_u64(50_000_000_000)); // maxFee
        fields.extend_from_slice(&rlp::encode_u64(21000)); // gasLimit
        fields.extend_from_slice(&rlp::encode_bytes(&[0xde; 20])); // to
        fields.extend_from_slice(&rlp::encode_u64(1_000_000_000_000_000_000)); // value
        fields.extend_from_slice(&rlp::encode_bytes(&[])); // data
        fields.extend_from_slice(&rlp::encode_list(&[])); // accessList

        let rlp_payload = rlp::encode_list(&fields);

        // Prepend type byte
        let mut tx_data = vec![0x02];
        tx_data.extend_from_slice(&rlp_payload);

        let parsed = TransactionParser::parse(&tx_data).unwrap();

        assert_eq!(parsed.chain_id, Some(1));
        assert_eq!(parsed.tx_type, TransactionType::FeeMarket);
        assert!(parsed.max_priority_fee.is_some());
    }
}
