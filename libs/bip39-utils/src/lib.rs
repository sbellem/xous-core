//! BIP39 mnemonic wordlist and conversion utilities.
//!
//! Provides the English BIP39 wordlist and functions for converting
//! between byte entropy and mnemonic word sequences.

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec, vec::Vec};

pub mod en;
pub use en::*;

use sha2::Digest;

#[derive(Debug, Eq, PartialEq)]
pub enum Bip39Error {
    InvalidLength,
    InvalidChecksum,
    InvalidWordAt(usize),
}

/// Convert an array of bytes (entropy) to a list of BIP39 mnemonic words.
///
/// Valid entropy lengths: 16, 20, 24, 28, or 32 bytes
/// (producing 12, 15, 18, 21, or 24 words respectively).
///
/// Returns `Bip39Error::InvalidLength` if the byte length is not valid.
pub fn bytes_to_bip39(bytes: &Vec<u8>) -> Result<Vec<String>, Bip39Error> {
    let mut result = Vec::<String>::new();
    match bytes.len() {
        16 | 20 | 24 | 28 | 32 => (),
        _ => return Err(Bip39Error::InvalidLength),
    }
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let checksum_bits = bytes.len() / 4;
    let checksum = digest.as_slice()[0] >> (8 - checksum_bits);

    let mut bits_in_bucket = 0;
    let mut bucket = 0u32;
    for &b in bytes {
        bucket <<= 8;
        bucket |= b as u32;
        bits_in_bucket += 8;
        if bits_in_bucket >= 11 {
            let codeword = bucket >> (bits_in_bucket - 11);
            bucket &= !((0b111_1111_1111u32) << (bits_in_bucket - 11));
            bits_in_bucket -= 11;
            result.push(BIP39_TABLE[codeword as usize].to_string());
        }
    }
    assert!(bits_in_bucket + checksum_bits == 11);
    bucket <<= checksum_bits;
    bucket |= checksum as u32;
    assert!(bucket < 2048);
    result.push(BIP39_TABLE[bucket as usize].to_string());
    Ok(result)
}

/// Convert a list of BIP39 mnemonic words back to the original entropy bytes.
///
/// Words are case-insensitive. Valid word counts: 12, 15, 18, 21, or 24.
/// Returns `InvalidWordAt(index)` at the first invalid word detected.
/// Returns `InvalidChecksum` if the checksum doesn't match.
pub fn bip39_to_bytes(bip39: &Vec<String>) -> Result<Vec<u8>, Bip39Error> {
    match bip39.len() {
        12 | 15 | 18 | 21 | 24 => (),
        _ => return Err(Bip39Error::InvalidLength),
    }

    let mut indices = Vec::<u32>::new();
    for (index, bip) in bip39.iter().enumerate() {
        if let Some(i) = BIP39_TABLE.iter().position(|&x| x == bip) {
            indices.push(i as u32);
        } else {
            return Err(Bip39Error::InvalidWordAt(index));
        }
    }

    // collate into u8 vec
    let mut data = Vec::<u8>::new();
    let mut bucket = 0u32;
    let mut bits_in_bucket = 0;
    for index in indices {
        bucket = (bucket << 11) | index;
        bits_in_bucket += 11;

        while bits_in_bucket >= 8 {
            data.push((bucket >> (bits_in_bucket - 8)) as u8);
            bucket &= !(0b1111_1111 << bits_in_bucket - 8);
            bits_in_bucket -= 8;
        }
    }
    // the bucket should now just contain the checksum
    let entered_checksum = if bits_in_bucket == 0 {
        data.pop().unwrap()
    } else {
        bucket as u8
    };

    let mut hasher = sha2::Sha256::new();
    hasher.update(&data);
    let digest = hasher.finalize();
    let checksum_bits = data.len() / 4;
    let checksum = digest.as_slice()[0] >> (8 - checksum_bits);
    if checksum == entered_checksum {
        Ok(data)
    } else {
        #[cfg(feature = "log")]
        log::warn!("checksum didn't match: {:x} vs {:x}", checksum, entered_checksum);
        Err(Bip39Error::InvalidChecksum)
    }
}

pub const BIP39_SUGGEST_LIMIT: usize = 5;

/// Return a list of BIP39 word suggestions matching the given prefix.
///
/// First tries prefix matching; falls back to substring matching if no
/// prefix matches are found. Limited to `BIP39_SUGGEST_LIMIT` results.
pub fn suggest_bip39(start: &str) -> Vec<String> {
    let mut ret = Vec::<String>::new();
    for bip in BIP39_TABLE {
        if bip.starts_with(start) {
            ret.push(bip.to_string());
            if ret.len() >= BIP39_SUGGEST_LIMIT {
                break;
            }
        }
    }
    if ret.len() > 0 {
        return ret;
    }
    for bip in BIP39_TABLE {
        if bip.contains(start) {
            ret.push(bip.to_string());
            if ret.len() >= BIP39_SUGGEST_LIMIT {
                break;
            }
        }
    }
    ret
}

/// Returns `true` if the given word is a valid BIP39 word (case-insensitive).
pub fn is_valid_bip39(word: &str) -> bool {
    let lword = word.to_ascii_lowercase();
    for w in BIP39_TABLE {
        if lword == w {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bip39_to_bytes() {
        let phrase = vec![
            "alert".to_string(),
            "record".to_string(),
            "income".to_string(),
            "curve".to_string(),
            "mercy".to_string(),
            "tree".to_string(),
            "heavy".to_string(),
            "loan".to_string(),
            "hen".to_string(),
            "recycle".to_string(),
            "mean".to_string(),
            "devote".to_string(),
        ];
        let refnum = 0b00000110001101100111100111001010000110110010100010110101110011111101101010011100000110000110101100110110011111100010011100011110u128;
        let refvec = refnum.to_be_bytes().to_vec();

        assert_eq!(Ok(refvec), bip39_to_bytes(&phrase));
    }

    #[test]
    fn test_bytes_to_bip39() {
        let refnum = 0b00000110001101100111100111001010000110110010100010110101110011111101101010011100000110000110101100110110011111100010011100011110u128;
        let refvec = refnum.to_be_bytes().to_vec();
        let phrase = vec![
            "alert".to_string(),
            "record".to_string(),
            "income".to_string(),
            "curve".to_string(),
            "mercy".to_string(),
            "tree".to_string(),
            "heavy".to_string(),
            "loan".to_string(),
            "hen".to_string(),
            "recycle".to_string(),
            "mean".to_string(),
            "devote".to_string(),
        ];
        assert_eq!(bytes_to_bip39(&refvec), Ok(phrase));
    }

    #[test]
    fn test_is_valid_bip39() {
        assert_eq!(is_valid_bip39("alert"), true);
        assert_eq!(is_valid_bip39("rEcOrD"), true);
        assert_eq!(is_valid_bip39("foobar"), false);
        assert_eq!(is_valid_bip39(""), false);
    }

    #[test]
    fn test_suggest_prefix() {
        let suggestions = suggest_bip39("ag");
        let reference =
            vec!["again".to_string(), "age".to_string(), "agent".to_string(), "agree".to_string()];
        assert_eq!(suggestions, reference);
    }

    #[test]
    fn test_roundtrip_24_words() {
        // 32 bytes of entropy -> 24 words -> back to 32 bytes
        let entropy: Vec<u8> = (0u8..32).collect();
        let words = bytes_to_bip39(&entropy).unwrap();
        assert_eq!(words.len(), 24);
        let recovered = bip39_to_bytes(&words).unwrap();
        assert_eq!(entropy, recovered);
    }
}
