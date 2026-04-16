/// Eventually more language support can be added here:
///
/// In order to integrate this well, we need to re-do the language build
/// system to be based off of af #cfg feature, so that we can pick up
/// the feature in this crate and select the right word list.
///
/// We don't compile all the word lists in because code size is precious.
///
/// Each language should simply create its table assigning to be symbol
/// `const BIP39_TABLE: [&'static str; 2048]`. This allows the rest of
/// the code to refer to the table without change, all we do is swap out
/// which language module is included in the two lines below.
pub mod en;
pub use en::*;

// Re-export conversion functions from the shared bip39-utils crate.
pub(crate) use bip39_utils::{
    bytes_to_bip39, bip39_to_bytes, suggest_bip39, is_valid_bip39,
    Bip39Error, BIP39_SUGGEST_LIMIT,
};

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_11_to_8() {
        let indices = [
            0b00000110001,
            0b10110011110,
            0b01110010100,
            0b00110110010,
            0b10001011010,
            0b11100111111,
            0b01101010011,
            0b10000011000,
            0b01101011001,
            0b10110011111,
            0b10001001110,
            0b00111100110,
        ];
        let refnum = 0b00000110001101100111100111001010000110110010100010110101110011111101101010011100000110000110101100110110011111100010011100011110u128;

        let mut refvec = refnum.to_be_bytes().to_vec();
        refvec.push(6); // checksum

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
        if bits_in_bucket != 0 {
            data.push(bucket as u8);
        }
        assert!(data.len() == refvec.len());
        for (index, (&a, &b)) in refvec.iter().zip(data.iter()).enumerate() {
            if a != b {
                println!("index {} error: a[{}{:x})] != b[{}({:x})]", index, a, a, b, b);
            } else {
                println!("index {} match: a[{}({:x})] == b[{}({:x})]", index, a, a, b, b);
            }
            assert!(a == b);
        }
    }
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
        let mut refvec = refnum.to_be_bytes().to_vec();

        assert_eq!(Ok(refvec), bip39_to_bytes(&phrase));
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
}
