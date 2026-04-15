use String;

use crate::{CommonEnv, ShellCmdApi};
use ethapp_api::{
    Bip32Path, EthAppClient, SignPersonalMessageRequest, SignTransactionRequest,
};

pub struct Eth {
    client: Option<EthAppClient>,
}
impl core::fmt::Debug for Eth {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Eth").field("connected", &self.client.is_some()).finish()
    }
}
impl Eth {
    pub fn new() -> Self { Eth { client: None } }

    fn client(&mut self) -> Result<&EthAppClient, xous::Error> {
        if self.client.is_none() {
            match EthAppClient::new() {
                Ok(c) => self.client = Some(c),
                Err(e) => {
                    log::error!("eth: failed to connect to ethapp: {:?}", e);
                    return Err(xous::Error::InternalError);
                }
            }
        }
        Ok(self.client.as_ref().unwrap())
    }
}

impl<'a> ShellCmdApi<'a> for Eth {
    cmd_api!(eth);

    fn process(&mut self, args: String, _env: &mut CommonEnv) -> Result<Option<String>, xous::Error> {
        use core::fmt::Write;
        let mut ret = String::new();

        let helpstring = "eth [ping|config|address|accounts|signmsg|sign|gentx]";

        let mut parts = args.split_whitespace();
        let cmd = parts.next().unwrap_or("").to_string();
        let args: Vec<String> = parts.map(|s| s.to_string()).collect();

        match cmd.as_str() {
            "ping" => {
                let client = self.client()?;
                match client.ping() {
                    Ok(()) => write!(ret, "pong").unwrap(),
                    Err(e) => write!(ret, "ping failed: {:?}", e).unwrap(),
                }
            }
            "config" => {
                let client = self.client()?;
                match client.get_app_configuration() {
                    Ok(cfg) => {
                        write!(
                            ret,
                            "v{}.{}.{} protocol={} blind_signing={} eth2={}",
                            cfg.version_major,
                            cfg.version_minor,
                            cfg.version_patch,
                            cfg.protocol_version,
                            cfg.blind_signing_enabled,
                            cfg.eth2_supported,
                        )
                        .unwrap();
                    }
                    Err(e) => write!(ret, "config failed: {:?}", e).unwrap(),
                }
            }
            "address" => {
                let index: u32 = args.first().and_then(|s| s.parse().ok()).unwrap_or(0);
                let path = Bip32Path::ethereum(0, 0, index);
                let client = self.client()?;
                match client.get_address(&path) {
                    Ok(addr) => {
                        write!(ret, "m/44'/60'/0'/0/{} -> 0x", index).unwrap();
                        for b in &addr {
                            write!(ret, "{:02x}", b).unwrap();
                        }
                    }
                    Err(e) => write!(ret, "address failed: {:?}", e).unwrap(),
                }
            }
            "accounts" => {
                let count: u32 = args.first().and_then(|s| s.parse().ok()).unwrap_or(5);
                let client = self.client()?;
                for i in 0..count {
                    let path = Bip32Path::ethereum(0, 0, i);
                    match client.get_address(&path) {
                        Ok(addr) => {
                            write!(ret, "[{}] 0x", i).unwrap();
                            for b in &addr {
                                write!(ret, "{:02x}", b).unwrap();
                            }
                            if i + 1 < count {
                                ret.push('\n');
                            }
                        }
                        Err(e) => {
                            write!(ret, "[{}] error: {:?}", i, e).unwrap();
                            break;
                        }
                    }
                }
            }
            "signmsg" => {
                if args.is_empty() {
                    write!(ret, "eth signmsg <message text>").unwrap();
                    return Ok(Some(ret));
                }
                let message = args.join(" ");
                let path = Bip32Path::ethereum(0, 0, 0);
                let request = SignPersonalMessageRequest {
                    path,
                    message: message.as_bytes().to_vec(),
                };
                let client = self.client()?;
                match client.sign_personal_message(&request) {
                    Ok(sig) => {
                        write!(ret, "v={}\nr=", sig.v).unwrap();
                        for b in &sig.r {
                            write!(ret, "{:02x}", b).unwrap();
                        }
                        ret.push_str("\ns=");
                        for b in &sig.s {
                            write!(ret, "{:02x}", b).unwrap();
                        }
                    }
                    Err(e) => write!(ret, "signmsg failed: {:?}", e).unwrap(),
                }
            }
            "sign" => {
                if args.is_empty() {
                    write!(ret, "eth sign <rlp-encoded tx hex>").unwrap();
                    return Ok(Some(ret));
                }
                let hex_str = args[0].strip_prefix("0x").unwrap_or(&args[0]);
                let tx_data = match hex_decode(hex_str) {
                    Some(d) => d,
                    None => {
                        write!(ret, "invalid hex").unwrap();
                        return Ok(Some(ret));
                    }
                };
                let path = Bip32Path::ethereum(0, 0, 0);
                let request = SignTransactionRequest {
                    path,
                    tx_data,
                };
                let client = self.client()?;
                match client.sign_transaction(&request) {
                    Ok(sig) => {
                        write!(ret, "v={}\nr=", sig.v).unwrap();
                        for b in &sig.r {
                            write!(ret, "{:02x}", b).unwrap();
                        }
                        ret.push_str("\ns=");
                        for b in &sig.s {
                            write!(ret, "{:02x}", b).unwrap();
                        }
                    }
                    Err(e) => write!(ret, "sign failed: {:?}", e).unwrap(),
                }
            }
            "gentx" => {
                // eth gentx <to> <value_wei>
                // Builds a legacy EIP-155 transaction and signs it.
                // Uses hardcoded nonce=0, gasPrice=1gwei, gasLimit=21000, chainId=1.
                if args.len() < 2 {
                    write!(ret, "eth gentx <to_address> <value_wei>").unwrap();
                    return Ok(Some(ret));
                }
                let to_hex = args[0].strip_prefix("0x").unwrap_or(&args[0]);
                let to_addr = match hex_decode(to_hex) {
                    Some(a) if a.len() == 20 => a,
                    _ => {
                        write!(ret, "invalid address (need 20 bytes hex)").unwrap();
                        return Ok(Some(ret));
                    }
                };
                let value_wei: u64 = match args[1].parse() {
                    Ok(v) => v,
                    Err(_) => {
                        write!(ret, "invalid value (need integer wei)").unwrap();
                        return Ok(Some(ret));
                    }
                };

                // Build RLP for legacy EIP-155 tx: [nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0]
                let tx_data = rlp_encode_legacy_tx(&to_addr, value_wei);

                let path = Bip32Path::ethereum(0, 0, 0);
                let request = SignTransactionRequest { path, tx_data };
                let client = self.client()?;
                match client.sign_transaction(&request) {
                    Ok(sig) => {
                        write!(ret, "to: 0x{}\nvalue: {} wei\n", to_hex, value_wei).unwrap();
                        write!(ret, "v={}\nr=", sig.v).unwrap();
                        for b in &sig.r {
                            write!(ret, "{:02x}", b).unwrap();
                        }
                        ret.push_str("\ns=");
                        for b in &sig.s {
                            write!(ret, "{:02x}", b).unwrap();
                        }
                        // Build the full signed transaction
                        let signed_tx = rlp_encode_signed_legacy_tx(
                            &to_addr, value_wei, &sig.v, &sig.r, &sig.s,
                        );
                        ret.push_str("\nraw: 0x");
                        for b in &signed_tx {
                            write!(ret, "{:02x}", b).unwrap();
                        }
                    }
                    Err(e) => write!(ret, "gentx failed: {:?}", e).unwrap(),
                }
            }
            _ => {
                write!(ret, "{}", helpstring).unwrap();
            }
        }

        Ok(Some(ret))
    }
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for chunk in s.as_bytes().chunks(2) {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Build RLP-encoded signed legacy transaction.
/// Fields: [nonce, gasPrice, gasLimit, to, value, data, v, r, s]
/// Hardcoded: nonce=0, gasPrice=1gwei, gasLimit=21000
fn rlp_encode_signed_legacy_tx(to: &[u8], value_wei: u64, v: &u64, r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
    let mut items = Vec::new();
    items.extend_from_slice(&rlp_encode_u64(0));           // nonce
    items.extend_from_slice(&rlp_encode_u64(1_000_000_000)); // gasPrice: 1 gwei
    items.extend_from_slice(&rlp_encode_u64(21_000));      // gasLimit
    items.extend_from_slice(&rlp_encode_bytes(to));        // to
    items.extend_from_slice(&rlp_encode_u64(value_wei));   // value
    items.extend_from_slice(&rlp_encode_bytes(&[]));       // data (empty)
    items.extend_from_slice(&rlp_encode_u64(*v));          // v
    items.extend_from_slice(&rlp_encode_bytes(trim_leading_zeros(r))); // r
    items.extend_from_slice(&rlp_encode_bytes(trim_leading_zeros(s))); // s
    rlp_encode_list(&items)
}

fn trim_leading_zeros(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    &bytes[start..]
}

/// Build RLP-encoded legacy EIP-155 transaction for signing.
/// Fields: [nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0]
/// Hardcoded: nonce=0, gasPrice=1gwei, gasLimit=21000, chainId=1
fn rlp_encode_legacy_tx(to: &[u8], value_wei: u64) -> Vec<u8> {
    let mut items = Vec::new();
    items.extend_from_slice(&rlp_encode_u64(0));           // nonce
    items.extend_from_slice(&rlp_encode_u64(1_000_000_000)); // gasPrice: 1 gwei
    items.extend_from_slice(&rlp_encode_u64(21_000));      // gasLimit
    items.extend_from_slice(&rlp_encode_bytes(to));        // to
    items.extend_from_slice(&rlp_encode_u64(value_wei));   // value
    items.extend_from_slice(&rlp_encode_bytes(&[]));       // data (empty)
    items.extend_from_slice(&rlp_encode_u64(1));           // chainId (mainnet)
    items.extend_from_slice(&rlp_encode_u64(0));           // 0 (EIP-155)
    items.extend_from_slice(&rlp_encode_u64(0));           // 0 (EIP-155)
    rlp_encode_list(&items)
}

fn rlp_encode_u64(value: u64) -> Vec<u8> {
    if value == 0 {
        return vec![0x80];
    }
    let bytes = value.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(8);
    let significant = &bytes[start..];
    if significant.len() == 1 && significant[0] < 0x80 {
        significant.to_vec()
    } else {
        let mut result = vec![0x80 + significant.len() as u8];
        result.extend_from_slice(significant);
        result
    }
}

fn rlp_encode_bytes(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return vec![0x80];
    }
    if data.len() == 1 && data[0] < 0x80 {
        return data.to_vec();
    }
    let mut result = vec![0x80 + data.len() as u8];
    result.extend_from_slice(data);
    result
}

fn rlp_encode_list(items: &[u8]) -> Vec<u8> {
    if items.len() <= 55 {
        let mut result = vec![0xc0 + items.len() as u8];
        result.extend_from_slice(items);
        result
    } else {
        let len_bytes = items.len().to_be_bytes();
        let start = len_bytes.iter().position(|&b| b != 0).unwrap_or(len_bytes.len());
        let len_bytes = &len_bytes[start..];
        let mut result = vec![0xf7 + len_bytes.len() as u8];
        result.extend_from_slice(len_bytes);
        result.extend_from_slice(items);
        result
    }
}
