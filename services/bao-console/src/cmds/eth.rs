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

        let helpstring = "eth [ping|config|address|accounts|signmsg|sign|gentx|seedimport|mnimport|mngenerate|clearseed|dangerous]";

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
                // eth gentx <to> <value_wei> [nonce=N] [chain=ID] [gasprice=WEI] [gaslimit=N]
                if args.len() < 2 {
                    write!(ret, "eth gentx <to> <value_wei> [nonce=N] [chain=ID] [gasprice=WEI] [gaslimit=N]").unwrap();
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

                // Parse optional key=value parameters
                let mut nonce: u64 = 0;
                let mut chain_id: u64 = 11155111; // Sepolia
                let mut gas_price: u64 = 1_000_000_000; // 1 gwei
                let mut gas_limit: u64 = 21_000;
                for arg in args.iter().skip(2) {
                    if let Some((key, val)) = arg.split_once('=') {
                        match key {
                            "nonce" => nonce = val.parse().unwrap_or(0),
                            "chain" => chain_id = val.parse().unwrap_or(11155111),
                            "gasprice" => gas_price = val.parse().unwrap_or(1_000_000_000),
                            "gaslimit" => gas_limit = val.parse().unwrap_or(21_000),
                            _ => {
                                write!(ret, "unknown param: {}", key).unwrap();
                                return Ok(Some(ret));
                            }
                        }
                    }
                }

                let tx_params = TxParams { nonce, gas_price, gas_limit, chain_id };
                let tx_data = rlp_encode_legacy_tx(&to_addr, value_wei, &tx_params);

                let path = Bip32Path::ethereum(0, 0, 0);
                let request = SignTransactionRequest { path, tx_data };
                let client = self.client()?;
                match client.sign_transaction(&request) {
                    Ok(sig) => {
                        write!(ret, "chain: {} ({})\n", chain_id, chain_name(chain_id)).unwrap();
                        write!(ret, "to: 0x{}\n", to_hex).unwrap();
                        write!(ret, "value: {} wei\n", value_wei).unwrap();
                        write!(ret, "nonce: {}  gas: {}  gasPrice: {} wei\n",
                            nonce, gas_limit, gas_price).unwrap();
                        write!(ret, "v={}\nr=", sig.v).unwrap();
                        for b in &sig.r {
                            write!(ret, "{:02x}", b).unwrap();
                        }
                        ret.push_str("\ns=");
                        for b in &sig.s {
                            write!(ret, "{:02x}", b).unwrap();
                        }
                        let signed_tx = rlp_encode_signed_legacy_tx(
                            &to_addr, value_wei, &tx_params, &sig.v, &sig.r, &sig.s,
                        );
                        ret.push_str("\nraw: 0x");
                        for b in &signed_tx {
                            write!(ret, "{:02x}", b).unwrap();
                        }
                    }
                    Err(e) => write!(ret, "gentx failed: {:?}", e).unwrap(),
                }
            }
            "mngenerate" => {
                let client = self.client()?;
                match client.generate_mnemonic() {
                    Ok(()) => {
                        write!(ret, "mnemonic generated (check device screen)").unwrap();
                        // Show the derived address
                        let path = Bip32Path::ethereum(0, 0, 0);
                        if let Ok(addr) = client.get_address(&path) {
                            ret.push_str("\naddress[0]: 0x");
                            for b in &addr {
                                write!(ret, "{:02x}", b).unwrap();
                            }
                        }
                    }
                    Err(e) => write!(ret, "mngenerate failed: {:?}", e).unwrap(),
                }
            }
            "clearseed" => {
                let client = self.client()?;
                match client.clear_seed() {
                    Ok(()) => write!(ret, "seed cleared").unwrap(),
                    Err(e) => write!(ret, "clearseed failed: {:?}", e).unwrap(),
                }
            }
            "dangerous" => {
                let client = self.client()?;
                match client.enable_dangerous_mainnet() {
                    Ok(()) => {
                        write!(ret, "*** WARNING: DANGEROUS MAINNET MODE ENABLED ***\n").unwrap();
                        write!(ret, "This device has NO trusted display.\n").unwrap();
                        write!(ret, "Mainnet signing is now permitted for this session.\n").unwrap();
                        write!(ret, "YOU are responsible for verifying every transaction.\n").unwrap();
                        write!(ret, "The host software is UNTRUSTED. Resets on reboot.").unwrap();
                    }
                    Err(e) => write!(ret, "dangerous mode failed: {:?}", e).unwrap(),
                }
            }
            "mnimport" => {
                // eth mnimport <word1> <word2> ... <word12 or word24>
                if args.len() != 12 && args.len() != 24 {
                    write!(ret, "eth mnimport <12 or 24 BIP39 words>").unwrap();
                    return Ok(Some(ret));
                }
                let mnemonic = args.join(" ");
                let client = self.client()?;
                match client.import_mnemonic(&mnemonic) {
                    Ok(()) => {
                        write!(ret, "mnemonic imported").unwrap();
                        // Show the derived address
                        let path = Bip32Path::ethereum(0, 0, 0);
                        if let Ok(addr) = client.get_address(&path) {
                            ret.push_str("\naddress[0]: 0x");
                            for b in &addr {
                                write!(ret, "{:02x}", b).unwrap();
                            }
                        }
                    }
                    Err(e) => write!(ret, "mnimport failed: {:?}", e).unwrap(),
                }
            }
            "seedimport" => {
                // eth seedimport <128-char hex = 64 bytes>
                if args.len() != 1 {
                    write!(ret, "eth seedimport <64-byte-seed-hex>").unwrap();
                    return Ok(Some(ret));
                }
                let hex_str = args[0].strip_prefix("0x").unwrap_or(&args[0]);
                let seed_bytes = match hex_decode(hex_str) {
                    Some(b) if b.len() == 64 => {
                        let mut arr = [0u8; 64];
                        arr.copy_from_slice(&b);
                        arr
                    }
                    _ => {
                        write!(ret, "invalid seed (need exactly 64 bytes / 128 hex chars)").unwrap();
                        return Ok(Some(ret));
                    }
                };
                let client = self.client()?;
                match client.set_seed(&seed_bytes) {
                    Ok(()) => {
                        write!(ret, "seed imported (in-memory, lost on reboot)").unwrap();
                    }
                    Err(e) => write!(ret, "seedimport failed: {:?}", e).unwrap(),
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

struct TxParams {
    nonce: u64,
    gas_price: u64,
    gas_limit: u64,
    chain_id: u64,
}

/// Build RLP-encoded signed legacy transaction.
/// Fields: [nonce, gasPrice, gasLimit, to, value, data, v, r, s]
fn rlp_encode_signed_legacy_tx(
    to: &[u8], value_wei: u64, p: &TxParams, v: &u64, r: &[u8; 32], s: &[u8; 32],
) -> Vec<u8> {
    let mut items = Vec::new();
    items.extend_from_slice(&rlp_encode_u64(p.nonce));
    items.extend_from_slice(&rlp_encode_u64(p.gas_price));
    items.extend_from_slice(&rlp_encode_u64(p.gas_limit));
    items.extend_from_slice(&rlp_encode_bytes(to));
    items.extend_from_slice(&rlp_encode_u64(value_wei));
    items.extend_from_slice(&rlp_encode_bytes(&[]));       // data (empty)
    items.extend_from_slice(&rlp_encode_u64(*v));
    items.extend_from_slice(&rlp_encode_bytes(trim_leading_zeros(r)));
    items.extend_from_slice(&rlp_encode_bytes(trim_leading_zeros(s)));
    rlp_encode_list(&items)
}

fn trim_leading_zeros(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    &bytes[start..]
}

/// Build RLP-encoded legacy EIP-155 transaction for signing.
/// Fields: [nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0]
fn rlp_encode_legacy_tx(to: &[u8], value_wei: u64, p: &TxParams) -> Vec<u8> {
    let mut items = Vec::new();
    items.extend_from_slice(&rlp_encode_u64(p.nonce));
    items.extend_from_slice(&rlp_encode_u64(p.gas_price));
    items.extend_from_slice(&rlp_encode_u64(p.gas_limit));
    items.extend_from_slice(&rlp_encode_bytes(to));
    items.extend_from_slice(&rlp_encode_u64(value_wei));
    items.extend_from_slice(&rlp_encode_bytes(&[]));       // data (empty)
    items.extend_from_slice(&rlp_encode_u64(p.chain_id));
    items.extend_from_slice(&rlp_encode_u64(0));           // 0 (EIP-155)
    items.extend_from_slice(&rlp_encode_u64(0));           // 0 (EIP-155)
    rlp_encode_list(&items)
}

fn chain_name(id: u64) -> &'static str {
    match id {
        1 => "mainnet",
        5 => "goerli",
        11155111 => "sepolia",
        17000 => "holesky",
        10 => "optimism",
        42161 => "arbitrum",
        137 => "polygon",
        56 => "bsc",
        _ => "unknown",
    }
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
