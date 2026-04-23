//! Minimal Ethereum JSON-RPC client for fetching chain state.
//!
//! Used to gather the data needed to construct an unsigned transaction:
//! nonce, chain ID, gas price / EIP-1559 fees, gas estimate, balance.

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(15);

pub struct RpcClient {
    url: String,
    agent: ureq::Agent,
    id: u64,
}

impl RpcClient {
    pub fn new(url: &str) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout(TIMEOUT)
            .build();
        Self {
            url: url.to_string(),
            agent,
            id: 0,
        }
    }

    fn call(&mut self, method: &str, params: Value) -> Result<Value> {
        self.id += 1;
        let body = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": self.id,
        });
        let resp: Value = self
            .agent
            .post(&self.url)
            .set("Content-Type", "application/json")
            .send_json(body)
            .with_context(|| format!("RPC request failed: {}", method))?
            .into_json()
            .context("RPC response not valid JSON")?;

        if let Some(err) = resp.get("error") {
            bail!("RPC error from {}: {}", method, err);
        }
        Ok(resp.get("result").cloned().unwrap_or(Value::Null))
    }

    pub fn chain_id(&mut self) -> Result<u64> {
        let v = self.call("eth_chainId", json!([]))?;
        parse_hex_u64(&v)
    }

    pub fn balance(&mut self, address: &str) -> Result<u128> {
        let v = self.call("eth_getBalance", json!([address, "latest"]))?;
        parse_hex_u128(&v)
    }

    /// Pending nonce — counts in-flight transactions, what you want for new txs.
    pub fn nonce(&mut self, address: &str) -> Result<u64> {
        let v = self.call("eth_getTransactionCount", json!([address, "pending"]))?;
        parse_hex_u64(&v)
    }

    pub fn gas_price(&mut self) -> Result<u128> {
        let v = self.call("eth_gasPrice", json!([]))?;
        parse_hex_u128(&v)
    }

    /// Estimate gas for a transaction. Returns the raw estimate (caller may
    /// want to add a buffer of 1.1×–1.5× for safety).
    pub fn estimate_gas(
        &mut self,
        from: &str,
        to: &str,
        value: u128,
        data: &[u8],
    ) -> Result<u64> {
        let mut tx = serde_json::Map::new();
        tx.insert("from".into(), json!(from));
        tx.insert("to".into(), json!(to));
        if value > 0 {
            tx.insert("value".into(), json!(format!("0x{:x}", value)));
        }
        if !data.is_empty() {
            tx.insert("data".into(), json!(format!("0x{}", hex::encode(data))));
        }
        let v = self.call("eth_estimateGas", json!([Value::Object(tx)]))?;
        parse_hex_u64(&v)
    }

    /// Broadcast a signed transaction. Returns the transaction hash.
    pub fn send_raw_transaction(&mut self, signed_tx: &[u8]) -> Result<String> {
        let hex_tx = format!("0x{}", hex::encode(signed_tx));
        let v = self.call("eth_sendRawTransaction", json!([hex_tx]))?;
        v.as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("expected hex tx hash, got {:?}", v))
    }

    /// Get a transaction receipt. Returns None if the tx isn't mined yet.
    pub fn get_transaction_receipt(&mut self, tx_hash: &str) -> Result<Option<Value>> {
        let v = self.call("eth_getTransactionReceipt", json!([tx_hash]))?;
        if v.is_null() {
            Ok(None)
        } else {
            Ok(Some(v))
        }
    }

    /// EIP-1559 fee suggestion via eth_feeHistory.
    /// Returns Some((priority_fee_per_gas, base_fee_for_next_block)) if the
    /// chain supports EIP-1559, None otherwise.
    pub fn fee_suggestion(&mut self) -> Result<Option<FeeSuggestion>> {
        // Last 4 blocks, 50th percentile priority fee
        let v = match self.call("eth_feeHistory", json!(["0x4", "latest", [50.0]])) {
            Ok(v) => v,
            Err(_) => return Ok(None), // chain doesn't support EIP-1559
        };
        let base_fees = v
            .get("baseFeePerGas")
            .and_then(|b| b.as_array())
            .ok_or_else(|| anyhow!("missing baseFeePerGas"))?;
        // baseFeePerGas has N+1 entries (one for the next block)
        let next_base = base_fees
            .last()
            .ok_or_else(|| anyhow!("empty baseFeePerGas"))?;
        let next_base_fee = parse_hex_u128(next_base)?;

        let priority_fee = if let Some(rewards) = v.get("reward").and_then(|r| r.as_array()) {
            let mut sum = 0u128;
            let mut count = 0u128;
            for block in rewards {
                if let Some(percentiles) = block.as_array() {
                    if let Some(p) = percentiles.first() {
                        if let Ok(v) = parse_hex_u128(p) {
                            sum += v;
                            count += 1;
                        }
                    }
                }
            }
            if count > 0 {
                sum / count
            } else {
                1_500_000_000 // 1.5 gwei fallback
            }
        } else {
            1_500_000_000
        };

        Ok(Some(FeeSuggestion {
            priority_fee_per_gas: priority_fee,
            next_base_fee,
        }))
    }
}

pub struct FeeSuggestion {
    pub priority_fee_per_gas: u128,
    pub next_base_fee: u128,
}

impl FeeSuggestion {
    /// A safe maxFeePerGas: 2× current base fee + priority fee.
    /// (Base fee can rise up to 12.5% per block; 2× covers ~6 blocks of growth.)
    pub fn max_fee_per_gas(&self) -> u128 {
        self.next_base_fee.saturating_mul(2) + self.priority_fee_per_gas
    }
}

fn parse_hex_u64(v: &Value) -> Result<u64> {
    let s = v
        .as_str()
        .ok_or_else(|| anyhow!("expected hex string, got {:?}", v))?;
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(s, 16).context("parse hex u64")
}

fn parse_hex_u128(v: &Value) -> Result<u128> {
    let s = v
        .as_str()
        .ok_or_else(|| anyhow!("expected hex string, got {:?}", v))?;
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.is_empty() {
        return Ok(0);
    }
    u128::from_str_radix(s, 16).context("parse hex u128")
}
