//! Service state management.
//!
//! This module manages the runtime state of the ethapp service,
//! including:
//! - Platform connections (TRNG, GAM, PDDB)
//! - Metadata cache (tokens, NFTs, domains, methods)
//! - Session settings
//!
//! # Security
//!
//! - Cached metadata is marked as UNVERIFIED unless signature checked
//! - Settings loaded from PDDB are validated on read
//! - State is cleared on service restart

use std::collections::BTreeMap;

use ethapp_common::{
    AppConfiguration, DomainInfo, EthAddress, EthAppError, MethodInfo, NftInfo, TokenInfo,
    PROTOCOL_VERSION,
};

#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
use crate::platform::XousPlatform;
#[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
use crate::platform::MockPlatform;

use crate::platform::Platform;

/// Maximum number of cached items per category.
const MAX_CACHE_SIZE: usize = 64;

/// Service state.
pub struct ServiceState {
    /// Platform abstraction.
    #[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
    pub platform: XousPlatform,
    #[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
    pub platform: MockPlatform,

    /// Application configuration.
    pub config: AppConfiguration,

    /// Imported seed (set at runtime via SetSeed opcode).
    pub imported_seed: Option<crate::crypto::Seed>,

    /// Cached attestation signing key (loaded from PDDB on first use).
    /// Independent of wallet seed — survives seed wipes.
    pub attestation_key: Option<k256::ecdsa::SigningKey>,

    /// DANGEROUS: when true, allows signing on mainnet chains even on
    /// displayless dev-mode/autoapprove builds. Must be explicitly
    /// enabled per session via the EnableDangerousMainnet opcode.
    /// Resets to false on service restart.
    pub dangerous_mainnet: bool,

    /// Cached token information (key: chain_id:address).
    token_cache: BTreeMap<(u64, EthAddress), TokenInfo>,

    /// Cached NFT information (key: chain_id:address).
    nft_cache: BTreeMap<(u64, EthAddress), NftInfo>,

    /// Cached domain resolutions (key: address).
    domain_cache: BTreeMap<EthAddress, DomainInfo>,

    /// Cached method information (key: chain_id:address:selector).
    method_cache: BTreeMap<(u64, EthAddress, [u8; 4]), MethodInfo>,

    /// Current context for metadata lookup.
    context_chain_id: Option<u64>,
    context_address: Option<EthAddress>,

    /// Statistics for debugging.
    stats: ServiceStats,
}

/// Service statistics.
#[derive(Default)]
pub struct ServiceStats {
    /// Number of successful sign operations.
    pub signs_completed: u64,
    /// Number of rejected operations.
    pub signs_rejected: u64,
    /// Number of errors.
    pub errors: u64,
}

impl ServiceState {
    /// Create a new service state.
    pub fn new() -> Self {
        Self {
            #[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
            platform: XousPlatform::new(),
            #[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
            platform: MockPlatform::new(),
            imported_seed: None,
            attestation_key: None,
            dangerous_mainnet: false,
            config: AppConfiguration {
                version_major: 0,
                version_minor: 1,
                version_patch: 0,
                blind_signing_enabled: cfg!(feature = "blind-signing"),
                eip712_filtering_enabled: true,
                eth2_supported: cfg!(feature = "eth2"),
                protocol_version: PROTOCOL_VERSION,
            },
            token_cache: BTreeMap::new(),
            nft_cache: BTreeMap::new(),
            domain_cache: BTreeMap::new(),
            method_cache: BTreeMap::new(),
            context_chain_id: None,
            context_address: None,
            stats: ServiceStats::default(),
        }
    }

    /// Initialize platform connections.
    pub fn init_platform(&mut self) -> Result<(), EthAppError> {
        self.platform.init()
    }

    // =========================================================================
    // Attestation Key
    // =========================================================================

    /// Get the attestation signing key, loading from PDDB if not cached.
    pub fn get_attestation_key(&mut self) -> Result<&k256::ecdsa::SigningKey, EthAppError> {
        if self.attestation_key.is_none() {
            if let Ok(Some(bytes)) = self.platform.load_value(crate::platform::PDDB_KEY_ATTESTATION) {
                if bytes.len() == 32 {
                    if let Ok(key) = k256::ecdsa::SigningKey::from_bytes(
                        (&bytes[..]).into()
                    ) {
                        self.attestation_key = Some(key);
                    }
                }
            }
        }
        self.attestation_key.as_ref().ok_or(EthAppError::AttestationNotInitialized)
    }

    // =========================================================================
    // Metadata Cache Operations
    // =========================================================================

    /// Add token info to cache.
    ///
    /// # Security
    ///
    /// Token info should be verified before caching.
    /// Caller must ensure signature validation if required.
    pub fn cache_token_info(&mut self, info: TokenInfo) -> bool {
        if self.token_cache.len() >= MAX_CACHE_SIZE {
            // Evict oldest entry (BTreeMap preserves insertion order approximately)
            if let Some(key) = self.token_cache.keys().next().cloned() {
                self.token_cache.remove(&key);
            }
        }

        let key = (info.chain_id, info.address);
        self.token_cache.insert(key, info);
        true
    }

    /// Look up token info from cache.
    pub fn get_token_info(&self, chain_id: u64, address: &EthAddress) -> Option<&TokenInfo> {
        self.token_cache.get(&(chain_id, *address))
    }

    /// Add NFT info to cache.
    pub fn cache_nft_info(&mut self, info: NftInfo) -> bool {
        if self.nft_cache.len() >= MAX_CACHE_SIZE {
            if let Some(key) = self.nft_cache.keys().next().cloned() {
                self.nft_cache.remove(&key);
            }
        }

        let key = (info.chain_id, info.address);
        self.nft_cache.insert(key, info);
        true
    }

    /// Look up NFT info from cache.
    pub fn get_nft_info(&self, chain_id: u64, address: &EthAddress) -> Option<&NftInfo> {
        self.nft_cache.get(&(chain_id, *address))
    }

    /// Add domain info to cache.
    pub fn cache_domain_info(&mut self, info: DomainInfo) -> bool {
        if self.domain_cache.len() >= MAX_CACHE_SIZE {
            if let Some(key) = self.domain_cache.keys().next().cloned() {
                self.domain_cache.remove(&key);
            }
        }

        let key = info.address;
        self.domain_cache.insert(key, info);
        true
    }

    /// Look up domain info from cache.
    pub fn get_domain_info(&self, address: &EthAddress) -> Option<&DomainInfo> {
        self.domain_cache.get(address)
    }

    /// Add method info to cache.
    pub fn cache_method_info(&mut self, info: MethodInfo) -> bool {
        if self.method_cache.len() >= MAX_CACHE_SIZE {
            if let Some(key) = self.method_cache.keys().next().cloned() {
                self.method_cache.remove(&key);
            }
        }

        let key = (info.chain_id, info.address, info.selector);
        self.method_cache.insert(key, info);
        true
    }

    /// Look up method info from cache.
    pub fn get_method_info(
        &self,
        chain_id: u64,
        address: &EthAddress,
        selector: &[u8; 4],
    ) -> Option<&MethodInfo> {
        self.method_cache.get(&(chain_id, *address, *selector))
    }

    /// Clear all cached metadata.
    pub fn clear_metadata_cache(&mut self) {
        self.token_cache.clear();
        self.nft_cache.clear();
        self.domain_cache.clear();
        self.method_cache.clear();
        self.context_chain_id = None;
        self.context_address = None;
    }

    // =========================================================================
    // Context Management
    // =========================================================================

    /// Set the current context for metadata lookup.
    pub fn set_context(&mut self, chain_id: u64, address: EthAddress) {
        self.context_chain_id = Some(chain_id);
        self.context_address = Some(address);
    }

    /// Get the current context.
    pub fn get_context(&self) -> Option<(u64, EthAddress)> {
        match (self.context_chain_id, self.context_address) {
            (Some(chain_id), Some(address)) => Some((chain_id, address)),
            _ => None,
        }
    }

    /// Clear the current context.
    pub fn clear_context(&mut self) {
        self.context_chain_id = None;
        self.context_address = None;
    }

    // =========================================================================
    // Statistics
    // =========================================================================

    /// Record a successful signing operation.
    pub fn record_sign_success(&mut self) {
        self.stats.signs_completed += 1;
    }

    /// Record a rejected operation.
    pub fn record_sign_rejected(&mut self) {
        self.stats.signs_rejected += 1;
    }

    /// Record an error.
    pub fn record_error(&mut self) {
        self.stats.errors += 1;
    }

    /// Get current statistics.
    pub fn get_stats(&self) -> &ServiceStats {
        &self.stats
    }
}

impl Default for ServiceState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_cache() {
        let mut state = ServiceState::new();

        let info = TokenInfo {
            chain_id: 1,
            address: [0xde; 20],
            ticker: "TEST".into(),
            decimals: 18,
        };

        assert!(state.cache_token_info(info.clone()));
        let cached = state.get_token_info(1, &[0xde; 20]);
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().ticker, "TEST");
    }

    #[test]
    fn test_context() {
        let mut state = ServiceState::new();

        assert!(state.get_context().is_none());

        state.set_context(1, [0xab; 20]);
        let ctx = state.get_context();
        assert!(ctx.is_some());
        let (chain_id, address) = ctx.unwrap();
        assert_eq!(chain_id, 1);
        assert_eq!(address, [0xab; 20]);

        state.clear_context();
        assert!(state.get_context().is_none());
    }

    #[test]
    fn test_cache_eviction() {
        let mut state = ServiceState::new();

        // Fill cache beyond limit
        for i in 0..MAX_CACHE_SIZE + 10 {
            let info = TokenInfo {
                chain_id: i as u64,
                address: [i as u8; 20],
                ticker: "T".into(),
                decimals: 18,
            };
            state.cache_token_info(info);
        }

        // Cache should not exceed MAX_CACHE_SIZE
        assert!(state.token_cache.len() <= MAX_CACHE_SIZE);
    }
}
