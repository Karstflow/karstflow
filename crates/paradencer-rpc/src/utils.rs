/// Utility functions for RPC operations
use crate::state::RpcCommitment;
use serde_json::Value;

/// Generate a deterministic blockhash from slot
pub fn generate_blockhash(slot: u64) -> String {
    format!("{:064x}", slot.wrapping_mul(0x9e3779b97f4a7c15))
}

/// Generate a synthetic transaction signature
pub fn generate_signature(data: &[u8], slot: u64) -> String {
    use std::hash::{Hash, Hasher};

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    data.hash(&mut hasher);
    slot.hash(&mut hasher);

    let hash = hasher.finish();
    bs58::encode(&hash.to_le_bytes())
        .into_string()
        .chars()
        .cycle()
        .take(88)
        .collect()
}

/// Parse commitment level from string
pub fn parse_commitment(commitment_str: &str) -> Option<RpcCommitment> {
    match commitment_str.to_lowercase().as_str() {
        "processed" => Some(RpcCommitment::Processed),
        "confirmed" => Some(RpcCommitment::Confirmed),
        "finalized" => Some(RpcCommitment::Finalized),
        _ => None,
    }
}

/// Convert commitment to string
pub fn commitment_to_string(commitment: RpcCommitment) -> &'static str {
    match commitment {
        RpcCommitment::Processed => "processed",
        RpcCommitment::Confirmed => "confirmed",
        RpcCommitment::Finalized => "finalized",
    }
}

/// Extract commitment from JSON value
pub fn extract_commitment(value: &Value) -> Option<RpcCommitment> {
    value
        .get("commitment")
        .and_then(|v| v.as_str())
        .and_then(parse_commitment)
}

/// Create a context object for RPC responses
pub fn create_context(slot: u64) -> Value {
    serde_json::json!({
        "slot": slot,
        "apiVersion": "1.18.0"
    })
}

/// Create a context with slot and optional fields
pub fn create_extended_context(slot: u64, extras: Vec<(&str, Value)>) -> Value {
    let mut context = serde_json::json!({
        "slot": slot,
        "apiVersion": "1.18.0"
    });

    if let Some(obj) = context.as_object_mut() {
        for (key, value) in extras {
            obj.insert(key.to_string(), value);
        }
    }

    context
}

/// Validate pubkey string format
pub fn validate_pubkey(pubkey: &str) -> bool {
    if pubkey.len() < 32 || pubkey.len() > 44 {
        return false;
    }

    bs58::decode(pubkey).into_vec().is_ok()
}

/// Validate signature string format
pub fn validate_signature(signature: &str) -> bool {
    if signature.len() != 88 {
        return false;
    }

    bs58::decode(signature).into_vec().is_ok()
}

/// Calculate rent exemption minimum balance
pub fn calculate_rent_exemption(data_len: usize) -> u64 {
    const LAMPORTS_PER_BYTE_YEAR: u64 = 3480;
    const EXEMPTION_THRESHOLD: u64 = 2;

    let account_size = data_len + 128; // Account overhead
    (account_size as u64 * LAMPORTS_PER_BYTE_YEAR * EXEMPTION_THRESHOLD) / 365
}

/// Format lamports to SOL
pub fn lamports_to_sol(lamports: u64) -> f64 {
    lamports as f64 / 1_000_000_000.0
}

/// Format SOL to lamports
pub fn sol_to_lamports(sol: f64) -> u64 {
    (sol * 1_000_000_000.0) as u64
}

/// Encode account data in various formats
pub fn encode_account_data(data: &[u8], encoding: &str) -> Value {
    match encoding {
        "base58" => {
            serde_json::json!([bs58::encode(data).into_string(), "base58"])
        }
        "base64" => {
            serde_json::json!([base64_encode(data), "base64"])
        }
        "base64+zstd" => {
            let compressed = compress_zstd(data);
            serde_json::json!([base64_encode(&compressed), "base64+zstd"])
        }
        "jsonParsed" => {
            serde_json::json!({
                "parsed": {},
                "program": "unknown",
                "space": data.len()
            })
        }
        _ => serde_json::json!([bs58::encode(data).into_string(), "base58"]),
    }
}

/// Encode raw bytes to base64 (standard alphabet, padded).
fn base64_encode(data: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    STANDARD.encode(data)
}

/// Compress data with zstd at default compression level.
fn compress_zstd(data: &[u8]) -> Vec<u8> {
    zstd::encode_all(data, 3).unwrap_or_else(|_| data.to_vec())
}

/// Calculate transaction fee based on signature count and compute units
pub fn calculate_transaction_fee(signature_count: usize, compute_units: u64) -> u64 {
    const LAMPORTS_PER_SIGNATURE: u64 = 5000;
    const LAMPORTS_PER_COMPUTE_UNIT: u64 = 1;

    (signature_count as u64 * LAMPORTS_PER_SIGNATURE) + (compute_units * LAMPORTS_PER_COMPUTE_UNIT)
}

/// Generate epoch schedule information
pub fn get_epoch_schedule() -> Value {
    serde_json::json!({
        "slotsPerEpoch": 432000,
        "leaderScheduleSlotOffset": 432000,
        "warmup": false,
        "firstNormalEpoch": 0,
        "firstNormalSlot": 0
    })
}

/// Generate inflation governor info
pub fn get_inflation_governor() -> Value {
    serde_json::json!({
        "initial": 0.08,
        "terminal": 0.015,
        "taper": 0.15,
        "foundation": 0.05,
        "foundationTerm": 7.0
    })
}

/// Generate version info
pub fn get_version_info() -> Value {
    serde_json::json!({
        "paradencer-core": "0.1.0",
        "protocol-version": "solana-2.1-compatible",
        "feature-set": 3580551974u32
    })
}

/// Slot timing utilities
pub mod slot_timing {
    const SLOT_DURATION_MS: u64 = 400;

    /// Convert slot to estimated timestamp
    pub fn slot_to_timestamp(slot: u64, genesis_timestamp: i64) -> i64 {
        genesis_timestamp + ((slot * SLOT_DURATION_MS) / 1000) as i64
    }

    /// Convert timestamp to estimated slot
    pub fn timestamp_to_slot(timestamp: i64, genesis_timestamp: i64) -> u64 {
        let elapsed_secs = (timestamp - genesis_timestamp).max(0) as u64;
        (elapsed_secs * 1000) / SLOT_DURATION_MS
    }

    /// Calculate slots per day
    pub const fn slots_per_day() -> u64 {
        (24 * 60 * 60 * 1000) / SLOT_DURATION_MS
    }

    /// Calculate slots per hour
    pub const fn slots_per_hour() -> u64 {
        (60 * 60 * 1000) / SLOT_DURATION_MS
    }
}

/// Data slice utilities
pub mod data_slice {
    use serde_json::Value;

    #[derive(Debug, Clone)]
    pub struct DataSlice {
        pub offset: usize,
        pub length: usize,
    }

    impl DataSlice {
        pub fn new(offset: usize, length: usize) -> Self {
            Self { offset, length }
        }

        pub fn apply<'a>(&self, data: &'a [u8]) -> &'a [u8] {
            let end = (self.offset + self.length).min(data.len());
            if self.offset >= data.len() {
                &[]
            } else {
                &data[self.offset..end]
            }
        }

        pub fn from_json(value: &Value) -> Option<Self> {
            let offset = value.get("offset")?.as_u64()? as usize;
            let length = value.get("length")?.as_u64()? as usize;
            Some(Self::new(offset, length))
        }
    }
}

/// Performance metrics utilities
pub mod metrics {
    use std::time::Instant;

    pub struct Timer {
        start: Instant,
        name: String,
    }

    impl Timer {
        pub fn new(name: impl Into<String>) -> Self {
            Self {
                start: Instant::now(),
                name: name.into(),
            }
        }

        pub fn elapsed_ms(&self) -> u64 {
            self.start.elapsed().as_millis() as u64
        }

        pub fn elapsed_us(&self) -> u64 {
            self.start.elapsed().as_micros() as u64
        }
    }

    impl Drop for Timer {
        fn drop(&mut self) {
            tracing::debug!(
                target: "rpc_metrics",
                "{} took {}μs",
                self.name,
                self.elapsed_us()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_blockhash() {
        let hash1 = generate_blockhash(1000);
        let hash2 = generate_blockhash(1001);

        assert_eq!(hash1.len(), 64);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_generate_signature() {
        let data = vec![1, 2, 3, 4];
        let sig1 = generate_signature(&data, 1000);
        let sig2 = generate_signature(&data, 1001);

        assert_eq!(sig1.len(), 88);
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_parse_commitment() {
        assert_eq!(
            parse_commitment("processed"),
            Some(RpcCommitment::Processed)
        );
        assert_eq!(
            parse_commitment("confirmed"),
            Some(RpcCommitment::Confirmed)
        );
        assert_eq!(
            parse_commitment("finalized"),
            Some(RpcCommitment::Finalized)
        );
        assert_eq!(parse_commitment("invalid"), None);
    }

    #[test]
    fn test_commitment_to_string() {
        assert_eq!(commitment_to_string(RpcCommitment::Processed), "processed");
        assert_eq!(commitment_to_string(RpcCommitment::Confirmed), "confirmed");
        assert_eq!(commitment_to_string(RpcCommitment::Finalized), "finalized");
    }

    #[test]
    fn test_validate_pubkey() {
        assert!(validate_pubkey("11111111111111111111111111111111"));
        assert!(!validate_pubkey("invalid"));
        assert!(!validate_pubkey(""));
    }

    #[test]
    fn test_calculate_rent_exemption() {
        let exemption = calculate_rent_exemption(100);
        assert!(exemption > 0);

        let exemption_large = calculate_rent_exemption(1000);
        assert!(exemption_large > exemption);
    }

    #[test]
    fn test_lamports_to_sol() {
        assert_eq!(lamports_to_sol(1_000_000_000), 1.0);
        assert_eq!(lamports_to_sol(500_000_000), 0.5);
        assert_eq!(lamports_to_sol(0), 0.0);
    }

    #[test]
    fn test_sol_to_lamports() {
        assert_eq!(sol_to_lamports(1.0), 1_000_000_000);
        assert_eq!(sol_to_lamports(0.5), 500_000_000);
        assert_eq!(sol_to_lamports(0.0), 0);
    }

    #[test]
    fn test_calculate_transaction_fee() {
        let fee = calculate_transaction_fee(1, 5000);
        assert_eq!(fee, 5000 + 5000); // 1 sig + 5000 CU
    }

    #[test]
    fn test_slot_timing() {
        use slot_timing::*;

        let genesis = 1600000000;
        let timestamp = slot_to_timestamp(1000, genesis);
        assert_eq!(timestamp, genesis + 400);

        let slot = timestamp_to_slot(timestamp, genesis);
        assert_eq!(slot, 1000);

        assert_eq!(slots_per_hour(), 9000);
        assert_eq!(slots_per_day(), 216000);
    }

    #[test]
    fn test_data_slice() {
        use data_slice::*;

        let data = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let slice = DataSlice::new(2, 5);

        let result = slice.apply(&data);
        assert_eq!(result, &[2, 3, 4, 5, 6]);
    }

    #[test]
    fn test_data_slice_boundary() {
        use data_slice::*;

        let data = vec![0, 1, 2, 3];
        let slice = DataSlice::new(2, 10); // Beyond length

        let result = slice.apply(&data);
        assert_eq!(result, &[2, 3]);
    }

    #[test]
    fn test_create_context() {
        let context = create_context(1000);
        assert_eq!(context["slot"], 1000);
        assert!(context["apiVersion"].is_string());
    }

    #[test]
    fn test_create_extended_context() {
        let context = create_extended_context(
            1000,
            vec![
                ("blockHeight", serde_json::json!(500)),
                ("totalTransactions", serde_json::json!(10000)),
            ],
        );

        assert_eq!(context["slot"], 1000);
        assert_eq!(context["blockHeight"], 500);
        assert_eq!(context["totalTransactions"], 10000);
    }

    #[test]
    fn test_encode_account_data_base58() {
        let data = vec![1, 2, 3, 4];
        let encoded = encode_account_data(&data, "base58");

        assert!(encoded.is_array());
        let arr = encoded.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[1], "base58");
    }

    #[test]
    fn test_metrics_timer() {
        use metrics::Timer;

        let timer = Timer::new("test");
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(timer.elapsed_ms() >= 10);
    }
}
