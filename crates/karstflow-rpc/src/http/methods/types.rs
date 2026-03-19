use serde::Serialize;

// ── Serialization helper ──

/// Convert a typed response struct to `serde_json::Value`.
pub fn to_value<T: Serialize>(response: &T) -> serde_json::Value {
    serde_json::to_value(response).expect("response serialization failed")
}

// ── Common wrapper types ──

#[derive(Serialize, Debug, Clone)]
pub struct RpcContext {
    pub slot: u64,
}

/// Generic JSON-RPC response wrapper: `{ "context": { "slot": N }, "value": T }`.
#[derive(Serialize, Debug, Clone)]
pub struct RpcResponse<T: Serialize> {
    pub context: RpcContext,
    pub value: T,
}

impl<T: Serialize> RpcResponse<T> {
    pub fn new(slot: u64, value: T) -> Self {
        Self {
            context: RpcContext { slot },
            value,
        }
    }
}

// ── Basic / Epoch types ──

#[derive(Serialize, Debug, Clone)]
pub struct GetVersionResponse {
    #[serde(rename = "solana-core")]
    pub solana_core: String,
    #[serde(rename = "feature-set")]
    pub feature_set: u32,
}

#[derive(Serialize, Debug, Clone)]
pub struct GetIdentityResponse {
    pub identity: String,
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct EpochSchedule {
    pub slots_per_epoch: u64,
    pub leader_schedule_slot_offset: u64,
    pub warmup: bool,
    pub first_normal_epoch: u64,
    pub first_normal_slot: u64,
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct EpochInfo {
    pub absolute_slot: u64,
    pub block_height: u64,
    pub epoch: u64,
    pub slot_index: u64,
    pub slots_in_epoch: u64,
    pub transaction_count: u64,
}

#[derive(Serialize, Debug, Clone)]
pub struct HighestSnapshotSlot {
    pub full: u64,
    pub incremental: u64,
}

// ── Ledger / Blockhash types ──

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FeeCalculator {
    pub lamports_per_signature: u64,
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LatestBlockhashValue {
    pub blockhash: String,
    pub last_valid_block_height: u64,
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RecentBlockhashValue {
    pub blockhash: String,
    pub fee_calculator: FeeCalculator,
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FeesValue {
    pub blockhash: String,
    pub fee_calculator: FeeCalculator,
    pub last_valid_slot: u64,
    pub last_valid_block_height: u64,
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PerformanceSample {
    pub slot: u64,
    pub num_transactions: u64,
    pub num_slots: u64,
    pub sample_period_secs: u64,
    pub num_non_vote_transactions: u64,
}

// ── Account types ──

/// Encoded account data — serializes as `["encoded_string", "encoding_name"]`.
#[derive(Serialize, Debug, Clone)]
#[serde(untagged)]
pub enum AccountData {
    Encoded(String, String),
    JsonParsed {
        program: String,
        parsed: serde_json::Value,
    },
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AccountValue {
    pub lamports: u64,
    pub owner: String,
    pub executable: bool,
    pub rent_epoch: u64,
    pub data: AccountData,
    pub space: usize,
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TokenAmount {
    pub amount: String,
    pub decimals: u8,
    pub ui_amount: f64,
    pub ui_amount_string: String,
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SupplyValue {
    pub total: u64,
    pub circulating: u64,
    pub non_circulating: u64,
    pub non_circulating_accounts: Vec<String>,
}

#[derive(Serialize, Debug, Clone)]
pub struct LargestAccount {
    pub address: String,
    pub lamports: u64,
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TokenLargestAccount {
    pub address: String,
    pub amount: String,
    pub decimals: u8,
    pub ui_amount: f64,
    pub ui_amount_string: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct ProgramAccount {
    pub pubkey: String,
    pub account: AccountValue,
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SignatureStatus {
    pub slot: u64,
    pub confirmations: Option<u64>,
    pub status: serde_json::Value,
    pub err: serde_json::Value,
    pub confirmation_status: String,
}

// ── Inflation types ──

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct InflationGovernor {
    pub foundation: f64,
    pub foundation_term: f64,
    pub initial: f64,
    pub taper: f64,
    pub terminal: f64,
}

#[derive(Serialize, Debug, Clone)]
pub struct InflationRate {
    pub total: f64,
    pub validator: f64,
    pub foundation: f64,
    pub epoch: u64,
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct InflationReward {
    pub epoch: u64,
    pub effective_slot: u64,
    pub amount: i64,
    pub post_balance: u64,
    pub commission: u8,
}

// ── Transaction simulation types ──

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SimulateTransactionValue {
    pub err: serde_json::Value,
    pub logs: serde_json::Value,
    pub units_consumed: u64,
    pub accounts: serde_json::Value,
    pub return_data: serde_json::Value,
    pub replacement_blockhash: serde_json::Value,
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SimulateAccountValue {
    pub lamports: u64,
    pub owner: String,
    pub executable: bool,
    pub rent_epoch: u64,
    pub space: usize,
    pub data: AccountData,
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ReturnData {
    pub program_id: String,
    pub data: (String, String),
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ReplacementBlockhash {
    pub blockhash: String,
    pub last_valid_block_height: u64,
}

// ── Cluster types ──

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ClusterNode {
    pub pubkey: String,
    pub gossip: Option<String>,
    pub tpu: Option<String>,
    pub rpc: Option<String>,
    pub version: Option<String>,
    pub feature_set: Option<u64>,
    pub shred_version: u16,
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct VoteAccountInfo {
    pub vote_pubkey: String,
    pub node_pubkey: String,
    pub activated_stake: u64,
    pub epoch_vote_account: bool,
    pub commission: u8,
    pub last_vote: u64,
    pub root_slot: u64,
    pub epoch_credits: Vec<(u64, u64, u64)>,
}

#[derive(Serialize, Debug, Clone)]
pub struct VoteAccountsResponse {
    pub current: Vec<VoteAccountInfo>,
    pub delinquent: Vec<VoteAccountInfo>,
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BlockProductionValue {
    pub by_identity: serde_json::Value,
    pub range: BlockProductionRange,
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BlockProductionRange {
    pub first_slot: u64,
    pub last_slot: u64,
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PrioritizationFee {
    pub slot: u64,
    pub prioritization_fee: u64,
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SignatureForAddress {
    pub signature: String,
    pub slot: u64,
    pub err: serde_json::Value,
    pub memo: serde_json::Value,
    pub block_time: Option<i64>,
    pub confirmation_status: String,
}

// ── History types ──

#[derive(Serialize, Debug, Clone)]
pub struct BlockCommitmentResponse {
    pub commitment: Option<Vec<u64>>,
    #[serde(rename = "totalStake")]
    pub total_stake: u64,
}

// ── WebSocket notification types ──

#[derive(Serialize, Debug, Clone)]
pub struct SlotNotification {
    pub parent: u64,
    pub slot: u64,
    pub root: u64,
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AccountNotificationValue {
    pub lamports: u64,
    pub owner: String,
    pub data: AccountData,
    pub executable: bool,
    pub rent_epoch: u64,
    pub pubkey: String,
    pub space: usize,
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SignatureNotificationValue {
    pub err: serde_json::Value,
    pub confirmation_status: &'static str,
    pub signature: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct VoteNotification {
    pub hash: String,
    pub slots: Vec<u64>,
    pub timestamp: u128,
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LogsNotificationValue {
    pub signature: String,
    pub err: serde_json::Value,
    #[serde(rename = "logsFilter")]
    pub logs_filter: String,
    pub logs: Vec<String>,
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ProgramNotificationAccount {
    pub lamports: u64,
    pub owner: String,
    pub data: AccountData,
    pub executable: bool,
    pub rent_epoch: u64,
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ProgramNotificationValue {
    pub pubkey: String,
    pub account: ProgramNotificationAccount,
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ProgramNotificationSyntheticValue {
    pub pubkey: String,
    #[serde(rename = "filtersApplied")]
    pub filters_applied: serde_json::Value,
    pub account: ProgramNotificationAccount,
}

#[derive(Serialize, Debug, Clone)]
pub struct SlotsUpdateNotification {
    #[serde(rename = "type")]
    pub update_type: &'static str,
    pub slot: u64,
    pub parent: u64,
    pub timestamp: u128,
}

#[derive(Serialize, Debug, Clone)]
pub struct ProgramFilterDataSize {
    #[serde(rename = "dataSize")]
    pub data_size: u64,
}

#[derive(Serialize, Debug, Clone)]
pub struct ProgramFilterMemcmp {
    pub memcmp: ProgramFilterMemcmpInner,
}

#[derive(Serialize, Debug, Clone)]
pub struct ProgramFilterMemcmpInner {
    pub offset: usize,
    pub bytes: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_value_serializes_struct() {
        let resp = GetVersionResponse {
            solana_core: "2.2.0".into(),
            feature_set: 4_215_500_110,
        };
        let val = to_value(&resp);
        assert_eq!(val["solana-core"], "2.2.0");
        assert_eq!(val["feature-set"], 4_215_500_110_u64);
    }

    #[test]
    fn rpc_response_wraps_value() {
        let resp = RpcResponse::new(42, true);
        let val = to_value(&resp);
        assert_eq!(val["context"]["slot"], 42);
        assert_eq!(val["value"], true);
    }

    #[test]
    fn rpc_response_with_null_value() {
        let resp: RpcResponse<Option<u64>> = RpcResponse::new(0, None);
        let val = to_value(&resp);
        assert!(val["value"].is_null());
    }

    #[test]
    fn epoch_info_camel_case_fields() {
        let info = EpochInfo {
            absolute_slot: 100,
            block_height: 50,
            epoch: 1,
            slot_index: 10,
            slots_in_epoch: 432000,
            transaction_count: 999,
        };
        let val = to_value(&info);
        assert_eq!(val["absoluteSlot"], 100);
        assert_eq!(val["blockHeight"], 50);
        assert_eq!(val["slotsInEpoch"], 432000);
    }

    #[test]
    fn account_data_encoded_variant() {
        let data = AccountData::Encoded("abc".into(), "base64".into());
        let val = to_value(&data);
        let arr = val.as_array().unwrap();
        assert_eq!(arr[0], "abc");
        assert_eq!(arr[1], "base64");
    }

    #[test]
    fn account_data_json_parsed_variant() {
        let data = AccountData::JsonParsed {
            program: "spl-token".into(),
            parsed: serde_json::json!({"type": "account"}),
        };
        let val = to_value(&data);
        assert_eq!(val["program"], "spl-token");
        assert!(val["parsed"].is_object());
    }

    #[test]
    fn fee_calculator_camel_case() {
        let fc = FeeCalculator {
            lamports_per_signature: 5000,
        };
        let val = to_value(&fc);
        assert_eq!(val["lamportsPerSignature"], 5000);
    }

    #[test]
    fn slot_notification_fields() {
        let notif = SlotNotification {
            parent: 99,
            slot: 100,
            root: 68,
        };
        let val = to_value(&notif);
        assert_eq!(val["parent"], 99);
        assert_eq!(val["slot"], 100);
        assert_eq!(val["root"], 68);
    }

    #[test]
    fn cluster_node_optional_fields() {
        let node = ClusterNode {
            pubkey: "abc".into(),
            gossip: None,
            tpu: Some("127.0.0.1:8001".into()),
            rpc: None,
            version: Some("1.0.0".into()),
            feature_set: None,
            shred_version: 42,
        };
        let val = to_value(&node);
        assert_eq!(val["pubkey"], "abc");
        assert!(val["gossip"].is_null());
        assert_eq!(val["tpu"], "127.0.0.1:8001");
        assert_eq!(val["shredVersion"], 42);
    }

    #[test]
    fn inflation_governor_fields() {
        let gov = InflationGovernor {
            foundation: 0.05,
            foundation_term: 7.0,
            initial: 0.08,
            taper: 0.15,
            terminal: 0.015,
        };
        let val = to_value(&gov);
        assert_eq!(val["initial"], 0.08);
        assert_eq!(val["terminal"], 0.015);
    }

    #[test]
    fn prioritization_fee_camel_case() {
        let fee = PrioritizationFee {
            slot: 500,
            prioritization_fee: 1000,
        };
        let val = to_value(&fee);
        assert_eq!(val["slot"], 500);
        assert_eq!(val["prioritizationFee"], 1000);
    }
}
