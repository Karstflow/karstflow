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
    #[serde(rename = "paradencer-core")]
    pub paradencer_core: String,
    #[serde(rename = "feature-set")]
    pub feature_set: String,
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
    pub confirmations: u64,
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
