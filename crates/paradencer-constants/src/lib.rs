pub mod address_lookup_table;
pub mod block_limits;
pub mod blockstore;
pub mod compute_budget_program;
pub mod config_program;
pub mod features;
pub mod genesis;
pub mod precompiles;
pub mod program_cache;

pub mod economics {
    // Fee constants
    pub const LAMPORTS_PER_SIGNATURE: u64 = 5_000;
    pub const DEFAULT_TARGET_SIGNATURES_PER_SLOT: u64 = 20_000;
    pub const DEFAULT_FEE_BURN_PERCENT: u8 = 50;
    pub const MIN_LAMPORTS_PER_SIGNATURE: u64 = 0;
    pub const MAX_LAMPORTS_PER_SIGNATURE: u64 = 100_000;

    // Rent and stake constants
    pub const RENT_EXEMPTION_BASE_LAMPORTS: u64 = 890_880;
    pub const RENT_EXEMPTION_LAMPORTS_PER_BYTE: u64 = 6_960;
    pub const MIN_STAKE_DELEGATION_LAMPORTS: u64 = 1_000_000_000;
    pub const BASE_NETWORK_SUPPLY_LAMPORTS: u64 = 1_000_000_000;
    pub const TOKEN_UI_DECIMALS_DIVISOR: f64 = 1_000_000_000_f64;
    pub const DEFAULT_VOTE_COMMISSION_PERCENT: u8 = 5;

    pub const INFLATION_FOUNDATION_RATE: f64 = 0.05_f64;
    pub const INFLATION_FOUNDATION_TERM: f64 = 7.0_f64;
    pub const INFLATION_INITIAL_RATE: f64 = 0.08_f64;
    pub const INFLATION_TAPER_RATE: f64 = 0.15_f64;
    pub const INFLATION_TERMINAL_RATE: f64 = 0.015_f64;
    pub const INFLATION_TOTAL_BASE_RATE: f64 = 0.06_f64;
    pub const INFLATION_EPOCH_DECAY_STEP: f64 = 0.00001_f64;

    pub const INFLATION_REWARD_MODULUS: u64 = 10_000;
    pub const INFLATION_REWARD_BASE_AMOUNT: i64 = 1_000;
}

pub mod ledger {
    pub const SLOTS_PER_EPOCH: u64 = 432_000;
    pub const RECENT_BLOCKHASH_VALIDITY_WINDOW: u64 = 150;
    pub const MAX_PERFORMANCE_SAMPLES: u64 = 32;
    pub const TICKS_PER_SLOT: u64 = 64;
    pub const DEFAULT_TICKS_PER_SECOND: u64 = 160;
    pub const DEFAULT_MS_PER_SLOT: u64 = 400;
    pub const GENESIS_EPOCH: u64 = 0;
    pub const GENESIS_SLOT: u64 = 0;

    // Nonce account constants
    pub const NONCE_ACCOUNT_SIZE: usize = 80; // Size of serialized nonce account data
}

pub mod consensus {
    pub const MAX_VALIDATORS_IN_SCHEDULE: usize = 5_000;
    pub const LEADER_SCHEDULE_SLOT_OFFSET: u64 = 432_000;
    pub const MIN_LEADER_SCHEDULE_EPOCH_OFFSET: u64 = 1;
    pub const VOTE_THRESHOLD_SIZE: f64 = 2.0_f64 / 3.0_f64;
    pub const SWITCH_FORK_THRESHOLD: f64 = 0.38_f64;
    pub const MAX_LOCKOUT_HISTORY: usize = 31;
    pub const VOTE_THRESHOLD_DEPTH: usize = 8;
    pub const INITIAL_LOCKOUT: u32 = 2;
    pub const MAX_EPOCH_CREDITS_HISTORY: usize = 64;
}

pub mod rpc {
    pub const DEFAULT_BLOCKS_END_OFFSET: u64 = 500;
    pub const MAX_BLOCKS_RANGE_LEN: u64 = 500;

    pub const SIGNATURES_FOR_ADDRESS_DEFAULT_LIMIT: u64 = 1_000;
    pub const SIGNATURES_FOR_ADDRESS_MAX_LIMIT: u64 = 1_000;
    pub const SIGNATURES_FOR_ADDRESS_RESPONSE_MAX_ROWS: u64 = 25;

    pub const PRIORITIZATION_FEE_ROWS: u64 = 16;
    pub const PRIORITIZATION_FEE_BASE: u64 = 100;
    pub const PRIORITIZATION_FEE_PER_ACCOUNT_STEP: u64 = 5;
    pub const PRIORITIZATION_FEE_PER_ROW_STEP: u64 = 3;

    pub const TVU_BASE_PORT: u16 = 8_000;
    pub const TVU_PORT_SLOT_MODULUS: u64 = 1_000;

    pub const DEFAULT_TOKEN_ACCOUNT_SPACE: u64 = 165;
    pub const MAX_SIGNATURE_CONFIRMATIONS: u64 = 32;
    pub const LEADER_SCHEDULE_ROTATION: u64 = 4;
    pub const LEADER_SCHEDULE_ENTRIES: u64 = 3;
    pub const VOTE_ROOT_SLOT_BACKTRACK: u64 = 32;
    pub const SLOT_LEADERS_MAX_LIMIT: u64 = 5_000;

    pub const TRANSACTION_ENCODING_BASE58: &str = "base58";
    pub const TRANSACTION_ENCODING_BASE64: &str = "base64";
    pub const TRANSACTION_ENCODING_JSON: &str = "json";
    pub const TRANSACTION_ENCODING_JSON_PARSED: &str = "jsonParsed";

    pub const SEND_TX_SIGNATURE_HASH_MULTIPLIER: u64 = 131;
    pub const SEND_TX_ENCODING_BONUS_BASE58: u64 = 17;
    pub const SEND_TX_ENCODING_BONUS_BASE64: u64 = 29;
    pub const SEND_TX_PREFLIGHT_PENALTY_SKIP: u64 = 3;
    pub const SEND_TX_PREFLIGHT_PENALTY_CHECK: u64 = 11;
    pub const SEND_TX_MAX_RETRIES_CAP: u64 = 64;
    pub const SEND_TX_COMMITMENT_BIAS_PROCESSED: u64 = 1;
    pub const SEND_TX_COMMITMENT_BIAS_CONFIRMED: u64 = 2;
    pub const SEND_TX_COMMITMENT_BIAS_FINALIZED: u64 = 3;

    pub const SIMULATE_MAX_ACCOUNTS: usize = 128;
    pub const SIMULATE_UNITS_CONSUMED_BASE: u64 = 5_000;
    pub const SIMULATE_UNITS_CONSUMED_SIG_VERIFY_BONUS: u64 = 500;
    pub const SIMULATE_UNITS_PER_TRANSACTION_CHAR: u64 = 2;
    pub const SIMULATE_UNITS_ENCODING_BASE58: u64 = 25;
    pub const SIMULATE_UNITS_ENCODING_BASE64: u64 = 10;
    pub const SIMULATE_ACCOUNT_LAMPORTS: u64 = 1_000_000;
    pub const SIMULATE_REPLACEMENT_BLOCKHASH_VALIDITY_OFFSET: u64 = 150;

    pub const WS_SNAPSHOT_FEED_INTERVAL_MILLIS: u64 = 250;
    pub const WS_SNAPSHOT_FEED_CHANNEL_CAPACITY: usize = 256;
}

pub mod time {
    pub const SYNTHETIC_UNIX_TIMESTAMP_BASE: i64 = 1_700_000_000_i64;
}

pub mod execution {
    // Compute unit limits
    pub const MAX_COMPUTE_UNIT_LIMIT: u64 = 1_400_000;
    pub const MAX_COMPUTE_UNITS: u64 = MAX_COMPUTE_UNIT_LIMIT; // Alias for compatibility
    pub const DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT: u64 = 200_000;
    pub const DEFAULT_COMPUTE_UNITS: u64 = 150;
    pub const MAX_BUILTIN_ALLOCATION_COMPUTE_UNIT_LIMIT: u64 = 3_000;

    // Heap size limits
    pub const MIN_HEAP_FRAME_BYTES: u32 = 32 * 1024; // 32KB
    pub const MAX_HEAP_FRAME_BYTES: u32 = 256 * 1024; // 256KB
    pub const DEFAULT_HEAP_FRAME_BYTES: u32 = 32 * 1024; // 32KB
    pub const HEAP_FRAME_BYTES_GRANULARITY: u32 = 1024;

    // Account data size limits
    pub const MAX_LOADED_ACCOUNTS_DATA_SIZE: u64 = 64 * 1024 * 1024; // 64MB

    // Legacy compute costs (deprecated but kept for reference)
    pub const DEFAULT_INSTRUCTION_BASE_COST: u64 = 150;
    pub const COMPUTE_UNIT_COST_PER_ACCOUNT: u64 = 100;
    pub const COMPUTE_UNIT_COST_PER_DATA_BYTE: u64 = 10;
    pub const COMPUTE_UNIT_COST_ACCOUNT_WRITEBACK: u64 = 200;
}

pub mod vote_program {
    // Vote program instruction types
    pub const INSTRUCTION_INITIALIZE_ACCOUNT: u32 = 0;
    pub const INSTRUCTION_AUTHORIZE: u32 = 1;
    pub const INSTRUCTION_VOTE: u32 = 2;
    pub const INSTRUCTION_WITHDRAW: u32 = 3;
    pub const INSTRUCTION_UPDATE_VALIDATOR_IDENTITY: u32 = 4;
    pub const INSTRUCTION_UPDATE_COMMISSION: u32 = 5;
    pub const INSTRUCTION_VOTE_SWITCH: u32 = 6;
    pub const INSTRUCTION_AUTHORIZE_CHECKED: u32 = 7;
    pub const INSTRUCTION_UPDATE_VOTE_STATE: u32 = 8;
    pub const INSTRUCTION_UPDATE_VOTE_STATE_SWITCH: u32 = 9;
    pub const INSTRUCTION_COMPACT_UPDATE_VOTE_STATE: u32 = 10;
    pub const INSTRUCTION_COMPACT_UPDATE_VOTE_STATE_SWITCH: u32 = 11;
    pub const INSTRUCTION_TOWER_SYNC: u32 = 12;
    pub const INSTRUCTION_TOWER_SYNC_SWITCH: u32 = 13;
    pub const INSTRUCTION_AUTHORIZE_WITH_SEED: u32 = 14;
    pub const INSTRUCTION_AUTHORIZE_CHECKED_WITH_SEED: u32 = 15;
    pub const INSTRUCTION_INITIALIZE_ACCOUNT_V2: u32 = 16;

    // Vote program error codes
    pub const ERR_VOTE_TOO_OLD: u32 = 0;
    pub const ERR_SLOTS_MISMATCH: u32 = 1;
    pub const ERR_SLOTS_HASH_MISMATCH: u32 = 2;
    pub const ERR_EMPTY_SLOTS: u32 = 3;
    pub const ERR_TIMESTAMP_TOO_OLD: u32 = 4;
    pub const ERR_TOO_SOON_TO_REAUTHORIZE: u32 = 5;
    pub const ERR_LOCKOUT_CONFLICT: u32 = 6;
    pub const ERR_NEW_VOTE_STATE_LOCKOUT_MISMATCH: u32 = 7;
    pub const ERR_SLOTS_NOT_ORDERED: u32 = 8;
    pub const ERR_CONFIRMATIONS_NOT_ORDERED: u32 = 9;
    pub const ERR_ZERO_CONFIRMATIONS: u32 = 10;
    pub const ERR_CONFIRMATION_TOO_LARGE: u32 = 11;
    pub const ERR_ROOT_ROLL_BACK: u32 = 12;
    pub const ERR_CONFIRMATION_ROLL_BACK: u32 = 13;
    pub const ERR_SLOT_SMALLER_THAN_ROOT: u32 = 14;
    pub const ERR_TOO_MANY_VOTES: u32 = 15;
    pub const ERR_VOTES_TOO_OLD_ALL_FILTERED: u32 = 16;
    pub const ERR_ROOT_ON_DIFFERENT_FORK: u32 = 17;
    pub const ERR_ACTIVE_VOTE_ACCOUNT_CLOSE: u32 = 18;
    pub const ERR_COMMISSION_UPDATE_TOO_LATE: u32 = 19;

    // Vote state constants
    pub const VOTE_CREDITS_MAXIMUM_PER_SLOT: u64 = 16;
    pub const VOTE_CREDITS_GRACE_SLOTS: u64 = 2;
    pub const DEFAULT_BLOCK_REVENUE_COMMISSION_BPS: u64 = 10_000;

    // Vote state sizes
    pub const VOTE_STATE_V2_SIZE: usize = 3731;
    pub const VOTE_STATE_V3_SIZE: usize = 3762;
    pub const VOTE_STATE_V4_SIZE: usize = 3762;

    // Vote program compute costs
    pub const COMPUTE_COST_INITIALIZE: u64 = 500;
    pub const COMPUTE_COST_VOTE: u64 = 800;
    pub const COMPUTE_COST_UPDATE_VOTE_STATE: u64 = 1200;
    pub const COMPUTE_COST_WITHDRAW: u64 = 400;
    pub const COMPUTE_COST_UPDATE_COMMISSION: u64 = 300;
    pub const COMPUTE_COST_AUTHORIZE: u64 = 350;
    pub const COMPUTE_COST_BASE_INSTRUCTION: u64 = 200;
}

pub mod system_program {
    // System program error codes
    pub const ERR_ACCOUNT_ALREADY_IN_USE: u32 = 0;
    pub const ERR_RESULT_WITH_NEGATIVE_LAMPORTS: u32 = 1;
    pub const ERR_INVALID_PROGRAM_ID: u32 = 2;
    pub const ERR_INVALID_ACCOUNT_DATA_LENGTH: u32 = 3;
    pub const ERR_MAX_SEED_LENGTH_EXCEEDED: u32 = 4;
    pub const ERR_ADDRESS_WITH_SEED_MISMATCH: u32 = 5;
    pub const ERR_NONCE_NO_RECENT_BLOCKHASHES: u32 = 6;
    pub const ERR_NONCE_BLOCKHASH_NOT_EXPIRED: u32 = 7;
    pub const ERR_NONCE_UNEXPECTED_BLOCKHASH_VALUE: u32 = 8;

    // Account size limits
    pub const MAX_ACCOUNT_DATA_SIZE: u64 = 10 * 1024 * 1024; // 10 MB
    pub const MAX_SEED_LENGTH: usize = 32;

    // Instruction compute costs
    pub const COMPUTE_COST_BASE: u64 = 150;
    pub const COMPUTE_COST_CREATE_ACCOUNT: u64 = 500;
    pub const COMPUTE_COST_TRANSFER: u64 = 300;
    pub const COMPUTE_COST_ASSIGN: u64 = 200;
    pub const COMPUTE_COST_ALLOCATE: u64 = 400;
    pub const COMPUTE_COST_NONCE_ADVANCE: u64 = 300;
    pub const COMPUTE_COST_NONCE_WITHDRAW: u64 = 400;
    pub const COMPUTE_COST_NONCE_INITIALIZE: u64 = 500;
    pub const COMPUTE_COST_NONCE_AUTHORIZE: u64 = 300;
}

pub mod stake_program {
    // Stake program instruction types
    pub const INSTRUCTION_INITIALIZE: u32 = 0;
    pub const INSTRUCTION_AUTHORIZE: u32 = 1;
    pub const INSTRUCTION_DELEGATE_STAKE: u32 = 2;
    pub const INSTRUCTION_SPLIT: u32 = 3;
    pub const INSTRUCTION_WITHDRAW: u32 = 4;
    pub const INSTRUCTION_DEACTIVATE: u32 = 5;
    pub const INSTRUCTION_SET_LOCKUP: u32 = 6;
    pub const INSTRUCTION_MERGE: u32 = 7;
    pub const INSTRUCTION_AUTHORIZE_WITH_SEED: u32 = 8;
    pub const INSTRUCTION_INITIALIZE_CHECKED: u32 = 9;
    pub const INSTRUCTION_AUTHORIZE_CHECKED: u32 = 10;
    pub const INSTRUCTION_AUTHORIZE_CHECKED_WITH_SEED: u32 = 11;
    pub const INSTRUCTION_SET_LOCKUP_CHECKED: u32 = 12;
    pub const INSTRUCTION_GET_MINIMUM_DELEGATION: u32 = 13;
    pub const INSTRUCTION_DEACTIVATE_DELINQUENT: u32 = 14;
    pub const INSTRUCTION_REDELEGATE: u32 = 15;
    pub const INSTRUCTION_MOVE_STAKE: u32 = 16;
    pub const INSTRUCTION_MOVE_LAMPORTS: u32 = 17;

    // Stake program error codes
    pub const ERR_NO_CREDITS_TO_REDEEM: u32 = 0;
    pub const ERR_LOCKUP_IN_FORCE: u32 = 1;
    pub const ERR_ALREADY_DEACTIVATED: u32 = 2;
    pub const ERR_TOO_SOON_TO_REDELEGATE: u32 = 3;
    pub const ERR_INSUFFICIENT_STAKE: u32 = 4;
    pub const ERR_MERGE_TRANSIENT_STAKE: u32 = 5;
    pub const ERR_MERGE_MISMATCH: u32 = 6;
    pub const ERR_CUSTODIAN_MISSING: u32 = 7;
    pub const ERR_CUSTODIAN_SIGNATURE_MISSING: u32 = 8;
    pub const ERR_INSUFFICIENT_REFERENCE_VOTES: u32 = 9;
    pub const ERR_VOTE_ADDRESS_MISMATCH: u32 = 10;
    pub const ERR_MINIMUM_DELINQUENT_EPOCHS_NOT_MET: u32 = 11;
    pub const ERR_INSUFFICIENT_DELEGATION: u32 = 12;
    pub const ERR_REDELEGATE_TRANSIENT_OR_INACTIVE: u32 = 13;
    pub const ERR_REDELEGATE_TO_SAME_VOTE_ACCOUNT: u32 = 14;
    pub const ERR_REDELEGATED_STAKE_MUST_ACTIVATE: u32 = 15;
    pub const ERR_EPOCH_REWARDS_ACTIVE: u32 = 16;

    // Stake state constants
    pub const STAKE_STATE_V2_SIZE: usize = 200;

    // Stake program compute costs
    pub const COMPUTE_COST_INITIALIZE: u64 = 500;
    pub const COMPUTE_COST_DELEGATE: u64 = 1000;
    pub const COMPUTE_COST_DEACTIVATE: u64 = 600;
    pub const COMPUTE_COST_WITHDRAW: u64 = 500;
    pub const COMPUTE_COST_AUTHORIZE: u64 = 400;
    pub const COMPUTE_COST_SPLIT: u64 = 800;
    pub const COMPUTE_COST_MERGE: u64 = 900;
    pub const COMPUTE_COST_BASE_INSTRUCTION: u64 = 250;
}

pub mod quic {
    pub const DEFAULT_MAX_CONCURRENT_CONNECTIONS: u32 = 2000;
    pub const DEFAULT_MAX_CONCURRENT_UNI_STREAMS: u64 = 128;
    pub const DEFAULT_MAX_CONCURRENT_BI_STREAMS: u64 = 0;
    pub const DEFAULT_MAX_IDLE_TIMEOUT_MS: u64 = 30_000;
    pub const DEFAULT_KEEP_ALIVE_INTERVAL_MS: u64 = 5_000;
    pub const DEFAULT_MAX_PACKET_SIZE: usize = 1280;
    pub const DEFAULT_INITIAL_MTU: u16 = 1200;

    pub const MAX_STREAM_READ_SIZE: usize = 10 * 1024 * 1024; // 10 MB
    pub const STREAM_READ_CHUNK_SIZE: usize = 64 * 1024; // 64 KB
    pub const MAX_PACKETS_PER_STREAM: usize = 128;
    pub const PACKET_CHANNEL_CAPACITY: usize = 4096;
    pub const PROCESSOR_BATCH_SIZE: usize = 256;
}

pub mod syscalls;
pub mod sysvars;

pub mod transaction {
    // Transaction format constants
    pub const SIGNATURE_SIZE: usize = 64;
    pub const PUBKEY_SIZE: usize = 32;
    pub const BLOCKHASH_SIZE: usize = 32;

    // Maximum limits
    pub const MAX_SIGNATURES: usize = 12;
    pub const MAX_ACCOUNTS: usize = 128;
    pub const MAX_INSTRUCTIONS: usize = 64;
    pub const MAX_TRANSACTION_SIZE: usize = 1232;
    pub const MIN_TRANSACTION_SIZE: usize = 134;

    // Transaction version constants
    pub const TRANSACTION_VERSION_LEGACY: u8 = 0xFF;
    pub const TRANSACTION_VERSION_V0: u8 = 0x00;

    // Deduplication cache settings
    pub const DEDUP_CACHE_CAPACITY: usize = 10_000;
    pub const DEDUP_CACHE_TTL_MS: u64 = 150_000; // 150 seconds (blockhash validity window)

    // Verification batch size
    pub const VERIFICATION_BATCH_SIZE: usize = 128;
}
