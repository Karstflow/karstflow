use paradencer_types::{Pubkey, PUBKEY_BYTES};

/// System Program ID - handles account creation, transfers, and allocation
pub const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::new([0u8; PUBKEY_BYTES]);

/// Vote Program ID - handles validator voting and stake delegation
pub const VOTE_PROGRAM_ID: Pubkey = Pubkey::new([
    7, 97, 72, 29, 53, 116, 116, 187, 124, 77, 118, 36, 235, 211, 189, 179, 216, 53, 94, 115, 209,
    16, 67, 252, 13, 163, 83, 128, 0, 0, 0, 0,
]);

/// Stake Program ID - handles stake delegation and rewards
/// Stake11111111111111111111111111111111111111
pub const STAKE_PROGRAM_ID: Pubkey = Pubkey::new([
    6, 161, 216, 23, 145, 55, 84, 42, 152, 52, 55, 189, 254, 42, 122, 178, 85, 127, 83, 92, 138,
    120, 114, 43, 104, 164, 157, 192, 0, 0, 0, 0,
]);

/// SPL Token Program ID - handles fungible token operations
/// TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
pub const TOKEN_PROGRAM_ID: Pubkey = Pubkey::new([
    6, 221, 246, 225, 215, 101, 161, 147, 217, 203, 225, 70, 206, 235, 121, 172, 28, 180, 133, 237,
    95, 91, 55, 145, 58, 140, 245, 133, 126, 255, 0, 169,
]);

/// BPF Loader Program ID - handles custom BPF program loading and execution
/// BPFLoaderUpgradeab1e11111111111111111111111
pub const BPF_LOADER_PROGRAM_ID: Pubkey = Pubkey::new([
    2, 168, 246, 145, 78, 136, 161, 107, 189, 35, 149, 133, 95, 100, 4, 217, 180, 186, 232, 154,
    116, 170, 109, 102, 96, 0, 0, 0, 0, 0, 0, 0,
]);

/// SPL Token-2022 Program ID - handles Token Program with extensions
/// TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb
pub const TOKEN_2022_PROGRAM_ID: Pubkey = Pubkey::new([
    6, 221, 246, 225, 218, 117, 190, 239, 122, 225, 172, 90, 194, 172, 9, 203, 93, 7, 164, 94, 23,
    98, 89, 102, 145, 98, 234, 217, 137, 254, 0, 118,
]);

/// SPL Associated Token Account Program ID - manages associated token accounts
/// ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL
pub const ASSOCIATED_TOKEN_PROGRAM_ID: Pubkey = Pubkey::new([
    140, 151, 37, 143, 78, 36, 137, 241, 187, 61, 16, 41, 20, 142, 13, 131, 11, 90, 19, 153, 218,
    255, 16, 132, 4, 142, 123, 216, 219, 233, 248, 89,
]);

/// SPL Memo Program ID (v1) - records UTF-8 messages in transaction logs
/// Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo
pub const MEMO_PROGRAM_ID: Pubkey = Pubkey::new([
    5, 74, 83, 97, 55, 90, 145, 186, 125, 140, 146, 79, 97, 51, 175, 8, 100, 72, 198, 87, 70, 130,
    54, 14, 176, 135, 167, 168, 233, 25, 221, 0,
]);

/// SPL Memo Program ID (v3) - newer version with improved validation
/// MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr
pub const MEMO_PROGRAM_V3_ID: Pubkey = Pubkey::new([
    5, 74, 83, 99, 9, 162, 142, 187, 241, 11, 151, 64, 136, 141, 221, 137, 87, 162, 189, 176, 18,
    198, 137, 128, 137, 180, 63, 143, 34, 123, 73, 165,
]);

/// Address Lookup Table Program ID - manages versioned transaction lookup tables
/// AddressLookupTab1e1111111111111111111111111
pub const ADDRESS_LOOKUP_TABLE_PROGRAM_ID: Pubkey = Pubkey::new([
    4, 133, 52, 245, 98, 251, 80, 133, 199, 173, 120, 183, 202, 183, 164, 158, 42, 107, 32, 198,
    44, 49, 93, 134, 13, 160, 0, 0, 0, 0, 0, 0,
]);

/// Compute Budget Program ID - sets per-transaction compute limits
/// ComputeBudget111111111111111111111111111111
pub const COMPUTE_BUDGET_PROGRAM_ID: Pubkey = Pubkey::new([
    3, 6, 70, 111, 229, 33, 23, 50, 255, 236, 173, 186, 114, 195, 155, 231, 188, 140, 229, 187,
    197, 247, 18, 107, 44, 67, 0, 0, 0, 0, 0, 0,
]);

/// Config Program ID - stores configuration data on-chain
/// Config1111111111111111111111111111111111111
pub const CONFIG_PROGRAM_ID: Pubkey = Pubkey::new([
    3, 6, 18, 108, 178, 137, 242, 44, 249, 84, 157, 82, 6, 234, 105, 62, 97, 119, 1, 192, 120, 69,
    146, 137, 0, 0, 0, 0, 0, 0, 0, 0,
]);

/// Ed25519 signature verification precompile
/// Ed25519SigVerify111111111111111111111111111
pub const ED25519_PROGRAM_ID: Pubkey = Pubkey::new([
    3, 125, 70, 166, 52, 91, 247, 32, 14, 208, 73, 151, 48, 86, 222, 124, 200, 134, 133, 33, 163,
    89, 17, 106, 55, 182, 46, 138, 0, 0, 0, 0,
]);

/// Secp256k1 ECDSA recovery precompile
/// KeccakSecp256k11111111111111111111111111111
pub const SECP256K1_PROGRAM_ID: Pubkey = Pubkey::new([
    6, 163, 105, 129, 210, 14, 50, 50, 105, 161, 226, 85, 175, 113, 231, 188, 93, 10, 225, 176, 68,
    94, 13, 94, 116, 92, 75, 127, 0, 0, 0, 0,
]);

// ---------------------------------------------------------------------------
// Sysvar account addresses
// ---------------------------------------------------------------------------

/// Sysvar program owner for all sysvar accounts.
/// Sysvar1111111111111111111111111111111111111
pub const SYSVAR_PROGRAM_ID: Pubkey = Pubkey::new([
    6, 167, 213, 23, 24, 199, 116, 201, 40, 86, 99, 152, 105, 29, 94, 182, 139, 94, 184, 163, 155,
    75, 109, 92, 115, 85, 91, 42, 0, 0, 0, 0,
]);

/// Clock sysvar - SysvarC1ock11111111111111111111111111111111
pub const CLOCK_SYSVAR_ID: Pubkey = Pubkey::new([
    6, 167, 213, 23, 24, 199, 116, 201, 40, 86, 99, 152, 105, 29, 94, 182, 139, 94, 184, 163, 155,
    75, 109, 92, 115, 85, 91, 42, 0, 0, 0, 0,
]);

/// EpochSchedule sysvar - SysvarEpochSchedu1e111111111111111111111111
pub const EPOCH_SCHEDULE_SYSVAR_ID: Pubkey = Pubkey::new([
    6, 167, 213, 23, 25, 44, 92, 81, 33, 140, 201, 76, 142, 17, 155, 231, 94, 33, 154, 86, 85, 238,
    218, 128, 75, 27, 203, 76, 0, 0, 0, 0,
]);

/// Rent sysvar - SysvarRent111111111111111111111111111111111
pub const RENT_SYSVAR_ID: Pubkey = Pubkey::new([
    6, 167, 213, 23, 25, 47, 10, 175, 198, 242, 101, 227, 251, 119, 204, 122, 218, 130, 197, 41,
    208, 190, 59, 19, 110, 45, 0, 0, 0, 0, 0, 0,
]);

/// SlotHashes sysvar - SysvarS1otHashes111111111111111111111111111
pub const SLOT_HASHES_SYSVAR_ID: Pubkey = Pubkey::new([
    6, 167, 213, 23, 25, 44, 86, 142, 224, 138, 132, 95, 115, 210, 151, 136, 207, 3, 92, 49, 69,
    178, 26, 179, 68, 216, 6, 46, 0, 0, 0, 0,
]);

/// SlotHistory sysvar - SysvarS1otHistory11111111111111111111111111
pub const SLOT_HISTORY_SYSVAR_ID: Pubkey = Pubkey::new([
    6, 167, 213, 23, 25, 44, 86, 142, 224, 138, 132, 95, 115, 210, 151, 136, 207, 3, 92, 49, 69,
    178, 26, 180, 68, 216, 6, 46, 0, 0, 0, 0,
]);

/// StakeHistory sysvar - SysvarStakeHistory1111111111111111111111111
pub const STAKE_HISTORY_SYSVAR_ID: Pubkey = Pubkey::new([
    6, 167, 213, 23, 25, 47, 10, 175, 198, 242, 101, 227, 251, 119, 204, 122, 218, 130, 197, 41,
    208, 190, 59, 19, 110, 45, 0, 0, 0, 1, 0, 0,
]);

/// RecentBlockhashes sysvar (deprecated) - SysvarRecentB1telephones11111111111111
pub const RECENT_BLOCKHASHES_SYSVAR_ID: Pubkey = Pubkey::new([
    6, 167, 213, 23, 25, 47, 10, 175, 198, 242, 101, 227, 251, 119, 204, 122, 218, 130, 197, 41,
    208, 190, 59, 19, 110, 45, 0, 0, 0, 2, 0, 0,
]);

/// Instructions sysvar - Sysvar1nstructions1111111111111111111111111
pub const INSTRUCTIONS_SYSVAR_ID: Pubkey = Pubkey::new([
    6, 167, 213, 23, 24, 117, 247, 41, 0, 117, 43, 2, 118, 106, 216, 124, 150, 130, 158, 181, 119,
    90, 0, 114, 63, 124, 0, 0, 0, 0, 0, 0,
]);

/// EpochRewards sysvar - SysvarEpochRewards1111111111111111111111111
pub const EPOCH_REWARDS_SYSVAR_ID: Pubkey = Pubkey::new([
    6, 167, 213, 23, 25, 44, 92, 81, 33, 140, 201, 76, 142, 17, 155, 231, 94, 33, 154, 86, 85, 238,
    218, 128, 75, 27, 203, 77, 0, 0, 0, 0,
]);

/// LastRestartSlot sysvar - SysvarLastRestartS1ot1111111111111111111111
pub const LAST_RESTART_SLOT_SYSVAR_ID: Pubkey = Pubkey::new([
    6, 167, 213, 23, 24, 226, 173, 203, 107, 100, 198, 181, 229, 149, 30, 159, 68, 129, 202, 165,
    244, 253, 112, 49, 148, 83, 200, 90, 0, 0, 0, 0,
]);

/// BPF Loader V4 Program ID - next-generation program loader
/// LoaderV411111111111111111111111111111111111
pub const LOADER_V4_PROGRAM_ID: Pubkey = Pubkey::new([
    0x05, 0x12, 0xb4, 0x11, 0x51, 0x51, 0xe3, 0x7a, 0xad, 0x0a, 0x8b, 0xc5, 0xd3, 0x88, 0x2e, 0x7b,
    0x7f, 0xda, 0x4c, 0xf3, 0xd2, 0xc0, 0x28, 0xc8, 0xcf, 0x83, 0x36, 0x18, 0x00, 0x00, 0x00, 0x00,
]);

/// BPF Loader Deprecated Program ID - original BPF program loader (v1)
/// BPFLoader1111111111111111111111111111111111
pub const BPF_LOADER_DEPRECATED_PROGRAM_ID: Pubkey = Pubkey::new([
    0x02, 0xa8, 0xf6, 0x91, 0x4e, 0x44, 0x67, 0x4f, 0xc0, 0x09, 0x02, 0x37, 0xe1, 0x17, 0x33, 0x03,
    0xd7, 0xba, 0x39, 0x95, 0x68, 0x49, 0x12, 0xee, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
]);

/// BPF Loader V2 Program ID (non-upgradeable)
/// BPFLoader2111111111111111111111111111111111
pub const BPF_LOADER_V2_PROGRAM_ID: Pubkey = Pubkey::new([
    0x02, 0xa8, 0xf6, 0x91, 0x4e, 0x44, 0x67, 0x4f, 0xc0, 0x09, 0x02, 0x37, 0xe1, 0x17, 0x33, 0x03,
    0xd7, 0xba, 0x39, 0x95, 0x68, 0x49, 0x12, 0xee, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
]);

/// Feature Program ID - owner of on-chain feature gate accounts
/// Feature111111111111111111111111111111111111
pub const FEATURE_PROGRAM_ID: Pubkey = Pubkey::new([
    3, 192, 160, 205, 203, 6, 210, 218, 239, 174, 130, 209, 111, 238, 122, 207, 97, 236, 115, 123,
    35, 72, 27, 33, 148, 106, 118, 112, 0, 0, 0, 0,
]);

/// Alias: the BPF Loader Program ID is the upgradeable loader.
pub const UPGRADEABLE_LOADER_PROGRAM_ID: Pubkey = BPF_LOADER_PROGRAM_ID;

/// Secp256r1 ECDSA verification precompile
/// Secp256r1SigVerify1111111111111111111111111
pub const SECP256R1_PROGRAM_ID: Pubkey = Pubkey::new([
    0x06, 0xa3, 0x69, 0x83, 0xd2, 0x0e, 0x20, 0x32, 0x69, 0xa1, 0xe2, 0x55, 0xaf, 0x71, 0xe7, 0xbc,
    0x5d, 0x0a, 0xe1, 0xb0, 0x44, 0x5e, 0x0d, 0x5e, 0x74, 0x5c, 0x4b, 0x80, 0x00, 0x00, 0x00, 0x00,
]);

/// Fees sysvar (deprecated) - SysvarFees111111111111111111111111111111111
pub const FEES_SYSVAR_ID: Pubkey = Pubkey::new([
    6, 167, 213, 23, 24, 199, 116, 201, 40, 86, 99, 152, 105, 29, 94, 182, 139, 94, 184, 163, 155,
    75, 109, 92, 115, 85, 91, 42, 0, 0, 0, 1,
]);
