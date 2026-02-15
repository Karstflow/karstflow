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
    6, 161, 216, 23, 145, 55, 84, 42, 152, 52, 55, 189, 254, 42, 122, 178, 85, 127, 83, 92, 138, 120,
    114, 43, 104, 164, 157, 192, 0, 0, 0, 0,
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
    6, 221, 246, 225, 218, 117, 190, 239, 122, 225, 172, 90, 194, 172, 9, 203, 93, 7, 164, 94,
    23, 98, 89, 102, 145, 98, 234, 217, 137, 254, 0, 118,
]);

/// SPL Associated Token Account Program ID - manages associated token accounts
/// ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL
pub const ASSOCIATED_TOKEN_PROGRAM_ID: Pubkey = Pubkey::new([
    140, 151, 37, 143, 78, 36, 137, 241, 187, 61, 16, 41, 20, 142, 13, 131, 11, 90, 19, 153,
    218, 255, 16, 132, 4, 142, 123, 216, 219, 233, 248, 89,
]);

/// SPL Memo Program ID (v1) - records UTF-8 messages in transaction logs
/// Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo
pub const MEMO_PROGRAM_ID: Pubkey = Pubkey::new([
    5, 74, 83, 97, 55, 90, 145, 186, 125, 140, 146, 79, 97, 51, 175, 8, 100, 72, 198, 87, 70,
    130, 54, 14, 176, 135, 167, 168, 233, 25, 221, 0,
]);

/// SPL Memo Program ID (v3) - newer version with improved validation
/// MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr
pub const MEMO_PROGRAM_V3_ID: Pubkey = Pubkey::new([
    5, 74, 83, 99, 9, 162, 142, 187, 241, 11, 151, 64, 136, 141, 221, 137, 87, 162, 189, 176,
    18, 198, 137, 128, 137, 180, 63, 143, 34, 123, 73, 165,
]);
