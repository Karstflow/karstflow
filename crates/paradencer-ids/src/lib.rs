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
