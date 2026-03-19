//! Embedded BPF program binaries for genesis deployment.
//!
//! These are the official SPL and core BPF programs from the Solana ecosystem.
//! They are embedded at compile time via `include_bytes!()` and deployed to
//! genesis accounts so nodes starting from genesis have real program code.
//!
//! Programs sourced from: agave/program-binaries (Solana Labs)

use karstflow_storage::{GenesisAccount, Pubkey};

/// SPL Token program (v3.5.0)
const SPL_TOKEN: &[u8] = include_bytes!("programs/spl_token-3.5.0.so");
/// SPL Token 2022 program (v10.0.0)
const SPL_TOKEN_2022: &[u8] = include_bytes!("programs/spl_token_2022-10.0.0.so");
/// SPL Memo program v1 (v1.0.0)
const SPL_MEMO_V1: &[u8] = include_bytes!("programs/spl_memo-1.0.0.so");
/// SPL Memo program v3 (v3.0.0)
const SPL_MEMO_V3: &[u8] = include_bytes!("programs/spl_memo-3.0.0.so");
/// SPL Associated Token Account program (v1.1.1)
const SPL_ATA: &[u8] = include_bytes!("programs/spl_associated_token_account-1.1.1.so");
/// Core BPF: Address Lookup Table (v3.0.0)
const CORE_ALT: &[u8] = include_bytes!("programs/core_bpf_address_lookup_table-3.0.0.so");
/// Core BPF: Config (v3.0.0)
const CORE_CONFIG: &[u8] = include_bytes!("programs/core_bpf_config-3.0.0.so");
/// Core BPF: Feature Gate (v0.0.1)
const CORE_FEATURE_GATE: &[u8] = include_bytes!("programs/core_bpf_feature_gate-0.0.1.so");
/// Core BPF: Stake (v1.0.1) — reserved for future builtin-to-BPF migration.
#[allow(dead_code)]
const CORE_STAKE: &[u8] = include_bytes!("programs/core_bpf_stake-1.0.1.so");

/// Program binary with its deployment address.
struct ProgramBinary {
    /// Program ID (the executable account address).
    id: Pubkey,
    /// Owner (loader program).
    owner: Pubkey,
    /// ELF binary data.
    elf: &'static [u8],
    /// Human-readable name for logging.
    name: &'static str,
}

/// All SPL programs to deploy at genesis.
fn spl_programs() -> Vec<ProgramBinary> {
    vec![
        ProgramBinary {
            id: karstflow_ids::TOKEN_PROGRAM_ID,
            owner: karstflow_ids::BPF_LOADER_PROGRAM_ID,
            elf: SPL_TOKEN,
            name: "spl-token",
        },
        ProgramBinary {
            id: karstflow_ids::TOKEN_2022_PROGRAM_ID,
            owner: karstflow_ids::BPF_LOADER_PROGRAM_ID,
            elf: SPL_TOKEN_2022,
            name: "spl-token-2022",
        },
        ProgramBinary {
            id: karstflow_ids::MEMO_PROGRAM_ID,
            owner: karstflow_ids::BPF_LOADER_PROGRAM_ID,
            elf: SPL_MEMO_V1,
            name: "spl-memo-v1",
        },
        ProgramBinary {
            id: karstflow_ids::MEMO_PROGRAM_V3_ID,
            owner: karstflow_ids::BPF_LOADER_PROGRAM_ID,
            elf: SPL_MEMO_V3,
            name: "spl-memo-v3",
        },
        ProgramBinary {
            id: karstflow_ids::ASSOCIATED_TOKEN_PROGRAM_ID,
            owner: karstflow_ids::BPF_LOADER_PROGRAM_ID,
            elf: SPL_ATA,
            name: "spl-associated-token-account",
        },
    ]
}

/// Core BPF programs (migrated from builtins).
fn core_bpf_programs() -> Vec<ProgramBinary> {
    vec![
        // Note: these core programs use BPF_LOADER_UPGRADEABLE in production,
        // but for genesis simplicity we deploy with BPF_LOADER_V2.
        // TODO: use UpgradeableLoaderState for proper deployment.
        ProgramBinary {
            id: karstflow_ids::ADDRESS_LOOKUP_TABLE_PROGRAM_ID,
            owner: karstflow_ids::BPF_LOADER_PROGRAM_ID,
            elf: CORE_ALT,
            name: "core-address-lookup-table",
        },
        ProgramBinary {
            id: karstflow_ids::CONFIG_PROGRAM_ID,
            owner: karstflow_ids::BPF_LOADER_PROGRAM_ID,
            elf: CORE_CONFIG,
            name: "core-config",
        },
        ProgramBinary {
            id: karstflow_ids::FEATURE_PROGRAM_ID,
            owner: karstflow_ids::BPF_LOADER_PROGRAM_ID,
            elf: CORE_FEATURE_GATE,
            name: "core-feature-gate",
        },
        // Stake program is still a builtin in karstflow — skip BPF version.
        // ProgramBinary { id: STAKE_PROGRAM_ID, ... },
    ]
}

/// Generate genesis accounts for all embedded BPF programs.
///
/// For BPF Loader v2 programs: single executable account with ELF as data.
/// For Upgradeable Loader programs: Program account + ProgramData account
/// (following the standard Solana deployment model).
pub fn genesis_program_accounts() -> Vec<(Pubkey, GenesisAccount)> {
    let mut accounts = Vec::new();

    let all_programs: Vec<ProgramBinary> = spl_programs()
        .into_iter()
        .chain(core_bpf_programs())
        .collect();

    for prog in all_programs {
        let data_len = prog.elf.len();
        let lamports = (data_len as u64 + 128) * 6960;

        tracing::info!(
            program = prog.name,
            id = %prog.id,
            elf_size = data_len,
            "embedding BPF program in genesis"
        );

        accounts.push((
            prog.id,
            GenesisAccount {
                lamports,
                data: prog.elf.to_vec(),
                owner: prog.owner,
                executable: true,
                rent_epoch: u64::MAX,
            },
        ));
    }

    accounts
}
