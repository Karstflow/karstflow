//! Embedded BPF program binaries for genesis deployment.
//!
//! These are the official SPL and core BPF programs from the Solana ecosystem.
//! They are embedded at compile time via `include_bytes!()` and deployed to
//! genesis accounts so nodes starting from genesis have real program code.
//!
//! Programs sourced from: agave/program-binaries (Solana Labs)

use karstflow_constants::bpf_loader_program::SIZE_OF_PROGRAM;
use karstflow_constants::economics::{
    RENT_EXEMPTION_BASE_LAMPORTS, RENT_EXEMPTION_LAMPORTS_PER_BYTE,
};
use karstflow_sbpf::UpgradeableLoaderState;
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
///
/// These are deployed under the upgradeable loader as a `Program` account
/// pointing at a separate `ProgramData` account, which is the shape they have
/// upstream after the builtin-to-BPF migration runs. Karstflow has no migration
/// yet, so genesis writes the end state directly.
fn core_bpf_programs() -> Vec<ProgramBinary> {
    vec![
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

/// The address a program's programdata account lives at.
///
/// The runtime reaches this account through the pointer in the program
/// account and never re-derives it, but clients do derive it — to read a
/// program's bytecode, or to name it in an upgrade — so genesis has to put it
/// where they will look.
pub fn programdata_address(program_id: &Pubkey) -> Pubkey {
    let (address, _bump) = karstflow_sbpf::syscalls::find_program_address(
        &[program_id.as_bytes()],
        &karstflow_ids::BPF_LOADER_PROGRAM_ID,
    )
    .expect("a single 32-byte seed is always within the PDA limits");
    address
}

/// Rent-exempt funding for an account of this size, on the genesis rent rate.
fn exempt_lamports(data_len: usize) -> u64 {
    RENT_EXEMPTION_BASE_LAMPORTS + data_len as u64 * RENT_EXEMPTION_LAMPORTS_PER_BYTE
}

/// Generate genesis accounts for all embedded BPF programs.
///
/// The two loaders keep the bytecode in different places, so a program's
/// account layout follows from its owner rather than from the program:
///
/// - v2 and older: one executable account, ELF as its data.
/// - upgradeable: a `Program` account holding a pointer, and a `ProgramData`
///   account holding the ELF behind a 45-byte header.
///
/// The core programs take the second form because that is what they look like
/// upstream once migrated. Their upgrade authority is `None` — a migrated core
/// program is immutable, and nothing may upgrade it in place.
pub fn genesis_program_accounts() -> Vec<(Pubkey, GenesisAccount)> {
    let mut accounts = Vec::new();

    for prog in spl_programs() {
        tracing::info!(
            program = prog.name,
            id = %prog.id,
            elf_size = prog.elf.len(),
            "embedding BPF program in genesis"
        );

        accounts.push((
            prog.id,
            GenesisAccount {
                lamports: exempt_lamports(prog.elf.len()),
                data: prog.elf.to_vec(),
                owner: prog.owner,
                executable: true,
                rent_epoch: u64::MAX,
            },
        ));
    }

    for prog in core_bpf_programs() {
        let programdata_id = programdata_address(&prog.id);

        tracing::info!(
            program = prog.name,
            id = %prog.id,
            programdata = %programdata_id,
            elf_size = prog.elf.len(),
            "embedding core BPF program in genesis"
        );

        let program_state = UpgradeableLoaderState::Program {
            programdata_address: programdata_id,
        };
        let mut programdata = UpgradeableLoaderState::ProgramData {
            slot: 0,
            upgrade_authority: None,
        }
        .serialize();
        programdata.extend_from_slice(prog.elf);

        accounts.push((
            prog.id,
            GenesisAccount {
                lamports: exempt_lamports(SIZE_OF_PROGRAM),
                data: program_state.serialize(),
                owner: prog.owner,
                executable: true,
                rent_epoch: u64::MAX,
            },
        ));
        accounts.push((
            programdata_id,
            GenesisAccount {
                lamports: exempt_lamports(programdata.len()),
                data: programdata,
                owner: prog.owner,
                // Only the program account is dispatchable. The account holding
                // the bytecode is data, and marking it executable would offer it
                // to the loader as a program in its own right.
                executable: false,
                rent_epoch: u64::MAX,
            },
        ));
    }

    accounts
}

#[cfg(test)]
mod tests {
    use super::*;
    use karstflow_constants::bpf_loader_program::SIZE_OF_PROGRAMDATA_METADATA;

    fn account_at<'a>(
        accounts: &'a [(Pubkey, GenesisAccount)],
        key: &Pubkey,
    ) -> Option<&'a GenesisAccount> {
        accounts
            .iter()
            .find(|(pubkey, _)| pubkey == key)
            .map(|(_, account)| account)
    }

    /// Programdata addresses derived outside this codebase, by an independent
    /// implementation of the PDA algorithm.
    ///
    /// Every other assertion here compares the pointer against the same
    /// function that wrote it, so all of them would survive a wrong derivation
    /// intact — they prove the two halves agree with each other, not that
    /// either agrees with the protocol. These strings are the outside opinion.
    /// If they ever stop matching, a client deriving a program's data address
    /// looks somewhere karstflow did not put it.
    const CANONICAL_PROGRAMDATA: [(&str, &str); 3] = [
        (
            "AddressLookupTab1e1111111111111111111111111",
            "4zSpbk5jGQyMmUrqCSjFZbRKwsrMXBPsyTzjhJEAsefG",
        ),
        (
            "Config1111111111111111111111111111111111111",
            "CHKQ74qcDUJbwc4snCEZXL8tV1WQvXqioArLGgUHPZq9",
        ),
        (
            "Feature111111111111111111111111111111111111",
            "H253PPA38ecQvnpSvfWgqBfMuVgZ656CEXLgTHwZQHfs",
        ),
    ];

    #[test]
    fn derived_programdata_addresses_match_an_independent_derivation() {
        for (program, expected) in CANONICAL_PROGRAMDATA {
            let program_id = [
                karstflow_ids::ADDRESS_LOOKUP_TABLE_PROGRAM_ID,
                karstflow_ids::CONFIG_PROGRAM_ID,
                karstflow_ids::FEATURE_PROGRAM_ID,
            ]
            .into_iter()
            .find(|id| id.to_string() == program)
            .unwrap_or_else(|| panic!("no program id matches {program}"));

            assert_eq!(
                programdata_address(&program_id).to_string(),
                expected,
                "programdata address for {program} diverged from the canonical derivation"
            );
        }
    }

    #[test]
    fn a_core_program_resolves_through_its_programdata_account_to_the_elf() {
        // The one property that matters: following the pointer the way the VM
        // does must arrive back at the bytes that were embedded. Asserting the
        // two accounts exist would not catch a header written at the wrong
        // offset, which is the mistake this layout invites.
        let accounts = genesis_program_accounts();
        let program_id = karstflow_ids::ADDRESS_LOOKUP_TABLE_PROGRAM_ID;

        let program = account_at(&accounts, &program_id).expect("program account");
        assert_eq!(program.owner, karstflow_ids::BPF_LOADER_PROGRAM_ID);
        assert!(program.executable);
        assert_eq!(program.data.len(), SIZE_OF_PROGRAM);

        let state = UpgradeableLoaderState::deserialize(&program.data).expect("program state");
        let UpgradeableLoaderState::Program {
            programdata_address: pointer,
        } = state
        else {
            panic!("expected a Program state, got {state:?}");
        };
        assert_eq!(pointer, programdata_address(&program_id));

        let programdata = account_at(&accounts, &pointer).expect("programdata account");
        assert!(
            !programdata.executable,
            "the account holding bytecode is data, not a program"
        );
        assert_eq!(
            &programdata.data[SIZE_OF_PROGRAMDATA_METADATA..],
            CORE_ALT,
            "following the pointer must land on the embedded ELF"
        );
    }

    #[test]
    fn a_core_program_carries_no_upgrade_authority() {
        // A migrated core program is immutable upstream. An authority here
        // would let whoever holds it replace a core program in place.
        let accounts = genesis_program_accounts();
        let pointer = programdata_address(&karstflow_ids::CONFIG_PROGRAM_ID);
        let programdata = account_at(&accounts, &pointer).expect("programdata account");

        let state = UpgradeableLoaderState::deserialize(&programdata.data).expect("programdata");
        let UpgradeableLoaderState::ProgramData {
            slot,
            upgrade_authority,
        } = state
        else {
            panic!("expected a ProgramData state, got {state:?}");
        };
        assert_eq!(slot, 0);
        assert_eq!(upgrade_authority, None);
    }

    #[test]
    fn spl_programs_keep_the_single_account_layout() {
        // They are not core-BPF migrations and must not acquire a programdata
        // account: the loader reads their bytecode from the program account.
        let accounts = genesis_program_accounts();
        let token = account_at(&accounts, &karstflow_ids::TOKEN_PROGRAM_ID).expect("spl token");

        assert!(token.executable);
        assert_eq!(token.data.len(), SPL_TOKEN.len());
        assert!(
            account_at(
                &accounts,
                &programdata_address(&karstflow_ids::TOKEN_PROGRAM_ID)
            )
            .is_none(),
            "no programdata account should exist for an SPL program"
        );
    }

    #[test]
    fn every_genesis_account_is_rent_exempt_for_its_own_size() {
        // Underfunding the programdata account is the easy mistake here, since
        // it is far larger than the program account that names it.
        for (pubkey, account) in genesis_program_accounts() {
            assert_eq!(
                account.lamports,
                exempt_lamports(account.data.len()),
                "account {pubkey} funded for the wrong size"
            );
        }
    }
}
