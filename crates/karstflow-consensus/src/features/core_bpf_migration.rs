//! Migration of a builtin program to a core BPF program.
//!
//! At the slot a migration feature activates, the program it names stops being
//! a builtin and becomes an ordinary upgradeable-loader deployment: a `Program`
//! account pointing at a `ProgramData` account that holds bytecode uploaded, in
//! advance, to a buffer at a fixed address.
//!
//! The bytecode is not ours to supply. A migration reads it from that buffer
//! and refuses to run if the buffer is missing, malformed, or hashes to
//! something other than the build pinned in the config. On a chain started from
//! karstflow's own genesis no such buffer exists, so nothing here fires; it
//! matters when replaying or forking a chain that has them.

use crate::features::FeatureSet;
use crate::Rent;
use karstflow_constants::bpf_loader_program as loader;
use karstflow_types::{Account, AccountData, AccountMeta, Pubkey, UpgradeableLoaderState};
use sha2::{Digest, Sha256};

/// What the program being migrated looks like beforehand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationTarget {
    /// A builtin with an account: it must exist and be owned by the native loader.
    Builtin,
    /// A builtin with no account at all: its address must still be empty.
    Stateless,
}

/// One program's migration, keyed by the feature that triggers it.
#[derive(Debug, Clone)]
pub struct CoreBpfMigration {
    /// The feature whose activation slot this migration runs in.
    pub feature_id: Pubkey,
    /// The program being migrated.
    pub program_id: Pubkey,
    /// Where the new bytecode was uploaded.
    pub source_buffer: Pubkey,
    /// Authority the migrated program keeps. `None` makes it immutable, which
    /// is what both live migrations use.
    pub upgrade_authority: Option<Pubkey>,
    pub target: MigrationTarget,
    /// SHA-256 the buffer's bytecode must hash to, when the config pins one.
    pub verified_build_hash: Option<[u8; 32]>,
}

/// Why a migration declined to run.
///
/// Every one of these leaves the chain untouched. A migration is all-or-nothing
/// by construction: it computes the whole write set before anything is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationError {
    /// A builtin target's account is missing.
    ProgramAccountNotFound,
    /// A builtin target is not owned by the native loader.
    IncorrectProgramOwner,
    /// A stateless target's address is already occupied.
    ProgramAccountAlreadyExists,
    /// The programdata address is occupied by something that is not an
    /// acceptable placeholder.
    ProgramHasDataAccount,
    /// The source buffer is missing.
    SourceBufferNotFound,
    /// The source buffer is not owned by the upgradeable loader.
    IncorrectBufferOwner,
    /// The source buffer is too short, or is not in the `Buffer` state.
    InvalidBufferAccount,
    /// The buffer's bytecode does not hash to the pinned build.
    BuildHashMismatch,
    /// The config names an authority the buffer does not carry.
    UpgradeAuthorityMismatch,
}

/// The accounts a migration writes, and what it does to the money.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationOutcome {
    /// Every account the migration replaces, in the order it writes them.
    pub writes: Vec<(Pubkey, Account)>,
    /// Lamports held by the accounts being replaced.
    pub lamports_burned: u64,
    /// Lamports held by the accounts being created.
    pub lamports_funded: u64,
}

/// The two migrations configured at the current protocol version.
///
/// Both are stateless targets, and both are immutable once migrated. The
/// builtin-target arm exists because the protocol defines it, not because
/// anything here uses it — upstream's table of migrating builtins is empty at
/// this version and carries a note that it is kept for future ones.
pub fn configured_migrations() -> Vec<CoreBpfMigration> {
    use crate::features::known_features as kf;

    vec![
        CoreBpfMigration {
            feature_id: kf::migrate_feature_gate_program_to_core_bpf(),
            program_id: karstflow_ids::FEATURE_PROGRAM_ID,
            source_buffer: karstflow_ids::FEATURE_PROGRAM_BUFFER_ADDRESS,
            upgrade_authority: None,
            target: MigrationTarget::Stateless,
            verified_build_hash: None,
        },
        CoreBpfMigration {
            feature_id: kf::enshrine_slashing_program(),
            program_id: karstflow_ids::SLASHING_PROGRAM_ID,
            source_buffer: karstflow_ids::SLASHING_PROGRAM_BUFFER_ADDRESS,
            upgrade_authority: None,
            target: MigrationTarget::Stateless,
            verified_build_hash: Some(SLASHING_PROGRAM_BUILD_HASH),
        },
    ]
}

/// The build the slashing program's buffer must hash to (SIMD-0204).
///
/// Pinned upstream with a note that it is provisional until the program is
/// finalized, so a mismatch here is as likely to mean the pin moved as that a
/// buffer is wrong.
const SLASHING_PROGRAM_BUILD_HASH: [u8; 32] = [
    0x92, 0x60, 0xb9, 0xac, 0x8d, 0xfa, 0x1a, 0x6e, 0xd1, 0x02, 0x23, 0x80, 0xa7, 0x13, 0xbe, 0xc7,
    0xb7, 0x59, 0x79, 0xae, 0x13, 0x6e, 0x91, 0xf9, 0xa8, 0x67, 0x95, 0xb5, 0x1c, 0x6c, 0x48, 0x9f,
];

/// The programdata address a migrated program's bytecode lives at.
fn programdata_address(program_id: &Pubkey) -> Pubkey {
    let (address, _bump) = Pubkey::find_program_address(
        &[program_id.as_bytes()],
        &karstflow_ids::BPF_LOADER_PROGRAM_ID,
    )
    .expect("a single 32-byte seed is always within the PDA limits");
    address
}

/// Run a migration against the given account state.
///
/// Pure: it reads through `read` and returns the writes rather than performing
/// them, so the whole thing can be exercised without a bank.
pub fn migrate(
    config: &CoreBpfMigration,
    slot: u64,
    rent: &Rent,
    relax_programdata_check: bool,
    read: &dyn Fn(&Pubkey) -> Option<Account>,
) -> Result<MigrationOutcome, MigrationError> {
    let program_lamports = match config.target {
        MigrationTarget::Builtin => {
            let account = read(&config.program_id).ok_or(MigrationError::ProgramAccountNotFound)?;
            if account.meta.owner != karstflow_ids::NATIVE_LOADER_PROGRAM_ID {
                return Err(MigrationError::IncorrectProgramOwner);
            }
            account.meta.lamports
        }
        MigrationTarget::Stateless => {
            if read(&config.program_id).is_some() {
                return Err(MigrationError::ProgramAccountAlreadyExists);
            }
            0
        }
    };

    let programdata_id = programdata_address(&config.program_id);

    // The programdata address must be free. SIMD-0444 softens that to allow a
    // system-owned account someone has pre-funded — its lamports carry into the
    // new account's funding rather than blocking the migration.
    let carried_lamports = match read(&programdata_id) {
        None => 0,
        Some(existing) => {
            if !relax_programdata_check {
                return Err(MigrationError::ProgramHasDataAccount);
            }
            if existing.meta.owner != karstflow_ids::SYSTEM_PROGRAM_ID {
                return Err(MigrationError::ProgramHasDataAccount);
            }
            existing.meta.lamports
        }
    };

    let source = read(&config.source_buffer).ok_or(MigrationError::SourceBufferNotFound)?;
    let elf = validated_buffer_elf(&source, config)?;

    // A config that names an authority requires the buffer to carry the same
    // one, so that whoever uploaded the bytecode is the party the migration was
    // arranged with.
    if let Some(expected) = config.upgrade_authority {
        let state = UpgradeableLoaderState::deserialize(source.data.as_slice())
            .map_err(|_| MigrationError::InvalidBufferAccount)?;
        match state {
            UpgradeableLoaderState::Buffer {
                authority: Some(actual),
            } if actual == expected => {}
            _ => return Err(MigrationError::UpgradeAuthorityMismatch),
        }
    }

    let new_program = loader_owned(
        UpgradeableLoaderState::Program {
            programdata_address: programdata_id,
        }
        .serialize(),
        rent.minimum_balance(loader::SIZE_OF_PROGRAM),
        true,
    );

    let mut programdata_bytes = UpgradeableLoaderState::ProgramData {
        slot,
        upgrade_authority: config.upgrade_authority,
    }
    .serialize();
    programdata_bytes.extend_from_slice(elf);
    let programdata_space = programdata_bytes.len();
    let new_programdata = loader_owned(
        programdata_bytes,
        rent.minimum_balance(programdata_space),
        false,
    );

    let lamports_burned = program_lamports
        .saturating_add(source.meta.lamports)
        .saturating_add(carried_lamports);
    let lamports_funded = new_program
        .meta
        .lamports
        .saturating_add(new_programdata.meta.lamports);

    // The source buffer is drained rather than deleted: its bytecode now lives
    // in the programdata account, and leaving a funded copy behind would let it
    // be migrated a second time.
    let drained = Account::default();

    Ok(MigrationOutcome {
        writes: vec![
            (config.program_id, new_program),
            (programdata_id, new_programdata),
            (config.source_buffer, drained),
        ],
        lamports_burned,
        lamports_funded,
    })
}

/// The bytecode inside a source buffer, once the buffer has been vouched for.
fn validated_buffer_elf<'a>(
    source: &'a Account,
    config: &CoreBpfMigration,
) -> Result<&'a [u8], MigrationError> {
    if source.meta.owner != karstflow_ids::BPF_LOADER_PROGRAM_ID {
        return Err(MigrationError::IncorrectBufferOwner);
    }
    let data = source.data.as_slice();
    if data.len() < loader::SIZE_OF_BUFFER_METADATA {
        return Err(MigrationError::InvalidBufferAccount);
    }
    if u32::from_le_bytes(data[0..4].try_into().expect("checked length")) != loader::STATE_BUFFER {
        return Err(MigrationError::InvalidBufferAccount);
    }

    let elf = &data[loader::SIZE_OF_BUFFER_METADATA..];

    if let Some(expected) = config.verified_build_hash {
        // A buffer is allocated at the size the deployment will need and
        // written into from the front, so the tail is zeros that were never
        // part of the program. Hashing them would make the check depend on how
        // much room the uploader asked for.
        let end = elf
            .iter()
            .rposition(|byte| *byte != 0)
            .map_or(0, |last| last + 1);
        let digest: [u8; 32] = Sha256::digest(&elf[..end]).into();
        if digest != expected {
            return Err(MigrationError::BuildHashMismatch);
        }
    }

    Ok(elf)
}

fn loader_owned(data: Vec<u8>, lamports: u64, executable: bool) -> Account {
    Account {
        data: AccountData::new(data),
        meta: AccountMeta {
            lamports,
            owner: karstflow_ids::BPF_LOADER_PROGRAM_ID,
            executable,
            rent_epoch: u64::MAX,
        },
    }
}

/// Migrations whose feature activates in exactly this slot.
///
/// Keyed off [`FeatureSet::just_activated`] rather than `is_active`, because a
/// migration is a one-shot rewrite: running it again in a later slot would find
/// its own output and refuse, which is a correct outcome reached the wrong way.
pub fn migrations_activating_in(feature_set: &FeatureSet, slot: u64) -> Vec<CoreBpfMigration> {
    configured_migrations()
        .into_iter()
        .filter(|config| feature_set.just_activated(&config.feature_id, slot))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const ELF: &[u8] = b"\x7fELF-not-really-but-enough-to-move";

    fn rent() -> Rent {
        Rent::default_config()
    }

    /// A source buffer holding `elf`, padded out to `capacity` bytes of ELF
    /// room. Buffers are allocated for the largest program they might hold, so
    /// the padding is the normal case rather than an edge one.
    fn buffer(authority: Option<Pubkey>, elf: &[u8], capacity: usize) -> Account {
        let mut data = UpgradeableLoaderState::Buffer { authority }.serialize();
        data.extend_from_slice(elf);
        data.resize(loader::SIZE_OF_BUFFER_METADATA + capacity, 0);
        Account {
            data: AccountData::new(data),
            meta: AccountMeta {
                lamports: 1_000,
                owner: karstflow_ids::BPF_LOADER_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
        }
    }

    fn owned_by(owner: Pubkey, lamports: u64) -> Account {
        Account {
            data: AccountData::new(Vec::new()),
            meta: AccountMeta {
                lamports,
                owner,
                executable: false,
                rent_epoch: 0,
            },
        }
    }

    fn stateless_config(verified_build_hash: Option<[u8; 32]>) -> CoreBpfMigration {
        CoreBpfMigration {
            feature_id: Pubkey::new([9u8; 32]),
            program_id: karstflow_ids::FEATURE_PROGRAM_ID,
            source_buffer: karstflow_ids::FEATURE_PROGRAM_BUFFER_ADDRESS,
            upgrade_authority: None,
            target: MigrationTarget::Stateless,
            verified_build_hash,
        }
    }

    fn run(
        config: &CoreBpfMigration,
        accounts: HashMap<Pubkey, Account>,
        relax: bool,
    ) -> Result<MigrationOutcome, MigrationError> {
        migrate(config, 42, &rent(), relax, &|key| {
            accounts.get(key).cloned()
        })
    }

    fn with_buffer(config: &CoreBpfMigration, account: Account) -> HashMap<Pubkey, Account> {
        HashMap::from([(config.source_buffer, account)])
    }

    #[test]
    fn a_stateless_migration_produces_the_pair_and_drains_the_buffer() {
        let config = stateless_config(None);
        let accounts = with_buffer(&config, buffer(None, ELF, ELF.len()));

        let outcome = run(&config, accounts, false).expect("migration runs");
        assert_eq!(outcome.writes.len(), 3);

        let (program_key, program) = &outcome.writes[0];
        assert_eq!(*program_key, config.program_id);
        assert!(program.meta.executable);
        let expected_programdata = programdata_address(&config.program_id);
        assert_eq!(
            UpgradeableLoaderState::deserialize(program.data.as_slice()).unwrap(),
            UpgradeableLoaderState::Program {
                programdata_address: expected_programdata
            }
        );

        let (programdata_key, programdata) = &outcome.writes[1];
        assert_eq!(*programdata_key, expected_programdata);
        assert!(
            !programdata.meta.executable,
            "the bytecode account is data, not a program"
        );
        assert_eq!(
            &programdata.data.as_slice()[loader::SIZE_OF_PROGRAMDATA_METADATA..],
            ELF
        );
        assert_eq!(
            UpgradeableLoaderState::deserialize(programdata.data.as_slice()).unwrap(),
            UpgradeableLoaderState::ProgramData {
                slot: 42,
                upgrade_authority: None
            },
            "the deployment slot is the activation slot and the program is immutable"
        );

        let (buffer_key, drained) = &outcome.writes[2];
        assert_eq!(*buffer_key, config.source_buffer);
        assert_eq!(drained.meta.lamports, 0);
        assert!(
            drained.data.as_slice().is_empty(),
            "a funded buffer left behind could be migrated a second time"
        );
    }

    #[test]
    fn a_stateless_target_refuses_when_its_address_is_occupied() {
        let config = stateless_config(None);
        let mut accounts = with_buffer(&config, buffer(None, ELF, ELF.len()));
        accounts.insert(
            config.program_id,
            owned_by(karstflow_ids::SYSTEM_PROGRAM_ID, 1),
        );

        assert_eq!(
            run(&config, accounts, false),
            Err(MigrationError::ProgramAccountAlreadyExists)
        );
    }

    #[test]
    fn a_builtin_target_requires_the_native_loader_as_owner() {
        let mut config = stateless_config(None);
        config.target = MigrationTarget::Builtin;
        let accounts = with_buffer(&config, buffer(None, ELF, ELF.len()));

        // Absent entirely.
        assert_eq!(
            run(&config, accounts.clone(), false),
            Err(MigrationError::ProgramAccountNotFound)
        );

        // Present but owned by someone else.
        let mut wrong_owner = accounts.clone();
        wrong_owner.insert(
            config.program_id,
            owned_by(karstflow_ids::SYSTEM_PROGRAM_ID, 5),
        );
        assert_eq!(
            run(&config, wrong_owner, false),
            Err(MigrationError::IncorrectProgramOwner)
        );

        // Present and correct: its lamports join the burn.
        let mut correct = accounts;
        correct.insert(
            config.program_id,
            owned_by(karstflow_ids::NATIVE_LOADER_PROGRAM_ID, 7),
        );
        let outcome = run(&config, correct, false).expect("migration runs");
        assert_eq!(outcome.lamports_burned, 7 + 1_000);
    }

    #[test]
    fn an_occupied_programdata_address_blocks_unless_simd_0444_relaxes_it() {
        let config = stateless_config(None);
        let programdata = programdata_address(&config.program_id);

        let mut system_owned = with_buffer(&config, buffer(None, ELF, ELF.len()));
        system_owned.insert(programdata, owned_by(karstflow_ids::SYSTEM_PROGRAM_ID, 500));

        assert_eq!(
            run(&config, system_owned.clone(), false),
            Err(MigrationError::ProgramHasDataAccount),
            "without the feature, any occupant blocks the migration"
        );

        let outcome = run(&config, system_owned, true).expect("relaxed check admits it");
        assert_eq!(
            outcome.lamports_burned,
            500 + 1_000,
            "a pre-funded placeholder's lamports carry into the accounting"
        );

        // Relaxation admits system-owned accounts only.
        let mut foreign = with_buffer(&config, buffer(None, ELF, ELF.len()));
        foreign.insert(programdata, owned_by(Pubkey::new([3u8; 32]), 500));
        assert_eq!(
            run(&config, foreign, true),
            Err(MigrationError::ProgramHasDataAccount)
        );
    }

    #[test]
    fn the_source_buffer_must_exist_and_be_a_buffer_the_loader_owns() {
        let config = stateless_config(None);

        assert_eq!(
            run(&config, HashMap::new(), false),
            Err(MigrationError::SourceBufferNotFound)
        );

        let mut wrong_owner = buffer(None, ELF, ELF.len());
        wrong_owner.meta.owner = karstflow_ids::SYSTEM_PROGRAM_ID;
        assert_eq!(
            run(&config, with_buffer(&config, wrong_owner), false),
            Err(MigrationError::IncorrectBufferOwner)
        );

        let mut truncated = buffer(None, ELF, ELF.len());
        truncated.data = AccountData::new(vec![0u8; loader::SIZE_OF_BUFFER_METADATA - 1]);
        assert_eq!(
            run(&config, with_buffer(&config, truncated), false),
            Err(MigrationError::InvalidBufferAccount)
        );

        // Right size, right owner, wrong state — a ProgramData account here
        // would otherwise be read as if its header were a buffer's.
        let mut wrong_state = buffer(None, ELF, ELF.len());
        let mut data = UpgradeableLoaderState::ProgramData {
            slot: 0,
            upgrade_authority: None,
        }
        .serialize();
        data.extend_from_slice(ELF);
        wrong_state.data = AccountData::new(data);
        assert_eq!(
            run(&config, with_buffer(&config, wrong_state), false),
            Err(MigrationError::InvalidBufferAccount)
        );
    }

    #[test]
    fn the_build_hash_ignores_the_buffers_trailing_padding() {
        // This is the whole reason the strip exists: the same program in a
        // roomier buffer must hash the same, or the check would depend on how
        // much space the uploader happened to request.
        let digest: [u8; 32] = Sha256::digest(ELF).into();
        let config = stateless_config(Some(digest));

        for capacity in [ELF.len(), ELF.len() + 1, ELF.len() + 4096] {
            let accounts = with_buffer(&config, buffer(None, ELF, capacity));
            assert!(
                run(&config, accounts, false).is_ok(),
                "capacity {capacity} should not change the hash"
            );
        }

        let wrong = stateless_config(Some([0xAB; 32]));
        assert_eq!(
            run(
                &wrong,
                with_buffer(&wrong, buffer(None, ELF, ELF.len())),
                false
            ),
            Err(MigrationError::BuildHashMismatch)
        );
    }

    #[test]
    fn a_named_upgrade_authority_must_match_the_buffers() {
        let authority = Pubkey::new([5u8; 32]);
        let mut config = stateless_config(None);
        config.upgrade_authority = Some(authority);

        let matching = with_buffer(&config, buffer(Some(authority), ELF, ELF.len()));
        let outcome = run(&config, matching, false).expect("authorities agree");
        assert_eq!(
            UpgradeableLoaderState::deserialize(outcome.writes[1].1.data.as_slice()).unwrap(),
            UpgradeableLoaderState::ProgramData {
                slot: 42,
                upgrade_authority: Some(authority)
            }
        );

        let other = with_buffer(
            &config,
            buffer(Some(Pubkey::new([6u8; 32])), ELF, ELF.len()),
        );
        assert_eq!(
            run(&config, other, false),
            Err(MigrationError::UpgradeAuthorityMismatch)
        );

        let none = with_buffer(&config, buffer(None, ELF, ELF.len()));
        assert_eq!(
            run(&config, none, false),
            Err(MigrationError::UpgradeAuthorityMismatch),
            "a buffer with no authority cannot satisfy a config that names one"
        );
    }

    #[test]
    fn both_new_accounts_are_funded_to_their_own_rent_exempt_minimum() {
        let config = stateless_config(None);
        let outcome = run(
            &config,
            with_buffer(&config, buffer(None, ELF, ELF.len())),
            false,
        )
        .expect("migration runs");

        let rent = rent();
        let program_lamports = outcome.writes[0].1.meta.lamports;
        let programdata_lamports = outcome.writes[1].1.meta.lamports;
        assert_eq!(
            program_lamports,
            rent.minimum_balance(loader::SIZE_OF_PROGRAM)
        );
        assert_eq!(
            programdata_lamports,
            rent.minimum_balance(outcome.writes[1].1.data.as_slice().len())
        );
        assert_eq!(
            outcome.lamports_funded,
            program_lamports + programdata_lamports
        );
    }

    #[test]
    fn migrations_fire_only_in_their_activation_slot() {
        // QB-042: dev mode activates every feature at slot 0, so a migration
        // keyed off `is_active` would be indistinguishable from one keyed off
        // `just_activated` under the default environment. This builds the
        // feature state explicitly for that reason.
        let configs = configured_migrations();
        let feature = configs[0].feature_id;

        let mut features = FeatureSet::new();
        features.activate(feature, 10);

        let firing = migrations_activating_in(&features, 10);
        assert_eq!(firing.len(), 1);
        assert_eq!(firing[0].feature_id, feature);

        assert!(
            migrations_activating_in(&features, 11).is_empty(),
            "a migration that re-fired would find its own output and refuse"
        );
        assert!(migrations_activating_in(&features, 9).is_empty());
    }

    #[test]
    fn the_configured_migrations_are_the_two_stateless_ones() {
        // Upstream's table of migrating *builtins* is empty at this version;
        // only the two stateless programs carry a config. If a future rebase
        // adds one, this is where it should show up.
        let configs = configured_migrations();
        assert_eq!(configs.len(), 2);
        assert!(configs
            .iter()
            .all(|c| c.target == MigrationTarget::Stateless));
        assert!(
            configs.iter().all(|c| c.upgrade_authority.is_none()),
            "a migrated core program is immutable"
        );
    }
}
