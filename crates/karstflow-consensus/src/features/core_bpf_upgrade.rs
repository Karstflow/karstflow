//! Replacing the bytecode of a program that is already deployed.
//!
//! A migration turns a builtin into a deployment; an upgrade changes what an
//! existing deployment runs. Both read their new bytecode from a buffer at a
//! fixed address and both are triggered by a feature activating, but they start
//! from different account shapes and so validate different things.
//!
//! Two upgrades exist. One replaces the programdata of a program already under
//! the upgradeable loader, leaving its `Program` account alone. The other
//! converts a program held in the older single-account layout into the two
//! accounts the upgradeable loader uses, which means creating both.
//!
//! Neither fires on a chain started from karstflow's own genesis, for two
//! independent reasons: the source buffers do not exist, and the programs these
//! target are builtins here rather than deployments. They matter when replaying
//! or forking a chain that has both.

use crate::features::core_bpf_migration::{
    empty_account, loader_owned, programdata_address, validated_buffer_elf, MigrationError,
    MigrationOutcome,
};
use crate::features::FeatureSet;
use crate::Rent;
use karstflow_constants::bpf_loader_program as loader;
use karstflow_types::{Account, Pubkey, UpgradeableLoaderState};

/// Checks whether bytecode would survive being deployed.
///
/// Upstream runs the loader's deploy checks inside both upgrade paths and
/// aborts when they fail, so a buffer holding an ELF that could never run never
/// reaches an account. Those checks are the execution layer's, and this crate
/// does not depend on it — so the check arrives as a trait, implemented where
/// both are visible, exactly as `ExecutionBackend` does for instructions.
///
/// Note the migrate path deliberately does NOT use this: upstream's
/// `migrate_builtin_to_core_bpf1` carries a FIXME and does not call the checks,
/// and adding them there would introduce a divergence while removing one.
pub trait ElfValidator: Send + Sync + std::fmt::Debug {
    /// `Ok(())` if the bytecode would deploy; `Err` describing why not.
    fn validate_for_deploy(&self, elf: &[u8]) -> Result<(), String>;
}

/// Run the deploy checks, treating an absent validator as a refusal.
///
/// Fail-closed rather than fail-open, and the choice is deliberate. An
/// always-passing check is a misrepresentation — the reason a `|_| true`
/// closure was rejected when this was designed — and `None => accept` is the
/// same misrepresentation with the falsehood moved one level out. Declining
/// leaves the chain exactly as it was, which is already the ordinary outcome of
/// every upgrade on a chain without the buffers, and is recoverable and visible
/// in a way that installing unchecked bytecode is not.
fn check_deployable(
    validator: Option<&dyn ElfValidator>,
    elf: &[u8],
) -> Result<(), MigrationError> {
    match validator {
        Some(validator) => validator
            .validate_for_deploy(elf)
            .map_err(|_| MigrationError::InvalidBytecode),
        None => Err(MigrationError::NoElfValidator),
    }
}

/// Which of the two upgrade paths a configured upgrade takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpgradeKind {
    /// The program is already an upgradeable deployment; replace its bytecode.
    CoreBpf,
    /// The program is in the older single-account layout; convert it.
    LoaderV2ToV3,
}

/// One program's upgrade, keyed by the feature that triggers it.
#[derive(Debug, Clone)]
pub struct ConfiguredUpgrade {
    pub feature_id: Pubkey,
    pub program_id: Pubkey,
    pub source_buffer: Pubkey,
    pub kind: UpgradeKind,
}

/// The four upgrades configured at the current protocol version, in the order
/// upstream dispatches them.
///
/// The order is load-bearing rather than cosmetic: three of the four target the
/// same stake program, so if two of their features activate in the same slot
/// the last one to run decides what the program ends up running.
///
/// The first entry looks wrong and is not: a feature named for the vote state
/// upgrades the *stake* program, from a buffer whose own name says so. It is
/// transcribed as the protocol has it.
pub fn configured_upgrades() -> Vec<ConfiguredUpgrade> {
    use crate::features::known_features as kf;

    vec![
        ConfiguredUpgrade {
            feature_id: kf::vote_state_v4(),
            program_id: karstflow_ids::STAKE_PROGRAM_ID,
            source_buffer: karstflow_ids::STAKE_PROGRAM_VOTE_STATE_V4_BUFFER_ADDRESS,
            kind: UpgradeKind::CoreBpf,
        },
        ConfiguredUpgrade {
            feature_id: kf::replace_spl_token_with_p_token(),
            program_id: karstflow_ids::TOKEN_PROGRAM_ID,
            source_buffer: karstflow_ids::PTOKEN_PROGRAM_BUFFER_ADDRESS,
            kind: UpgradeKind::LoaderV2ToV3,
        },
        ConfiguredUpgrade {
            feature_id: kf::upgrade_bpf_stake_program_to_v5(),
            program_id: karstflow_ids::STAKE_PROGRAM_ID,
            source_buffer: karstflow_ids::STAKE_PROGRAM_V5_BUFFER_ADDRESS,
            kind: UpgradeKind::CoreBpf,
        },
        ConfiguredUpgrade {
            feature_id: kf::upgrade_bpf_stake_program_to_v5_1(),
            program_id: karstflow_ids::STAKE_PROGRAM_ID,
            source_buffer: karstflow_ids::STAKE_PROGRAM_V5_1_BUFFER_ADDRESS,
            kind: UpgradeKind::CoreBpf,
        },
    ]
}

/// Upgrades whose feature activates in exactly this slot, in dispatch order.
///
/// Keyed off [`FeatureSet::just_activated`] for the same reason migrations are:
/// re-running one in a later slot would consume a buffer that is already empty
/// and decline, which is the right outcome reached by accident rather than by
/// the rule.
pub fn upgrades_activating_in(feature_set: &FeatureSet, slot: u64) -> Vec<ConfiguredUpgrade> {
    configured_upgrades()
        .into_iter()
        .filter(|config| feature_set.just_activated(&config.feature_id, slot))
        .collect()
}

/// Run a configured upgrade down whichever path its kind names.
pub fn apply(
    config: &ConfiguredUpgrade,
    slot: u64,
    rent: &Rent,
    allow_prefunded: bool,
    validator: Option<&dyn ElfValidator>,
    read: &dyn Fn(&Pubkey) -> Option<Account>,
) -> Result<MigrationOutcome, MigrationError> {
    match config.kind {
        UpgradeKind::CoreBpf => upgrade_core_bpf_program(
            &config.program_id,
            &config.source_buffer,
            slot,
            rent,
            validator,
            read,
        ),
        UpgradeKind::LoaderV2ToV3 => upgrade_loader_v2_with_loader_v3(
            &config.program_id,
            &config.source_buffer,
            slot,
            rent,
            allow_prefunded,
            validator,
            read,
        ),
    }
}

/// Replace the bytecode of a program already deployed under the upgradeable
/// loader.
///
/// The `Program` account is untouched — it already points where it should. Only
/// the programdata is rebuilt, at the current slot, keeping whatever upgrade
/// authority the program had.
pub fn upgrade_core_bpf_program(
    program_id: &Pubkey,
    source_buffer: &Pubkey,
    slot: u64,
    rent: &Rent,
    validator: Option<&dyn ElfValidator>,
    read: &dyn Fn(&Pubkey) -> Option<Account>,
) -> Result<MigrationOutcome, MigrationError> {
    let target = core_bpf_target(program_id, read)?;

    let source = read(source_buffer).ok_or(MigrationError::SourceBufferNotFound)?;
    // No pinned build hash on this path: an upgrade replaces bytecode that was
    // already vouched for once, and upstream passes no hash here.
    let elf = validated_buffer_elf(&source, None)?;

    // Whoever uploaded the replacement must be the party the program was left
    // upgradeable for. A program with no authority is immutable and skips the
    // check, because there is no one to match against.
    if let Some(expected) = target.upgrade_authority {
        match UpgradeableLoaderState::deserialize(source.data.as_slice()) {
            Ok(UpgradeableLoaderState::Buffer {
                authority: Some(actual),
            }) if actual == expected => {}
            _ => return Err(MigrationError::UpgradeAuthorityMismatch),
        }
    }

    // Before anything is written: upstream aborts here rather than installing
    // bytecode that could never run.
    check_deployable(validator, elf)?;

    let new_programdata = build_programdata(elf, slot, target.upgrade_authority, rent);

    let lamports_burned = target
        .programdata_lamports
        .saturating_add(source.meta.lamports);
    let lamports_funded = new_programdata.meta.lamports;

    Ok(MigrationOutcome {
        writes: vec![
            (target.programdata_id, new_programdata),
            (*source_buffer, empty_account()),
        ],
        lamports_burned,
        lamports_funded,
    })
}

/// Convert a program held in the older single-account layout into an
/// upgradeable-loader pair.
///
/// Both accounts are created: the `Program` account replaces the old one at the
/// same address, and the programdata is new. The result is immutable — upstream
/// supplies no upgrade authority here.
///
/// `allow_prefunded` is SIMD-0444. Without it the programdata address must be
/// empty; with it, a system-owned account someone funded in advance is accepted
/// and its lamports carry into the new account's funding rather than blocking
/// the upgrade.
pub fn upgrade_loader_v2_with_loader_v3(
    program_id: &Pubkey,
    source_buffer: &Pubkey,
    slot: u64,
    rent: &Rent,
    allow_prefunded: bool,
    validator: Option<&dyn ElfValidator>,
    read: &dyn Fn(&Pubkey) -> Option<Account>,
) -> Result<MigrationOutcome, MigrationError> {
    let target = loader_v2_target(program_id, allow_prefunded, read)?;

    let source = read(source_buffer).ok_or(MigrationError::SourceBufferNotFound)?;
    let elf = validated_buffer_elf(&source, None)?;

    check_deployable(validator, elf)?;

    let new_program = loader_owned(
        UpgradeableLoaderState::Program {
            programdata_address: target.programdata_id,
        }
        .serialize(),
        rent.minimum_balance(loader::SIZE_OF_PROGRAM),
        true,
    );
    let new_programdata = build_programdata(elf, slot, None, rent);

    let lamports_burned = target
        .program_lamports
        .saturating_add(source.meta.lamports)
        .saturating_add(target.carried_lamports);
    let lamports_funded = new_program
        .meta
        .lamports
        .saturating_add(new_programdata.meta.lamports);

    Ok(MigrationOutcome {
        writes: vec![
            (*program_id, new_program),
            (target.programdata_id, new_programdata),
            (*source_buffer, empty_account()),
        ],
        lamports_burned,
        lamports_funded,
    })
}

/// A programdata account holding `elf`, deployed at `slot`.
fn build_programdata(
    elf: &[u8],
    slot: u64,
    upgrade_authority: Option<Pubkey>,
    rent: &Rent,
) -> Account {
    let mut bytes = UpgradeableLoaderState::ProgramData {
        slot,
        upgrade_authority,
    }
    .serialize();
    bytes.extend_from_slice(elf);
    let space = bytes.len();
    loader_owned(bytes, rent.minimum_balance(space), false)
}

/// What an already-deployed upgradeable program looks like before an upgrade.
struct CoreBpfTarget {
    programdata_id: Pubkey,
    programdata_lamports: u64,
    upgrade_authority: Option<Pubkey>,
}

/// Check that `program_id` is a well-formed upgradeable deployment, and read
/// back the parts an upgrade needs.
///
/// Both accounts are validated, not just the one being replaced: a `Program`
/// account pointing somewhere other than its own derived address, or a
/// programdata account in the wrong state, means the pair is not the deployment
/// it claims to be and an upgrade would be writing into someone else's account.
fn core_bpf_target(
    program_id: &Pubkey,
    read: &dyn Fn(&Pubkey) -> Option<Account>,
) -> Result<CoreBpfTarget, MigrationError> {
    let program = read(program_id).ok_or(MigrationError::ProgramAccountNotFound)?;
    if program.meta.owner != karstflow_ids::BPF_LOADER_PROGRAM_ID {
        return Err(MigrationError::IncorrectProgramOwner);
    }
    if !program.meta.executable {
        return Err(MigrationError::ProgramAccountNotExecutable);
    }

    let programdata_id = programdata_address(program_id);
    match UpgradeableLoaderState::deserialize(program.data.as_slice()) {
        Ok(UpgradeableLoaderState::Program {
            programdata_address: pointer,
        }) if pointer == programdata_id => {}
        _ => return Err(MigrationError::InvalidProgramAccount),
    }

    let programdata = read(&programdata_id).ok_or(MigrationError::ProgramDataAccountNotFound)?;
    if programdata.meta.owner != karstflow_ids::BPF_LOADER_PROGRAM_ID {
        return Err(MigrationError::InvalidProgramDataAccount);
    }
    let upgrade_authority = match UpgradeableLoaderState::deserialize(programdata.data.as_slice()) {
        Ok(UpgradeableLoaderState::ProgramData {
            upgrade_authority, ..
        }) => upgrade_authority,
        _ => return Err(MigrationError::InvalidProgramDataAccount),
    };

    Ok(CoreBpfTarget {
        programdata_id,
        programdata_lamports: programdata.meta.lamports,
        upgrade_authority,
    })
}

/// What a program in the older single-account layout looks like before it is
/// converted.
struct LoaderV2Target {
    programdata_id: Pubkey,
    program_lamports: u64,
    /// Lamports found at the programdata address and folded into the funding,
    /// which is only ever non-zero under SIMD-0444.
    carried_lamports: u64,
}

fn loader_v2_target(
    program_id: &Pubkey,
    allow_prefunded: bool,
    read: &dyn Fn(&Pubkey) -> Option<Account>,
) -> Result<LoaderV2Target, MigrationError> {
    let program = read(program_id).ok_or(MigrationError::ProgramAccountNotFound)?;
    if program.meta.owner != karstflow_ids::BPF_LOADER_V2_PROGRAM_ID {
        return Err(MigrationError::IncorrectProgramOwner);
    }
    if !program.meta.executable {
        return Err(MigrationError::ProgramAccountNotExecutable);
    }

    let programdata_id = programdata_address(program_id);
    let carried_lamports = match read(&programdata_id) {
        None => 0,
        Some(existing) => {
            if !allow_prefunded || existing.meta.owner != karstflow_ids::SYSTEM_PROGRAM_ID {
                return Err(MigrationError::ProgramHasDataAccount);
            }
            existing.meta.lamports
        }
    };

    Ok(LoaderV2Target {
        programdata_id,
        program_lamports: program.meta.lamports,
        carried_lamports,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::core_bpf_migration::programdata_address;
    use karstflow_types::{AccountData, AccountMeta};
    use std::collections::HashMap;

    const ELF: &[u8] = b"\x7fELF-replacement-bytecode";

    fn rent() -> Rent {
        Rent::default_config()
    }

    /// A validator that passes everything. Used by the tests that are about
    /// something other than validation, so the check does not mask what they
    /// assert.
    #[derive(Debug)]
    struct Accepting;
    impl ElfValidator for Accepting {
        fn validate_for_deploy(&self, _elf: &[u8]) -> Result<(), String> {
            Ok(())
        }
    }
    fn accepting() -> Option<&'static dyn ElfValidator> {
        Some(&Accepting)
    }

    /// A validator that rejects everything, standing in for a buffer whose
    /// bytecode would not survive a deploy.
    #[derive(Debug)]
    struct Rejecting;
    impl ElfValidator for Rejecting {
        fn validate_for_deploy(&self, _elf: &[u8]) -> Result<(), String> {
            Err("not a program".into())
        }
    }
    fn rejecting() -> Option<&'static dyn ElfValidator> {
        Some(&Rejecting)
    }

    fn pk(byte: u8) -> Pubkey {
        Pubkey::new([byte; 32])
    }

    fn account(data: Vec<u8>, lamports: u64, owner: Pubkey, executable: bool) -> Account {
        Account {
            data: AccountData::new(data),
            meta: AccountMeta {
                lamports,
                owner,
                executable,
                rent_epoch: 0,
            },
        }
    }

    fn buffer(authority: Option<Pubkey>, elf: &[u8]) -> Account {
        let mut data = UpgradeableLoaderState::Buffer { authority }.serialize();
        data.extend_from_slice(elf);
        account(data, 5_000, karstflow_ids::BPF_LOADER_PROGRAM_ID, false)
    }

    /// A well-formed upgradeable deployment: the `Program` account and the
    /// programdata account it points at.
    fn deployed(
        program_id: &Pubkey,
        authority: Option<Pubkey>,
        old_elf: &[u8],
    ) -> Vec<(Pubkey, Account)> {
        let programdata_id = programdata_address(program_id);
        let program = account(
            UpgradeableLoaderState::Program {
                programdata_address: programdata_id,
            }
            .serialize(),
            1_000,
            karstflow_ids::BPF_LOADER_PROGRAM_ID,
            true,
        );
        let mut pd = UpgradeableLoaderState::ProgramData {
            slot: 1,
            upgrade_authority: authority,
        }
        .serialize();
        pd.extend_from_slice(old_elf);
        let programdata = account(pd, 7_000, karstflow_ids::BPF_LOADER_PROGRAM_ID, false);
        vec![(*program_id, program), (programdata_id, programdata)]
    }

    fn chain(entries: Vec<(Pubkey, Account)>) -> HashMap<Pubkey, Account> {
        entries.into_iter().collect()
    }

    fn reader(state: &HashMap<Pubkey, Account>) -> impl Fn(&Pubkey) -> Option<Account> + '_ {
        move |pubkey| state.get(pubkey).cloned()
    }

    /// The programdata bytes an outcome wrote for `program_id`.
    fn written_programdata(outcome: &MigrationOutcome, program_id: &Pubkey) -> Account {
        let id = programdata_address(program_id);
        outcome
            .writes
            .iter()
            .find(|(pubkey, _)| *pubkey == id)
            .map(|(_, account)| account.clone())
            .expect("the programdata write")
    }

    #[test]
    fn a_core_bpf_upgrade_replaces_the_programdata_and_drains_the_buffer() {
        let program_id = pk(1);
        let source_id = pk(2);
        let mut state = chain(deployed(&program_id, None, b"old bytecode"));
        state.insert(source_id, buffer(None, ELF));

        let outcome = upgrade_core_bpf_program(
            &program_id,
            &source_id,
            42,
            &rent(),
            accepting(),
            &reader(&state),
        )
        .expect("the upgrade runs");

        // The Program account is untouched: it already points where it should.
        assert!(
            !outcome
                .writes
                .iter()
                .any(|(pubkey, _)| *pubkey == program_id),
            "an upgrade does not rewrite the program account"
        );

        let programdata = written_programdata(&outcome, &program_id);
        assert_eq!(
            &programdata.data.as_slice()[loader::SIZE_OF_PROGRAMDATA_METADATA..],
            ELF,
            "the new bytecode is the buffer's"
        );
        assert!(
            !programdata.meta.executable,
            "programdata is not executable"
        );
        match UpgradeableLoaderState::deserialize(programdata.data.as_slice()).unwrap() {
            UpgradeableLoaderState::ProgramData { slot, .. } => {
                assert_eq!(slot, 42, "redeployed at the activation slot");
            }
            other => panic!("expected ProgramData, got {other:?}"),
        }

        let drained = outcome
            .writes
            .iter()
            .find(|(pubkey, _)| *pubkey == source_id)
            .map(|(_, account)| account)
            .expect("the buffer write");
        assert_eq!(drained.meta.lamports, 0);
        assert!(drained.data.as_slice().is_empty());

        // Burn is the old programdata plus the buffer; the program account's
        // own lamports are not touched because the account is not replaced.
        assert_eq!(outcome.lamports_burned, 7_000 + 5_000);
        assert_eq!(outcome.lamports_funded, programdata.meta.lamports);
    }

    #[test]
    fn a_core_bpf_upgrade_keeps_the_programs_upgrade_authority() {
        let program_id = pk(1);
        let source_id = pk(2);
        let authority = pk(9);
        let mut state = chain(deployed(&program_id, Some(authority), b"old"));
        state.insert(source_id, buffer(Some(authority), ELF));

        let outcome = upgrade_core_bpf_program(
            &program_id,
            &source_id,
            7,
            &rent(),
            accepting(),
            &reader(&state),
        )
        .expect("the upgrade runs");

        match UpgradeableLoaderState::deserialize(
            written_programdata(&outcome, &program_id).data.as_slice(),
        )
        .unwrap()
        {
            UpgradeableLoaderState::ProgramData {
                upgrade_authority, ..
            } => assert_eq!(upgrade_authority, Some(authority)),
            other => panic!("expected ProgramData, got {other:?}"),
        }
    }

    #[test]
    fn a_core_bpf_upgrade_refuses_a_buffer_from_another_authority() {
        let program_id = pk(1);
        let source_id = pk(2);
        let mut state = chain(deployed(&program_id, Some(pk(9)), b"old"));
        state.insert(source_id, buffer(Some(pk(10)), ELF));

        assert_eq!(
            upgrade_core_bpf_program(
                &program_id,
                &source_id,
                7,
                &rent(),
                accepting(),
                &reader(&state)
            ),
            Err(MigrationError::UpgradeAuthorityMismatch)
        );
    }

    #[test]
    fn an_immutable_program_upgrades_from_a_buffer_with_any_authority() {
        // There is no authority to match against, so the buffer's is not
        // consulted. This is the difference the `if let` in the upgrade makes,
        // and without a test it would read as an oversight.
        let program_id = pk(1);
        let source_id = pk(2);
        let mut state = chain(deployed(&program_id, None, b"old"));
        state.insert(source_id, buffer(Some(pk(10)), ELF));

        assert!(upgrade_core_bpf_program(
            &program_id,
            &source_id,
            7,
            &rent(),
            accepting(),
            &reader(&state)
        )
        .is_ok());
    }

    #[test]
    fn a_core_bpf_upgrade_needs_a_program_pointing_at_its_own_programdata() {
        let program_id = pk(1);
        let source_id = pk(2);
        let mut state = chain(deployed(&program_id, None, b"old"));
        // A Program account naming somebody else's programdata is not the
        // deployment it claims to be, and upgrading it would write into an
        // account that belongs to another program.
        state.insert(
            program_id,
            account(
                UpgradeableLoaderState::Program {
                    programdata_address: pk(77),
                }
                .serialize(),
                1_000,
                karstflow_ids::BPF_LOADER_PROGRAM_ID,
                true,
            ),
        );
        state.insert(source_id, buffer(None, ELF));

        assert_eq!(
            upgrade_core_bpf_program(
                &program_id,
                &source_id,
                7,
                &rent(),
                accepting(),
                &reader(&state)
            ),
            Err(MigrationError::InvalidProgramAccount)
        );
    }

    #[test]
    fn a_core_bpf_upgrade_needs_an_executable_program_account() {
        let program_id = pk(1);
        let source_id = pk(2);
        let mut state = chain(deployed(&program_id, None, b"old"));
        state.get_mut(&program_id).unwrap().meta.executable = false;
        state.insert(source_id, buffer(None, ELF));

        assert_eq!(
            upgrade_core_bpf_program(
                &program_id,
                &source_id,
                7,
                &rent(),
                accepting(),
                &reader(&state)
            ),
            Err(MigrationError::ProgramAccountNotExecutable)
        );
    }

    #[test]
    fn a_core_bpf_upgrade_needs_the_programdata_account_to_exist() {
        let program_id = pk(1);
        let source_id = pk(2);
        let mut state = chain(deployed(&program_id, None, b"old"));
        state.remove(&programdata_address(&program_id));
        state.insert(source_id, buffer(None, ELF));

        assert_eq!(
            upgrade_core_bpf_program(
                &program_id,
                &source_id,
                7,
                &rent(),
                accepting(),
                &reader(&state)
            ),
            Err(MigrationError::ProgramDataAccountNotFound)
        );
    }

    #[test]
    fn a_core_bpf_upgrade_refuses_a_target_owned_by_the_wrong_loader() {
        let program_id = pk(1);
        let source_id = pk(2);
        let mut state = chain(deployed(&program_id, None, b"old"));
        state.get_mut(&program_id).unwrap().meta.owner = karstflow_ids::BPF_LOADER_V2_PROGRAM_ID;
        state.insert(source_id, buffer(None, ELF));

        assert_eq!(
            upgrade_core_bpf_program(
                &program_id,
                &source_id,
                7,
                &rent(),
                accepting(),
                &reader(&state)
            ),
            Err(MigrationError::IncorrectProgramOwner)
        );
    }

    #[test]
    fn a_loader_v2_upgrade_produces_the_pair_from_a_single_account() {
        let program_id = pk(3);
        let source_id = pk(4);
        let mut state = chain(vec![(
            program_id,
            account(
                b"old v2 bytecode".to_vec(),
                2_000,
                karstflow_ids::BPF_LOADER_V2_PROGRAM_ID,
                true,
            ),
        )]);
        state.insert(source_id, buffer(None, ELF));

        let outcome = upgrade_loader_v2_with_loader_v3(
            &program_id,
            &source_id,
            9,
            &rent(),
            false,
            accepting(),
            &reader(&state),
        )
        .expect("the upgrade runs");

        let program = outcome
            .writes
            .iter()
            .find(|(pubkey, _)| *pubkey == program_id)
            .map(|(_, account)| account)
            .expect("the program write");
        assert!(program.meta.executable);
        assert_eq!(program.meta.owner, karstflow_ids::BPF_LOADER_PROGRAM_ID);
        match UpgradeableLoaderState::deserialize(program.data.as_slice()).unwrap() {
            UpgradeableLoaderState::Program {
                programdata_address: pointer,
            } => assert_eq!(pointer, programdata_address(&program_id)),
            other => panic!("expected Program, got {other:?}"),
        }

        let programdata = written_programdata(&outcome, &program_id);
        assert_eq!(
            &programdata.data.as_slice()[loader::SIZE_OF_PROGRAMDATA_METADATA..],
            ELF
        );
        // Upstream supplies no authority here, so the converted program is
        // immutable.
        match UpgradeableLoaderState::deserialize(programdata.data.as_slice()).unwrap() {
            UpgradeableLoaderState::ProgramData {
                upgrade_authority, ..
            } => assert_eq!(upgrade_authority, None),
            other => panic!("expected ProgramData, got {other:?}"),
        }

        assert_eq!(outcome.lamports_burned, 2_000 + 5_000);
        assert_eq!(
            outcome.lamports_funded,
            program.meta.lamports + programdata.meta.lamports
        );
    }

    #[test]
    fn a_loader_v2_upgrade_refuses_a_program_already_under_the_upgradeable_loader() {
        let program_id = pk(3);
        let source_id = pk(4);
        let mut state = chain(deployed(&program_id, None, b"old"));
        state.insert(source_id, buffer(None, ELF));

        assert_eq!(
            upgrade_loader_v2_with_loader_v3(
                &program_id,
                &source_id,
                9,
                &rent(),
                false,
                accepting(),
                &reader(&state)
            ),
            Err(MigrationError::IncorrectProgramOwner)
        );
    }

    /// The whole of SIMD-0444 on this path, in both directions.
    #[test]
    fn a_prefunded_programdata_blocks_the_upgrade_only_without_simd_0444() {
        let program_id = pk(3);
        let source_id = pk(4);
        let mut state = chain(vec![(
            program_id,
            account(
                b"old".to_vec(),
                2_000,
                karstflow_ids::BPF_LOADER_V2_PROGRAM_ID,
                true,
            ),
        )]);
        state.insert(source_id, buffer(None, ELF));
        state.insert(
            programdata_address(&program_id),
            account(Vec::new(), 3_333, karstflow_ids::SYSTEM_PROGRAM_ID, false),
        );

        assert_eq!(
            upgrade_loader_v2_with_loader_v3(
                &program_id,
                &source_id,
                9,
                &rent(),
                false,
                accepting(),
                &reader(&state)
            ),
            Err(MigrationError::ProgramHasDataAccount),
            "without the feature the address must be empty"
        );

        let outcome = upgrade_loader_v2_with_loader_v3(
            &program_id,
            &source_id,
            9,
            &rent(),
            true,
            accepting(),
            &reader(&state),
        )
        .expect("with the feature a pre-funded system account is acceptable");

        // The pre-funded lamports are destroyed alongside the rest rather than
        // silently vanishing, which is what makes the burn/fund pair balance.
        assert_eq!(outcome.lamports_burned, 2_000 + 5_000 + 3_333);
    }

    #[test]
    fn a_prefunded_programdata_owned_by_anyone_else_is_refused_under_simd_0444() {
        let program_id = pk(3);
        let source_id = pk(4);
        let mut state = chain(vec![(
            program_id,
            account(
                b"old".to_vec(),
                2_000,
                karstflow_ids::BPF_LOADER_V2_PROGRAM_ID,
                true,
            ),
        )]);
        state.insert(source_id, buffer(None, ELF));
        state.insert(
            programdata_address(&program_id),
            account(Vec::new(), 3_333, pk(200), false),
        );

        assert_eq!(
            upgrade_loader_v2_with_loader_v3(
                &program_id,
                &source_id,
                9,
                &rent(),
                true,
                accepting(),
                &reader(&state)
            ),
            Err(MigrationError::ProgramHasDataAccount),
            "the relaxation admits a system account, not any account"
        );
    }

    #[test]
    fn an_upgrade_without_its_buffer_declines() {
        let program_id = pk(1);
        let state = chain(deployed(&program_id, None, b"old"));

        assert_eq!(
            upgrade_core_bpf_program(
                &program_id,
                &pk(2),
                7,
                &rent(),
                accepting(),
                &reader(&state)
            ),
            Err(MigrationError::SourceBufferNotFound)
        );
    }

    #[test]
    fn upgrades_fire_only_in_their_activation_slot() {
        // QB-042: the default dev feature set has everything active at slot 0,
        // so this builds its own. `just_activated` is what keeps a one-shot
        // rewrite from being attempted again every later slot.
        let mut features = FeatureSet::default();
        let config = configured_upgrades()
            .into_iter()
            .next()
            .expect("at least one configured upgrade");
        features.activate(config.feature_id, 100);

        assert_eq!(upgrades_activating_in(&features, 100).len(), 1);
        assert!(upgrades_activating_in(&features, 101).is_empty());
        assert!(upgrades_activating_in(&features, 99).is_empty());
    }

    /// The dispatch order decides the end state when several fire at once.
    #[test]
    fn the_three_stake_upgrades_are_dispatched_newest_last() {
        use crate::features::known_features as kf;

        let stake: Vec<Pubkey> = configured_upgrades()
            .into_iter()
            .filter(|config| config.program_id == karstflow_ids::STAKE_PROGRAM_ID)
            .map(|config| config.feature_id)
            .collect();

        assert_eq!(
            stake,
            vec![
                kf::vote_state_v4(),
                kf::upgrade_bpf_stake_program_to_v5(),
                kf::upgrade_bpf_stake_program_to_v5_1(),
            ],
            "three upgrades share the stake program, so whichever runs last wins"
        );
    }

    #[test]
    fn an_upgrade_declines_bytecode_that_would_not_deploy() {
        // Upstream aborts here rather than installing a program that could
        // never run. Nothing is written, so the chain is exactly as it was.
        let program_id = pk(1);
        let source_id = pk(2);
        let mut state = chain(deployed(&program_id, None, b"old"));
        state.insert(source_id, buffer(None, ELF));

        assert_eq!(
            upgrade_core_bpf_program(
                &program_id,
                &source_id,
                7,
                &rent(),
                rejecting(),
                &reader(&state)
            ),
            Err(MigrationError::InvalidBytecode)
        );
    }

    #[test]
    fn a_loader_v2_upgrade_declines_bytecode_that_would_not_deploy() {
        let program_id = pk(3);
        let source_id = pk(4);
        let mut state = chain(vec![(
            program_id,
            account(
                b"old".to_vec(),
                2_000,
                karstflow_ids::BPF_LOADER_V2_PROGRAM_ID,
                true,
            ),
        )]);
        state.insert(source_id, buffer(None, ELF));

        assert_eq!(
            upgrade_loader_v2_with_loader_v3(
                &program_id,
                &source_id,
                9,
                &rent(),
                false,
                rejecting(),
                &reader(&state)
            ),
            Err(MigrationError::InvalidBytecode)
        );
    }

    /// The fail-closed decision, as a test rather than a comment.
    #[test]
    fn an_unwired_validator_declines_instead_of_installing_unchecked_bytecode() {
        let program_id = pk(1);
        let source_id = pk(2);
        let mut state = chain(deployed(&program_id, None, b"old"));
        state.insert(source_id, buffer(None, ELF));

        assert_eq!(
            upgrade_core_bpf_program(&program_id, &source_id, 7, &rent(), None, &reader(&state)),
            Err(MigrationError::NoElfValidator),
            "no validator means no upgrade, not an unchecked one"
        );
    }

    /// The migrate path must NOT gain this check (QB-064 precision).
    #[test]
    fn the_migrate_path_still_runs_without_a_validator() {
        use crate::features::core_bpf_migration::{migrate, MigrationTarget};

        let config = crate::features::core_bpf_migration::configured_migrations()
            .into_iter()
            .find(|config| config.verified_build_hash.is_none())
            .expect("a migration without a pinned build hash");
        assert_eq!(config.target, MigrationTarget::Stateless);

        let mut state: HashMap<Pubkey, Account> = HashMap::new();
        state.insert(config.source_buffer, buffer(None, ELF));

        // Upstream does not run the deploy checks in the migrate path — it
        // carries a FIXME there — so a migration must not inherit the upgrade
        // paths' refusal. There is no validator anywhere in this call.
        assert!(
            migrate(&config, 7, &rent(), false, &reader(&state)).is_ok(),
            "a migration does not depend on a validator the upgrades need"
        );
    }

    /// The whole configuration table, encoded outside this codebase.
    ///
    /// Every other assertion in this module compares a transcribed constant
    /// against itself and would survive a transposed byte, or a buffer wired to
    /// the wrong feature, entirely intact. These strings are the outside
    /// opinion — and several carry vanity prefixes that say what they are, so a
    /// mis-pairing is visible rather than merely different.
    ///
    /// Rows are `(feature, program, buffer)` in dispatch order, which makes the
    /// order load-bearing here too.
    const CANONICAL: [(&str, &str, &str); 4] = [
        (
            "Gx4XFcrVMt4HUvPzTpTSVkdDVgcDSjKhDN1RqRS6KDuZ",
            "Stake11111111111111111111111111111111111111",
            "BM11F4hqrpinQs28sEZfzQ2fYddivYs4NEAHF6QMjkJF",
        ),
        (
            "ptokFjwyJtrwCa9Kgo9xoDS59V4QccBGEaRFnRPnSdP",
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "ptok6rngomXrDbWf5v5Mkmu5CEbB51hzSCPDoj9DrvF",
        ),
        (
            "STk5Xj8hdAx3sTzmtJ3QysKkq6X2A3yj73JtxttiRyk",
            "Stake11111111111111111111111111111111111111",
            "4EBQBjw1kqF1dqUBb6fc5Ji4tCEQgNf9ESGGX3smwXwh",
        ),
        (
            "s51VGwCAgebo2745DSUris72RavoLkXGUmVJosESCXr",
            "Stake11111111111111111111111111111111111111",
            "p51x11QCYMHwuVS1MBcLHKb3MezWyqGS5BEB41CA1dk",
        ),
    ];

    #[test]
    fn the_configured_upgrades_match_an_independent_encoding() {
        let configured = configured_upgrades();
        assert_eq!(
            configured.len(),
            CANONICAL.len(),
            "a configured upgrade with no canonical row is unverified"
        );

        for (config, (feature, program, buffer)) in configured.iter().zip(CANONICAL.iter()) {
            assert_eq!(&config.feature_id.to_string(), feature);
            assert_eq!(&config.program_id.to_string(), program, "for {feature}");
            assert_eq!(&config.source_buffer.to_string(), buffer, "for {feature}");
        }
    }
}
