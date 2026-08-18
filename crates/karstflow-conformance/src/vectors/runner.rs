//! Executes decoded fixtures against the execution backend and grades them.
//!
//! Grading is deliberately per-field. A single pass/fail boolean would collapse
//! "we computed a different balance" and "we do not implement this program yet"
//! into one number, and those two need opposite responses.

use super::model::{AcctState, InstrFixture};
use karstflow_consensus::{ExecutionBackend, InstructionInfo, InstructionResult, SlotContext};
use karstflow_types::{Account, AccountData, AccountMeta, Pubkey};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

thread_local! {
    /// Source location of the most recent panic seen on this thread.
    ///
    /// The unwind payload carries a panic's message but not where it happened,
    /// and the location is the part that identifies the defect. A hook is the
    /// only place it is available, so it is stashed there and read back after
    /// the unwind.
    static LAST_PANIC_LOCATION: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Replace the default panic hook with one that records the panic location and
/// prints nothing.
///
/// A corpus run provokes panics deliberately; letting each one print a full
/// message would bury the report it is meant to produce.
pub fn install_quiet_panic_hook() {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        std::panic::set_hook(Box::new(|info| {
            let location = info
                .location()
                .map(|loc| format!("{}:{}", loc.file(), loc.line()))
                .unwrap_or_else(|| "unknown location".to_string());
            LAST_PANIC_LOCATION.with(|cell| *cell.borrow_mut() = Some(location));
        }));
    });
}

fn take_panic_location() -> Option<String> {
    LAST_PANIC_LOCATION.with(|cell| cell.borrow_mut().take())
}

/// A single way a replay disagreed with its fixture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mismatch {
    /// The fixture expected success and the replay failed, or the reverse.
    Outcome {
        /// Whether the fixture expected the instruction to succeed.
        expected_ok: bool,
        /// The failure message when the replay produced one.
        actual_error: Option<String>,
    },
    /// Compute units consumed differ.
    ComputeUnits {
        /// Units the fixture says the instruction costs.
        expected: u64,
        /// Units the replay charged.
        actual: u64,
    },
    /// An account's post-state differs field-wise.
    Account {
        /// The account that differs.
        address: Pubkey,
        /// Which field disagreed — `lamports`, `owner`, `executable` or `data`.
        field: &'static str,
    },
    /// The fixture names an account the replay knows nothing about.
    AccountMissing(Pubkey),
    /// The replay modified an account the fixture does not list as changed.
    AccountUnexpected(Pubkey),
    /// Program return data differs.
    ReturnData,
}

impl Mismatch {
    /// Stable label used to group mismatches in the corpus summary.
    pub fn class(&self) -> &'static str {
        match self {
            Mismatch::Outcome { .. } => "outcome",
            Mismatch::ComputeUnits { .. } => "compute-units",
            Mismatch::Account { field, .. } => field,
            Mismatch::AccountMissing(_) => "account-missing",
            Mismatch::AccountUnexpected(_) => "account-unexpected",
            Mismatch::ReturnData => "return-data",
        }
    }
}

/// Why a fixture could not be graded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    /// The fixture carries no effects message, so there is nothing to compare.
    NoEffects,
    /// An instruction account index points outside the account list.
    AccountIndexOutOfRange,
    /// The fixture bytes did not decode.
    DecodeFailed(String),
}

impl SkipReason {
    /// Stable label used to group skips in the corpus summary.
    pub fn class(&self) -> &'static str {
        match self {
            SkipReason::NoEffects => "no-effects",
            SkipReason::AccountIndexOutOfRange => "account-index-out-of-range",
            SkipReason::DecodeFailed(_) => "decode-failed",
        }
    }
}

/// The graded outcome of one fixture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Every compared field agreed.
    Pass,
    /// At least one field disagreed.
    Mismatch(Vec<Mismatch>),
    /// The fixture was not gradeable.
    Skipped(SkipReason),
    /// Executing the fixture panicked, carrying the panic's location and text.
    ///
    /// This is graded separately from a mismatch and is strictly worse than
    /// one. A wrong answer is a correctness bug; a panic on instruction data
    /// that arrived from the network is a liveness bug, because the input is
    /// attacker-chosen and the crash takes the thread with it.
    Panicked(String),
}

/// Maps the first 8 bytes of each known feature id to its full 32-byte key.
///
/// Fixtures identify active features by that truncated prefix, so resolving one
/// back to a full id is what lets a fixture's feature set be applied.
fn feature_prefix_index() -> &'static HashMap<u64, [u8; 32]> {
    static INDEX: OnceLock<HashMap<u64, [u8; 32]>> = OnceLock::new();
    INDEX.get_or_init(|| {
        karstflow_consensus::features::known_features::FEATURE_REGISTRY
            .iter()
            .map(|(_, id)| {
                let mut prefix = [0u8; 8];
                prefix.copy_from_slice(&id[..8]);
                (u64::from_le_bytes(prefix), *id)
            })
            .collect()
    })
}

/// Resolve a fixture's feature prefixes into full feature ids.
///
/// Returns the resolved set and the count that no known feature matched — an
/// unresolved prefix means the fixture was generated against a feature this
/// registry does not carry, which is a registry-coverage signal worth counting
/// rather than swallowing.
pub fn resolve_features(prefixes: &[u64]) -> (HashSet<[u8; 32]>, usize) {
    let index = feature_prefix_index();
    let mut resolved = HashSet::new();
    let mut unknown = 0usize;
    for prefix in prefixes {
        match index.get(prefix) {
            Some(id) => {
                resolved.insert(*id);
            }
            None => unknown += 1,
        }
    }
    (resolved, unknown)
}

fn to_account(state: &AcctState) -> Account {
    Account {
        meta: AccountMeta {
            lamports: state.lamports,
            owner: Pubkey::new(state.owner),
            executable: state.executable,
            rent_epoch: 0,
        },
        data: AccountData::new(state.data.clone()),
    }
}

/// Build the slot context a fixture implies: its feature set, plus any sysvar
/// accounts it supplies, so syscalls reading sysvars see the fixture's values
/// rather than defaults.
fn slot_context_for(fixture: &InstrFixture) -> (SlotContext, usize) {
    let (active_features, unknown_features) = resolve_features(&fixture.input.features);
    let mut context = SlotContext {
        active_features,
        ..SlotContext::default()
    };
    for account in &fixture.input.accounts {
        if account.owner == *karstflow_ids::SYSVAR_PROGRAM_ID.as_bytes() {
            context
                .sysvar_data
                .insert(account.address, account.data.clone());
        }
    }
    (context, unknown_features)
}

/// Whether an account holds a program deployed under one of the BPF loaders.
///
/// Only such an account carries bytecode the backend has to be handed. A
/// builtin's account is owned by the native loader and is never needed for
/// execution, and passing one anyway lengthens the instruction's account list
/// — which handlers can see, and which several loader fixtures reacted to.
fn is_deployed_program(state: &AcctState) -> bool {
    const LOADERS: [Pubkey; 4] = [
        karstflow_ids::BPF_LOADER_PROGRAM_ID,
        karstflow_ids::BPF_LOADER_V2_PROGRAM_ID,
        karstflow_ids::BPF_LOADER_DEPRECATED_PROGRAM_ID,
        karstflow_ids::LOADER_V4_PROGRAM_ID,
    ];
    state.executable && LOADERS.iter().any(|id| *id.as_bytes() == state.owner)
}

/// The programdata account address a deployed program points at, when it is an
/// upgradeable program. Every other loader keeps the bytecode in the program
/// account itself.
fn programdata_address(state: &AcctState) -> Option<[u8; 32]> {
    use karstflow_constants::bpf_loader_program as loader;

    if state.owner != *karstflow_ids::BPF_LOADER_PROGRAM_ID.as_bytes() {
        return None;
    }
    if state.data.len() < loader::SIZE_OF_PROGRAM {
        return None;
    }
    if u32::from_le_bytes(state.data[0..4].try_into().ok()?) != loader::STATE_PROGRAM {
        return None;
    }
    state.data[4..36].try_into().ok()
}

/// A graded replay, together with the reason the replay itself failed.
///
/// The verdict alone cannot answer "why did we fail here", because a fixture
/// that expected an error and got one grades as agreement on the outcome —
/// the failure reason never reaches the summary, and a whole group can sit at
/// `actual: 0` with nothing to say what refused to run.
#[derive(Debug, Clone)]
pub struct Replay {
    /// How the replay graded against the fixture.
    pub verdict: Verdict,
    /// The replay's own failure message, when it failed.
    pub failure_reason: Option<String>,
}

/// Replay one fixture and grade it.
pub fn run_fixture(fixture: &InstrFixture, backend: &dyn ExecutionBackend) -> Replay {
    if !fixture.output_present {
        return Replay {
            verdict: Verdict::Skipped(SkipReason::NoEffects),
            failure_reason: None,
        };
    }

    let mut accounts = Vec::with_capacity(fixture.input.instr_accounts.len());
    for reference in &fixture.input.instr_accounts {
        let Some(state) = fixture.input.accounts.get(reference.index as usize) else {
            return Replay {
                verdict: Verdict::Skipped(SkipReason::AccountIndexOutOfRange),
                failure_reason: None,
            };
        };
        accounts.push((
            Pubkey::new(state.address),
            to_account(state),
            reference.is_writable,
            reference.is_signer,
        ));
    }

    // A deployed program is identified by the instruction's program id, and
    // the fixture carries its account in the context rather than in the
    // instruction's account list. The backend cannot execute bytecode it was
    // never handed, so a fixture whose program is absent from the accounts
    // above is refused as an unknown program and reports consuming nothing —
    // which then grades as agreement whenever the fixture expected an error.
    // Appending the program's own account is what makes the group measure
    // execution instead of measuring the refusal to execute.
    let program_id = Pubkey::new(fixture.input.program_id);
    if !accounts.iter().any(|(key, ..)| *key == program_id) {
        if let Some(state) = fixture
            .input
            .accounts
            .iter()
            .find(|state| state.address == fixture.input.program_id)
            .filter(|state| is_deployed_program(state))
        {
            // Read-only and unsigned: it is present to be loaded, not to widen
            // what the instruction may touch.
            accounts.push((program_id, to_account(state), false, false));

            // An upgradeable program is split across two accounts: this one
            // holds a pointer, and the bytecode is in the programdata account
            // it names. Handing over only the pointer is the same failure as
            // handing over nothing.
            if let Some(address) = programdata_address(state) {
                if !accounts.iter().any(|(key, ..)| key.as_bytes() == &address) {
                    if let Some(data) = fixture
                        .input
                        .accounts
                        .iter()
                        .find(|state| state.address == address)
                    {
                        accounts.push((Pubkey::new(address), to_account(data), false, false));
                    }
                }
            }
        }
    }

    let (slot_context, _unknown_features) = slot_context_for(fixture);
    let info = InstructionInfo {
        program_id,
        accounts,
        data: fixture.input.data.clone(),
        slot_context,
        sibling_instructions: vec![],
    };

    // A fixture's instruction data is arbitrary bytes by design — that is what
    // makes the corpus useful. Executing it must therefore be treated as
    // fallible in the strongest sense, or one panicking fixture ends the run
    // and hides every fixture behind it.
    let cu_avail = fixture.input.cu_avail;
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        backend.execute_instruction(&info, cu_avail)
    }));

    match outcome {
        Ok(result) => Replay {
            verdict: grade(fixture, &result),
            failure_reason: result.error.clone(),
        },
        Err(payload) => {
            let location = take_panic_location().unwrap_or_else(|| "unknown".to_string());
            Replay {
                verdict: Verdict::Panicked(format!("{location}: {}", panic_message(&payload))),
                failure_reason: None,
            }
        }
    }
}

fn panic_message(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(text) = payload.downcast_ref::<&str>() {
        (*text).to_string()
    } else if let Some(text) = payload.downcast_ref::<String>() {
        text.clone()
    } else {
        "non-string panic payload".to_string()
    }
}

/// Compare a replay's result against the fixture's expected effects.
fn grade(fixture: &InstrFixture, actual: &InstructionResult) -> Verdict {
    let mut mismatches = Vec::new();
    let expected_ok = fixture.output.result == 0;

    if expected_ok != actual.success {
        mismatches.push(Mismatch::Outcome {
            expected_ok,
            actual_error: actual.error.clone(),
        });
    }

    let expected_consumed = fixture
        .input
        .cu_avail
        .saturating_sub(fixture.output.cu_avail);
    if expected_consumed != actual.compute_units_consumed {
        mismatches.push(Mismatch::ComputeUnits {
            expected: expected_consumed,
            actual: actual.compute_units_consumed,
        });
    }

    let actual_return = actual
        .return_data
        .as_ref()
        .map(|(_, data)| data.as_slice())
        .unwrap_or_default();
    if actual_return != fixture.output.return_data.as_slice() {
        mismatches.push(Mismatch::ReturnData);
    }

    compare_accounts(fixture, actual, &mut mismatches);

    if mismatches.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Mismatch(mismatches)
    }
}

/// Compare post-state account by account.
///
/// The expected side lists the post-state of EVERY context account, not only
/// the ones that changed, and echoes the input state for those the instruction
/// left alone. The `modified_accounts` name and the schema comment both say
/// otherwise; the reference harness is what actually generates the corpus, and
/// it loops over the full input account list.
///
/// The replay side must therefore be read the same way: an account the backend
/// did not return is not missing, it is unchanged, and its pre-state is its
/// post-state. Treating absence as a mismatch instead reports every untouched
/// sysvar in every fixture as a defect.
fn compare_accounts(
    fixture: &InstrFixture,
    actual: &InstructionResult,
    mismatches: &mut Vec<Mismatch>,
) {
    let pre_state: HashMap<Pubkey, &AcctState> = fixture
        .input
        .accounts
        .iter()
        .map(|state| (Pubkey::new(state.address), state))
        .collect();

    let mut expected_addresses = HashSet::new();
    for expected in &fixture.output.modified_accounts {
        let address = Pubkey::new(expected.address);
        expected_addresses.insert(address);

        let (lamports, owner, executable, data): (u64, [u8; 32], bool, &[u8]) =
            match actual.modified_accounts.get(&address) {
                Some(produced) => (
                    produced.meta.lamports,
                    *produced.meta.owner.as_bytes(),
                    produced.meta.executable,
                    produced.data.as_ref(),
                ),
                None => match pre_state.get(&address) {
                    Some(before) => (
                        before.lamports,
                        before.owner,
                        before.executable,
                        before.data.as_slice(),
                    ),
                    None => {
                        mismatches.push(Mismatch::AccountMissing(address));
                        continue;
                    }
                },
            };

        if lamports != expected.lamports {
            mismatches.push(Mismatch::Account {
                address,
                field: "lamports",
            });
        }
        if owner != expected.owner {
            mismatches.push(Mismatch::Account {
                address,
                field: "owner",
            });
        }
        if executable != expected.executable {
            mismatches.push(Mismatch::Account {
                address,
                field: "executable",
            });
        }
        if data != expected.data.as_slice() {
            mismatches.push(Mismatch::Account {
                address,
                field: "data",
            });
        }
    }

    // The expected side covers every context account, so anything the replay
    // returned beyond it is an account the instruction should never have been
    // able to reach.
    for (address, produced) in &actual.modified_accounts {
        if expected_addresses.contains(address) || !pre_state.contains_key(address) {
            continue;
        }
        let before = pre_state[address];
        let changed = produced.meta.lamports != before.lamports
            || produced.meta.owner.as_bytes() != &before.owner
            || produced.meta.executable != before.executable
            || produced.data.as_ref() != before.data.as_slice();
        if changed {
            mismatches.push(Mismatch::AccountUnexpected(*address));
        }
    }
}
