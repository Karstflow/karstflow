/// W002: Integration smoke tests for the dev-mode bootstrap path.
///
/// Verifies that `bootstrap_from_development_genesis()` creates a working
/// bank state with correctly funded accounts, and that the airdrop mechanism
/// (`credit_lamports`) correctly updates balances.
use crate::bootstrap::{bootstrap_from_development_genesis, development_faucet_pubkey};
use paradencer_constants::genesis::{DEV_FAUCET_LAMPORTS, DEV_IDENTITY_LAMPORTS};
use paradencer_storage::Pubkey;

// ---------------------------------------------------------------------------
// Genesis state tests
// ---------------------------------------------------------------------------

#[test]
fn dev_mode_genesis_bootstrap_root_at_slot_zero() {
    let consensus = bootstrap_from_development_genesis(None, None).unwrap();
    let forks = consensus.bank_forks.read().unwrap();
    assert_eq!(forks.root_slot(), 0);
}

#[test]
fn dev_mode_genesis_bootstrap_faucet_has_expected_balance() {
    let consensus = bootstrap_from_development_genesis(None, None).unwrap();
    let forks = consensus.bank_forks.read().unwrap();
    let bank = forks.working_bank();
    let faucet = development_faucet_pubkey();
    let account = bank.accounts().get_published_account(&faucet).unwrap();
    assert_eq!(
        account.meta.lamports, DEV_FAUCET_LAMPORTS,
        "faucet should have {DEV_FAUCET_LAMPORTS} lamports (500M SOL)"
    );
}

#[test]
fn dev_mode_genesis_bootstrap_identity_has_expected_balance() {
    let identity = Pubkey::new_unique();
    let consensus = bootstrap_from_development_genesis(None, Some(&identity)).unwrap();
    let forks = consensus.bank_forks.read().unwrap();
    let bank = forks.working_bank();
    let account = bank.accounts().get_published_account(&identity).unwrap();
    assert_eq!(
        account.meta.lamports, DEV_IDENTITY_LAMPORTS,
        "identity should have {DEV_IDENTITY_LAMPORTS} lamports (500 SOL)"
    );
}

#[test]
fn dev_mode_genesis_bootstrap_without_identity_still_succeeds() {
    // No identity pubkey — bootstrap must succeed and return a valid bank.
    let consensus = bootstrap_from_development_genesis(None, None).unwrap();
    let forks = consensus.bank_forks.read().unwrap();
    assert!(forks.working_bank().slot() == 0);
}

#[test]
fn dev_mode_faucet_pubkey_is_deterministic() {
    let a = development_faucet_pubkey();
    let b = development_faucet_pubkey();
    assert_eq!(a, b, "faucet pubkey must be the same on every call");
}

// ---------------------------------------------------------------------------
// Airdrop (credit_lamports) tests
// ---------------------------------------------------------------------------

#[test]
fn dev_mode_airdrop_increases_recipient_balance_from_zero() {
    let consensus = bootstrap_from_development_genesis(None, None).unwrap();
    let forks = consensus.bank_forks.read().unwrap();
    let bank = forks.working_bank();

    let recipient = Pubkey::new_unique();
    assert!(
        bank.accounts().get_published_account(&recipient).is_none(),
        "fresh account should not exist before airdrop"
    );

    bank.credit_lamports(&recipient, 1_000_000);

    let account = bank.accounts().get_published_account(&recipient).unwrap();
    assert_eq!(account.meta.lamports, 1_000_000);
}

#[test]
fn dev_mode_airdrop_accumulates_on_repeated_calls() {
    let consensus = bootstrap_from_development_genesis(None, None).unwrap();
    let forks = consensus.bank_forks.read().unwrap();
    let bank = forks.working_bank();

    let recipient = Pubkey::new_unique();
    bank.credit_lamports(&recipient, 500_000);
    bank.credit_lamports(&recipient, 250_000);

    let account = bank.accounts().get_published_account(&recipient).unwrap();
    assert_eq!(
        account.meta.lamports, 750_000,
        "two airdrops should accumulate"
    );
}

#[test]
fn dev_mode_airdrop_does_not_affect_other_accounts() {
    let consensus = bootstrap_from_development_genesis(None, None).unwrap();
    let forks = consensus.bank_forks.read().unwrap();
    let bank = forks.working_bank();

    let faucet_before = bank
        .accounts()
        .get_published_account(&development_faucet_pubkey())
        .unwrap()
        .meta
        .lamports;

    let recipient = Pubkey::new_unique();
    bank.credit_lamports(&recipient, 100_000);

    let faucet_after = bank
        .accounts()
        .get_published_account(&development_faucet_pubkey())
        .unwrap()
        .meta
        .lamports;

    assert_eq!(
        faucet_before, faucet_after,
        "airdrop should not reduce the faucet balance"
    );
}

#[test]
fn dev_mode_airdrop_to_identity_increases_balance_above_initial() {
    let identity = Pubkey::new_unique();
    let consensus = bootstrap_from_development_genesis(None, Some(&identity)).unwrap();
    let forks = consensus.bank_forks.read().unwrap();
    let bank = forks.working_bank();

    let before = bank
        .accounts()
        .get_published_account(&identity)
        .unwrap()
        .meta
        .lamports;

    bank.credit_lamports(&identity, 1_000_000_000);

    let after = bank
        .accounts()
        .get_published_account(&identity)
        .unwrap()
        .meta
        .lamports;

    assert_eq!(after, before + 1_000_000_000);
}
