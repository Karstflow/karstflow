//! Transaction-level conformance tests.
//!
//! Each test bootstraps a development genesis bank, executes a full
//! transaction (signature verification, fee payment, instruction dispatch),
//! and verifies the outcome.

use crate::harness::transaction::*;
use karstflow_consensus::{CompiledInstruction, SanitizedTransaction};
use karstflow_ids::SYSTEM_PROGRAM_ID;
use karstflow_types::{Account, AccountData, AccountMeta, Pubkey};
use std::collections::HashMap;

/// Build a legacy sanitized transaction with correct field names.
fn make_legacy_txn(
    account_keys: Vec<Pubkey>,
    recent_blockhash: [u8; 32],
    instructions: Vec<CompiledInstruction>,
    num_readonly_unsigned: u8,
) -> SanitizedTransaction {
    SanitizedTransaction::legacy(
        account_keys,
        recent_blockhash,
        instructions,
        1, // num_signatures
        0, // num_readonly_signed
        num_readonly_unsigned,
        vec![[0u8; 64]], // placeholder signature (dev genesis skips sig verify)
        vec![],          // message_bytes (not verified in dev mode)
    )
}

/// Build a SOL transfer transaction from the faucet to a recipient.
fn build_faucet_transfer(
    setup: &TransactionSetup,
    recipient: &Pubkey,
    lamports: u64,
) -> SanitizedTransaction {
    let faucet = setup.faucet;
    let recent_blockhash = setup.bank.last_blockhash();

    // Transfer instruction data: discriminant 2 + u64 amount
    let mut data = Vec::with_capacity(12);
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());

    make_legacy_txn(
        vec![faucet, *recipient, SYSTEM_PROGRAM_ID],
        recent_blockhash,
        vec![CompiledInstruction {
            program_id_index: 2,
            account_indices: vec![0, 1],
            data,
        }],
        1,
    )
}

// -----------------------------------------------------------------------
// Basic transfer
// -----------------------------------------------------------------------

#[test]
#[ignore]
fn transaction_transfer_updates_balances() {
    let recipient = Pubkey::new_unique();
    let setup = execute_transaction(&HashMap::new());
    let txn = build_faucet_transfer(&setup, &recipient, 1_000_000);

    let result = setup.execute(&txn);

    assert!(result.success, "transfer transaction should succeed");
    assert!(result.fee > 0, "fee should be charged");

    // Recipient should have received lamports.
    let recipient_post = result
        .modified_accounts
        .get(&recipient)
        .expect("recipient should be in modified accounts");
    assert_eq!(recipient_post.meta.lamports, 1_000_000);
}

#[test]
#[ignore]
fn transaction_transfer_insufficient_fails() {
    let recipient = Pubkey::new_unique();
    let broke = Pubkey::new_unique();

    // Inject broke account with 0 lamports.
    let mut pre = HashMap::new();
    pre.insert(
        broke,
        Account {
            meta: AccountMeta {
                lamports: 0,
                owner: SYSTEM_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        },
    );

    let setup = execute_transaction(&pre);

    // Try to transfer from broke account.
    let mut data = Vec::with_capacity(12);
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&1_000u64.to_le_bytes());

    let txn = make_legacy_txn(
        vec![broke, recipient, SYSTEM_PROGRAM_ID],
        setup.bank.last_blockhash(),
        vec![CompiledInstruction {
            program_id_index: 2,
            account_indices: vec![0, 1],
            data,
        }],
        1,
    );

    let result = setup.execute(&txn);

    assert!(!result.success, "broke transfer should fail");
}

// -----------------------------------------------------------------------
// Multiple instructions in one transaction
// -----------------------------------------------------------------------

#[test]
#[ignore]
fn transaction_multiple_transfers() {
    let recipient_a = Pubkey::new_unique();
    let recipient_b = Pubkey::new_unique();
    let setup = execute_transaction(&HashMap::new());
    let faucet = setup.faucet;
    let blockhash = setup.bank.last_blockhash();

    let mut data_a = Vec::with_capacity(12);
    data_a.extend_from_slice(&2u32.to_le_bytes());
    data_a.extend_from_slice(&100_000u64.to_le_bytes());

    let mut data_b = Vec::with_capacity(12);
    data_b.extend_from_slice(&2u32.to_le_bytes());
    data_b.extend_from_slice(&200_000u64.to_le_bytes());

    let txn = make_legacy_txn(
        vec![faucet, recipient_a, recipient_b, SYSTEM_PROGRAM_ID],
        blockhash,
        vec![
            CompiledInstruction {
                program_id_index: 3,
                account_indices: vec![0, 1],
                data: data_a,
            },
            CompiledInstruction {
                program_id_index: 3,
                account_indices: vec![0, 2],
                data: data_b,
            },
        ],
        1,
    );

    let result = setup.execute(&txn);

    assert!(result.success, "multi-transfer should succeed");
    assert_eq!(
        result.modified_accounts[&recipient_a].meta.lamports,
        100_000
    );
    assert_eq!(
        result.modified_accounts[&recipient_b].meta.lamports,
        200_000
    );
}

// -----------------------------------------------------------------------
// Fee verification
// -----------------------------------------------------------------------

#[test]
#[ignore]
fn transaction_fee_deducted_from_payer() {
    let recipient = Pubkey::new_unique();
    let setup = execute_transaction(&HashMap::new());
    let faucet = setup.faucet;

    // Get faucet balance before.
    let faucet_before = setup
        .bank
        .accounts()
        .get_published_account(&faucet)
        .unwrap()
        .meta
        .lamports;

    let txn = build_faucet_transfer(&setup, &recipient, 1_000);
    let result = setup.execute(&txn);

    assert!(result.success);
    assert!(result.fee > 0);

    // Faucet post-balance should be: before - transferred - fee
    let faucet_post = result
        .modified_accounts
        .get(&faucet)
        .expect("faucet modified");
    assert_eq!(
        faucet_post.meta.lamports,
        faucet_before - 1_000 - result.fee
    );
}

// -----------------------------------------------------------------------
// Logs
// -----------------------------------------------------------------------

#[test]
#[ignore]
fn transaction_produces_execution_logs() {
    let recipient = Pubkey::new_unique();
    let setup = execute_transaction(&HashMap::new());
    let txn = build_faucet_transfer(&setup, &recipient, 100);

    let result = setup.execute(&txn);

    assert!(result.success);
    assert!(!result.logs.is_empty(), "should produce execution logs");
}
