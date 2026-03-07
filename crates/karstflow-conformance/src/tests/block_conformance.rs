//! Block-level conformance tests.
//!
//! Each test executes a sequence of transactions as a block, finalizes the
//! slot, and verifies the bank hash and per-transaction results.

use crate::harness::block::*;
use crate::harness::transaction::execute_transaction;
use karstflow_consensus::{CompiledInstruction, SanitizedTransaction};
use karstflow_ids::SYSTEM_PROGRAM_ID;
use karstflow_types::{Account, AccountData, AccountMeta, Pubkey};
use std::collections::HashMap;

/// Build a SOL transfer transaction for block tests.
fn transfer_txn(
    faucet: Pubkey,
    recipient: Pubkey,
    lamports: u64,
    blockhash: [u8; 32],
) -> SanitizedTransaction {
    let mut data = Vec::with_capacity(12);
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());

    SanitizedTransaction::legacy(
        vec![faucet, recipient, SYSTEM_PROGRAM_ID],
        blockhash,
        vec![CompiledInstruction {
            program_id_index: 2,
            account_indices: vec![0, 1],
            data,
        }],
        1, // num_signatures
        0, // num_readonly_signed
        1, // num_readonly_unsigned
        vec![[0u8; 64]],
        vec![],
    )
}

// -----------------------------------------------------------------------
// Empty block
// -----------------------------------------------------------------------

#[test]
#[ignore]
fn block_empty_produces_bank_hash() {
    let result = execute_block(&HashMap::new(), &[]);

    assert!(
        result.bank_hash.is_some(),
        "empty block should still produce bank hash"
    );
    assert_eq!(result.successful_count, 0);
    assert_eq!(result.failed_count, 0);
}

// -----------------------------------------------------------------------
// Single transaction block
// -----------------------------------------------------------------------

#[test]
#[ignore]
fn block_single_transfer() {
    let recipient = Pubkey::new_unique();

    let setup = execute_transaction(&HashMap::new());
    let faucet = setup.faucet;
    let blockhash = setup.bank.last_blockhash();

    let txn = transfer_txn(faucet, recipient, 500_000, blockhash);
    let result = execute_block(&HashMap::new(), &[txn]);

    assert_eq!(result.successful_count, 1);
    assert_eq!(result.failed_count, 0);
    assert!(result.bank_hash.is_some());
}

// -----------------------------------------------------------------------
// Multiple transactions block
// -----------------------------------------------------------------------

#[test]
#[ignore]
fn block_multiple_transfers() {
    let r1 = Pubkey::new_unique();
    let r2 = Pubkey::new_unique();

    let setup = execute_transaction(&HashMap::new());
    let faucet = setup.faucet;
    let blockhash = setup.bank.last_blockhash();

    let txn1 = transfer_txn(faucet, r1, 100_000, blockhash);
    let txn2 = transfer_txn(faucet, r2, 200_000, blockhash);
    let result = execute_block(&HashMap::new(), &[txn1, txn2]);

    assert_eq!(result.successful_count, 2);
    assert_eq!(result.failed_count, 0);
    assert!(result.bank_hash.is_some());
}

// -----------------------------------------------------------------------
// Mixed success/failure block
// -----------------------------------------------------------------------

#[test]
#[ignore]
fn block_mixed_success_and_failure() {
    let recipient = Pubkey::new_unique();
    let broke = Pubkey::new_unique();

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
    let faucet = setup.faucet;
    let blockhash = setup.bank.last_blockhash();

    // Good transaction from faucet.
    let txn_ok = transfer_txn(faucet, recipient, 1_000, blockhash);

    // Bad transaction from broke account.
    let txn_fail = transfer_txn(broke, recipient, 1_000, blockhash);

    let result = execute_block(&pre, &[txn_ok, txn_fail]);

    assert_eq!(result.successful_count, 1);
    assert_eq!(result.failed_count, 1);
    assert!(result.bank_hash.is_some());
}

// -----------------------------------------------------------------------
// Bank hash determinism
// -----------------------------------------------------------------------

#[test]
#[ignore]
fn block_bank_hash_is_deterministic() {
    let recipient = Pubkey::new_unique();

    let setup = execute_transaction(&HashMap::new());
    let faucet = setup.faucet;
    let blockhash = setup.bank.last_blockhash();

    let txn = transfer_txn(faucet, recipient, 42_000, blockhash);

    let result1 = execute_block(&HashMap::new(), std::slice::from_ref(&txn));
    let result2 = execute_block(&HashMap::new(), std::slice::from_ref(&txn));

    assert!(result1.bank_hash.is_some());
    assert_eq!(
        result1.bank_hash, result2.bank_hash,
        "same inputs should produce same bank hash"
    );
}
