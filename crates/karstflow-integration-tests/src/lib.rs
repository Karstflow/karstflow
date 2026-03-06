//! Integration tests for the karstflow validator.
//!
//! All tests are `#[ignore]` so they don't run with `cargo test --workspace`.
//! Run explicitly: `just integration` or
//! `cargo test -p karstflow-integration-tests -- --ignored`

#[cfg(test)]
mod tests {
    use karstflow_consensus::{BlockhashInfo, CompiledInstruction, SanitizedTransaction};
    use karstflow_constants::execution::MAX_COMPUTE_UNITS;
    use karstflow_control::{bootstrap_from_development_genesis, development_faucet_pubkey};
    use karstflow_ids::SYSTEM_PROGRAM_ID;
    use karstflow_stages::SbpfExecutionAdapter;
    use karstflow_storage::Pubkey;
    use karstflow_types::compact::encode_compact_u16;

    /// Build the message bytes for a legacy transaction (the data that gets signed).
    ///
    /// Format: header(3) | compact_len(keys) | keys | blockhash(32) | compact_len(ixs) | ixs
    fn build_message_bytes(
        num_required_signatures: u8,
        num_readonly_signed: u8,
        num_readonly_unsigned: u8,
        account_keys: &[Pubkey],
        recent_blockhash: &[u8; 32],
        instructions: &[(u8, &[u8], &[u8])], // (program_id_index, accounts, data)
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        let mut compact = [0u8; 3];

        // Header
        buf.push(num_required_signatures);
        buf.push(num_readonly_signed);
        buf.push(num_readonly_unsigned);

        // Account keys
        let len = encode_compact_u16(account_keys.len() as u16, &mut compact);
        buf.extend_from_slice(&compact[..len]);
        for key in account_keys {
            buf.extend_from_slice(key.as_bytes());
        }

        // Recent blockhash
        buf.extend_from_slice(recent_blockhash);

        // Instructions
        let len = encode_compact_u16(instructions.len() as u16, &mut compact);
        buf.extend_from_slice(&compact[..len]);
        for (prog_idx, accounts, data) in instructions {
            buf.push(*prog_idx);

            let len = encode_compact_u16(accounts.len() as u16, &mut compact);
            buf.extend_from_slice(&compact[..len]);
            buf.extend_from_slice(accounts);

            let len = encode_compact_u16(data.len() as u16, &mut compact);
            buf.extend_from_slice(&compact[..len]);
            buf.extend_from_slice(data);
        }

        buf
    }

    /// Build a System::Transfer instruction data (discriminant 2, u64 LE amount).
    fn system_transfer_data(lamports: u64) -> Vec<u8> {
        let mut data = Vec::with_capacity(12);
        data.extend_from_slice(&2u32.to_le_bytes()); // Transfer discriminant
        data.extend_from_slice(&lamports.to_le_bytes());
        data
    }

    // -----------------------------------------------------------------------
    // Dev Genesis Bootstrap
    // -----------------------------------------------------------------------

    #[test]
    #[ignore]
    fn bootstrap_dev_genesis_creates_working_bank() {
        let consensus = bootstrap_from_development_genesis(None, None).unwrap();
        let forks = consensus.bank_forks.read().unwrap();
        let bank = forks.working_bank();

        assert_eq!(bank.slot(), 0);
        assert_eq!(forks.root_slot(), 0);

        // Faucet account should exist with expected balance
        let faucet = development_faucet_pubkey();
        let account = bank.accounts().get_published_account(&faucet).unwrap();
        assert!(account.meta.lamports > 0, "faucet should be funded");
    }

    #[test]
    #[ignore]
    fn bootstrap_dev_genesis_with_custom_identity() {
        let identity = Pubkey::new_unique();
        let consensus = bootstrap_from_development_genesis(None, Some(&identity)).unwrap();
        let forks = consensus.bank_forks.read().unwrap();
        let bank = forks.working_bank();

        let account = bank.accounts().get_published_account(&identity).unwrap();
        assert!(account.meta.lamports > 0, "identity should be funded");
    }

    // -----------------------------------------------------------------------
    // SOL Transfer via Bank (no signing — uses empty signatures path)
    // -----------------------------------------------------------------------

    #[test]
    #[ignore]
    fn sol_transfer_via_bank_updates_balances() {
        let consensus = bootstrap_from_development_genesis(None, None).unwrap();
        let forks = consensus.bank_forks.read().unwrap();
        let bank = forks.working_bank();
        let backend = SbpfExecutionAdapter::with_defaults();

        let sender = Pubkey::new_unique();
        let receiver = Pubkey::new_unique();

        // Fund sender via airdrop
        bank.credit_lamports(&sender, 10_000_000);

        // Register a blockhash so the transaction's blockhash is valid
        let blockhash = [0x42u8; 32];
        let info = BlockhashInfo::new(Pubkey::from(blockhash), 5000, 1);
        bank.blockhash_queue().write().unwrap().register_hash(info);

        // Build a System::Transfer instruction
        let transfer_data = system_transfer_data(1_000_000);
        let message_bytes = build_message_bytes(
            1,
            0,
            1,
            &[sender, receiver, SYSTEM_PROGRAM_ID],
            &blockhash,
            &[(2, &[0, 1], &transfer_data)],
        );

        let tx = SanitizedTransaction::legacy(
            vec![sender, receiver, SYSTEM_PROGRAM_ID],
            blockhash,
            vec![CompiledInstruction {
                program_id_index: 2,
                account_indices: vec![0, 1],
                data: transfer_data.clone(),
            }],
            1,      // num_signatures
            0,      // num_readonly_signed
            1,      // num_readonly_unsigned
            vec![], // empty signatures — skips sig verification
            message_bytes,
        );

        let result = bank.process_transaction(&tx, &backend, MAX_COMPUTE_UNITS);

        assert!(
            result.success,
            "SOL transfer should succeed: {:?}",
            result.error
        );

        // Verify balances changed
        let sender_after = bank
            .accounts()
            .get_published_account(&sender)
            .unwrap()
            .meta
            .lamports;
        let receiver_after = bank
            .accounts()
            .get_published_account(&receiver)
            .unwrap()
            .meta
            .lamports;

        // Sender started with 10M, transferred 1M, minus fees
        assert!(
            sender_after < 10_000_000,
            "sender balance should decrease: got {sender_after}"
        );
        assert_eq!(
            receiver_after, 1_000_000,
            "receiver should have 1M lamports"
        );
    }

    // -----------------------------------------------------------------------
    // SOL Transfer with Ed25519 Signature Verification
    // -----------------------------------------------------------------------

    #[test]
    #[ignore]
    fn sol_transfer_with_real_signature() {
        let consensus = bootstrap_from_development_genesis(None, None).unwrap();
        let forks = consensus.bank_forks.read().unwrap();
        let bank = forks.working_bank();
        let backend = SbpfExecutionAdapter::with_defaults();

        // Generate a real Ed25519 keypair
        let (secret_key, sender_bytes) = karstflow_crypto::generate_keypair();
        let sender = Pubkey::from(sender_bytes);
        let receiver = Pubkey::new_unique();

        // Fund sender
        bank.credit_lamports(&sender, 10_000_000);

        // Register blockhash
        let blockhash = [0x77u8; 32];
        let info = BlockhashInfo::new(Pubkey::from(blockhash), 5000, 1);
        bank.blockhash_queue().write().unwrap().register_hash(info);

        // Build message bytes (what gets signed)
        let transfer_data = system_transfer_data(500_000);
        let message_bytes = build_message_bytes(
            1,
            0,
            1,
            &[sender, receiver, SYSTEM_PROGRAM_ID],
            &blockhash,
            &[(2, &[0, 1], &transfer_data)],
        );

        // Sign the message
        let signature = karstflow_crypto::sign_message(&secret_key, &message_bytes).unwrap();

        let tx = SanitizedTransaction::legacy(
            vec![sender, receiver, SYSTEM_PROGRAM_ID],
            blockhash,
            vec![CompiledInstruction {
                program_id_index: 2,
                account_indices: vec![0, 1],
                data: transfer_data.clone(),
            }],
            1,               // num_signatures
            0,               // num_readonly_signed
            1,               // num_readonly_unsigned
            vec![signature], // real Ed25519 signature
            message_bytes,
        );

        let result = bank.process_transaction(&tx, &backend, MAX_COMPUTE_UNITS);

        assert!(
            result.success,
            "signed SOL transfer should succeed: {:?}",
            result.error
        );

        let receiver_balance = bank
            .accounts()
            .get_published_account(&receiver)
            .unwrap()
            .meta
            .lamports;
        assert_eq!(receiver_balance, 500_000);
    }

    // -----------------------------------------------------------------------
    // Multiple Transfers in Sequence
    // -----------------------------------------------------------------------

    #[test]
    #[ignore]
    fn multiple_transfers_accumulate_correctly() {
        let consensus = bootstrap_from_development_genesis(None, None).unwrap();
        let forks = consensus.bank_forks.read().unwrap();
        let bank = forks.working_bank();
        let backend = SbpfExecutionAdapter::with_defaults();

        let sender = Pubkey::new_unique();
        let receiver = Pubkey::new_unique();
        bank.credit_lamports(&sender, 100_000_000);

        let blockhash = [0x11u8; 32];
        let info = BlockhashInfo::new(Pubkey::from(blockhash), 5000, 1);
        bank.blockhash_queue().write().unwrap().register_hash(info);

        // Execute 3 transfers
        for amount in [1_000_000u64, 2_000_000, 3_000_000] {
            let transfer_data = system_transfer_data(amount);
            let message_bytes = build_message_bytes(
                1,
                0,
                1,
                &[sender, receiver, SYSTEM_PROGRAM_ID],
                &blockhash,
                &[(2, &[0, 1], &transfer_data)],
            );

            let tx = SanitizedTransaction::legacy(
                vec![sender, receiver, SYSTEM_PROGRAM_ID],
                blockhash,
                vec![CompiledInstruction {
                    program_id_index: 2,
                    account_indices: vec![0, 1],
                    data: transfer_data,
                }],
                1,
                0,
                1,
                vec![],
                message_bytes,
            );

            let result = bank.process_transaction(&tx, &backend, MAX_COMPUTE_UNITS);
            assert!(
                result.success,
                "transfer of {amount} should succeed: {:?}",
                result.error
            );
        }

        let receiver_balance = bank
            .accounts()
            .get_published_account(&receiver)
            .unwrap()
            .meta
            .lamports;
        assert_eq!(
            receiver_balance, 6_000_000,
            "receiver should have accumulated 1M + 2M + 3M"
        );
    }

    // -----------------------------------------------------------------------
    // Transfer to Self
    // -----------------------------------------------------------------------

    #[test]
    #[ignore]
    fn transfer_to_self_preserves_balance_minus_fees() {
        let consensus = bootstrap_from_development_genesis(None, None).unwrap();
        let forks = consensus.bank_forks.read().unwrap();
        let bank = forks.working_bank();
        let backend = SbpfExecutionAdapter::with_defaults();

        let account = Pubkey::new_unique();
        bank.credit_lamports(&account, 10_000_000);

        let blockhash = [0x22u8; 32];
        let info = BlockhashInfo::new(Pubkey::from(blockhash), 5000, 1);
        bank.blockhash_queue().write().unwrap().register_hash(info);

        let transfer_data = system_transfer_data(1_000_000);
        let message_bytes = build_message_bytes(
            1,
            0,
            0,
            &[account, SYSTEM_PROGRAM_ID],
            &blockhash,
            &[(1, &[0, 0], &transfer_data)],
        );

        let tx = SanitizedTransaction::legacy(
            vec![account, SYSTEM_PROGRAM_ID],
            blockhash,
            vec![CompiledInstruction {
                program_id_index: 1,
                account_indices: vec![0, 0], // sender == receiver
                data: transfer_data,
            }],
            1,
            0,
            0,
            vec![],
            message_bytes,
        );

        let result = bank.process_transaction(&tx, &backend, MAX_COMPUTE_UNITS);
        // Self-transfer may succeed or fail depending on the system program's
        // duplicate account handling. Either way, the bank should not panic.
        let balance = bank
            .accounts()
            .get_published_account(&account)
            .unwrap()
            .meta
            .lamports;

        if result.success {
            // Balance should decrease by just the fee
            assert!(balance < 10_000_000);
            assert!(balance > 9_000_000, "only fee should be deducted");
        }
    }

    // -----------------------------------------------------------------------
    // Insufficient Funds
    // -----------------------------------------------------------------------

    #[test]
    #[ignore]
    fn transfer_insufficient_funds_fails() {
        let consensus = bootstrap_from_development_genesis(None, None).unwrap();
        let forks = consensus.bank_forks.read().unwrap();
        let bank = forks.working_bank();
        let backend = SbpfExecutionAdapter::with_defaults();

        let sender = Pubkey::new_unique();
        let receiver = Pubkey::new_unique();
        bank.credit_lamports(&sender, 1_000); // only 1000 lamports

        let blockhash = [0x33u8; 32];
        let info = BlockhashInfo::new(Pubkey::from(blockhash), 5000, 1);
        bank.blockhash_queue().write().unwrap().register_hash(info);

        let transfer_data = system_transfer_data(1_000_000); // transfer 1M > balance
        let message_bytes = build_message_bytes(
            1,
            0,
            1,
            &[sender, receiver, SYSTEM_PROGRAM_ID],
            &blockhash,
            &[(2, &[0, 1], &transfer_data)],
        );

        let tx = SanitizedTransaction::legacy(
            vec![sender, receiver, SYSTEM_PROGRAM_ID],
            blockhash,
            vec![CompiledInstruction {
                program_id_index: 2,
                account_indices: vec![0, 1],
                data: transfer_data,
            }],
            1,
            0,
            1,
            vec![],
            message_bytes,
        );

        let result = bank.process_transaction(&tx, &backend, MAX_COMPUTE_UNITS);
        assert!(
            !result.success,
            "transfer should fail with insufficient funds"
        );
    }

    // -----------------------------------------------------------------------
    // Airdrop (credit_lamports) + Transfer end-to-end
    // -----------------------------------------------------------------------

    #[test]
    #[ignore]
    fn airdrop_then_transfer_end_to_end() {
        let identity = Pubkey::new_unique();
        let consensus = bootstrap_from_development_genesis(None, Some(&identity)).unwrap();
        let forks = consensus.bank_forks.read().unwrap();
        let bank = forks.working_bank();
        let backend = SbpfExecutionAdapter::with_defaults();

        // Create a fresh recipient
        let recipient = Pubkey::new_unique();

        // Airdrop to identity (simulating requestAirdrop)
        let initial = bank
            .accounts()
            .get_published_account(&identity)
            .unwrap()
            .meta
            .lamports;
        bank.credit_lamports(&identity, 5_000_000_000); // 5 SOL

        let after_airdrop = bank
            .accounts()
            .get_published_account(&identity)
            .unwrap()
            .meta
            .lamports;
        assert_eq!(after_airdrop, initial + 5_000_000_000);

        // Now transfer from identity to recipient
        let blockhash = [0x44u8; 32];
        let info = BlockhashInfo::new(Pubkey::from(blockhash), 5000, 1);
        bank.blockhash_queue().write().unwrap().register_hash(info);

        let transfer_data = system_transfer_data(1_000_000_000); // 1 SOL
        let message_bytes = build_message_bytes(
            1,
            0,
            1,
            &[identity, recipient, SYSTEM_PROGRAM_ID],
            &blockhash,
            &[(2, &[0, 1], &transfer_data)],
        );

        let tx = SanitizedTransaction::legacy(
            vec![identity, recipient, SYSTEM_PROGRAM_ID],
            blockhash,
            vec![CompiledInstruction {
                program_id_index: 2,
                account_indices: vec![0, 1],
                data: transfer_data,
            }],
            1,
            0,
            1,
            vec![],
            message_bytes,
        );

        let result = bank.process_transaction(&tx, &backend, MAX_COMPUTE_UNITS);
        assert!(
            result.success,
            "transfer after airdrop should succeed: {:?}",
            result.error
        );

        let recipient_balance = bank
            .accounts()
            .get_published_account(&recipient)
            .unwrap()
            .meta
            .lamports;
        assert_eq!(
            recipient_balance, 1_000_000_000,
            "recipient should have 1 SOL"
        );
    }
}
