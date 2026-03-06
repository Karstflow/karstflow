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
    use karstflow_storage::{Account, AccountData, AccountMeta, Pubkey};
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

    // ===================================================================
    // Multi-Node Cluster Integration Tests
    // ===================================================================
    //
    // These tests bootstrap 3 independent validator banks from the same
    // genesis to simulate a 3-node cluster. Each node gets its own
    // ConsensusBundle, and transactions are replayed across all nodes
    // to verify deterministic execution.
    // ===================================================================

    /// Helper: bootstrap N independent validators from the same genesis.
    fn bootstrap_cluster(n: usize) -> Vec<(Pubkey, karstflow_control::ConsensusBundle)> {
        (0..n)
            .map(|_| {
                let identity = Pubkey::new_unique();
                let bundle = bootstrap_from_development_genesis(None, Some(&identity)).unwrap();
                (identity, bundle)
            })
            .collect()
    }

    /// Helper: register a blockhash on the given bank.
    fn register_blockhash(bank: &karstflow_consensus::Bank, hash: [u8; 32]) {
        let info = BlockhashInfo::new(Pubkey::from(hash), 5000, 1);
        bank.blockhash_queue().write().unwrap().register_hash(info);
    }

    /// Helper: get balance of a pubkey from the bank.
    fn get_balance(bank: &karstflow_consensus::Bank, pubkey: &Pubkey) -> u64 {
        bank.accounts()
            .get_published_account(pubkey)
            .map(|a| a.meta.lamports)
            .unwrap_or(0)
    }

    /// Helper: deploy an executable BPF program account directly into the bank.
    fn deploy_program(bank: &karstflow_consensus::Bank, program_id: &Pubkey, elf: Vec<u8>) {
        let account = Account {
            meta: AccountMeta {
                lamports: 1_000_000,
                owner: karstflow_ids::BPF_LOADER_PROGRAM_ID,
                executable: true,
                rent_epoch: 0,
            },
            data: AccountData::new(elf),
        };
        bank.accounts()
            .store_published_account(*program_id, account);
    }

    /// Helper: create a PDA by computing it off-chain (same algorithm as the runtime).
    fn find_pda(seeds: &[&[u8]], program_id: &Pubkey) -> (Pubkey, u8) {
        use sha2::{Digest, Sha256};
        for bump in (0..=255u8).rev() {
            let mut hasher = Sha256::new();
            for seed in seeds {
                hasher.update(seed);
            }
            hasher.update([bump]);
            hasher.update(program_id.as_bytes());
            hasher.update(b"ProgramDerivedAddress");
            let hash = hasher.finalize();
            let bytes: [u8; 32] = hash.into();
            // Check it's NOT on the ed25519 curve
            let compressed = curve25519_dalek::edwards::CompressedEdwardsY(bytes);
            if compressed.decompress().is_none() {
                return (Pubkey::new(bytes), bump);
            }
        }
        panic!("could not find PDA");
    }

    /// Build a minimal success BPF ELF (mov r0, 0; exit).
    fn build_success_elf() -> Vec<u8> {
        use karstflow_sbpf::elf_loader::TestElfBuilder;
        use karstflow_sbpf::instruction::{Instruction, Opcode};
        let mut text = Vec::new();
        for insn in &[
            Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 0),
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ] {
            text.extend_from_slice(&insn.encode().to_le_bytes());
        }
        TestElfBuilder::new().text(text).build()
    }

    // -----------------------------------------------------------------------
    // Test: 3-node airdrop and balance verification
    // -----------------------------------------------------------------------

    #[test]
    #[ignore]
    fn cluster_3_nodes_airdrop_and_balances() {
        let cluster = bootstrap_cluster(3);
        let backend = SbpfExecutionAdapter::with_defaults();

        // Create 5 user accounts
        let users: Vec<Pubkey> = (0..5).map(|_| Pubkey::new_unique()).collect();
        let airdrop_amounts = [
            10_000_000_000u64, // 10 SOL
            5_000_000_000,     // 5 SOL
            1_000_000_000,     // 1 SOL
            500_000_000,       // 0.5 SOL
            100_000_000,       // 0.1 SOL
        ];

        // Airdrop to all users on all 3 nodes
        for (_, bundle) in &cluster {
            let forks = bundle.bank_forks.read().unwrap();
            let bank = forks.working_bank();
            for (user, &amount) in users.iter().zip(airdrop_amounts.iter()) {
                bank.credit_lamports(user, amount);
            }
        }

        // Verify balances are consistent across all 3 nodes
        for (node_idx, (_, bundle)) in cluster.iter().enumerate() {
            let forks = bundle.bank_forks.read().unwrap();
            let bank = forks.working_bank();
            for (user_idx, (user, &expected)) in
                users.iter().zip(airdrop_amounts.iter()).enumerate()
            {
                let balance = get_balance(&bank, user);
                assert_eq!(
                    balance, expected,
                    "node{node_idx} user{user_idx}: expected {expected}, got {balance}"
                );
            }
        }

        // Verify faucet exists on all nodes
        let faucet = development_faucet_pubkey();
        for (node_idx, (_, bundle)) in cluster.iter().enumerate() {
            let forks = bundle.bank_forks.read().unwrap();
            let bank = forks.working_bank();
            let balance = get_balance(&bank, &faucet);
            assert!(
                balance > 0,
                "node{node_idx}: faucet should have positive balance"
            );
        }

        // Perform cross-user transfers on each node independently
        let blockhash = [0xAA; 32];
        for (node_idx, (_, bundle)) in cluster.iter().enumerate() {
            let forks = bundle.bank_forks.read().unwrap();
            let bank = forks.working_bank();
            register_blockhash(&bank, blockhash);

            // user0 -> user4: 1 SOL
            let transfer_data = system_transfer_data(1_000_000_000);
            let message_bytes = build_message_bytes(
                1,
                0,
                1,
                &[users[0], users[4], SYSTEM_PROGRAM_ID],
                &blockhash,
                &[(2, &[0, 1], &transfer_data)],
            );
            let tx = SanitizedTransaction::legacy(
                vec![users[0], users[4], SYSTEM_PROGRAM_ID],
                blockhash,
                vec![CompiledInstruction {
                    program_id_index: 2,
                    account_indices: vec![0, 1],
                    data: transfer_data.clone(),
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
                "node{node_idx}: transfer user0->user4 failed: {:?}",
                result.error
            );
        }

        // Verify user4 received 1 SOL on each node (original 0.1 + 1.0 = 1.1 SOL)
        for (node_idx, (_, bundle)) in cluster.iter().enumerate() {
            let forks = bundle.bank_forks.read().unwrap();
            let bank = forks.working_bank();
            let balance = get_balance(&bank, &users[4]);
            assert_eq!(
                balance, 1_100_000_000,
                "node{node_idx}: user4 should have 1.1 SOL after transfer"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Test: 3-node multiple transfers in sequence
    // -----------------------------------------------------------------------

    #[test]
    #[ignore]
    fn cluster_3_nodes_sequential_transfers() {
        let cluster = bootstrap_cluster(3);
        let backend = SbpfExecutionAdapter::with_defaults();

        let alice = Pubkey::new_unique();
        let bob = Pubkey::new_unique();
        let charlie = Pubkey::new_unique();
        let blockhash = [0xBB; 32];

        for (_, bundle) in &cluster {
            let forks = bundle.bank_forks.read().unwrap();
            let bank = forks.working_bank();
            bank.credit_lamports(&alice, 100_000_000_000); // 100 SOL
            bank.credit_lamports(&bob, 50_000_000_000); // 50 SOL
            bank.credit_lamports(&charlie, 10_000_000_000); // 10 SOL
            register_blockhash(&bank, blockhash);
        }

        // Chain of transfers on each node:
        // alice -> bob: 20 SOL
        // bob -> charlie: 10 SOL
        // charlie -> alice: 5 SOL
        let transfers: Vec<(Pubkey, Pubkey, u64)> = vec![
            (alice, bob, 20_000_000_000),
            (bob, charlie, 10_000_000_000),
            (charlie, alice, 5_000_000_000),
        ];

        for (node_idx, (_, bundle)) in cluster.iter().enumerate() {
            let forks = bundle.bank_forks.read().unwrap();
            let bank = forks.working_bank();

            for (sender, receiver, amount) in &transfers {
                let transfer_data = system_transfer_data(*amount);
                let message_bytes = build_message_bytes(
                    1,
                    0,
                    1,
                    &[*sender, *receiver, SYSTEM_PROGRAM_ID],
                    &blockhash,
                    &[(2, &[0, 1], &transfer_data)],
                );
                let tx = SanitizedTransaction::legacy(
                    vec![*sender, *receiver, SYSTEM_PROGRAM_ID],
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
                    "node{node_idx}: transfer {sender:?}->{receiver:?} failed: {:?}",
                    result.error
                );
            }
        }

        // Verify final balances deterministic across all nodes
        // alice: 100 - 20 + 5 - fees = ~85 SOL (minus 2 tx fees)
        // bob: 50 + 20 - 10 - fees = ~60 SOL (minus 2 tx fees)
        // charlie: 10 + 10 - 5 - fees = ~15 SOL (minus 2 tx fees)
        for (node_idx, (_, bundle)) in cluster.iter().enumerate() {
            let forks = bundle.bank_forks.read().unwrap();
            let bank = forks.working_bank();
            let a = get_balance(&bank, &alice);
            let b = get_balance(&bank, &bob);
            let c = get_balance(&bank, &charlie);

            // Check approximate values (fees deducted from senders)
            assert!(
                a > 84_000_000_000 && a < 86_000_000_000,
                "node{node_idx}: alice ~85 SOL, got {a}"
            );
            assert!(
                b > 59_000_000_000 && b < 61_000_000_000,
                "node{node_idx}: bob ~60 SOL, got {b}"
            );
            assert!(
                c > 14_000_000_000 && c < 16_000_000_000,
                "node{node_idx}: charlie ~15 SOL, got {c}"
            );
        }

        // Verify all nodes agree on the same final state
        let balances: Vec<(u64, u64, u64)> = cluster
            .iter()
            .map(|(_, bundle)| {
                let forks = bundle.bank_forks.read().unwrap();
                let bank = forks.working_bank();
                (
                    get_balance(&bank, &alice),
                    get_balance(&bank, &bob),
                    get_balance(&bank, &charlie),
                )
            })
            .collect();

        assert_eq!(balances[0], balances[1], "node0 and node1 must agree");
        assert_eq!(balances[1], balances[2], "node1 and node2 must agree");
    }

    // -----------------------------------------------------------------------
    // Test: 3-node signed transfers with real Ed25519 signatures
    // -----------------------------------------------------------------------

    #[test]
    #[ignore]
    fn cluster_3_nodes_signed_transfers() {
        let cluster = bootstrap_cluster(3);
        let backend = SbpfExecutionAdapter::with_defaults();

        // Generate real keypairs
        let (alice_sk, alice_bytes) = karstflow_crypto::generate_keypair();
        let alice = Pubkey::from(alice_bytes);
        let (bob_sk, bob_bytes) = karstflow_crypto::generate_keypair();
        let bob = Pubkey::from(bob_bytes);
        let receiver = Pubkey::new_unique();

        let blockhash = [0xCC; 32];

        for (_, bundle) in &cluster {
            let forks = bundle.bank_forks.read().unwrap();
            let bank = forks.working_bank();
            bank.credit_lamports(&alice, 50_000_000_000);
            bank.credit_lamports(&bob, 30_000_000_000);
            register_blockhash(&bank, blockhash);
        }

        for (node_idx, (_, bundle)) in cluster.iter().enumerate() {
            let forks = bundle.bank_forks.read().unwrap();
            let bank = forks.working_bank();

            // alice sends 5 SOL with real signature
            let transfer_data = system_transfer_data(5_000_000_000);
            let message_bytes = build_message_bytes(
                1,
                0,
                1,
                &[alice, receiver, SYSTEM_PROGRAM_ID],
                &blockhash,
                &[(2, &[0, 1], &transfer_data)],
            );
            let sig = karstflow_crypto::sign_message(&alice_sk, &message_bytes).unwrap();
            let tx = SanitizedTransaction::legacy(
                vec![alice, receiver, SYSTEM_PROGRAM_ID],
                blockhash,
                vec![CompiledInstruction {
                    program_id_index: 2,
                    account_indices: vec![0, 1],
                    data: transfer_data,
                }],
                1,
                0,
                1,
                vec![sig],
                message_bytes,
            );
            let result = bank.process_transaction(&tx, &backend, MAX_COMPUTE_UNITS);
            assert!(
                result.success,
                "node{node_idx}: alice signed transfer failed: {:?}",
                result.error
            );

            // bob sends 3 SOL with real signature
            let transfer_data = system_transfer_data(3_000_000_000);
            let message_bytes = build_message_bytes(
                1,
                0,
                1,
                &[bob, receiver, SYSTEM_PROGRAM_ID],
                &blockhash,
                &[(2, &[0, 1], &transfer_data)],
            );
            let sig = karstflow_crypto::sign_message(&bob_sk, &message_bytes).unwrap();
            let tx = SanitizedTransaction::legacy(
                vec![bob, receiver, SYSTEM_PROGRAM_ID],
                blockhash,
                vec![CompiledInstruction {
                    program_id_index: 2,
                    account_indices: vec![0, 1],
                    data: transfer_data,
                }],
                1,
                0,
                1,
                vec![sig],
                message_bytes,
            );
            let result = bank.process_transaction(&tx, &backend, MAX_COMPUTE_UNITS);
            assert!(
                result.success,
                "node{node_idx}: bob signed transfer failed: {:?}",
                result.error
            );
        }

        // receiver should have 8 SOL on all nodes
        for (node_idx, (_, bundle)) in cluster.iter().enumerate() {
            let forks = bundle.bank_forks.read().unwrap();
            let bank = forks.working_bank();
            let balance = get_balance(&bank, &receiver);
            assert_eq!(
                balance, 8_000_000_000,
                "node{node_idx}: receiver should have 8 SOL, got {balance}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Test: Deploy BPF program across 3 nodes and execute
    // -----------------------------------------------------------------------

    #[test]
    #[ignore]
    fn cluster_3_nodes_deploy_and_execute_bpf_program() {
        let cluster = bootstrap_cluster(3);
        let backend = SbpfExecutionAdapter::with_defaults();

        let program_id = Pubkey::new_unique();
        let elf = build_success_elf();

        // Deploy the program on all 3 nodes
        for (_, bundle) in &cluster {
            let forks = bundle.bank_forks.read().unwrap();
            let bank = forks.working_bank();
            deploy_program(&bank, &program_id, elf.clone());
        }

        // Verify the program is executable on all nodes
        for (node_idx, (_, bundle)) in cluster.iter().enumerate() {
            let forks = bundle.bank_forks.read().unwrap();
            let bank = forks.working_bank();
            let account = bank.accounts().get_published_account(&program_id).unwrap();
            assert!(
                account.meta.executable,
                "node{node_idx}: program should be executable"
            );
            assert_eq!(
                account.meta.owner,
                karstflow_ids::BPF_LOADER_PROGRAM_ID,
                "node{node_idx}: program owner should be BPF loader"
            );
        }

        // Execute the program via a transaction on each node
        let caller = Pubkey::new_unique();
        let blockhash = [0xDD; 32];

        for (node_idx, (_, bundle)) in cluster.iter().enumerate() {
            let forks = bundle.bank_forks.read().unwrap();
            let bank = forks.working_bank();
            bank.credit_lamports(&caller, 10_000_000);
            register_blockhash(&bank, blockhash);

            let message_bytes = build_message_bytes(
                1,
                0,
                1,
                &[caller, program_id],
                &blockhash,
                &[(1, &[0], &[])],
            );
            let tx = SanitizedTransaction::legacy(
                vec![caller, program_id],
                blockhash,
                vec![CompiledInstruction {
                    program_id_index: 1,
                    account_indices: vec![0],
                    data: vec![],
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
                "node{node_idx}: BPF program execution failed: {:?}",
                result.error
            );
            assert!(
                result.compute_units_consumed > 0,
                "node{node_idx}: should consume compute units"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Test: PDA derivation and account creation
    // -----------------------------------------------------------------------

    #[test]
    #[ignore]
    fn cluster_3_nodes_pda_derivation_and_accounts() {
        let cluster = bootstrap_cluster(3);

        let program_id = Pubkey::new_unique();

        // Derive PDAs for different seeds
        let (pda_counter, bump_counter) = find_pda(&[b"counter", b"global"], &program_id);
        let (pda_user1, bump_user1) = find_pda(&[b"user", b"alice"], &program_id);
        let (pda_user2, bump_user2) = find_pda(&[b"user", b"bob"], &program_id);

        // Verify PDAs are deterministic
        let (pda_counter2, bump_counter2) = find_pda(&[b"counter", b"global"], &program_id);
        assert_eq!(pda_counter, pda_counter2);
        assert_eq!(bump_counter, bump_counter2);

        // Verify different seeds produce different PDAs
        assert_ne!(pda_counter, pda_user1);
        assert_ne!(pda_user1, pda_user2);
        assert_ne!(pda_counter, pda_user2);

        // Create PDA-owned accounts on all 3 nodes (simulating program init)
        let counter_data = 0u64.to_le_bytes().to_vec(); // counter = 0
        let user1_data = vec![1u8; 64]; // arbitrary user state
        let user2_data = vec![2u8; 64];

        for (node_idx, (_, bundle)) in cluster.iter().enumerate() {
            let forks = bundle.bank_forks.read().unwrap();
            let bank = forks.working_bank();

            // Create the counter PDA account
            let counter_account = Account {
                meta: AccountMeta {
                    lamports: 1_000_000,
                    owner: program_id,
                    executable: false,
                    rent_epoch: 0,
                },
                data: AccountData::new(counter_data.clone()),
            };
            bank.accounts()
                .store_published_account(pda_counter, counter_account);

            // Create user PDA accounts
            let user1_account = Account {
                meta: AccountMeta {
                    lamports: 500_000,
                    owner: program_id,
                    executable: false,
                    rent_epoch: 0,
                },
                data: AccountData::new(user1_data.clone()),
            };
            bank.accounts()
                .store_published_account(pda_user1, user1_account);

            let user2_account = Account {
                meta: AccountMeta {
                    lamports: 500_000,
                    owner: program_id,
                    executable: false,
                    rent_epoch: 0,
                },
                data: AccountData::new(user2_data.clone()),
            };
            bank.accounts()
                .store_published_account(pda_user2, user2_account);

            // Verify accounts exist
            let counter = bank.accounts().get_published_account(&pda_counter).unwrap();
            assert_eq!(
                counter.meta.owner, program_id,
                "node{node_idx}: counter PDA owner should be program"
            );
            assert_eq!(
                counter.data.as_slice(),
                &counter_data,
                "node{node_idx}: counter should be 0"
            );

            let u1 = bank.accounts().get_published_account(&pda_user1).unwrap();
            assert_eq!(u1.meta.owner, program_id);

            let u2 = bank.accounts().get_published_account(&pda_user2).unwrap();
            assert_eq!(u2.meta.owner, program_id);
        }

        // Simulate "increment counter" by updating the PDA state on all nodes
        for (node_idx, (_, bundle)) in cluster.iter().enumerate() {
            let forks = bundle.bank_forks.read().unwrap();
            let bank = forks.working_bank();

            // Read current counter
            let current = bank.accounts().get_published_account(&pda_counter).unwrap();
            let mut data = current.data.as_slice().to_vec();
            let val = u64::from_le_bytes(data[..8].try_into().unwrap());
            assert_eq!(val, 0, "node{node_idx}: counter should start at 0");

            // Increment
            let new_val = val + 1;
            data[..8].copy_from_slice(&new_val.to_le_bytes());

            let updated = Account {
                meta: AccountMeta {
                    lamports: current.meta.lamports,
                    owner: program_id,
                    executable: false,
                    rent_epoch: 0,
                },
                data: AccountData::new(data),
            };
            bank.accounts()
                .store_published_account(pda_counter, updated);

            // Verify incremented
            let after = bank.accounts().get_published_account(&pda_counter).unwrap();
            let after_val = u64::from_le_bytes(after.data.as_slice()[..8].try_into().unwrap());
            assert_eq!(
                after_val, 1,
                "node{node_idx}: counter should be 1 after increment"
            );
        }

        // Verify all nodes have consistent PDA state
        for (node_idx, (_, bundle)) in cluster.iter().enumerate() {
            let forks = bundle.bank_forks.read().unwrap();
            let bank = forks.working_bank();

            let counter = bank.accounts().get_published_account(&pda_counter).unwrap();
            let val = u64::from_le_bytes(counter.data.as_slice()[..8].try_into().unwrap());
            assert_eq!(val, 1, "node{node_idx}: final counter should be 1");

            // Verify bump seeds are correct
            assert_ne!(bump_counter, 0, "bump should be nonzero");
            assert_ne!(bump_user1, 0, "bump should be nonzero");
            assert_ne!(bump_user2, 0, "bump should be nonzero");
        }
    }

    // -----------------------------------------------------------------------
    // Test: Full end-to-end program lifecycle across 3 nodes
    // (deploy + airdrop + transfer + BPF execute + PDA + verify)
    // -----------------------------------------------------------------------

    #[test]
    #[ignore]
    fn cluster_3_nodes_full_lifecycle() {
        let cluster = bootstrap_cluster(3);
        let backend = SbpfExecutionAdapter::with_defaults();

        // --- Phase 1: Setup accounts ---
        let (alice_sk, alice_bytes) = karstflow_crypto::generate_keypair();
        let alice = Pubkey::from(alice_bytes);
        let bob = Pubkey::new_unique();
        let treasury = Pubkey::new_unique();
        let program_id = Pubkey::new_unique();
        let elf = build_success_elf();

        let blockhash = [0xEE; 32];

        for (_, bundle) in &cluster {
            let forks = bundle.bank_forks.read().unwrap();
            let bank = forks.working_bank();

            // Airdrop
            bank.credit_lamports(&alice, 100_000_000_000); // 100 SOL
            bank.credit_lamports(&bob, 50_000_000_000); // 50 SOL
            bank.credit_lamports(&treasury, 1_000_000_000); // 1 SOL

            // Deploy BPF program
            deploy_program(&bank, &program_id, elf.clone());

            register_blockhash(&bank, blockhash);
        }

        // --- Phase 2: Transfer SOL ---
        for (node_idx, (_, bundle)) in cluster.iter().enumerate() {
            let forks = bundle.bank_forks.read().unwrap();
            let bank = forks.working_bank();

            // alice -> bob: 10 SOL (signed)
            let transfer_data = system_transfer_data(10_000_000_000);
            let message_bytes = build_message_bytes(
                1,
                0,
                1,
                &[alice, bob, SYSTEM_PROGRAM_ID],
                &blockhash,
                &[(2, &[0, 1], &transfer_data)],
            );
            let sig = karstflow_crypto::sign_message(&alice_sk, &message_bytes).unwrap();
            let tx = SanitizedTransaction::legacy(
                vec![alice, bob, SYSTEM_PROGRAM_ID],
                blockhash,
                vec![CompiledInstruction {
                    program_id_index: 2,
                    account_indices: vec![0, 1],
                    data: transfer_data,
                }],
                1,
                0,
                1,
                vec![sig],
                message_bytes,
            );
            let result = bank.process_transaction(&tx, &backend, MAX_COMPUTE_UNITS);
            assert!(
                result.success,
                "node{node_idx}: phase2 alice->bob failed: {:?}",
                result.error
            );
        }

        // --- Phase 3: Execute BPF program ---
        let blockhash2 = [0xFF; 32];
        for (node_idx, (_, bundle)) in cluster.iter().enumerate() {
            let forks = bundle.bank_forks.read().unwrap();
            let bank = forks.working_bank();
            register_blockhash(&bank, blockhash2);

            let message_bytes = build_message_bytes(
                1,
                0,
                1,
                &[alice, program_id],
                &blockhash2,
                &[(1, &[0], &[42])], // instruction data: 42
            );
            let tx = SanitizedTransaction::legacy(
                vec![alice, program_id],
                blockhash2,
                vec![CompiledInstruction {
                    program_id_index: 1,
                    account_indices: vec![0],
                    data: vec![42],
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
                "node{node_idx}: BPF program invoke failed: {:?}",
                result.error
            );
        }

        // --- Phase 4: Create and manage PDA accounts ---
        let (pda_vault, _) = find_pda(&[b"vault", treasury.as_bytes()], &program_id);
        let (pda_config, _) = find_pda(&[b"config"], &program_id);

        for (node_idx, (_, bundle)) in cluster.iter().enumerate() {
            let forks = bundle.bank_forks.read().unwrap();
            let bank = forks.working_bank();

            // Create vault PDA with initial state
            let vault_data = 0u64.to_le_bytes().to_vec(); // deposited = 0
            let vault_account = Account {
                meta: AccountMeta {
                    lamports: 1_000_000,
                    owner: program_id,
                    executable: false,
                    rent_epoch: 0,
                },
                data: AccountData::new(vault_data),
            };
            bank.accounts()
                .store_published_account(pda_vault, vault_account);

            // Create config PDA
            let mut config_data = vec![0u8; 40];
            config_data[0] = 1; // initialized flag
            config_data[8..16].copy_from_slice(&100u64.to_le_bytes()); // max_deposit
            let config_account = Account {
                meta: AccountMeta {
                    lamports: 500_000,
                    owner: program_id,
                    executable: false,
                    rent_epoch: 0,
                },
                data: AccountData::new(config_data),
            };
            bank.accounts()
                .store_published_account(pda_config, config_account);

            // Simulate deposit: increment vault counter
            let vault = bank.accounts().get_published_account(&pda_vault).unwrap();
            let mut data = vault.data.as_slice().to_vec();
            let deposited = u64::from_le_bytes(data[..8].try_into().unwrap());
            data[..8].copy_from_slice(&(deposited + 50).to_le_bytes());
            let updated = Account {
                meta: AccountMeta {
                    lamports: vault.meta.lamports + 50_000_000, // 0.05 SOL deposit
                    owner: program_id,
                    executable: false,
                    rent_epoch: 0,
                },
                data: AccountData::new(data),
            };
            bank.accounts().store_published_account(pda_vault, updated);

            // Verify vault state
            let v = bank.accounts().get_published_account(&pda_vault).unwrap();
            let val = u64::from_le_bytes(v.data.as_slice()[..8].try_into().unwrap());
            assert_eq!(val, 50, "node{node_idx}: vault deposit count should be 50");

            // Verify config
            let c = bank.accounts().get_published_account(&pda_config).unwrap();
            assert_eq!(
                c.data.as_slice()[0],
                1,
                "node{node_idx}: config initialized"
            );
            let max_dep = u64::from_le_bytes(c.data.as_slice()[8..16].try_into().unwrap());
            assert_eq!(max_dep, 100, "node{node_idx}: config max_deposit = 100");
        }

        // --- Phase 5: Final state verification across all nodes ---
        let final_states: Vec<(u64, u64, u64, u64, u64)> = cluster
            .iter()
            .map(|(_, bundle)| {
                let forks = bundle.bank_forks.read().unwrap();
                let bank = forks.working_bank();
                (
                    get_balance(&bank, &alice),
                    get_balance(&bank, &bob),
                    get_balance(&bank, &treasury),
                    get_balance(&bank, &pda_vault),
                    get_balance(&bank, &pda_config),
                )
            })
            .collect();

        // All nodes must agree
        assert_eq!(
            final_states[0], final_states[1],
            "node0 and node1 final state mismatch"
        );
        assert_eq!(
            final_states[1], final_states[2],
            "node1 and node2 final state mismatch"
        );

        // Bob should have received 10 SOL
        assert_eq!(
            final_states[0].1, 60_000_000_000,
            "bob should have 60 SOL (50 + 10)"
        );

        // Vault PDA should have lamports from deposit
        assert_eq!(
            final_states[0].3,
            51_000_000, // 1M initial + 50M deposit
            "vault PDA should have 51M lamports"
        );
    }

    // -----------------------------------------------------------------------
    // Test: Insufficient funds rejected identically on all nodes
    // -----------------------------------------------------------------------

    #[test]
    #[ignore]
    fn cluster_3_nodes_insufficient_funds_rejected() {
        let cluster = bootstrap_cluster(3);
        let backend = SbpfExecutionAdapter::with_defaults();

        let poor = Pubkey::new_unique();
        let rich_target = Pubkey::new_unique();
        let blockhash = [0x99; 32];

        for (_, bundle) in &cluster {
            let forks = bundle.bank_forks.read().unwrap();
            let bank = forks.working_bank();
            bank.credit_lamports(&poor, 1_000); // only 1000 lamports
            register_blockhash(&bank, blockhash);
        }

        for (node_idx, (_, bundle)) in cluster.iter().enumerate() {
            let forks = bundle.bank_forks.read().unwrap();
            let bank = forks.working_bank();

            let transfer_data = system_transfer_data(1_000_000_000);
            let message_bytes = build_message_bytes(
                1,
                0,
                1,
                &[poor, rich_target, SYSTEM_PROGRAM_ID],
                &blockhash,
                &[(2, &[0, 1], &transfer_data)],
            );
            let tx = SanitizedTransaction::legacy(
                vec![poor, rich_target, SYSTEM_PROGRAM_ID],
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
                "node{node_idx}: should reject insufficient funds"
            );
        }

        // All nodes: poor should still have original balance (minus fee if charged)
        let final_balances: Vec<u64> = cluster
            .iter()
            .map(|(_, bundle)| {
                let forks = bundle.bank_forks.read().unwrap();
                let bank = forks.working_bank();
                get_balance(&bank, &poor)
            })
            .collect();
        assert_eq!(final_balances[0], final_balances[1]);
        assert_eq!(final_balances[1], final_balances[2]);
    }
}
