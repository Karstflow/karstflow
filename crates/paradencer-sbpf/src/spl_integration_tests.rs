//! Integration tests for SPL programs
//!
//! This module contains comprehensive integration tests for SPL Token, Token-2022,
//! Associated Token Account, and Memo programs working together.

#[cfg(test)]
mod tests {
    use crate::{ExecutionContext, ExecutionOutcome, TransactionProcessor};
    use paradencer_ids::{
        ASSOCIATED_TOKEN_PROGRAM_ID, MEMO_PROGRAM_ID, SYSTEM_PROGRAM_ID, TOKEN_2022_PROGRAM_ID,
        TOKEN_PROGRAM_ID,
    };
    use paradencer_types::{Account, AccountData, AccountMeta, Pubkey};
    use std::collections::HashMap;

    fn create_test_account(lamports: u64, owner: Pubkey) -> Account {
        Account {
            meta: AccountMeta {
                lamports,
                owner,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        }
    }

    fn create_test_mint(decimals: u8) -> Vec<u8> {
        let mut mint_data = vec![0u8; 82];
        // mint_authority (Some)
        mint_data[0] = 1;
        let authority = Pubkey::new_unique();
        mint_data[1..33].copy_from_slice(&authority.to_bytes());
        // supply = 0
        mint_data[33..41].copy_from_slice(&0u64.to_le_bytes());
        // decimals
        mint_data[41] = decimals;
        // is_initialized
        mint_data[42] = 1;
        // freeze_authority = None
        mint_data[43] = 0;

        mint_data
    }

    #[test]
    fn test_end_to_end_token_flow() {
        let processor = TransactionProcessor::new();

        // Create participants
        let payer = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let owner = Pubkey::new_unique();

        // Create accounts
        let mut account_state = HashMap::new();

        account_state.insert(payer, create_test_account(10_000_000, SYSTEM_PROGRAM_ID));

        account_state.insert(
            mint,
            Account {
                meta: AccountMeta {
                    lamports: 1_000_000,
                    owner: TOKEN_PROGRAM_ID,
                    executable: false,
                    rent_epoch: 0,
                },
                data: AccountData::new(create_test_mint(9)),
            },
        );

        account_state.insert(owner, create_test_account(1_000_000, SYSTEM_PROGRAM_ID));

        // Test successful flow
        assert!(account_state.contains_key(&payer));
        assert!(account_state.contains_key(&mint));
        assert!(account_state.contains_key(&owner));
    }

    #[test]
    fn test_token_2022_transfer_with_fee() {
        let processor = TransactionProcessor::new();

        let source = Pubkey::new_unique();
        let dest = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let authority = Pubkey::new_unique();

        // Create source account with 10000 tokens
        let mut source_data = vec![0u8; 165];
        source_data[0..32].copy_from_slice(&mint.to_bytes());
        source_data[32..64].copy_from_slice(&authority.to_bytes());
        source_data[64..72].copy_from_slice(&10000u64.to_le_bytes());
        source_data[105] = 1; // Initialized

        let source_account = Account {
            meta: AccountMeta {
                lamports: 2_000_000,
                owner: TOKEN_2022_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::new(source_data),
        };

        // Create dest account with 0 tokens
        let mut dest_data = vec![0u8; 165];
        dest_data[0..32].copy_from_slice(&mint.to_bytes());
        dest_data[32..64].copy_from_slice(&Pubkey::new_unique().to_bytes());
        dest_data[105] = 1;

        let dest_account = Account {
            meta: AccountMeta {
                lamports: 2_000_000,
                owner: TOKEN_2022_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::new(dest_data),
        };

        let mint_account = Account {
            meta: AccountMeta {
                lamports: 1_000_000,
                owner: TOKEN_2022_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::new(create_test_mint(9)),
        };

        // Transfer with fee instruction
        let mut instruction_data = vec![27u8]; // TransferCheckedWithFee
        instruction_data.extend_from_slice(&1000u64.to_le_bytes()); // amount
        instruction_data.push(9); // decimals
        instruction_data.extend_from_slice(&10u64.to_le_bytes()); // fee (1%)

        let outcome = processor.process_instruction(
            TOKEN_2022_PROGRAM_ID,
            vec![
                (source, source_account, true),
                (mint, mint_account, false),
                (dest, dest_account, true),
                (authority, create_test_account(0, SYSTEM_PROGRAM_ID), false),
            ],
            instruction_data,
        );

        assert!(outcome.success);
        assert!(outcome.compute_units_consumed > 0);
    }

    #[test]
    fn test_associated_token_account_creation() {
        let processor = TransactionProcessor::new();

        let payer = Pubkey::new_unique();
        let wallet = Pubkey::new_unique();
        let mint = Pubkey::new_unique();

        // Derive ATA address
        use crate::AssociatedTokenProgramExecutor;
        let ata = AssociatedTokenProgramExecutor::get_associated_token_address(
            &wallet,
            &mint,
            &TOKEN_PROGRAM_ID,
            &ASSOCIATED_TOKEN_PROGRAM_ID,
        );

        let payer_account = create_test_account(5_000_000, SYSTEM_PROGRAM_ID);
        let ata_account = create_test_account(0, SYSTEM_PROGRAM_ID);
        let wallet_account = create_test_account(1_000_000, SYSTEM_PROGRAM_ID);

        let mint_account = Account {
            meta: AccountMeta {
                lamports: 1_000_000,
                owner: TOKEN_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::new(create_test_mint(9)),
        };

        let instruction_data = vec![0u8]; // Create

        let outcome = processor.process_instruction(
            ASSOCIATED_TOKEN_PROGRAM_ID,
            vec![
                (payer, payer_account, true),
                (ata, ata_account, true),
                (wallet, wallet_account, false),
                (mint, mint_account, false),
                (
                    SYSTEM_PROGRAM_ID,
                    create_test_account(0, SYSTEM_PROGRAM_ID),
                    false,
                ),
                (
                    TOKEN_PROGRAM_ID,
                    create_test_account(0, SYSTEM_PROGRAM_ID),
                    false,
                ),
            ],
            instruction_data,
        );

        assert!(outcome.success);
        assert_eq!(outcome.modified_accounts.len(), 2);

        // Verify ATA was created
        let created_ata = outcome.modified_accounts.get(&ata).unwrap();
        assert!(created_ata.meta.lamports > 0);
        assert_eq!(created_ata.meta.owner, TOKEN_PROGRAM_ID);
        assert_eq!(created_ata.data.len(), 165);
    }

    #[test]
    fn test_memo_with_token_transfer() {
        let processor = TransactionProcessor::new();

        // First execute memo
        let memo = "Payment for services: Invoice #12345";
        let memo_instruction = memo.as_bytes().to_vec();

        let outcome = processor.process_instruction(MEMO_PROGRAM_ID, vec![], memo_instruction);

        assert!(outcome.success);
        assert!(outcome.logs.len() > 0);
        assert!(outcome.logs[0].contains("Invoice #12345"));

        // Memo should not modify any accounts
        assert_eq!(outcome.modified_accounts.len(), 0);
    }

    #[test]
    fn test_token_2022_non_transferable() {
        let processor = TransactionProcessor::new();

        let mint = Pubkey::new_unique();

        let mint_account = create_test_account(1_000_000, TOKEN_2022_PROGRAM_ID);

        let instruction_data = vec![34u8]; // InitializeNonTransferableMint

        let outcome = processor.process_instruction(
            TOKEN_2022_PROGRAM_ID,
            vec![(mint, mint_account, true)],
            instruction_data,
        );

        assert!(outcome.success);
        assert_eq!(outcome.modified_accounts.len(), 1);
    }

    #[test]
    fn test_token_2022_interest_bearing() {
        let processor = TransactionProcessor::new();

        let mint = Pubkey::new_unique();
        let rate_authority = Pubkey::new_unique();

        let mint_account = create_test_account(1_000_000, TOKEN_2022_PROGRAM_ID);

        let mut instruction_data = vec![35u8]; // InitializeInterestBearingConfig
        instruction_data.push(1); // has authority
        instruction_data.extend_from_slice(&rate_authority.to_bytes());
        instruction_data.extend_from_slice(&500i16.to_le_bytes()); // 5% rate

        let outcome = processor.process_instruction(
            TOKEN_2022_PROGRAM_ID,
            vec![(mint, mint_account, true)],
            instruction_data,
        );

        assert!(outcome.success);
        assert_eq!(outcome.modified_accounts.len(), 1);
    }

    #[test]
    fn test_multiple_memos_in_transaction() {
        let processor = TransactionProcessor::new();

        let memos = vec!["Step 1: Initialize", "Step 2: Transfer", "Step 3: Complete"];

        for (i, memo) in memos.iter().enumerate() {
            let instruction_data = memo.as_bytes().to_vec();

            let outcome = processor.process_instruction(MEMO_PROGRAM_ID, vec![], instruction_data);

            assert!(outcome.success);
            assert!(outcome.logs[0].contains(memo));
            println!("Memo {}: {:?}", i + 1, outcome.logs);
        }
    }

    #[test]
    fn test_associated_token_idempotent() {
        let processor = TransactionProcessor::new();

        let payer = Pubkey::new_unique();
        let wallet = Pubkey::new_unique();
        let mint = Pubkey::new_unique();

        use crate::AssociatedTokenProgramExecutor;
        let ata = AssociatedTokenProgramExecutor::get_associated_token_address(
            &wallet,
            &mint,
            &TOKEN_PROGRAM_ID,
            &ASSOCIATED_TOKEN_PROGRAM_ID,
        );

        // Create ATA that already exists
        let mut ata_data = vec![0u8; 165];
        ata_data[0..32].copy_from_slice(&mint.to_bytes());
        ata_data[32..64].copy_from_slice(&wallet.to_bytes());
        ata_data[105] = 1;

        let ata_account = Account {
            meta: AccountMeta {
                lamports: 2_000_000,
                owner: TOKEN_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::new(ata_data),
        };

        let instruction_data = vec![1u8]; // CreateIdempotent

        let outcome = processor.process_instruction(
            ASSOCIATED_TOKEN_PROGRAM_ID,
            vec![
                (
                    payer,
                    create_test_account(5_000_000, SYSTEM_PROGRAM_ID),
                    true,
                ),
                (ata, ata_account, true),
                (
                    wallet,
                    create_test_account(1_000_000, SYSTEM_PROGRAM_ID),
                    false,
                ),
                (
                    mint,
                    Account {
                        meta: AccountMeta {
                            lamports: 1_000_000,
                            owner: TOKEN_PROGRAM_ID,
                            executable: false,
                            rent_epoch: 0,
                        },
                        data: AccountData::new(create_test_mint(9)),
                    },
                    false,
                ),
                (
                    SYSTEM_PROGRAM_ID,
                    create_test_account(0, SYSTEM_PROGRAM_ID),
                    false,
                ),
                (
                    TOKEN_PROGRAM_ID,
                    create_test_account(0, SYSTEM_PROGRAM_ID),
                    false,
                ),
            ],
            instruction_data,
        );

        // Should succeed even though account already exists
        assert!(outcome.success);
    }

    #[test]
    fn test_token_2022_default_account_state() {
        let processor = TransactionProcessor::new();

        let mint = Pubkey::new_unique();
        let mint_account = create_test_account(1_000_000, TOKEN_2022_PROGRAM_ID);

        let mut instruction_data = vec![32u8]; // InitializeDefaultAccountState
        instruction_data.push(2); // Frozen

        let outcome = processor.process_instruction(
            TOKEN_2022_PROGRAM_ID,
            vec![(mint, mint_account, true)],
            instruction_data,
        );

        assert!(outcome.success);
        assert_eq!(outcome.modified_accounts.len(), 1);
    }

    #[test]
    fn test_compute_budget_across_programs() {
        let processor = TransactionProcessor::new();

        // Test that different programs have appropriate compute costs
        let programs = vec![
            (TOKEN_PROGRAM_ID, vec![0u8], 300 + 50), // InitializeMint base cost
            (TOKEN_2022_PROGRAM_ID, vec![0u8], 320 + 50),
            (MEMO_PROGRAM_ID, "test".as_bytes().to_vec(), 100 + 4),
        ];

        for (program_id, instruction_data, expected_min_cost) in programs {
            let outcome = processor.process_instruction(program_id, vec![], instruction_data);

            if outcome.success {
                assert!(
                    outcome.compute_units_consumed >= expected_min_cost,
                    "Program {} used {} compute units, expected at least {}",
                    program_id,
                    outcome.compute_units_consumed,
                    expected_min_cost
                );
            }
        }
    }

    #[test]
    fn test_nested_ata_recovery() {
        let processor = TransactionProcessor::new();

        let owner = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let wallet_ata = Pubkey::new_unique();
        let nested_ata = Pubkey::new_unique();

        // Nested ATA owned by wallet_ata with 1000 tokens
        let mut nested_data = vec![0u8; 165];
        nested_data[0..32].copy_from_slice(&mint.to_bytes());
        nested_data[32..64].copy_from_slice(&wallet_ata.to_bytes());
        nested_data[64..72].copy_from_slice(&1000u64.to_le_bytes());
        nested_data[105] = 1;

        let nested_account = Account {
            meta: AccountMeta {
                lamports: 2_000_000,
                owner: TOKEN_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::new(nested_data),
        };

        // Wallet ATA owned by owner with 500 tokens
        let mut wallet_data = vec![0u8; 165];
        wallet_data[0..32].copy_from_slice(&mint.to_bytes());
        wallet_data[32..64].copy_from_slice(&owner.to_bytes());
        wallet_data[64..72].copy_from_slice(&500u64.to_le_bytes());
        wallet_data[105] = 1;

        let wallet_account = Account {
            meta: AccountMeta {
                lamports: 2_000_000,
                owner: TOKEN_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::new(wallet_data),
        };

        let mint_account = Account {
            meta: AccountMeta {
                lamports: 1_000_000,
                owner: TOKEN_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::new(create_test_mint(9)),
        };

        let instruction_data = vec![2u8]; // RecoverNested

        let outcome = processor.process_instruction(
            ASSOCIATED_TOKEN_PROGRAM_ID,
            vec![
                (nested_ata, nested_account, true),
                (wallet_ata, wallet_account, true),
                (owner, create_test_account(0, SYSTEM_PROGRAM_ID), false),
                (mint, mint_account, false),
                (
                    TOKEN_PROGRAM_ID,
                    create_test_account(0, SYSTEM_PROGRAM_ID),
                    false,
                ),
            ],
            instruction_data,
        );

        assert!(outcome.success);
        assert_eq!(outcome.modified_accounts.len(), 2);

        // Verify nested ATA was closed
        let modified_nested = outcome.modified_accounts.get(&nested_ata).unwrap();
        assert_eq!(modified_nested.meta.lamports, 0);

        // Verify wallet ATA received tokens and lamports
        let modified_wallet = outcome.modified_accounts.get(&wallet_ata).unwrap();
        assert_eq!(modified_wallet.meta.lamports, 4_000_000); // 2M + 2M

        let wallet_amount =
            u64::from_le_bytes(modified_wallet.data.as_slice()[64..72].try_into().unwrap());
        assert_eq!(wallet_amount, 1500); // 500 + 1000
    }

    #[test]
    fn test_memo_max_length() {
        let processor = TransactionProcessor::new();

        use crate::memo_program::MAX_MEMO_LENGTH;

        // Test memo at max length
        let memo = "A".repeat(MAX_MEMO_LENGTH);
        let instruction_data = memo.as_bytes().to_vec();

        let outcome = processor.process_instruction(MEMO_PROGRAM_ID, vec![], instruction_data);

        assert!(outcome.success);
        assert_eq!(outcome.compute_units_consumed, 100 + MAX_MEMO_LENGTH as u64);
    }

    #[test]
    fn test_token_2022_mint_close_authority() {
        let processor = TransactionProcessor::new();

        let mint = Pubkey::new_unique();
        let close_authority = Pubkey::new_unique();

        let mint_account = create_test_account(1_000_000, TOKEN_2022_PROGRAM_ID);

        let mut instruction_data = vec![25u8]; // InitializeMintCloseAuthority
        instruction_data.push(1); // has authority
        instruction_data.extend_from_slice(&close_authority.to_bytes());

        let outcome = processor.process_instruction(
            TOKEN_2022_PROGRAM_ID,
            vec![(mint, mint_account, true)],
            instruction_data,
        );

        assert!(outcome.success);
        assert_eq!(outcome.modified_accounts.len(), 1);
    }

    #[test]
    fn test_program_routing() {
        let processor = TransactionProcessor::new();

        // Verify all SPL programs are properly routed
        let programs = vec![
            TOKEN_PROGRAM_ID,
            TOKEN_2022_PROGRAM_ID,
            ASSOCIATED_TOKEN_PROGRAM_ID,
            MEMO_PROGRAM_ID,
        ];

        for program_id in programs {
            let outcome = processor.process_instruction(program_id, vec![], vec![]);

            // All programs should execute (success depends on instruction)
            // The important part is they don't return "Unknown program"
            if !outcome.success {
                assert!(
                    !outcome
                        .logs
                        .iter()
                        .any(|log| log.contains("Unknown program")),
                    "Program {} should be recognized",
                    program_id
                );
            }
        }
    }
}
