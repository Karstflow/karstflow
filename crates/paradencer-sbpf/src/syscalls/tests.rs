//! Comprehensive tests for all syscall modules.

use super::*;
use paradencer_constants::syscalls::*;
use paradencer_types::{Account, Pubkey};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Helper to create a default context with a generous compute budget.
// ---------------------------------------------------------------------------

fn test_context() -> SyscallContext {
    SyscallContext::new(Pubkey::new_unique(), 1_000_000)
}

fn test_context_with_budget(budget: u64) -> SyscallContext {
    SyscallContext::new(Pubkey::new_unique(), budget)
}

// ===========================================================================
// CPI tests
// ===========================================================================

#[test]
fn cpi_invoke_with_valid_accounts() {
    let caller_id = Pubkey::new_unique();
    let callee_id = Pubkey::new_unique();
    let account_key = Pubkey::new_unique();

    let account = Account::new(1000, vec![], caller_id);
    let mut accounts = HashMap::new();
    accounts.insert(account_key, account);

    let mut ctx = SyscallContext::new(caller_id, 1_000_000);
    ctx.accounts = accounts;

    let instruction = CpiInstruction {
        program_id: callee_id,
        accounts: vec![CpiAccountMeta {
            pubkey: account_key,
            is_signer: false,
            is_writable: true,
        }],
        data: vec![1, 2, 3],
    };

    let account_infos = vec![
        CpiAccountInfo {
            pubkey: callee_id,
            lamports: 0,
            data: vec![],
            owner: Pubkey::new_unique(),
            executable: true,
        },
        CpiAccountInfo {
            pubkey: account_key,
            lamports: 1000,
            data: vec![],
            owner: caller_id,
            executable: false,
        },
    ];

    let result = invoke(&mut ctx, &instruction, &account_infos);
    assert!(result.is_ok());
}

#[test]
fn cpi_invoke_signed_with_signer_seeds() {
    let caller_id = Pubkey::new_unique();
    let callee_id = Pubkey::new_unique();
    let account_key = Pubkey::new_unique();

    let mut ctx = SyscallContext::new(caller_id, 1_000_000);
    ctx.accounts
        .insert(account_key, Account::new(1000, vec![], caller_id));

    let instruction = CpiInstruction {
        program_id: callee_id,
        accounts: vec![CpiAccountMeta {
            pubkey: account_key,
            is_signer: true,
            is_writable: true,
        }],
        data: vec![],
    };

    let account_infos = vec![
        CpiAccountInfo {
            pubkey: callee_id,
            lamports: 0,
            data: vec![],
            owner: Pubkey::new_unique(),
            executable: true,
        },
        CpiAccountInfo {
            pubkey: account_key,
            lamports: 1000,
            data: vec![],
            owner: caller_id,
            executable: false,
        },
    ];

    let seeds: &[&[u8]] = &[b"seed1", b"seed2"];
    let result = invoke_signed(&mut ctx, &instruction, &account_infos, &[seeds]);
    assert!(result.is_ok());
}

#[test]
fn cpi_exceeds_max_depth() {
    let caller_id = Pubkey::new_unique();
    let callee_id = Pubkey::new_unique();

    let mut ctx = SyscallContext::new(caller_id, 1_000_000);
    ctx.stack_depth = MAX_CPI_DEPTH; // Already at max

    let instruction = CpiInstruction {
        program_id: callee_id,
        accounts: vec![],
        data: vec![],
    };

    let result = invoke(&mut ctx, &instruction, &[]);
    assert_eq!(result, Err(SyscallError::MaxCpiDepthExceeded));
}

#[test]
fn cpi_reentrancy_detection() {
    let program_id = Pubkey::new_unique();
    let mut ctx = SyscallContext::new(program_id, 1_000_000);

    // Try to invoke the same program
    let instruction = CpiInstruction {
        program_id, // Same as caller
        accounts: vec![],
        data: vec![],
    };

    let result = invoke(&mut ctx, &instruction, &[]);
    assert_eq!(result, Err(SyscallError::ReentrancyDetected));
}

#[test]
fn cpi_account_privilege_validation() {
    let caller_id = Pubkey::new_unique();
    let callee_id = Pubkey::new_unique();
    let unknown_account = Pubkey::new_unique();

    // Context has no accounts
    let mut ctx = SyscallContext::new(caller_id, 1_000_000);

    let instruction = CpiInstruction {
        program_id: callee_id,
        accounts: vec![CpiAccountMeta {
            pubkey: unknown_account,
            is_signer: false,
            is_writable: true,
        }],
        data: vec![],
    };

    let account_infos = vec![
        CpiAccountInfo {
            pubkey: callee_id,
            lamports: 0,
            data: vec![],
            owner: Pubkey::new_unique(),
            executable: true,
        },
        CpiAccountInfo {
            pubkey: unknown_account,
            lamports: 100,
            data: vec![],
            owner: caller_id,
            executable: false,
        },
    ];

    let result = invoke(&mut ctx, &instruction, &account_infos);
    assert!(matches!(result, Err(SyscallError::AccessViolation(_))));
}

#[test]
fn cpi_instruction_size_limit() {
    let caller_id = Pubkey::new_unique();
    let callee_id = Pubkey::new_unique();
    let mut ctx = SyscallContext::new(caller_id, 10_000_000);

    let instruction = CpiInstruction {
        program_id: callee_id,
        accounts: vec![],
        data: vec![0u8; MAX_CPI_INSTRUCTION_SIZE + 1],
    };

    let result = invoke(&mut ctx, &instruction, &[]);
    assert_eq!(result, Err(SyscallError::MaxInstructionSizeExceeded));
}

#[test]
fn cpi_compute_cost_accounting() {
    let caller_id = Pubkey::new_unique();
    let callee_id = Pubkey::new_unique();
    let account_key = Pubkey::new_unique();

    let mut ctx = SyscallContext::new(caller_id, 1_000_000);
    ctx.accounts
        .insert(account_key, Account::new(100, vec![], caller_id));

    let initial_compute = ctx.compute_meter;

    let data_len = 100;
    let num_accounts = 2;
    let instruction = CpiInstruction {
        program_id: callee_id,
        accounts: vec![
            CpiAccountMeta {
                pubkey: account_key,
                is_signer: false,
                is_writable: true,
            },
            CpiAccountMeta {
                pubkey: account_key,
                is_signer: false,
                is_writable: false,
            },
        ],
        data: vec![0u8; data_len],
    };

    let account_infos = vec![
        CpiAccountInfo {
            pubkey: callee_id,
            lamports: 0,
            data: vec![],
            owner: Pubkey::new_unique(),
            executable: true,
        },
        CpiAccountInfo {
            pubkey: account_key,
            lamports: 100,
            data: vec![],
            owner: caller_id,
            executable: false,
        },
    ];

    invoke(&mut ctx, &instruction, &account_infos).unwrap();

    let expected_cost = CPI_BASE_COST
        + CPI_PER_ACCOUNT_COST * num_accounts as u64
        + CPI_PER_DATA_BYTE_COST * data_len as u64;

    assert_eq!(ctx.compute_meter, initial_compute - expected_cost);
}

#[test]
fn cpi_program_not_executable() {
    let caller_id = Pubkey::new_unique();
    let callee_id = Pubkey::new_unique();

    let mut ctx = SyscallContext::new(caller_id, 1_000_000);

    let instruction = CpiInstruction {
        program_id: callee_id,
        accounts: vec![],
        data: vec![],
    };

    let account_infos = vec![CpiAccountInfo {
        pubkey: callee_id,
        lamports: 0,
        data: vec![],
        owner: Pubkey::new_unique(),
        executable: false, // Not executable
    }];

    let result = invoke(&mut ctx, &instruction, &account_infos);
    assert_eq!(result, Err(SyscallError::ProgramNotExecutable));
}

#[test]
fn cpi_invalid_signer_seeds() {
    let caller_id = Pubkey::new_unique();
    let callee_id = Pubkey::new_unique();

    let mut ctx = SyscallContext::new(caller_id, 1_000_000);

    let instruction = CpiInstruction {
        program_id: callee_id,
        accounts: vec![],
        data: vec![],
    };

    // Too many seeds
    let too_many_seeds: Vec<&[u8]> = (0..MAX_SIGNER_SEEDS + 1).map(|_| &b"seed"[..]).collect();

    let result = invoke_signed(&mut ctx, &instruction, &[], &[&too_many_seeds]);
    assert_eq!(result, Err(SyscallError::InvalidSeeds));
}

#[test]
fn cpi_seed_too_long() {
    let caller_id = Pubkey::new_unique();
    let callee_id = Pubkey::new_unique();

    let mut ctx = SyscallContext::new(caller_id, 1_000_000);

    let instruction = CpiInstruction {
        program_id: callee_id,
        accounts: vec![],
        data: vec![],
    };

    let long_seed = vec![0u8; MAX_SEED_BYTES + 1];
    let seeds: &[&[u8]] = &[&long_seed];

    let result = invoke_signed(&mut ctx, &instruction, &[], &[seeds]);
    assert_eq!(result, Err(SyscallError::InvalidSeeds));
}

// ===========================================================================
// Crypto tests
// ===========================================================================

#[test]
fn sha256_produces_correct_hash() {
    let mut ctx = test_context();
    let data = b"hello world";

    let result = sha256(&mut ctx, data).unwrap();

    // Known SHA-256 of "hello world"
    let expected: [u8; 32] = [
        0xb9, 0x4d, 0x27, 0xb9, 0x93, 0x4d, 0x3e, 0x08, 0xa5, 0x2e, 0x52, 0xd7, 0xda, 0x7d, 0xab,
        0xfa, 0xc4, 0x84, 0xef, 0xe3, 0x7a, 0x53, 0x80, 0xee, 0x90, 0x88, 0xf7, 0xac, 0xe2, 0xef,
        0xcd, 0xe9,
    ];
    assert_eq!(result, expected);
}

#[test]
fn sha256_deducts_correct_compute_units() {
    let mut ctx = test_context();
    let data = vec![0u8; 100];
    let initial = ctx.compute_meter;

    sha256(&mut ctx, &data).unwrap();

    let expected_cost = SHA256_BASE_COST + SHA256_PER_BYTE_COST * 100;
    assert_eq!(ctx.compute_meter, initial - expected_cost);
}

#[test]
fn sha256_empty_input() {
    let mut ctx = test_context();
    let result = sha256(&mut ctx, b"").unwrap();

    // Known SHA-256 of empty string
    let expected: [u8; 32] = [
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9,
        0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
        0xb8, 0x55,
    ];
    assert_eq!(result, expected);
}

#[test]
fn sha256_insufficient_compute() {
    let mut ctx = test_context_with_budget(10);
    let data = vec![0u8; 1000]; // Would cost 100 + 2000 = 2100

    let result = sha256(&mut ctx, &data);
    assert_eq!(result, Err(SyscallError::ComputeBudgetExceeded));
}

#[test]
fn keccak256_produces_deterministic_hash() {
    let mut ctx = test_context();
    let data = b"test data";

    let result1 = keccak256(&mut ctx, data).unwrap();
    let result2 = keccak256(&mut ctx, data).unwrap();

    assert_eq!(result1, result2);
}

#[test]
fn keccak256_different_input_different_hash() {
    let mut ctx = test_context();

    let result1 = keccak256(&mut ctx, b"input1").unwrap();
    let result2 = keccak256(&mut ctx, b"input2").unwrap();

    assert_ne!(result1, result2);
}

#[test]
fn keccak256_deducts_compute() {
    let mut ctx = test_context();
    let data = vec![0u8; 50];
    let initial = ctx.compute_meter;

    keccak256(&mut ctx, &data).unwrap();

    let expected_cost = KECCAK256_BASE_COST + KECCAK256_PER_BYTE_COST * 50;
    assert_eq!(ctx.compute_meter, initial - expected_cost);
}

#[test]
fn secp256k1_recover_compute_cost() {
    let mut ctx = test_context();
    let initial = ctx.compute_meter;

    let hash = [0u8; 32];
    let signature = [0u8; 64];
    secp256k1_recover(&mut ctx, &hash, 0, &signature).unwrap();

    assert_eq!(ctx.compute_meter, initial - SECP256K1_RECOVER_COST);
}

#[test]
fn secp256k1_recover_invalid_recovery_id() {
    let mut ctx = test_context();
    let hash = [0u8; 32];
    let signature = [0u8; 64];

    let result = secp256k1_recover(&mut ctx, &hash, 4, &signature);
    assert!(matches!(result, Err(SyscallError::InvalidArgument(_))));
}

#[test]
fn secp256k1_recover_deterministic() {
    let mut ctx = test_context();
    let hash = [1u8; 32];
    let signature = [2u8; 64];

    let result1 = secp256k1_recover(&mut ctx, &hash, 1, &signature).unwrap();
    let result2 = secp256k1_recover(&mut ctx, &hash, 1, &signature).unwrap();

    assert_eq!(result1, result2);
}

// ===========================================================================
// Blake3 tests
// ===========================================================================

#[test]
fn blake3_produces_correct_hash() {
    let mut ctx = test_context();
    let data = b"hello world";

    let result = blake3_hash(&mut ctx, data).unwrap();

    // Verify against blake3 crate directly
    let expected = *blake3::hash(data).as_bytes();
    assert_eq!(result, expected);
}

#[test]
fn blake3_deducts_compute() {
    let mut ctx = test_context();
    let data = vec![0u8; 200];
    let initial = ctx.compute_meter;

    blake3_hash(&mut ctx, &data).unwrap();

    let expected_cost = BLAKE3_BASE_COST + BLAKE3_PER_BYTE_COST * 200;
    assert_eq!(ctx.compute_meter, initial - expected_cost);
}

#[test]
fn blake3_empty_input() {
    let mut ctx = test_context();
    let result = blake3_hash(&mut ctx, b"").unwrap();
    let expected = *blake3::hash(b"").as_bytes();
    assert_eq!(result, expected);
}

// ===========================================================================
// PDA tests
// ===========================================================================

#[test]
fn create_program_address_deterministic() {
    let mut ctx = test_context();
    let program_id = Pubkey::new([1u8; 32]);
    let seeds: &[&[u8]] = &[b"hello", b"world"];

    let result1 = create_program_address(&mut ctx, seeds, &program_id).unwrap();
    let result2 = create_program_address(&mut ctx, seeds, &program_id).unwrap();

    assert_eq!(result1, result2);
}

#[test]
fn create_program_address_different_seeds_different_result() {
    let mut ctx = test_context();
    let program_id = Pubkey::new([1u8; 32]);

    let result1 = create_program_address(&mut ctx, &[b"seed1"], &program_id).unwrap();
    let result2 = create_program_address(&mut ctx, &[b"seed2"], &program_id).unwrap();

    assert_ne!(result1, result2);
}

#[test]
fn create_program_address_different_programs_different_result() {
    let mut ctx = test_context();
    let seeds: &[&[u8]] = &[b"test"];

    let result1 = create_program_address(&mut ctx, seeds, &Pubkey::new([1u8; 32])).unwrap();
    let result2 = create_program_address(&mut ctx, seeds, &Pubkey::new([2u8; 32])).unwrap();

    assert_ne!(result1, result2);
}

#[test]
fn create_program_address_too_many_seeds() {
    let mut ctx = test_context();
    let program_id = Pubkey::new_unique();

    let seeds: Vec<&[u8]> = (0..MAX_SIGNER_SEEDS + 1).map(|_| &b"x"[..]).collect();

    let result = create_program_address(&mut ctx, &seeds, &program_id);
    assert_eq!(result, Err(SyscallError::InvalidSeeds));
}

#[test]
fn create_program_address_seed_too_long() {
    let mut ctx = test_context();
    let program_id = Pubkey::new_unique();
    let long_seed = vec![0u8; MAX_SEED_BYTES + 1];

    let result = create_program_address(&mut ctx, &[&long_seed], &program_id);
    assert_eq!(result, Err(SyscallError::InvalidSeeds));
}

#[test]
fn create_program_address_deducts_compute() {
    let mut ctx = test_context();
    let initial = ctx.compute_meter;
    let program_id = Pubkey::new_unique();

    create_program_address(&mut ctx, &[b"test"], &program_id).unwrap();

    assert_eq!(ctx.compute_meter, initial - CREATE_PROGRAM_ADDRESS_COST);
}

#[test]
fn try_find_program_address_returns_valid_pda() {
    let mut ctx = test_context();
    let program_id = Pubkey::new([3u8; 32]);
    let seeds: &[&[u8]] = &[b"test_pda"];

    let (pda, bump) = try_find_program_address(&mut ctx, seeds, &program_id).unwrap();

    // The PDA should be a valid 32-byte pubkey
    assert_eq!(pda.as_bytes().len(), 32);
    // Bump should be 255 for the first iteration (simplified)
    assert_eq!(bump, 255);
}

#[test]
fn try_find_program_address_deterministic() {
    let mut ctx = test_context();
    let program_id = Pubkey::new([5u8; 32]);
    let seeds: &[&[u8]] = &[b"deterministic"];

    let (pda1, bump1) = try_find_program_address(&mut ctx, seeds, &program_id).unwrap();
    let (pda2, bump2) = try_find_program_address(&mut ctx, seeds, &program_id).unwrap();

    assert_eq!(pda1, pda2);
    assert_eq!(bump1, bump2);
}

#[test]
fn try_find_program_address_deducts_compute() {
    let mut ctx = test_context();
    let initial = ctx.compute_meter;
    let program_id = Pubkey::new_unique();

    try_find_program_address(&mut ctx, &[b"test"], &program_id).unwrap();

    // At minimum: base cost + one iteration
    let min_cost = FIND_PROGRAM_ADDRESS_COST + FIND_PROGRAM_ADDRESS_PER_ITERATION;
    assert!(initial - ctx.compute_meter >= min_cost);
}

#[test]
fn try_find_program_address_too_many_seeds() {
    let mut ctx = test_context();
    let program_id = Pubkey::new_unique();

    // MAX_SIGNER_SEEDS seeds would leave no room for the bump seed
    let seeds: Vec<&[u8]> = (0..MAX_SIGNER_SEEDS).map(|_| &b"x"[..]).collect();

    let result = try_find_program_address(&mut ctx, &seeds, &program_id);
    assert_eq!(result, Err(SyscallError::InvalidSeeds));
}

// ===========================================================================
// Memory tests
// ===========================================================================

#[test]
fn memcpy_copies_correctly() {
    let mut ctx = test_context();
    let src = [1u8, 2, 3, 4, 5];
    let mut dst = [0u8; 5];

    sol_memcpy(&mut ctx, &mut dst, &src, 5).unwrap();
    assert_eq!(dst, [1, 2, 3, 4, 5]);
}

#[test]
fn memcpy_partial_copy() {
    let mut ctx = test_context();
    let src = [10u8, 20, 30, 40, 50];
    let mut dst = [0u8; 5];

    sol_memcpy(&mut ctx, &mut dst, &src, 3).unwrap();
    assert_eq!(dst, [10, 20, 30, 0, 0]);
}

#[test]
fn memcpy_destination_too_small() {
    let mut ctx = test_context();
    let src = [0u8; 10];
    let mut dst = [0u8; 5];

    let result = sol_memcpy(&mut ctx, &mut dst, &src, 10);
    assert!(matches!(result, Err(SyscallError::AccessViolation(_))));
}

#[test]
fn memcmp_equal_buffers() {
    let mut ctx = test_context();
    let a = [1u8, 2, 3];
    let b = [1u8, 2, 3];

    let result = sol_memcmp(&mut ctx, &a, &b, 3).unwrap();
    assert_eq!(result, 0);
}

#[test]
fn memcmp_first_less_than_second() {
    let mut ctx = test_context();
    let a = [1u8, 2, 3];
    let b = [1u8, 2, 4];

    let result = sol_memcmp(&mut ctx, &a, &b, 3).unwrap();
    assert!(result < 0);
}

#[test]
fn memcmp_first_greater_than_second() {
    let mut ctx = test_context();
    let a = [1u8, 3, 3];
    let b = [1u8, 2, 3];

    let result = sol_memcmp(&mut ctx, &a, &b, 3).unwrap();
    assert!(result > 0);
}

#[test]
fn memcmp_partial_comparison() {
    let mut ctx = test_context();
    let a = [1u8, 2, 100];
    let b = [1u8, 2, 200];

    // Only compare first 2 bytes, which are equal
    let result = sol_memcmp(&mut ctx, &a, &b, 2).unwrap();
    assert_eq!(result, 0);
}

#[test]
fn memmove_handles_copy() {
    let mut ctx = test_context();
    let src = [5u8, 6, 7, 8];
    let mut dst = [0u8; 4];

    sol_memmove(&mut ctx, &mut dst, &src, 4).unwrap();
    assert_eq!(dst, [5, 6, 7, 8]);
}

#[test]
fn memset_fills_correctly() {
    let mut ctx = test_context();
    let mut buf = [0u8; 8];

    sol_memset(&mut ctx, &mut buf, 0xFF, 8).unwrap();
    assert_eq!(buf, [0xFF; 8]);
}

#[test]
fn memset_partial_fill() {
    let mut ctx = test_context();
    let mut buf = [0u8; 8];

    sol_memset(&mut ctx, &mut buf, 0xAB, 4).unwrap();
    assert_eq!(buf, [0xAB, 0xAB, 0xAB, 0xAB, 0, 0, 0, 0]);
}

#[test]
fn memory_ops_deduct_compute() {
    let mut ctx = test_context();
    let initial = ctx.compute_meter;
    let mut buf = [0u8; 100];

    sol_memset(&mut ctx, &mut buf, 0, 100).unwrap();

    let expected_cost = MEMSET_BASE_COST + MEMSET_PER_BYTE_COST * 100;
    assert_eq!(ctx.compute_meter, initial - expected_cost);
}

#[test]
fn memset_destination_too_small() {
    let mut ctx = test_context();
    let mut buf = [0u8; 5];

    let result = sol_memset(&mut ctx, &mut buf, 0, 10);
    assert!(matches!(result, Err(SyscallError::AccessViolation(_))));
}

// ===========================================================================
// Logging tests
// ===========================================================================

#[test]
fn sol_log_appends_to_logs() {
    let mut ctx = test_context();

    sol_log(&mut ctx, "test message").unwrap();

    assert_eq!(ctx.logs.len(), 1);
    assert!(ctx.logs[0].contains("test message"));
}

#[test]
fn sol_log_multiple_messages() {
    let mut ctx = test_context();

    sol_log(&mut ctx, "first").unwrap();
    sol_log(&mut ctx, "second").unwrap();
    sol_log(&mut ctx, "third").unwrap();

    assert_eq!(ctx.logs.len(), 3);
    assert!(ctx.logs[0].contains("first"));
    assert!(ctx.logs[1].contains("second"));
    assert!(ctx.logs[2].contains("third"));
}

#[test]
fn sol_log_deducts_compute() {
    let mut ctx = test_context();
    let initial = ctx.compute_meter;

    let msg = "hello compute";
    sol_log(&mut ctx, msg).unwrap();

    let expected_cost = LOG_BASE_COST + LOG_PER_BYTE_COST * msg.len() as u64;
    assert_eq!(ctx.compute_meter, initial - expected_cost);
}

#[test]
fn sol_log_data_encodes_base64() {
    let mut ctx = test_context();

    let data_slices: &[&[u8]] = &[b"hello", b"world"];
    sol_log_data(&mut ctx, data_slices).unwrap();

    assert_eq!(ctx.logs.len(), 1);
    assert!(ctx.logs[0].starts_with("Program data: "));
    // "hello" in base64 is "aGVsbG8="
    assert!(ctx.logs[0].contains("aGVsbG8="));
}

#[test]
fn sol_log_compute_units_shows_remaining() {
    let mut ctx = test_context_with_budget(50_000);

    sol_log_compute_units(&mut ctx).unwrap();

    assert_eq!(ctx.logs.len(), 1);
    // After consuming LOG_COMPUTE_UNITS_COST, remaining should be 50000 - 100 = 49900
    assert!(ctx.logs[0].contains("49900"));
}

#[test]
fn sol_log_insufficient_compute() {
    let mut ctx = test_context_with_budget(50);

    let result = sol_log(
        &mut ctx,
        "this message is long enough to cost more than 50 compute units",
    );
    assert_eq!(result, Err(SyscallError::ComputeBudgetExceeded));
}

// ===========================================================================
// Return data tests
// ===========================================================================

#[test]
fn set_return_data_stores_data() {
    let mut ctx = test_context();
    let data = b"return value";
    let expected_pid = ctx.program_id;

    set_return_data(&mut ctx, data).unwrap();

    assert!(ctx.return_data.is_some());
    let (pid, stored) = ctx.return_data.as_ref().unwrap();
    assert_eq!(*pid, expected_pid);
    assert_eq!(stored.as_slice(), &data[..]);
}

#[test]
fn get_return_data_retrieves_stored() {
    let program_id = Pubkey::new_unique();
    let mut ctx = SyscallContext::new(program_id, 1_000_000);

    set_return_data(&mut ctx, b"test data").unwrap();
    let result = get_return_data(&mut ctx).unwrap();

    assert!(result.is_some());
    let (pid, data) = result.unwrap();
    assert_eq!(pid, program_id);
    assert_eq!(data, b"test data");
}

#[test]
fn get_return_data_none_when_empty() {
    let mut ctx = test_context();

    let result = get_return_data(&mut ctx).unwrap();
    assert!(result.is_none());
}

#[test]
fn return_data_size_limit() {
    let mut ctx = test_context();
    let data = vec![0u8; MAX_RETURN_DATA_SIZE + 1];

    let result = set_return_data(&mut ctx, &data);
    assert_eq!(result, Err(SyscallError::MaxReturnDataSizeExceeded));
}

#[test]
fn return_data_exactly_max_size() {
    let mut ctx = test_context();
    let data = vec![42u8; MAX_RETURN_DATA_SIZE];

    let result = set_return_data(&mut ctx, &data);
    assert!(result.is_ok());
}

#[test]
fn set_return_data_replaces_previous() {
    let mut ctx = test_context();

    set_return_data(&mut ctx, b"first").unwrap();
    set_return_data(&mut ctx, b"second").unwrap();

    let result = get_return_data(&mut ctx).unwrap();
    let (_, data) = result.unwrap();
    assert_eq!(data, b"second");
}

#[test]
fn return_data_deducts_compute() {
    let mut ctx = test_context();
    let initial = ctx.compute_meter;
    let data = vec![0u8; 100];

    set_return_data(&mut ctx, &data).unwrap();

    let expected_cost = SET_RETURN_DATA_COST + SET_RETURN_DATA_PER_BYTE * 100;
    assert_eq!(ctx.compute_meter, initial - expected_cost);
}

// ===========================================================================
// Runtime / sysvar tests
// ===========================================================================

#[test]
fn get_clock_returns_valid_values() {
    let mut ctx = test_context();

    let clock = get_clock(&mut ctx).unwrap();

    // Default values should be reasonable
    assert_eq!(clock.slot, 0);
    assert_eq!(clock.epoch, 0);
}

#[test]
fn get_clock_deducts_compute() {
    let mut ctx = test_context();
    let initial = ctx.compute_meter;

    get_clock(&mut ctx).unwrap();

    assert_eq!(ctx.compute_meter, initial - GET_SYSVAR_COST);
}

#[test]
fn get_epoch_schedule_returns_values() {
    let mut ctx = test_context();

    let schedule = get_epoch_schedule(&mut ctx).unwrap();

    assert_eq!(
        schedule.slots_per_epoch,
        paradencer_constants::ledger::SLOTS_PER_EPOCH
    );
}

#[test]
fn get_rent_returns_values() {
    let mut ctx = test_context();

    let rent = get_rent(&mut ctx).unwrap();

    assert!(rent.lamports_per_byte_year > 0);
    assert!(rent.exemption_threshold > 0.0);
}

#[test]
fn get_stack_height_returns_current_depth() {
    let mut ctx = test_context();
    ctx.stack_depth = 3;

    let height = get_stack_height(&mut ctx).unwrap();
    assert_eq!(height, 3);
}

#[test]
fn get_stack_height_zero_at_top_level() {
    let mut ctx = test_context();

    let height = get_stack_height(&mut ctx).unwrap();
    assert_eq!(height, 0);
}

#[test]
fn get_stack_height_deducts_compute() {
    let mut ctx = test_context();
    let initial = ctx.compute_meter;

    get_stack_height(&mut ctx).unwrap();

    assert_eq!(ctx.compute_meter, initial - GET_STACK_HEIGHT_COST);
}

#[test]
fn get_processed_sibling_instruction_returns_none() {
    let mut ctx = test_context();

    let result = get_processed_sibling_instruction(&mut ctx, 0).unwrap();
    assert!(result.is_none());
}

#[test]
fn get_processed_sibling_deducts_compute() {
    let mut ctx = test_context();
    let initial = ctx.compute_meter;

    get_processed_sibling_instruction(&mut ctx, 0).unwrap();

    assert_eq!(
        ctx.compute_meter,
        initial - GET_PROCESSED_SIBLING_INSTRUCTION_COST
    );
}

// ===========================================================================
// Curve tests
// ===========================================================================

#[test]
fn alt_bn128_add_deducts_compute() {
    let mut ctx = test_context();
    let initial = ctx.compute_meter;
    let input = [0u8; 128];

    alt_bn128::add(&mut ctx, &input).unwrap();

    assert_eq!(ctx.compute_meter, initial - ALT_BN128_ADD_COST);
}

#[test]
fn alt_bn128_add_wrong_input_size() {
    let mut ctx = test_context();
    let input = [0u8; 100]; // Wrong size

    let result = alt_bn128::add(&mut ctx, &input);
    assert!(matches!(result, Err(SyscallError::InvalidArgument(_))));
}

#[test]
fn alt_bn128_mul_deducts_compute() {
    let mut ctx = test_context();
    let initial = ctx.compute_meter;
    let input = [0u8; 96];

    alt_bn128::mul(&mut ctx, &input).unwrap();

    assert_eq!(ctx.compute_meter, initial - ALT_BN128_MUL_COST);
}

#[test]
fn alt_bn128_mul_wrong_input_size() {
    let mut ctx = test_context();
    let input = [0u8; 64]; // Wrong size

    let result = alt_bn128::mul(&mut ctx, &input);
    assert!(matches!(result, Err(SyscallError::InvalidArgument(_))));
}

#[test]
fn alt_bn128_pairing_deducts_compute() {
    let mut ctx = test_context();
    let initial = ctx.compute_meter;
    let input = [0u8; 192]; // One pair

    alt_bn128::pairing(&mut ctx, &input).unwrap();

    let expected = ALT_BN128_PAIRING_BASE_COST + ALT_BN128_PAIRING_PER_PAIR_COST;
    assert_eq!(ctx.compute_meter, initial - expected);
}

#[test]
fn alt_bn128_pairing_multiple_pairs() {
    let mut ctx = test_context();
    let initial = ctx.compute_meter;
    let input = [0u8; 384]; // Two pairs

    alt_bn128::pairing(&mut ctx, &input).unwrap();

    let expected = ALT_BN128_PAIRING_BASE_COST + ALT_BN128_PAIRING_PER_PAIR_COST * 2;
    assert_eq!(ctx.compute_meter, initial - expected);
}

#[test]
fn alt_bn128_pairing_wrong_input_size() {
    let mut ctx = test_context();
    let input = [0u8; 100]; // Not a multiple of 192

    let result = alt_bn128::pairing(&mut ctx, &input);
    assert!(matches!(result, Err(SyscallError::InvalidArgument(_))));
}

// ===========================================================================
// Compute budget exhaustion tests
// ===========================================================================

#[test]
fn consume_compute_exhaustion() {
    let mut ctx = test_context_with_budget(100);

    assert!(ctx.consume_compute(50).is_ok());
    assert_eq!(ctx.compute_meter, 50);

    assert!(ctx.consume_compute(50).is_ok());
    assert_eq!(ctx.compute_meter, 0);

    assert_eq!(
        ctx.consume_compute(1),
        Err(SyscallError::ComputeBudgetExceeded)
    );
}

#[test]
fn consume_compute_sets_meter_to_zero_on_overflow() {
    let mut ctx = test_context_with_budget(10);

    let result = ctx.consume_compute(100);
    assert_eq!(result, Err(SyscallError::ComputeBudgetExceeded));
    assert_eq!(ctx.compute_meter, 0);
}

#[test]
fn syscall_context_new_initializes_correctly() {
    let pid = Pubkey::new_unique();
    let ctx = SyscallContext::new(pid, 500_000);

    assert_eq!(ctx.program_id, pid);
    assert_eq!(ctx.compute_meter, 500_000);
    assert_eq!(ctx.stack_depth, 0);
    assert!(ctx.logs.is_empty());
    assert!(ctx.return_data.is_none());
    assert!(ctx.accounts.is_empty());
    assert!(ctx.modified_accounts.is_empty());
}
