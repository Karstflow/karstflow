use super::*;
use paradencer_types::Pubkey;

fn sample_genesis_account(lamports: u64, data_size: usize) -> GenesisAccount {
    GenesisAccount {
        lamports,
        data: vec![0xAB; data_size],
        owner: Pubkey::zeroed(),
        executable: false,
        rent_epoch: 0,
    }
}

fn sample_config_with_accounts(count: usize) -> GenesisConfig {
    let mut config = GenesisConfig::default_development();
    for i in 0..count {
        let mut bytes = [0u8; 32];
        bytes[0..8].copy_from_slice(&(i as u64).to_le_bytes());
        let pubkey = Pubkey::new(bytes);
        config
            .accounts
            .push((pubkey, sample_genesis_account(1000 * (i as u64 + 1), 64)));
    }
    config
}

#[test]
fn default_development_config_has_expected_values() {
    let config = GenesisConfig::default_development();

    assert_eq!(config.cluster_type, ClusterType::Development);
    assert_eq!(
        config.ticks_per_slot,
        paradencer_constants::ledger::TICKS_PER_SLOT
    );
    assert!(config.accounts.is_empty());
    assert!(config.native_instruction_processors.is_empty());
    assert!(config.rewards_pool_accounts.is_empty());
    assert_eq!(config.poh_config_target_tick_duration_ns, 6_250_000);
    assert_eq!(config.total_supply(), 0);
}

#[test]
fn default_fee_rate_governor() {
    let config = GenesisConfig::default_development();
    assert_eq!(
        config.fee_rate_governor.lamports_per_signature,
        paradencer_constants::economics::LAMPORTS_PER_SIGNATURE
    );
    assert_eq!(
        config.fee_rate_governor.burn_percent,
        paradencer_constants::economics::DEFAULT_FEE_BURN_PERCENT
    );
}

#[test]
fn default_inflation_parameters() {
    let config = GenesisConfig::default_development();
    assert!(
        (config.inflation.initial_rate - paradencer_constants::economics::INFLATION_INITIAL_RATE)
            .abs()
            < f64::EPSILON
    );
    assert!(
        (config.inflation.terminal_rate - paradencer_constants::economics::INFLATION_TERMINAL_RATE)
            .abs()
            < f64::EPSILON
    );
}

#[test]
fn total_supply_sums_all_accounts() {
    let mut config = GenesisConfig::default_development();
    config
        .accounts
        .push((Pubkey::new([1u8; 32]), sample_genesis_account(5000, 0)));
    config
        .accounts
        .push((Pubkey::new([2u8; 32]), sample_genesis_account(3000, 0)));
    config
        .rewards_pool_accounts
        .push((Pubkey::new([3u8; 32]), sample_genesis_account(2000, 0)));

    assert_eq!(config.total_supply(), 10_000);
}

#[test]
fn total_supply_empty_genesis() {
    let config = GenesisConfig::default_development();
    assert_eq!(config.total_supply(), 0);
}

#[test]
fn has_native_program_returns_true_when_registered() {
    let mut config = GenesisConfig::default_development();
    let program_id = Pubkey::new([42u8; 32]);
    config
        .native_instruction_processors
        .push(("my_program".to_string(), program_id));

    assert!(config.has_native_program(&program_id));
}

#[test]
fn has_native_program_returns_false_when_not_registered() {
    let config = GenesisConfig::default_development();
    let program_id = Pubkey::new([42u8; 32]);
    assert!(!config.has_native_program(&program_id));
}

#[test]
fn to_accounts_converts_all_accounts() {
    let mut config = GenesisConfig::default_development();
    config
        .accounts
        .push((Pubkey::new([1u8; 32]), sample_genesis_account(500, 16)));
    config
        .rewards_pool_accounts
        .push((Pubkey::new([2u8; 32]), sample_genesis_account(1000, 32)));

    let runtime_accounts = config.to_accounts();
    assert_eq!(runtime_accounts.len(), 2);

    let (pk1, acct1) = &runtime_accounts[0];
    assert_eq!(*pk1, Pubkey::new([1u8; 32]));
    assert_eq!(acct1.meta.lamports, 500);
    assert_eq!(acct1.data.len(), 16);

    let (pk2, acct2) = &runtime_accounts[1];
    assert_eq!(*pk2, Pubkey::new([2u8; 32]));
    assert_eq!(acct2.meta.lamports, 1000);
    assert_eq!(acct2.data.len(), 32);
}

#[test]
fn account_conversion_preserves_executable_flag() {
    let genesis = GenesisAccount {
        lamports: 100,
        data: vec![1, 2, 3],
        owner: Pubkey::new([5u8; 32]),
        executable: true,
        rent_epoch: 42,
    };
    let runtime = genesis.to_runtime_account();
    assert!(runtime.meta.executable);
    assert_eq!(runtime.meta.rent_epoch, 42);
    assert_eq!(runtime.meta.owner, Pubkey::new([5u8; 32]));
}

#[test]
fn bincode_round_trip() {
    let config = sample_config_with_accounts(10);
    let bytes = serialize_genesis(&config).expect("serialization should succeed");
    let restored = parse_genesis_bytes(&bytes).expect("deserialization should succeed");

    assert_eq!(config.cluster_type, restored.cluster_type);
    assert_eq!(config.ticks_per_slot, restored.ticks_per_slot);
    assert_eq!(config.accounts.len(), restored.accounts.len());
    assert_eq!(config.total_supply(), restored.total_supply());

    for i in 0..config.accounts.len() {
        assert_eq!(config.accounts[i].0, restored.accounts[i].0);
        assert_eq!(
            config.accounts[i].1.lamports,
            restored.accounts[i].1.lamports
        );
    }
}

#[test]
fn json_round_trip() {
    let config = sample_config_with_accounts(5);
    let json = serde_json::to_string(&config).expect("JSON serialization should succeed");
    let restored = parse_genesis_json(&json).expect("JSON deserialization should succeed");

    assert_eq!(config.cluster_type, restored.cluster_type);
    assert_eq!(config.accounts.len(), restored.accounts.len());
    assert_eq!(config.total_supply(), restored.total_supply());
}

#[test]
fn parse_genesis_with_many_accounts() {
    let config = sample_config_with_accounts(500);
    let bytes = serialize_genesis(&config).expect("serialization should succeed");
    let restored = parse_genesis_bytes(&bytes).expect("deserialization should succeed");

    assert_eq!(restored.accounts.len(), 500);
    assert_eq!(restored.total_supply(), config.total_supply());
}

#[test]
fn cluster_type_serialization() {
    for cluster in &[
        ClusterType::Mainnet,
        ClusterType::Devnet,
        ClusterType::Testnet,
        ClusterType::Development,
    ] {
        let json = serde_json::to_string(cluster).unwrap();
        let restored: ClusterType = serde_json::from_str(&json).unwrap();
        assert_eq!(*cluster, restored);
    }
}

#[test]
fn genesis_error_display() {
    let err = GenesisError::TooManyAccounts(2_000_000);
    assert!(err.to_string().contains("2000000"));

    let err = GenesisError::FileTooLarge(999);
    assert!(err.to_string().contains("999"));

    let err = GenesisError::DeserializationError("bad data".to_string());
    assert!(err.to_string().contains("bad data"));
}
