use crate::validate_dev_mode_rejects_production_cluster;
use karstflow_constants::genesis::{
    DEVNET_GENESIS_HASH, MAINNET_GENESIS_HASH, TESTNET_GENESIS_HASH,
};

#[test]
fn dev_mode_rejects_devnet_genesis_hash() {
    let result = validate_dev_mode_rejects_production_cluster(Some(DEVNET_GENESIS_HASH), &[]);
    let err = result.unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("devnet"), "error should mention devnet: {msg}");
    assert!(
        msg.contains("test-validator mode"),
        "error should mention test-validator mode: {msg}"
    );
}

#[test]
fn dev_mode_rejects_testnet_genesis_hash() {
    let result = validate_dev_mode_rejects_production_cluster(Some(TESTNET_GENESIS_HASH), &[]);
    let err = result.unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("testnet"),
        "error should mention testnet: {msg}"
    );
}

#[test]
fn dev_mode_rejects_mainnet_genesis_hash() {
    let result = validate_dev_mode_rejects_production_cluster(Some(MAINNET_GENESIS_HASH), &[]);
    let err = result.unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("mainnet"),
        "error should mention mainnet: {msg}"
    );
}

#[test]
fn dev_mode_rejects_devnet_entrypoints() {
    let eps = vec!["entrypoint.devnet.solana.com:8001".to_string()];
    let result = validate_dev_mode_rejects_production_cluster(None, &eps);
    let err = result.unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("devnet"), "error should mention devnet: {msg}");
}

#[test]
fn dev_mode_rejects_testnet_entrypoints() {
    let eps = vec!["entrypoint.testnet.solana.com:8001".to_string()];
    let result = validate_dev_mode_rejects_production_cluster(None, &eps);
    let err = result.unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("testnet"),
        "error should mention testnet: {msg}"
    );
}

#[test]
fn dev_mode_rejects_mainnet_entrypoints() {
    let eps = vec!["entrypoint.mainnet-beta.solana.com:8001".to_string()];
    let result = validate_dev_mode_rejects_production_cluster(None, &eps);
    let err = result.unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("mainnet"),
        "error should mention mainnet: {msg}"
    );
}

#[test]
fn dev_mode_allows_custom_entrypoints() {
    let eps = vec!["192.168.1.10:8001".to_string()];
    let result = validate_dev_mode_rejects_production_cluster(None, &eps);
    assert!(result.is_ok(), "custom IPs should be allowed in dev mode");
}

#[test]
fn dev_mode_allows_no_hash_and_no_entrypoints() {
    let result = validate_dev_mode_rejects_production_cluster(None, &[]);
    assert!(result.is_ok());
}

#[test]
fn dev_mode_allows_custom_genesis_hash() {
    let result = validate_dev_mode_rejects_production_cluster(
        Some("CuStOmGeNeSiSHaSh111111111111111111111111111"),
        &[],
    );
    assert!(result.is_ok());
}
