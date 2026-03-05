use crate::bootstrap::{load_node_config, resolve_validator_identity};
use crate::command::GenesisClusterParams;
use karstflow_config::NodeConfig;

#[test]
fn load_node_config_from_profile_file_path() {
    let profile_path = std::env::temp_dir().join(format!(
        "karstflow-bootstrap-{}.toml",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::write(&profile_path, "[runtime]\nworkers=5\n").unwrap();

    let result = load_node_config(Some(profile_path.as_path()));
    std::fs::remove_file(&profile_path).unwrap();

    assert!(result.is_ok());
    let config = result.unwrap();
    assert_eq!(config.runtime_spec.workers, 5);
}

#[test]
fn resolve_identity_generates_ephemeral_in_dev_mode() {
    // Build a minimal dev-mode config without touching env vars.
    // Using from_profile(None) is racy because parallel tests may set
    // KARSTFLOW_IDENTITY_KEYPAIR_PATH to a path whose keypair doesn't
    // match this test's expectations.
    let mut node_config = NodeConfig::from_profile(None).unwrap();
    node_config.identity_keypair_path = None;
    let identity = resolve_validator_identity(&node_config).unwrap();
    let derived = karstflow_crypto::public_key_from_secret(identity.secret_key());
    assert_eq!(&derived, identity.pubkey());
}

#[test]
fn resolve_identity_loads_from_file() {
    let (secret, pubkey) = karstflow_crypto::generate_keypair();
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(&secret);
    bytes.extend_from_slice(&pubkey);

    let json = format!(
        "[{}]",
        bytes
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(",")
    );

    let dir = tempfile::tempdir().expect("tmpdir");
    let path = dir.path().join("identity.json");
    std::fs::write(&path, &json).unwrap();

    let identity = karstflow_config::load_identity_keypair(&path).unwrap();
    assert_eq!(identity.secret_key(), &secret);
    assert_eq!(identity.pubkey(), &pubkey);
}

#[test]
fn genesis_cluster_produces_parseable_configs() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let params = GenesisClusterParams {
        node_count: 3,
        output_dir: dir.path().join("cluster"),
    };

    // Run genesis cluster generation.
    crate::runner::run_genesis_cluster_public(params).expect("genesis cluster should succeed");

    let cluster_dir = dir.path().join("cluster");

    // Verify genesis.bin exists.
    assert!(
        cluster_dir.join("genesis.bin").exists(),
        "genesis.bin missing"
    );

    // Verify start.sh exists and is non-empty.
    let start_sh = std::fs::read_to_string(cluster_dir.join("start.sh")).expect("start.sh");
    assert!(
        start_sh.contains("Starting local cluster"),
        "start.sh missing header"
    );

    // Verify each node's config.toml parses as valid NodeConfig.
    for i in 0..3 {
        let config_path = cluster_dir.join(format!("node{i}/config.toml"));
        assert!(config_path.exists(), "node{i}/config.toml missing");

        let config = load_node_config(Some(&config_path))
            .unwrap_or_else(|e| panic!("node{i}/config.toml failed to parse: {e}"));

        // Verify genesis_path points to absolute path.
        assert!(
            config.genesis_path.is_some(),
            "node{i} genesis_path not set"
        );
        let gp = config.genesis_path.as_ref().unwrap();
        assert!(
            gp.is_absolute(),
            "node{i} genesis_path should be absolute: {}",
            gp.display()
        );

        // Verify identity keypair loads and validates.
        let identity = resolve_validator_identity(&config)
            .unwrap_or_else(|e| panic!("node{i} identity failed: {e}"));
        let derived = karstflow_crypto::public_key_from_secret(identity.secret_key());
        assert_eq!(&derived, identity.pubkey(), "node{i} keypair mismatch");
    }
}
