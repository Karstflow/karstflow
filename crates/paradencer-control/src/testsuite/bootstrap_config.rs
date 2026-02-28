use crate::bootstrap::{load_node_config, resolve_validator_identity};
use paradencer_config::NodeConfig;

#[test]
fn load_node_config_from_profile_file_path() {
    let profile_path = std::env::temp_dir().join(format!(
        "paradencer-bootstrap-{}.toml",
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
    let node_config = NodeConfig::from_profile(None).unwrap();
    let identity = resolve_validator_identity(&node_config).unwrap();
    let derived = paradencer_crypto::public_key_from_secret(identity.secret_key());
    assert_eq!(&derived, identity.pubkey());
}

#[test]
fn resolve_identity_loads_from_file() {
    let (secret, pubkey) = paradencer_crypto::generate_keypair();
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

    let identity = paradencer_config::load_identity_keypair(&path).unwrap();
    assert_eq!(identity.secret_key(), &secret);
    assert_eq!(identity.pubkey(), &pubkey);
}
