use crate::bootstrap::load_node_config;
use crate::command::{ControlCommand, ControlCommandWithConfig, GenesisClusterParams};
use crate::errors::Result;
use crate::output::{render_keys_valid_line, render_version_line};
use crate::surface::{render_config_summary, validate_identity_keypair_from_env};
use crate::system_check;

pub fn dispatch_command<RunFn, PreflightFn, DiagnosticsFn>(
    parsed_command: ControlCommandWithConfig,
    run_handler: RunFn,
    preflight_handler: PreflightFn,
    diagnostics_handler: DiagnosticsFn,
) -> Result<()>
where
    RunFn: FnOnce(karstflow_config::NodeConfig) -> Result<()>,
    PreflightFn: FnOnce(karstflow_config::NodeConfig, u32, bool) -> Result<()>,
    DiagnosticsFn: FnOnce(karstflow_config::NodeConfig, u32, bool) -> Result<()>,
{
    match parsed_command.command {
        ControlCommand::Run => {
            let node_config = load_node_config(parsed_command.config_path.as_deref())?;
            run_handler(node_config)
        }
        ControlCommand::Preflight => {
            let node_config = load_node_config(parsed_command.config_path.as_deref())?;
            preflight_handler(
                node_config,
                parsed_command.probe_ticks,
                parsed_command.mainnet_readiness,
            )
        }
        ControlCommand::Diagnostics => {
            let node_config = load_node_config(parsed_command.config_path.as_deref())?;
            diagnostics_handler(
                node_config,
                parsed_command.probe_ticks,
                parsed_command.mainnet_readiness,
            )
        }
        ControlCommand::Config => {
            let node_config = load_node_config(parsed_command.config_path.as_deref())?;
            println!("{}", render_config_summary(&node_config));
            Ok(())
        }
        ControlCommand::Configure => {
            let mainnet = parsed_command.mainnet_readiness;
            let results = system_check::run_system_checks(mainnet);
            println!("{}", system_check::format_system_checks(&results));
            if system_check::all_checks_passed(&results) {
                Ok(())
            } else {
                Err(crate::errors::ControlPlaneError::Bootstrap {
                    message: "system prerequisites not met".to_string(),
                })
            }
        }
        ControlCommand::Monitor => {
            let node_config = load_node_config(parsed_command.config_path.as_deref())?;
            run_monitor(&node_config)
        }
        ControlCommand::Keys => {
            let keypair_path = validate_identity_keypair_from_env()?;
            println!("{}", render_keys_valid_line(&keypair_path));
            Ok(())
        }
        ControlCommand::Version => {
            println!(
                "{}",
                render_version_line("karstflow-node", env!("CARGO_PKG_VERSION"))
            );
            Ok(())
        }
        ControlCommand::GenesisInit => run_genesis_init(),
        ControlCommand::GenesisCluster(params) => run_genesis_cluster(params),
    }
}

/// Display live validator status by querying the local RPC endpoint.
///
/// Shows current slot, epoch, vote status, peer count, and health. Designed
/// as a lightweight alternative to a full dashboard — similar to `fdctl monitor`.
fn run_monitor(node_config: &karstflow_config::NodeConfig) -> Result<()> {
    let rpc_bind = match node_config.rpc_bind {
        Some(addr) => addr,
        None => {
            println!("RPC is not enabled in the current configuration.");
            return Ok(());
        }
    };
    println!("Karstflow Validator Monitor");
    println!("{}", "=".repeat(50));
    println!("  RPC endpoint:  http://{rpc_bind}");
    println!();

    // Attempt to connect to the local RPC endpoint.
    let url = format!("http://{rpc_bind}");
    match query_rpc_health(&url) {
        Ok(info) => {
            println!("  Status:        ONLINE");
            println!("  Slot:          {}", info.slot);
            println!("  Epoch:         {}", info.epoch);
            println!("  Block height:  {}", info.block_height);
            println!("  Health:        {}", info.health);
        }
        Err(e) => {
            println!("  Status:        OFFLINE ({e})");
            println!();
            println!("  The validator does not appear to be running.");
            println!("  Start it with: karstflow-node run");
        }
    }

    Ok(())
}

struct MonitorInfo {
    slot: u64,
    epoch: u64,
    block_height: u64,
    health: String,
}

fn query_rpc_health(url: &str) -> std::result::Result<MonitorInfo, String> {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    let addr = url.strip_prefix("http://").unwrap_or(url);

    let mut stream = TcpStream::connect_timeout(
        &addr
            .parse::<std::net::SocketAddr>()
            .map_err(|e| format!("invalid address: {e}"))?,
        Duration::from_secs(2),
    )
    .map_err(|e| format!("connection refused: {e}"))?;

    stream.set_read_timeout(Some(Duration::from_secs(3))).ok();

    // Send getEpochInfo RPC request.
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"getEpochInfo"}"#;
    let request = format!(
        "POST / HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("send failed: {e}"))?;

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|e| format!("read failed: {e}"))?;

    // Parse the JSON body from HTTP response.
    let json_start = response.find('{').ok_or("no JSON in response")?;
    let json_body = &response[json_start..];

    // Simple field extraction without full JSON parser dependency.
    let slot = extract_json_u64(json_body, "absoluteSlot").unwrap_or(0);
    let epoch = extract_json_u64(json_body, "epoch").unwrap_or(0);
    let block_height = extract_json_u64(json_body, "blockHeight").unwrap_or(0);

    Ok(MonitorInfo {
        slot,
        epoch,
        block_height,
        health: "ok".to_string(),
    })
}

/// Extract a u64 value from a flat JSON object by key name.
fn extract_json_u64(json: &str, key: &str) -> Option<u64> {
    let pattern = format!("\"{}\":", key);
    let start = json.find(&pattern)? + pattern.len();
    let rest = json[start..].trim_start();
    let end = rest.find(|c: char| !c.is_ascii_digit())?;
    rest[..end].parse().ok()
}

/// Interactive genesis generation.
///
/// Prompts for key parameters (or uses defaults) and writes a genesis.bin
/// file to the specified output path. Designed for easy local cluster
/// bootstrap without requiring a separate tool.
fn run_genesis_init() -> Result<()> {
    use std::io::{self, BufRead, Write};

    fn prompt(label: &str, default: &str) -> String {
        print!("{label} [{default}]: ");
        io::stdout().flush().ok();
        let mut line = String::new();
        io::stdin().lock().read_line(&mut line).ok();
        let trimmed = line.trim();
        if trimmed.is_empty() {
            default.to_string()
        } else {
            trimmed.to_string()
        }
    }

    println!("=== Karstflow Genesis Generator ===\n");

    let output_path = prompt("Output path", "genesis.bin");
    let cluster_type = prompt(
        "Cluster type (development/devnet/testnet/mainnet)",
        "development",
    );
    let ticks_per_slot = prompt("Ticks per slot", "64");
    let identity_lamports = prompt("Identity account lamports", "500000000000");
    let faucet_lamports = prompt("Faucet account lamports", "500000000000000000");
    let hashes_per_tick = prompt("Hashes per tick (empty for none)", "");

    let cluster_type_val = match cluster_type.as_str() {
        "development" | "dev" => karstflow_storage::ClusterType::Development,
        "devnet" => karstflow_storage::ClusterType::Devnet,
        "testnet" => karstflow_storage::ClusterType::Testnet,
        "mainnet" | "mainnet-beta" => karstflow_storage::ClusterType::Mainnet,
        _ => {
            return Err(crate::errors::ControlPlaneError::InvalidCommand {
                command: format!("unknown cluster type: {cluster_type}"),
            });
        }
    };

    let ticks: u64 =
        ticks_per_slot
            .parse()
            .map_err(|_| crate::errors::ControlPlaneError::InvalidCommand {
                command: format!("invalid ticks_per_slot: {ticks_per_slot}"),
            })?;

    let id_lamports: u64 = identity_lamports.parse().map_err(|_| {
        crate::errors::ControlPlaneError::InvalidCommand {
            command: format!("invalid identity lamports: {identity_lamports}"),
        }
    })?;

    let faucet_lamps: u64 =
        faucet_lamports
            .parse()
            .map_err(|_| crate::errors::ControlPlaneError::InvalidCommand {
                command: format!("invalid faucet lamports: {faucet_lamports}"),
            })?;

    let hashes: Option<u64> = if hashes_per_tick.is_empty() {
        None
    } else {
        Some(hashes_per_tick.parse().map_err(|_| {
            crate::errors::ControlPlaneError::InvalidCommand {
                command: format!("invalid hashes_per_tick: {hashes_per_tick}"),
            }
        })?)
    };

    let mut genesis = karstflow_storage::GenesisConfig::default_development();
    genesis.cluster_type = cluster_type_val;
    genesis.ticks_per_slot = ticks;
    genesis.poh_config_hashes_per_tick = hashes;

    // Add identity account.
    let identity = karstflow_storage::Pubkey::new_unique();
    genesis.accounts.push((
        identity,
        karstflow_storage::GenesisAccount {
            lamports: id_lamports,
            data: Vec::new(),
            owner: karstflow_ids::SYSTEM_PROGRAM_ID,
            executable: false,
            rent_epoch: u64::MAX,
        },
    ));

    // Add faucet account.
    let faucet = crate::bootstrap::development_faucet_pubkey();
    genesis.accounts.push((
        faucet,
        karstflow_storage::GenesisAccount {
            lamports: faucet_lamps,
            data: Vec::new(),
            owner: karstflow_ids::SYSTEM_PROGRAM_ID,
            executable: false,
            rent_epoch: u64::MAX,
        },
    ));

    let data = karstflow_storage::genesis::serialize_genesis(&genesis).map_err(|e| {
        crate::errors::ControlPlaneError::Bootstrap {
            message: format!("genesis serialization failed: {e}"),
        }
    })?;

    std::fs::write(&output_path, &data).map_err(|e| {
        crate::errors::ControlPlaneError::Bootstrap {
            message: format!("failed to write {output_path}: {e}"),
        }
    })?;

    println!("\nGenesis written to: {output_path}");
    println!("  Cluster type:    {cluster_type}");
    println!("  Ticks per slot:  {ticks}");
    println!("  Accounts:        {}", genesis.accounts.len());
    println!("  Identity:        {identity}");
    println!("  Faucet:          {faucet}");
    println!("  Total supply:    {} lamports", genesis.total_supply());
    println!("  File size:       {} bytes", data.len());

    Ok(())
}

/// Generate a local multi-validator cluster genesis.
///
/// Creates `node_count` Ed25519 keypairs, a shared genesis file, and
/// per-node configuration files. The output directory structure is:
///
/// ```text
/// {output_dir}/
///   genesis.bin              — shared genesis for all nodes
///   node0/
///     identity.json          — validator identity keypair (64-byte JSON array)
///     config.toml            — node configuration (ports, genesis path)
///   node1/
///     identity.json
///     config.toml
///   ...
///   start.sh                 — convenience script to start all nodes
/// ```
///
/// Also available as [`run_genesis_cluster_public`] for integration testing.
#[cfg(test)]
pub(crate) fn run_genesis_cluster_public(params: GenesisClusterParams) -> Result<()> {
    run_genesis_cluster(params)
}

fn run_genesis_cluster(params: GenesisClusterParams) -> Result<()> {
    use karstflow_constants::economics::LAMPORTS_PER_SOL;
    use karstflow_crypto::ed25519_batch::generate_keypair;
    use karstflow_storage::Pubkey;
    use std::fs;

    let GenesisClusterParams {
        node_count,
        output_dir,
    } = params;

    println!("=== Karstflow Local Cluster Genesis ===\n");
    println!(
        "Generating {node_count}-validator cluster in: {}",
        output_dir.display()
    );

    // Create output directory and resolve to absolute path for TOML configs.
    fs::create_dir_all(&output_dir).map_err(|e| crate::errors::ControlPlaneError::Bootstrap {
        message: format!(
            "failed to create output directory {}: {e}",
            output_dir.display()
        ),
    })?;
    let output_dir = fs::canonicalize(&output_dir).unwrap_or(output_dir);

    // Generate keypairs for all validators.
    let mut keypairs: Vec<([u8; 32], [u8; 32])> = Vec::with_capacity(node_count);
    let mut validators: Vec<(Pubkey, u64)> = Vec::with_capacity(node_count);

    for _ in 0..node_count {
        let (secret, pubkey_bytes) = generate_keypair();
        let pubkey = Pubkey::new(pubkey_bytes);
        keypairs.push((secret, pubkey_bytes));
        validators.push((pubkey, 1_000_000_000)); // Equal stake per validator
    }

    // Build genesis with all validators.
    let mut genesis = karstflow_storage::GenesisConfig::default_development();

    // Record initial validator set so every node sees the full leader schedule.
    genesis.initial_validators = keypairs
        .iter()
        .map(|(_, pubkey_bytes)| (Pubkey::new(*pubkey_bytes), 1_000_000_000_u64))
        .collect();

    // Add each validator identity account.
    for (_, pubkey_bytes) in &keypairs {
        let pubkey = Pubkey::new(*pubkey_bytes);
        genesis.accounts.push((
            pubkey,
            karstflow_storage::GenesisAccount {
                lamports: 500 * LAMPORTS_PER_SOL,
                data: Vec::new(),
                owner: karstflow_ids::SYSTEM_PROGRAM_ID,
                executable: false,
                rent_epoch: u64::MAX,
            },
        ));
    }

    // Add faucet account.
    let faucet = crate::bootstrap::development_faucet_pubkey();
    genesis.accounts.push((
        faucet,
        karstflow_storage::GenesisAccount {
            lamports: 500_000_000 * LAMPORTS_PER_SOL,
            data: Vec::new(),
            owner: karstflow_ids::SYSTEM_PROGRAM_ID,
            executable: false,
            rent_epoch: u64::MAX,
        },
    ));

    // Write genesis.bin.
    let genesis_data = karstflow_storage::genesis::serialize_genesis(&genesis).map_err(|e| {
        crate::errors::ControlPlaneError::Bootstrap {
            message: format!("genesis serialization failed: {e}"),
        }
    })?;
    let genesis_path = output_dir.join("genesis.bin");
    fs::write(&genesis_path, &genesis_data).map_err(|e| {
        crate::errors::ControlPlaneError::Bootstrap {
            message: format!("failed to write genesis.bin: {e}"),
        }
    })?;

    // Base ports: gossip 8001, RPC 8899, TPU 9001. Each subsequent node adds 10.
    const BASE_GOSSIP_PORT: u16 = 8001;
    const BASE_RPC_PORT: u16 = 8899;
    const BASE_TPU_PORT: u16 = 9001;
    const PORT_STEP: u16 = 10;

    // Bootstrap node gossip address (node 0) for all other nodes.
    let bootstrap_gossip = format!("127.0.0.1:{BASE_GOSSIP_PORT}");

    // Write per-node directories, keypairs, and configs.
    let mut start_lines: Vec<String> = vec![
        "#!/usr/bin/env bash".to_string(),
        "# Auto-generated by `karstflow-node genesis cluster`".to_string(),
        "set -e".to_string(),
        format!("CLUSTER_DIR=\"$(dirname \"$0\")\""),
        String::new(),
        "echo 'Starting local cluster...'".to_string(),
        String::new(),
    ];

    for (i, (secret_key, pubkey_bytes)) in keypairs.iter().enumerate() {
        let node_dir = output_dir.join(format!("node{i}"));
        fs::create_dir_all(&node_dir).map_err(|e| crate::errors::ControlPlaneError::Bootstrap {
            message: format!("failed to create node{i} directory: {e}"),
        })?;

        // Write identity keypair as JSON array (64 bytes: [secret..., pubkey...]).
        let mut keypair_bytes = Vec::with_capacity(64);
        keypair_bytes.extend_from_slice(secret_key);
        keypair_bytes.extend_from_slice(pubkey_bytes);
        let keypair_json = serde_json::to_string(&keypair_bytes).map_err(|e| {
            crate::errors::ControlPlaneError::Bootstrap {
                message: format!("keypair serialization failed: {e}"),
            }
        })?;
        let keypair_path = node_dir.join("identity.json");
        fs::write(&keypair_path, keypair_json.as_bytes()).map_err(|e| {
            crate::errors::ControlPlaneError::Bootstrap {
                message: format!("failed to write node{i}/identity.json: {e}"),
            }
        })?;

        // Calculate this node's ports.
        let gossip_port = BASE_GOSSIP_PORT + i as u16 * PORT_STEP;
        let rpc_port = BASE_RPC_PORT + i as u16 * PORT_STEP;
        let tpu_port = BASE_TPU_PORT + i as u16 * PORT_STEP;
        let tvu_port = gossip_port + 8;

        // Write per-node TOML config with absolute paths.
        let abs_dir = output_dir.display();
        let config_content = format!(
            "# Node {i} configuration — generated by genesis cluster\n\
             \n\
             [cluster]\n\
             mode = \"dev\"\n\
             gossip_bind_addr = \"127.0.0.1:{gossip_port}\"\n\
             gossip_allow_private_addresses = true\n\
             entrypoints = [\"{bootstrap_gossip}\"]\n\
             genesis_path = \"{abs_dir}/genesis.bin\"\n\
             data_dir = \"{abs_dir}/node{i}/data\"\n\
             identity_keypair_path = \"{abs_dir}/node{i}/identity.json\"\n\
             \n\
             [runtime]\n\
             mode = \"tokio\"\n\
             \n\
             [rpc]\n\
             enabled = true\n\
             bind = \"127.0.0.1:{rpc_port}\"\n\
             \n\
             [ingress_policy]\n\
             ingress_mode = \"udp\"\n\
             udp_bind_address = \"127.0.0.1:{tpu_port}\"\n\
             tvu_bind_address = \"127.0.0.1:{tvu_port}\"\n\
             \n\
             [logging]\n\
             stderr_level = \"info\"\n"
        );
        let config_path = node_dir.join("config.toml");
        fs::write(&config_path, config_content.as_bytes()).map_err(|e| {
            crate::errors::ControlPlaneError::Bootstrap {
                message: format!("failed to write node{i}/config.toml: {e}"),
            }
        })?;

        // Add start command to script.
        let pubkey_b58 = bs58::encode(pubkey_bytes).into_string();
        start_lines.push(format!(
            "echo 'Starting node{i} (pubkey: {pubkey_b58}, RPC: {rpc_port}, gossip: {gossip_port})'",
        ));
        start_lines.push(format!(
            "KARSTFLOW_NODE_CONFIG_PATH=\"$CLUSTER_DIR/node{i}/config.toml\" \\\n  \
             cargo run -p karstflow-node &"
        ));
        start_lines.push(String::new());
    }

    start_lines.push("echo 'All nodes started. PIDs in background.'".to_string());
    start_lines.push("echo 'Use: kill $(jobs -p)  to stop the cluster'".to_string());
    start_lines.push("wait".to_string());

    // Write start.sh.
    let start_sh = start_lines.join("\n");
    let start_path = output_dir.join("start.sh");
    fs::write(&start_path, start_sh.as_bytes()).map_err(|e| {
        crate::errors::ControlPlaneError::Bootstrap {
            message: format!("failed to write start.sh: {e}"),
        }
    })?;

    // Make start.sh executable on Unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(mut perms) = fs::metadata(&start_path).map(|m| m.permissions()) {
            perms.set_mode(0o755);
            let _ = fs::set_permissions(&start_path, perms);
        }
    }

    // Print summary.
    println!("\nCluster initialized successfully!\n");
    println!("  Validators:      {node_count}");
    println!("  Genesis:         {}", genesis_path.display());
    println!("  Genesis size:    {} bytes", genesis_data.len());
    println!("  Total accounts:  {}", genesis.accounts.len());
    println!("  Faucet:          {faucet}");
    println!();
    println!("Per-node layout:");
    for (i, (_, pubkey_bytes)) in keypairs.iter().enumerate() {
        let pubkey_b58 = bs58::encode(pubkey_bytes).into_string();
        let gossip_port = BASE_GOSSIP_PORT + i as u16 * PORT_STEP;
        let rpc_port = BASE_RPC_PORT + i as u16 * PORT_STEP;
        println!("  node{i}  identity={pubkey_b58}  gossip={gossip_port}  rpc={rpc_port}");
    }
    println!();
    println!("To start the cluster:");
    println!("  bash {}", output_dir.join("start.sh").display());
    println!();
    println!("Or start nodes individually:");
    for i in 0..node_count {
        println!(
            "  KARSTFLOW_NODE_CONFIG_PATH={} cargo run -p karstflow-node",
            output_dir.join(format!("node{i}/config.toml")).display()
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::dispatch_command;
    use crate::{ControlCommand, ControlCommandWithConfig};

    #[test]
    fn dispatch_invokes_run_handler() {
        let mut invoked = false;
        let parsed_command = ControlCommandWithConfig {
            command: ControlCommand::Run,
            config_path: None,
            probe_ticks: 0,
            mainnet_readiness: false,
        };
        let result = dispatch_command(
            parsed_command,
            |_node_config| {
                invoked = true;
                Ok(())
            },
            |_node_config, _probe_ticks, _mainnet_readiness| Ok(()),
            |_node_config, _probe_ticks, _mainnet_readiness| Ok(()),
        );
        assert!(result.is_ok());
        assert!(invoked);
    }

    #[test]
    #[ignore = "requires >=16GB RAM, >=4 cores, >=50GB disk — skipped on CI runners"]
    fn dispatch_configure_runs_system_checks() {
        let parsed_command = ControlCommandWithConfig {
            command: ControlCommand::Configure,
            config_path: None,
            probe_ticks: 0,
            mainnet_readiness: false,
        };
        // Configure doesn't need run/preflight/diagnostics handlers.
        let result = dispatch_command(
            parsed_command,
            |_node_config| Ok(()),
            |_node_config, _probe_ticks, _mainnet_readiness| Ok(()),
            |_node_config, _probe_ticks, _mainnet_readiness| Ok(()),
        );
        // On a dev machine, all non-mainnet checks should pass.
        assert!(result.is_ok());
    }

    #[test]
    fn dispatch_invokes_diagnostics_handler() {
        let mut invoked = false;
        let parsed_command = ControlCommandWithConfig {
            command: ControlCommand::Diagnostics,
            config_path: None,
            probe_ticks: 3,
            mainnet_readiness: true,
        };
        let result = dispatch_command(
            parsed_command,
            |_node_config| Ok(()),
            |_node_config, _probe_ticks, _mainnet_readiness| Ok(()),
            |_node_config, probe_ticks, mainnet_readiness| {
                invoked = true;
                assert_eq!(probe_ticks, 3);
                assert!(mainnet_readiness);
                Ok(())
            },
        );
        assert!(result.is_ok());
        assert!(invoked);
    }

    #[test]
    fn dispatch_invokes_preflight_handler_with_mainnet_readiness_flag() {
        let mut invoked = false;
        let parsed_command = ControlCommandWithConfig {
            command: ControlCommand::Preflight,
            config_path: None,
            probe_ticks: 1,
            mainnet_readiness: true,
        };
        let result = dispatch_command(
            parsed_command,
            |_node_config| Ok(()),
            |_node_config, probe_ticks, mainnet_readiness| {
                invoked = true;
                assert_eq!(probe_ticks, 1);
                assert!(mainnet_readiness);
                Ok(())
            },
            |_node_config, _probe_ticks, _mainnet_readiness| Ok(()),
        );
        assert!(result.is_ok());
        assert!(invoked);
    }
}
