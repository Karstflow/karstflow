use crate::bootstrap::load_node_config;
use crate::command::{ControlCommand, ControlCommandWithConfig};
use crate::errors::Result;
use crate::output::{render_keys_valid_line, render_version_line};
use crate::surface::{render_config_summary, validate_identity_keypair_from_env};

pub fn dispatch_command<RunFn, PreflightFn, DiagnosticsFn>(
    parsed_command: ControlCommandWithConfig,
    run_handler: RunFn,
    preflight_handler: PreflightFn,
    diagnostics_handler: DiagnosticsFn,
) -> Result<()>
where
    RunFn: FnOnce(paradencer_config::NodeConfig) -> Result<()>,
    PreflightFn: FnOnce(paradencer_config::NodeConfig, u32, bool) -> Result<()>,
    DiagnosticsFn: FnOnce(paradencer_config::NodeConfig, u32, bool) -> Result<()>,
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
        ControlCommand::Keys => {
            let keypair_path = validate_identity_keypair_from_env()?;
            println!("{}", render_keys_valid_line(&keypair_path));
            Ok(())
        }
        ControlCommand::Version => {
            println!(
                "{}",
                render_version_line("paradencer-node", env!("CARGO_PKG_VERSION"))
            );
            Ok(())
        }
        ControlCommand::GenesisInit => run_genesis_init(),
    }
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

    println!("=== Paradencer Genesis Generator ===\n");

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
        "development" | "dev" => paradencer_storage::ClusterType::Development,
        "devnet" => paradencer_storage::ClusterType::Devnet,
        "testnet" => paradencer_storage::ClusterType::Testnet,
        "mainnet" | "mainnet-beta" => paradencer_storage::ClusterType::Mainnet,
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

    let mut genesis = paradencer_storage::GenesisConfig::default_development();
    genesis.cluster_type = cluster_type_val;
    genesis.ticks_per_slot = ticks;
    genesis.poh_config_hashes_per_tick = hashes;

    // Add identity account.
    let identity = paradencer_storage::Pubkey::new_unique();
    genesis.accounts.push((
        identity,
        paradencer_storage::GenesisAccount {
            lamports: id_lamports,
            data: Vec::new(),
            owner: paradencer_ids::SYSTEM_PROGRAM_ID,
            executable: false,
            rent_epoch: u64::MAX,
        },
    ));

    // Add faucet account.
    let faucet = crate::bootstrap::development_faucet_pubkey();
    genesis.accounts.push((
        faucet,
        paradencer_storage::GenesisAccount {
            lamports: faucet_lamps,
            data: Vec::new(),
            owner: paradencer_ids::SYSTEM_PROGRAM_ID,
            executable: false,
            rent_epoch: u64::MAX,
        },
    ));

    let data = paradencer_storage::genesis::serialize_genesis(&genesis).map_err(|e| {
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
