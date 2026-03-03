use crate::errors::{ControlPlaneError, Result};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlCommandWithConfig {
    pub command: ControlCommand,
    pub config_path: Option<PathBuf>,
    pub probe_ticks: u32,
    pub mainnet_readiness: bool,
}

/// Parameters for `genesis cluster N` command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenesisClusterParams {
    /// Number of validators in the cluster.
    pub node_count: usize,
    /// Output directory for keypairs, genesis, and configs.
    pub output_dir: PathBuf,
}

/// Resolve a `--profile` name to a config file path.
///
/// Built-in profiles: `devnet`, `testnet`, `mainnet`.
/// Looks for `config/<profile>.toml` relative to the current directory,
/// then falls back to `<profile>` as a literal file path.
pub fn resolve_profile_path(profile: &str) -> PathBuf {
    let candidate = PathBuf::from(format!("config/{profile}.toml"));
    if candidate.exists() {
        return candidate;
    }
    PathBuf::from(profile)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlCommand {
    Run,
    Preflight,
    Diagnostics,
    Config,
    Keys,
    Version,
    GenesisInit,
    GenesisCluster(GenesisClusterParams),
}

pub fn parse_command(args: impl IntoIterator<Item = String>) -> Result<ControlCommandWithConfig> {
    let mut argv = args.into_iter();
    let _program_name = argv.next();

    let mut command = ControlCommand::Run;
    let mut config_path = None;
    let mut probe_ticks = 0_u32;
    let mut mainnet_readiness = false;

    while let Some(token) = argv.next() {
        match token.as_str() {
            "--config" => {
                let path = argv
                    .next()
                    .ok_or_else(|| ControlPlaneError::InvalidCommand {
                        command: "--config requires a path value".to_string(),
                    })?;
                config_path = Some(PathBuf::from(path));
            }
            "--profile" => {
                let profile_name =
                    argv.next()
                        .ok_or_else(|| ControlPlaneError::InvalidCommand {
                            command:
                                "--profile requires a name (devnet, testnet, mainnet, or path)"
                                    .to_string(),
                        })?;
                config_path = Some(resolve_profile_path(&profile_name));
            }
            "--with-tick" => {
                probe_ticks = probe_ticks.max(1);
            }
            "--probe-ticks" => {
                let value = argv
                    .next()
                    .ok_or_else(|| ControlPlaneError::InvalidCommand {
                        command: "--probe-ticks requires a positive integer".to_string(),
                    })?;
                let parsed =
                    value
                        .parse::<u32>()
                        .map_err(|_| ControlPlaneError::InvalidCommand {
                            command: format!("invalid --probe-ticks value '{value}'"),
                        })?;
                if parsed == 0 {
                    return Err(ControlPlaneError::InvalidCommand {
                        command: "--probe-ticks must be greater than zero".to_string(),
                    });
                }
                probe_ticks = parsed;
            }
            "--mainnet-readiness" => {
                mainnet_readiness = true;
            }
            "run" => command = ControlCommand::Run,
            "preflight" => command = ControlCommand::Preflight,
            "diagnostics" | "doctor" => command = ControlCommand::Diagnostics,
            "config" => command = ControlCommand::Config,
            "keys" => command = ControlCommand::Keys,
            "version" | "--version" | "-V" => command = ControlCommand::Version,
            "genesis" => {
                // Sub-command: `genesis init` | `genesis cluster N [--output-dir DIR]`
                if let Some(sub) = argv.next() {
                    match sub.as_str() {
                        "init" => command = ControlCommand::GenesisInit,
                        "cluster" => {
                            let count_str =
                                argv.next()
                                    .ok_or_else(|| ControlPlaneError::InvalidCommand {
                                        command: "genesis cluster requires a node count"
                                            .to_string(),
                                    })?;
                            let node_count: usize =
                                count_str.parse().map_err(|_| {
                                    ControlPlaneError::InvalidCommand {
                                        command: format!(
                                            "invalid node count '{count_str}': expected positive integer"
                                        ),
                                    }
                                })?;
                            if node_count == 0 || node_count > 100 {
                                return Err(ControlPlaneError::InvalidCommand {
                                    command: format!(
                                        "node count must be between 1 and 100, got {node_count}"
                                    ),
                                });
                            }
                            // Optional --output-dir DIR
                            let mut output_dir = PathBuf::from("cluster-data");
                            while let Some(opt) = argv.next() {
                                match opt.as_str() {
                                    "--output-dir" => {
                                        let dir = argv.next().ok_or_else(|| {
                                            ControlPlaneError::InvalidCommand {
                                                command: "--output-dir requires a path".to_string(),
                                            }
                                        })?;
                                        output_dir = PathBuf::from(dir);
                                    }
                                    _ => {
                                        return Err(ControlPlaneError::InvalidCommand {
                                            command: format!(
                                                "unknown option '{opt}' for genesis cluster"
                                            ),
                                        });
                                    }
                                }
                            }
                            command = ControlCommand::GenesisCluster(GenesisClusterParams {
                                node_count,
                                output_dir,
                            });
                        }
                        _ => {
                            return Err(ControlPlaneError::InvalidCommand {
                                command: format!("unknown genesis sub-command: {sub}"),
                            });
                        }
                    }
                } else {
                    return Err(ControlPlaneError::InvalidCommand {
                        command: "genesis requires a sub-command: init | cluster N".to_string(),
                    });
                }
            }
            _ => {
                return Err(ControlPlaneError::InvalidCommand { command: token });
            }
        }
    }

    let is_standalone_command = matches!(
        command,
        ControlCommand::Keys
            | ControlCommand::Version
            | ControlCommand::GenesisInit
            | ControlCommand::GenesisCluster(_)
    );
    if is_standalone_command && config_path.is_some() {
        return Err(ControlPlaneError::InvalidCommand {
            command: "--config is not supported for this command".to_string(),
        });
    }
    if probe_ticks > 0
        && !matches!(
            command,
            ControlCommand::Preflight | ControlCommand::Diagnostics
        )
    {
        return Err(ControlPlaneError::InvalidCommand {
            command: "--with-tick/--probe-ticks are supported only for preflight/diagnostics"
                .to_string(),
        });
    }
    if mainnet_readiness
        && !matches!(
            command,
            ControlCommand::Preflight | ControlCommand::Diagnostics
        )
    {
        return Err(ControlPlaneError::InvalidCommand {
            command: "--mainnet-readiness is supported only for preflight/diagnostics".to_string(),
        });
    }

    Ok(ControlCommandWithConfig {
        command,
        config_path,
        probe_ticks,
        mainnet_readiness,
    })
}

#[cfg(test)]
mod tests {
    use super::{parse_command, ControlCommand};

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn parse_command_defaults_to_run() {
        let parsed = parse_command(args(&["paradencer-node"])).unwrap();
        assert_eq!(parsed.command, ControlCommand::Run);
        assert!(parsed.config_path.is_none());
        assert_eq!(parsed.probe_ticks, 0);
        assert!(!parsed.mainnet_readiness);
    }

    #[test]
    fn parse_command_accepts_preflight() {
        let parsed = parse_command(args(&["paradencer-node", "preflight"])).unwrap();
        assert_eq!(parsed.command, ControlCommand::Preflight);
        assert_eq!(parsed.probe_ticks, 0);
        assert!(!parsed.mainnet_readiness);
    }

    #[test]
    fn parse_command_accepts_diagnostics_aliases() {
        let diagnostics = parse_command(args(&["paradencer-node", "diagnostics"])).unwrap();
        let doctor = parse_command(args(&["paradencer-node", "doctor"])).unwrap();
        assert_eq!(diagnostics.command, ControlCommand::Diagnostics);
        assert_eq!(doctor.command, ControlCommand::Diagnostics);
    }

    #[test]
    fn parse_command_accepts_config_path_for_diagnostics_command() {
        let parsed = parse_command(args(&[
            "paradencer-node",
            "diagnostics",
            "--config",
            "/tmp/paradencer.toml",
        ]))
        .unwrap();
        assert_eq!(parsed.command, ControlCommand::Diagnostics);
        assert_eq!(
            parsed.config_path.unwrap(),
            std::path::PathBuf::from("/tmp/paradencer.toml")
        );
        assert_eq!(parsed.probe_ticks, 0);
        assert!(!parsed.mainnet_readiness);
    }

    #[test]
    fn parse_command_accepts_version_aliases() {
        let parsed = parse_command(args(&["paradencer-node", "-V"])).unwrap();
        assert_eq!(parsed.command, ControlCommand::Version);
        assert_eq!(parsed.probe_ticks, 0);
        assert!(!parsed.mainnet_readiness);
    }

    #[test]
    fn parse_command_accepts_with_tick_for_preflight_and_diagnostics() {
        let preflight =
            parse_command(args(&["paradencer-node", "preflight", "--with-tick"])).unwrap();
        let diagnostics =
            parse_command(args(&["paradencer-node", "diagnostics", "--with-tick"])).unwrap();
        assert_eq!(preflight.command, ControlCommand::Preflight);
        assert_eq!(preflight.probe_ticks, 1);
        assert!(!preflight.mainnet_readiness);
        assert_eq!(diagnostics.command, ControlCommand::Diagnostics);
        assert_eq!(diagnostics.probe_ticks, 1);
        assert!(!diagnostics.mainnet_readiness);
    }

    #[test]
    fn parse_command_accepts_probe_ticks_value() {
        let parsed = parse_command(args(&[
            "paradencer-node",
            "diagnostics",
            "--probe-ticks",
            "4",
        ]))
        .unwrap();
        assert_eq!(parsed.command, ControlCommand::Diagnostics);
        assert_eq!(parsed.probe_ticks, 4);
        assert!(!parsed.mainnet_readiness);
    }

    #[test]
    fn parse_command_accepts_mainnet_readiness_flag_for_preflight_and_diagnostics() {
        let preflight = parse_command(args(&[
            "paradencer-node",
            "preflight",
            "--mainnet-readiness",
        ]))
        .unwrap();
        assert_eq!(preflight.command, ControlCommand::Preflight);
        assert!(preflight.mainnet_readiness);

        let diagnostics = parse_command(args(&[
            "paradencer-node",
            "diagnostics",
            "--mainnet-readiness",
        ]))
        .unwrap();
        assert_eq!(diagnostics.command, ControlCommand::Diagnostics);
        assert!(diagnostics.mainnet_readiness);
    }

    #[test]
    fn parse_command_accepts_config_and_keys() {
        let config_command = parse_command(args(&["paradencer-node", "config"])).unwrap();
        let keys_command = parse_command(args(&["paradencer-node", "keys"])).unwrap();
        assert_eq!(config_command.command, ControlCommand::Config);
        assert_eq!(keys_command.command, ControlCommand::Keys);
    }

    #[test]
    fn parse_command_accepts_config_path_for_run_command() {
        let parsed = parse_command(args(&[
            "paradencer-node",
            "run",
            "--config",
            "/tmp/paradencer.toml",
        ]))
        .unwrap();
        assert_eq!(parsed.command, ControlCommand::Run);
        assert_eq!(
            parsed.config_path.unwrap(),
            std::path::PathBuf::from("/tmp/paradencer.toml")
        );
    }

    #[test]
    fn parse_command_accepts_config_path_without_explicit_run_command() {
        let parsed = parse_command(args(&[
            "paradencer-node",
            "--config",
            "/tmp/paradencer.toml",
        ]))
        .unwrap();
        assert_eq!(parsed.command, ControlCommand::Run);
        assert_eq!(
            parsed.config_path.unwrap(),
            std::path::PathBuf::from("/tmp/paradencer.toml")
        );
    }

    #[test]
    fn parse_command_rejects_config_path_for_keys() {
        let result = parse_command(args(&[
            "paradencer-node",
            "keys",
            "--config",
            "/tmp/paradencer.toml",
        ]));
        assert!(result.is_err());
    }

    #[test]
    fn parse_command_rejects_unknown_command() {
        let result = parse_command(args(&["paradencer-node", "unknown"]));
        assert!(result.is_err());
    }

    #[test]
    fn parse_command_rejects_with_tick_for_run() {
        let result = parse_command(args(&["paradencer-node", "run", "--with-tick"]));
        assert!(result.is_err());
    }

    #[test]
    fn parse_command_rejects_probe_ticks_zero() {
        let result = parse_command(args(&[
            "paradencer-node",
            "preflight",
            "--probe-ticks",
            "0",
        ]));
        assert!(result.is_err());
    }

    #[test]
    fn parse_command_rejects_mainnet_readiness_for_non_diagnostics_command() {
        let result = parse_command(args(&["paradencer-node", "run", "--mainnet-readiness"]));
        assert!(result.is_err());
    }

    #[test]
    fn parse_command_accepts_genesis_cluster_with_node_count() {
        let parsed = parse_command(args(&["paradencer-node", "genesis", "cluster", "3"])).unwrap();
        match parsed.command {
            ControlCommand::GenesisCluster(p) => {
                assert_eq!(p.node_count, 3);
                assert_eq!(p.output_dir, std::path::PathBuf::from("cluster-data"));
            }
            _ => panic!("expected GenesisCluster"),
        }
    }

    #[test]
    fn parse_command_accepts_genesis_cluster_with_output_dir() {
        let parsed = parse_command(args(&[
            "paradencer-node",
            "genesis",
            "cluster",
            "5",
            "--output-dir",
            "/tmp/my-cluster",
        ]))
        .unwrap();
        match parsed.command {
            ControlCommand::GenesisCluster(p) => {
                assert_eq!(p.node_count, 5);
                assert_eq!(p.output_dir, std::path::PathBuf::from("/tmp/my-cluster"));
            }
            _ => panic!("expected GenesisCluster"),
        }
    }

    #[test]
    fn parse_command_rejects_genesis_cluster_zero_nodes() {
        let result = parse_command(args(&["paradencer-node", "genesis", "cluster", "0"]));
        assert!(result.is_err());
    }

    #[test]
    fn parse_command_rejects_genesis_cluster_over_limit() {
        let result = parse_command(args(&["paradencer-node", "genesis", "cluster", "101"]));
        assert!(result.is_err());
    }

    #[test]
    fn parse_command_rejects_genesis_cluster_with_config_flag() {
        let result = parse_command(args(&[
            "paradencer-node",
            "genesis",
            "cluster",
            "3",
            "--config",
            "/tmp/x.toml",
        ]));
        assert!(result.is_err());
    }
}
