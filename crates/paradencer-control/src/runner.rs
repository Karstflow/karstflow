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
    }
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
