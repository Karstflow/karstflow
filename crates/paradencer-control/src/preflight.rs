use crate::errors::{ControlPlaneError, Result};
use paradencer_config::{ClusterMode, NodeConfig};
use paradencer_net::IngressMode;
use paradencer_runtime::{
    probe_service_lifecycle, RuntimeError, Service, ServiceProbeOptions, ServiceProbeReport,
};
use std::net::{SocketAddr, UdpSocket};

pub fn run_network_socket_preflight(node_config: &NodeConfig) -> Result<()> {
    if node_config.cluster_mode != ClusterMode::Live {
        return Ok(());
    }

    if node_config.ingress_policy.ingress_mode == IngressMode::Udp {
        if let Some(bind_addr) = node_config.ingress_policy.udp_bind_address {
            let socket = UdpSocket::bind(bind_addr).map_err(|source| {
                ControlPlaneError::IngressUdpBindPreflight { bind_addr, source }
            })?;
            drop(socket);
        }
    }

    for entrypoint in &node_config.live_entrypoints {
        let wildcard_bind_addr = wildcard_probe_bind_addr_for(entrypoint);
        let probe_socket = UdpSocket::bind(wildcard_bind_addr).map_err(|source| {
            ControlPlaneError::LiveEntrypointProbeBind {
                entrypoint: *entrypoint,
                source,
            }
        })?;

        probe_socket.connect(entrypoint).map_err(|source| {
            ControlPlaneError::LiveEntrypointProbeConnect {
                entrypoint: *entrypoint,
                source,
            }
        })?;

        probe_socket
            .send(&[])
            .map_err(|source| ControlPlaneError::LiveEntrypointProbeSend {
                entrypoint: *entrypoint,
                source,
            })?;
    }

    Ok(())
}

pub fn run_service_startup_preflight(
    services: &mut [Box<dyn Service>],
    probe_ticks: u32,
) -> Result<()> {
    let report = run_service_startup_probe(services, probe_ticks);
    ensure_service_startup_probe_ok(&report)
}

pub fn run_service_startup_probe(
    services: &mut [Box<dyn Service>],
    probe_ticks: u32,
) -> ServiceProbeReport {
    probe_service_lifecycle(
        services,
        ServiceProbeOptions {
            tick_iterations: probe_ticks,
        },
    )
}

pub fn ensure_service_startup_probe_ok(report: &ServiceProbeReport) -> Result<()> {
    if let Some(failure) = report.first_failure() {
        return Err(ControlPlaneError::ServiceStartupPreflight {
            service_name: failure.service_name.clone(),
            phase: failure.phase,
            source: RuntimeError::service_failure(&failure.service_name, &failure.reason),
        });
    }
    Ok(())
}

fn wildcard_probe_bind_addr_for(entrypoint: &SocketAddr) -> SocketAddr {
    if entrypoint.is_ipv4() {
        "0.0.0.0:0"
            .parse::<SocketAddr>()
            .expect("hardcoded IPv4 wildcard socket addr must parse")
    } else {
        "[::]:0"
            .parse::<SocketAddr>()
            .expect("hardcoded IPv6 wildcard socket addr must parse")
    }
}

#[cfg(test)]
mod tests {
    use super::{run_service_startup_preflight, run_service_startup_probe};
    use paradencer_runtime::{RuntimeError, RuntimeResult, Service, ServiceContext};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    struct TestService {
        should_fail_start: bool,
        event_log: Arc<Mutex<Vec<&'static str>>>,
    }

    impl Service for TestService {
        fn name(&self) -> &'static str {
            "test-service"
        }

        fn tick_interval(&self) -> Duration {
            Duration::from_millis(1)
        }

        fn on_start(&mut self, _context: &ServiceContext) -> RuntimeResult<()> {
            self.event_log.lock().unwrap().push("start");
            if self.should_fail_start {
                return Err(RuntimeError::service_failure(
                    self.name(),
                    "synthetic startup failure",
                ));
            }
            Ok(())
        }

        fn tick(&mut self, _context: &ServiceContext) -> RuntimeResult<()> {
            Ok(())
        }

        fn on_stop(&mut self, _context: &ServiceContext) -> RuntimeResult<()> {
            self.event_log.lock().unwrap().push("stop");
            Ok(())
        }
    }

    #[test]
    fn startup_preflight_runs_start_then_stop_hooks() {
        let event_log = Arc::new(Mutex::new(Vec::new()));
        let mut services: Vec<Box<dyn Service>> = vec![Box::new(TestService {
            should_fail_start: false,
            event_log: event_log.clone(),
        })];

        run_service_startup_preflight(services.as_mut_slice(), 0).unwrap();

        let events = event_log.lock().unwrap().clone();
        assert_eq!(events, vec!["start", "stop"]);
    }

    #[test]
    fn startup_preflight_returns_error_when_start_fails() {
        let event_log = Arc::new(Mutex::new(Vec::new()));
        let mut services: Vec<Box<dyn Service>> = vec![Box::new(TestService {
            should_fail_start: true,
            event_log: event_log.clone(),
        })];

        let result = run_service_startup_preflight(services.as_mut_slice(), 0);
        assert!(result.is_err());

        let events = event_log.lock().unwrap().clone();
        assert_eq!(events, vec!["start"]);
    }

    #[test]
    fn startup_probe_returns_report_with_counts() {
        let event_log = Arc::new(Mutex::new(Vec::new()));
        let mut services: Vec<Box<dyn Service>> = vec![Box::new(TestService {
            should_fail_start: false,
            event_log,
        })];

        let report = run_service_startup_probe(services.as_mut_slice(), 2);
        assert_eq!(report.started_ok, 1);
        assert_eq!(report.ticked_ok, 2);
        assert_eq!(report.stopped_ok, 1);
        assert!(report.failures.is_empty());
    }
}
