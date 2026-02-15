use crate::service::{Service, ServiceContext, ShutdownSwitch};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceProbeFailure {
    pub service_name: String,
    pub phase: &'static str,
    pub reason: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServiceProbeReport {
    pub started_ok: usize,
    pub ticked_ok: usize,
    pub stopped_ok: usize,
    pub failures: Vec<ServiceProbeFailure>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceProbeOptions {
    pub tick_iterations: u32,
}

impl ServiceProbeOptions {
    pub const START_STOP_ONLY: Self = Self { tick_iterations: 0 };
}

impl ServiceProbeReport {
    pub fn first_failure(&self) -> Option<&ServiceProbeFailure> {
        self.failures.first()
    }
}

pub fn probe_service_lifecycle(
    services: &mut [Box<dyn Service>],
    options: ServiceProbeOptions,
) -> ServiceProbeReport {
    let context = ServiceContext::new(ShutdownSwitch::new());
    let mut report = ServiceProbeReport::default();
    let mut started_service_indices = Vec::new();

    for (index, service) in services.iter_mut().enumerate() {
        match service.on_start(&context) {
            Ok(()) => {
                report.started_ok = report.started_ok.saturating_add(1);
                started_service_indices.push(index);
            }
            Err(error) => {
                report.failures.push(ServiceProbeFailure {
                    service_name: service.name().to_string(),
                    phase: "on_start",
                    reason: error.to_string(),
                });
                break;
            }
        }

        for tick_index in 0..options.tick_iterations {
            match service.tick(&context) {
                Ok(()) => {
                    report.ticked_ok = report.ticked_ok.saturating_add(1);
                }
                Err(error) => {
                    report.failures.push(ServiceProbeFailure {
                        service_name: service.name().to_string(),
                        phase: "tick",
                        reason: format!("tick_index={tick_index}: {error}"),
                    });
                    break;
                }
            }
        }
        if !report.failures.is_empty() {
            break;
        }
    }

    for index in started_service_indices.into_iter().rev() {
        let service = &mut services[index];
        match service.on_stop(&context) {
            Ok(()) => {
                report.stopped_ok = report.stopped_ok.saturating_add(1);
            }
            Err(error) => report.failures.push(ServiceProbeFailure {
                service_name: service.name().to_string(),
                phase: "on_stop",
                reason: error.to_string(),
            }),
        }
    }

    report
}

#[cfg(test)]
mod tests {
    use super::{probe_service_lifecycle, ServiceProbeOptions};
    use crate::{RuntimeError, RuntimeResult, Service, ServiceContext};
    use std::time::Duration;

    struct ProbeTestService {
        service_name: &'static str,
        fail_phase: Option<&'static str>,
    }

    impl Service for ProbeTestService {
        fn name(&self) -> &'static str {
            self.service_name
        }

        fn tick_interval(&self) -> Duration {
            Duration::from_millis(1)
        }

        fn on_start(&mut self, _context: &ServiceContext) -> RuntimeResult<()> {
            if self.fail_phase == Some("on_start") {
                return Err(RuntimeError::service_failure(
                    self.name(),
                    "synthetic start failure",
                ));
            }
            Ok(())
        }

        fn tick(&mut self, _context: &ServiceContext) -> RuntimeResult<()> {
            if self.fail_phase == Some("tick") {
                return Err(RuntimeError::service_failure(
                    self.name(),
                    "synthetic tick failure",
                ));
            }
            Ok(())
        }

        fn on_stop(&mut self, _context: &ServiceContext) -> RuntimeResult<()> {
            if self.fail_phase == Some("on_stop") {
                return Err(RuntimeError::service_failure(
                    self.name(),
                    "synthetic stop failure",
                ));
            }
            Ok(())
        }
    }

    #[test]
    fn probe_report_tracks_successful_start_and_stop() {
        let mut services: Vec<Box<dyn Service>> = vec![Box::new(ProbeTestService {
            service_name: "svc-a",
            fail_phase: None,
        })];

        let report = probe_service_lifecycle(
            services.as_mut_slice(),
            ServiceProbeOptions::START_STOP_ONLY,
        );
        assert_eq!(report.started_ok, 1);
        assert_eq!(report.stopped_ok, 1);
        assert_eq!(report.ticked_ok, 0);
        assert!(report.failures.is_empty());
    }

    #[test]
    fn probe_report_captures_tick_failure_when_enabled() {
        let mut services: Vec<Box<dyn Service>> = vec![Box::new(ProbeTestService {
            service_name: "svc-a",
            fail_phase: Some("tick"),
        })];

        let report = probe_service_lifecycle(
            services.as_mut_slice(),
            ServiceProbeOptions { tick_iterations: 1 },
        );
        assert_eq!(report.started_ok, 1);
        assert_eq!(report.ticked_ok, 0);
        assert_eq!(report.stopped_ok, 1);
        assert_eq!(report.failures.len(), 1);
        let failure = &report.failures[0];
        assert_eq!(failure.service_name, "svc-a");
        assert_eq!(failure.phase, "tick");
    }

    #[test]
    fn probe_report_counts_multiple_ticks() {
        let mut services: Vec<Box<dyn Service>> = vec![Box::new(ProbeTestService {
            service_name: "svc-a",
            fail_phase: None,
        })];

        let report = probe_service_lifecycle(
            services.as_mut_slice(),
            ServiceProbeOptions { tick_iterations: 3 },
        );
        assert_eq!(report.started_ok, 1);
        assert_eq!(report.ticked_ok, 3);
        assert_eq!(report.stopped_ok, 1);
        assert!(report.failures.is_empty());
    }
}
