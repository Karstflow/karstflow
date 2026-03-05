//! Tile executor: runs tiles on pinned cores with CnC lifecycle.
//!
//! Combines [`TileAdapter`] wrapping of services with the mesh tile
//! runner infrastructure (CnC, heartbeat, metrics) for full
//! Firedancer-style execution.

use crate::affinity::{build_pinned_affinity_plan_from_available_cores, PinnedAssignmentSource};
use crate::service::{Service, ShutdownSwitch};
use crate::tile_adapter::TileAdapter;
use crate::{RuntimeError, RuntimeResult};
use karstflow_core::RuntimeSpec;
use karstflow_mesh::cnc::{TileCnc, TileSupervisor};
use karstflow_mesh::tile_metrics::TileMetrics;
use karstflow_mesh::tile_runner::{run_tile_simple, TileRunnerConfig};
use std::collections::HashMap;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tracing::{info, warn};

/// Run services as tiles on pinned cores with CnC lifecycle.
///
/// Each service is wrapped in a [`TileAdapter`] and executed via
/// [`run_tile_simple`] with CnC heartbeat monitoring and metrics.
/// A supervisor thread periodically checks tile health and initiates
/// shutdown if the stop flag is set or a tile enters an error state.
pub fn run_tiles(
    spec: &RuntimeSpec,
    services: Vec<Box<dyn Service>>,
    stop_flag: ShutdownSwitch,
) -> RuntimeResult<()> {
    let core_ids = core_affinity::get_core_ids().ok_or(RuntimeError::NoCpuCoresDetected)?;
    let available_core_ids = core_ids.iter().map(|c| c.id).collect::<Vec<_>>();
    let affinity_plan =
        build_pinned_affinity_plan_from_available_cores(spec, services.len(), &available_core_ids)?;
    let core_lookup = core_ids
        .into_iter()
        .map(|c| (c.id, c))
        .collect::<HashMap<usize, core_affinity::CoreId>>();

    let tile_count = services.len();
    let mut cnc_handles: Vec<Arc<TileCnc>> = Vec::with_capacity(tile_count);
    let mut metrics_handles: Vec<Arc<TileMetrics>> = Vec::with_capacity(tile_count);
    let mut join_handles = Vec::with_capacity(tile_count);
    let mut tile_names: Vec<String> = Vec::with_capacity(tile_count);

    for (index, service) in services.into_iter().enumerate() {
        let assigned_core_id = affinity_plan.assigned_core_ids[index];
        let assigned_core = *core_lookup.get(&assigned_core_id).ok_or(
            RuntimeError::ExplicitPinnedCoreUnavailable {
                core_id: assigned_core_id,
            },
        )?;

        let service_name = service.name().to_string();
        let assignment_mode = match affinity_plan.assignment_source {
            PinnedAssignmentSource::Auto => "auto",
            PinnedAssignmentSource::Explicit => "explicit",
        };

        info!(
            tile = %service_name,
            core_id = assigned_core.id,
            source = assignment_mode,
            "tile core assignment"
        );

        let cnc = Arc::new(TileCnc::new());
        let metrics = Arc::new(TileMetrics::new(&service_name, 0));
        cnc_handles.push(Arc::clone(&cnc));
        metrics_handles.push(Arc::clone(&metrics));
        tile_names.push(service_name.clone());

        let tile_stop = stop_flag.clone();
        let config = TileRunnerConfig::default();

        let builder = thread::Builder::new().name(service_name.clone());
        let handle = builder
            .spawn(move || {
                core_affinity::set_for_current(assigned_core);

                let mut adapter = TileAdapter::new(service, tile_stop);
                run_tile_simple(&mut adapter, &cnc, &metrics, &config);
            })
            .map_err(|source| RuntimeError::ThreadSpawn {
                service_name: service_name.clone(),
                source,
            })?;
        join_handles.push(handle);
    }

    // Supervisor loop: monitors tile health and propagates shutdown.
    let mut supervisor = TileSupervisor::new(Duration::from_secs(10));
    for (i, cnc) in cnc_handles.iter().enumerate() {
        // SAFETY: CnC handles are Arc-allocated and live for the duration
        // of this function — they outlive the supervisor.
        unsafe {
            supervisor.register(&tile_names[i], cnc);
        }
    }

    // Wait for all tiles to reach RUN state (with timeout).
    let boot_timeout = Duration::from_secs(30);
    let boot_start = std::time::Instant::now();
    loop {
        let report = supervisor.check();
        if report.running == tile_count {
            info!(tile_count, "all tiles running");
            break;
        }
        if report.errored > 0 {
            warn!(
                errored = report.errored,
                details = ?report.error_details,
                "tile(s) failed during boot"
            );
            supervisor.halt_all();
            break;
        }
        if boot_start.elapsed() > boot_timeout {
            warn!(
                booting = report.booting,
                running = report.running,
                "boot timeout — halting all tiles"
            );
            supervisor.halt_all();
            break;
        }
        if stop_flag.is_stop_requested() {
            supervisor.halt_all();
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    // Monitor loop: check health periodically until shutdown.
    while !stop_flag.is_stop_requested() {
        thread::sleep(Duration::from_millis(500));

        let report = supervisor.check();

        // If all tiles halted (e.g., one triggered shutdown), stop.
        if report.running == 0 && report.booting == 0 {
            break;
        }

        if !report.stuck_tiles.is_empty() {
            warn!(stuck = ?report.stuck_tiles, "stuck tile(s) detected");
        }
        if report.errored > 0 {
            warn!(
                errored = report.errored,
                details = ?report.error_details,
                "tile error(s) detected — initiating shutdown"
            );
            stop_flag.request_stop();
        }
    }

    // Propagate halt to all tiles.
    supervisor.halt_all();

    // Wait for tiles to finish with a timeout.
    let shutdown_timeout = Duration::from_secs(10);
    let shutdown_start = std::time::Instant::now();

    loop {
        let report = supervisor.check();
        if report.halted == tile_count || report.halted + report.errored == tile_count {
            break;
        }
        if shutdown_start.elapsed() > shutdown_timeout {
            warn!(
                halted = report.halted,
                errored = report.errored,
                still_running = report.running,
                "shutdown timeout — some tiles may not have stopped cleanly"
            );
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }

    // Join all threads.
    let mut had_panic = false;
    for handle in join_handles {
        if handle.join().is_err() {
            had_panic = true;
        }
    }

    if had_panic {
        Err(RuntimeError::ServiceThreadPanic)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::{Service, ServiceContext};
    use crate::RuntimeResult;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct TickCountService {
        name: &'static str,
        ticks: Arc<AtomicUsize>,
    }

    impl Service for TickCountService {
        fn name(&self) -> &'static str {
            self.name
        }
        fn tick(&mut self, _ctx: &ServiceContext) -> RuntimeResult<()> {
            self.ticks.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    #[test]
    fn tile_executor_runs_services() {
        let ticks_a = Arc::new(AtomicUsize::new(0));
        let ticks_b = Arc::new(AtomicUsize::new(0));

        let svc_a = TickCountService {
            name: "svc-a",
            ticks: ticks_a.clone(),
        };
        let svc_b = TickCountService {
            name: "svc-b",
            ticks: ticks_b.clone(),
        };

        let spec = RuntimeSpec {
            mode: karstflow_core::ExecutionMode::Tile,
            workers: 2,
            run_for_seconds: None,
            pinned_allow_core_sharing: true,
            pinned_core_policy: karstflow_core::PinnedCorePolicy::Adaptive,
            pinned_service_core_ids: None,
        };

        let stop = ShutdownSwitch::new();
        let stop_clone = stop.clone();

        let handle = thread::spawn(move || {
            let services: Vec<Box<dyn Service>> = vec![Box::new(svc_a), Box::new(svc_b)];
            run_tiles(&spec, services, stop_clone)
        });

        // Let tiles run briefly.
        thread::sleep(Duration::from_millis(50));

        // Signal shutdown.
        stop.request_stop();

        let result = handle.join().unwrap();
        assert!(result.is_ok());

        // Both services should have ticked.
        assert!(
            ticks_a.load(Ordering::Relaxed) > 0,
            "svc-a should have ticked"
        );
        assert!(
            ticks_b.load(Ordering::Relaxed) > 0,
            "svc-b should have ticked"
        );
    }

    #[test]
    fn tile_executor_handles_single_service() {
        let ticks = Arc::new(AtomicUsize::new(0));
        let svc = TickCountService {
            name: "solo",
            ticks: ticks.clone(),
        };

        let spec = RuntimeSpec {
            mode: karstflow_core::ExecutionMode::Tile,
            workers: 1,
            run_for_seconds: None,
            pinned_allow_core_sharing: true,
            pinned_core_policy: karstflow_core::PinnedCorePolicy::Adaptive,
            pinned_service_core_ids: None,
        };

        let stop = ShutdownSwitch::new();
        let stop_clone = stop.clone();

        let handle = thread::spawn(move || {
            let services: Vec<Box<dyn Service>> = vec![Box::new(svc)];
            run_tiles(&spec, services, stop_clone)
        });

        thread::sleep(Duration::from_millis(50));
        stop.request_stop();

        let result = handle.join().unwrap();
        assert!(result.is_ok());
        assert!(ticks.load(Ordering::Relaxed) > 0);
    }
}
