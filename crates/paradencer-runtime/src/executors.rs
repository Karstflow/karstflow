use crate::affinity::{build_pinned_affinity_plan_from_available_cores, PinnedAssignmentSource};
use crate::service::{Service, ServiceContext, ShutdownSwitch};
use crate::{RuntimeError, RuntimeResult};
use paradencer_core::{ExecutionMode, RuntimeSpec};
use std::collections::HashMap;
use std::thread;
use std::time::Duration;

pub fn run_services(spec: &RuntimeSpec, services: Vec<Box<dyn Service>>) -> RuntimeResult<()> {
    let stop_flag = ShutdownSwitch::new();

    if let Some(seconds) = spec.run_for_seconds {
        let stopper = stop_flag.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_secs(seconds));
            stopper.request_stop();
        });
    }

    match spec.mode {
        ExecutionMode::Tokio => run_tokio(spec, services, stop_flag),
        ExecutionMode::Pinned => run_pinned(spec, services, stop_flag),
    }
}

fn run_tokio(
    spec: &RuntimeSpec,
    services: Vec<Box<dyn Service>>,
    stop_flag: ShutdownSwitch,
) -> RuntimeResult<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(spec.workers.max(1))
        .enable_all()
        .build()?;

    runtime.block_on(async move {
        let mut join_handles = Vec::new();

        for mut service in services {
            let local_stop_flag = stop_flag.clone();
            join_handles.push(tokio::spawn(async move {
                let context = ServiceContext::new(local_stop_flag);

                service.on_start(&context)?;
                while !context.shutdown.is_stop_requested() {
                    service.tick(&context)?;
                    tokio::time::sleep(service.tick_interval()).await;
                }
                service.on_stop(&context)
            }));
        }

        for handle in join_handles {
            let task_result = handle.await?;
            task_result?;
        }

        Ok(())
    })
}

fn run_pinned(
    spec: &RuntimeSpec,
    services: Vec<Box<dyn Service>>,
    stop_flag: ShutdownSwitch,
) -> RuntimeResult<()> {
    let core_ids = core_affinity::get_core_ids().ok_or(RuntimeError::NoCpuCoresDetected)?;
    let available_core_ids = core_ids
        .iter()
        .map(|core_id| core_id.id)
        .collect::<Vec<_>>();
    let affinity_plan =
        build_pinned_affinity_plan_from_available_cores(spec, services.len(), &available_core_ids)?;
    let core_lookup = core_ids
        .into_iter()
        .map(|core_id| (core_id.id, core_id))
        .collect::<HashMap<usize, core_affinity::CoreId>>();

    let mut join_handles = Vec::new();

    for (index, mut service) in services.into_iter().enumerate() {
        let local_stop_flag = stop_flag.clone();
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

        println!(
            "[runtime] pinned assignment: service='{}' core_id={} source={}",
            service_name, assigned_core.id, assignment_mode
        );

        let builder = thread::Builder::new().name(service_name.clone());
        let handle = builder
            .spawn(move || {
                core_affinity::set_for_current(assigned_core);

                let context = ServiceContext::new(local_stop_flag);

                service.on_start(&context)?;
                while !context.shutdown.is_stop_requested() {
                    service.tick(&context)?;
                    thread::sleep(service.tick_interval());
                }
                service.on_stop(&context)
            })
            .map_err(|source| RuntimeError::ThreadSpawn {
                service_name: service_name.clone(),
                source,
            })?;
        join_handles.push(handle);
    }

    for handle in join_handles {
        handle
            .join()
            .map_err(|_| RuntimeError::ServiceThreadPanic)??;
    }

    Ok(())
}
