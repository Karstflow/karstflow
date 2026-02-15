use crate::validation::resolve_pinned_core_assignment;
use crate::{RuntimeError, RuntimeResult};
use paradencer_core::{ExecutionMode, RuntimeSpec};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedAffinityPlan {
    pub available_core_count: usize,
    pub assigned_core_ids: Vec<usize>,
    pub assignment_source: PinnedAssignmentSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinnedAssignmentSource {
    Auto,
    Explicit,
}

pub fn build_pinned_affinity_plan(
    runtime_spec: &RuntimeSpec,
    service_count: usize,
) -> RuntimeResult<Option<PinnedAffinityPlan>> {
    if runtime_spec.mode != ExecutionMode::Pinned {
        return Ok(None);
    }
    let available_core_ids = core_affinity::get_core_ids()
        .ok_or(RuntimeError::NoCpuCoresDetected)?
        .into_iter()
        .map(|core_id| core_id.id)
        .collect::<Vec<_>>();
    let plan = build_pinned_affinity_plan_from_available_cores(
        runtime_spec,
        service_count,
        &available_core_ids,
    )?;
    Ok(Some(plan))
}

pub(crate) fn build_pinned_affinity_plan_from_available_cores(
    runtime_spec: &RuntimeSpec,
    service_count: usize,
    available_core_ids: &[usize],
) -> RuntimeResult<PinnedAffinityPlan> {
    let assigned_core_ids = resolve_pinned_core_assignment(
        service_count,
        available_core_ids,
        runtime_spec.pinned_core_policy,
        runtime_spec.pinned_service_core_ids.as_deref(),
    )?;
    let assignment_source = if runtime_spec.pinned_service_core_ids.is_some() {
        PinnedAssignmentSource::Explicit
    } else {
        PinnedAssignmentSource::Auto
    };
    Ok(PinnedAffinityPlan {
        available_core_count: available_core_ids.len(),
        assigned_core_ids,
        assignment_source,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        build_pinned_affinity_plan_from_available_cores, PinnedAffinityPlan, PinnedAssignmentSource,
    };
    use paradencer_core::{ExecutionMode, PinnedCorePolicy, RuntimeSpec};

    fn pinned_runtime_spec() -> RuntimeSpec {
        RuntimeSpec {
            mode: ExecutionMode::Pinned,
            workers: 4,
            run_for_seconds: None,
            pinned_allow_core_sharing: true,
            pinned_core_policy: PinnedCorePolicy::Adaptive,
            pinned_service_core_ids: None,
        }
    }

    #[test]
    fn affinity_plan_uses_auto_round_robin_by_default() {
        let plan =
            build_pinned_affinity_plan_from_available_cores(&pinned_runtime_spec(), 4, &[2, 4])
                .unwrap();
        assert_eq!(
            plan,
            PinnedAffinityPlan {
                available_core_count: 2,
                assigned_core_ids: vec![2, 4, 2, 4],
                assignment_source: PinnedAssignmentSource::Auto,
            }
        );
    }

    #[test]
    fn affinity_plan_uses_explicit_map_when_provided() {
        let mut runtime_spec = pinned_runtime_spec();
        runtime_spec.pinned_service_core_ids = Some(vec![4, 2, 4]);
        let plan =
            build_pinned_affinity_plan_from_available_cores(&runtime_spec, 3, &[2, 4]).unwrap();
        assert_eq!(
            plan,
            PinnedAffinityPlan {
                available_core_count: 2,
                assigned_core_ids: vec![4, 2, 4],
                assignment_source: PinnedAssignmentSource::Explicit,
            }
        );
    }
}
