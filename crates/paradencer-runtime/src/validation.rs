use crate::{RuntimeError, RuntimeResult};
use paradencer_core::PinnedCorePolicy;
use std::collections::HashSet;

pub(crate) fn validate_pinned_assignment(
    service_count: usize,
    core_count: usize,
    pinned_core_policy: PinnedCorePolicy,
) -> RuntimeResult<()> {
    if service_count <= core_count {
        return Ok(());
    }

    match pinned_core_policy {
        PinnedCorePolicy::Strict => Err(RuntimeError::StrictPolicyInsufficientCores {
            service_count,
            core_count,
        }),
        PinnedCorePolicy::Shared => {
            eprintln!(
                "[runtime] warning: {} services will share {} cores in pinned mode (policy=shared)",
                service_count, core_count
            );
            Ok(())
        }
        PinnedCorePolicy::Adaptive => {
            let oversubscription_ratio = service_count as f64 / core_count as f64;
            if oversubscription_ratio <= 2.0 {
                eprintln!(
                    "[runtime] warning: {} services will share {} cores in pinned mode (policy=adaptive, ratio={oversubscription_ratio:.2})",
                    service_count,
                    core_count
                );
                Ok(())
            } else {
                Err(RuntimeError::AdaptivePolicyRejected {
                    oversubscription_ratio,
                    service_count,
                    core_count,
                })
            }
        }
    }
}

pub(crate) fn resolve_pinned_core_assignment(
    service_count: usize,
    available_core_ids: &[usize],
    pinned_core_policy: PinnedCorePolicy,
    pinned_service_core_ids: Option<&[usize]>,
) -> RuntimeResult<Vec<usize>> {
    validate_pinned_assignment(service_count, available_core_ids.len(), pinned_core_policy)?;

    if let Some(explicit_core_ids) = pinned_service_core_ids {
        if explicit_core_ids.len() != service_count {
            return Err(RuntimeError::ExplicitPinnedAssignmentLengthMismatch {
                service_count,
                assigned_count: explicit_core_ids.len(),
            });
        }

        let available = available_core_ids.iter().copied().collect::<HashSet<_>>();
        for core_id in explicit_core_ids {
            if !available.contains(core_id) {
                return Err(RuntimeError::ExplicitPinnedCoreUnavailable { core_id: *core_id });
            }
        }

        if pinned_core_policy == PinnedCorePolicy::Strict {
            let mut seen = HashSet::new();
            for core_id in explicit_core_ids {
                if !seen.insert(*core_id) {
                    return Err(RuntimeError::StrictPolicyDuplicateCoreAssignment {
                        core_id: *core_id,
                    });
                }
            }
        }

        return Ok(explicit_core_ids.to_vec());
    }

    Ok((0..service_count)
        .map(|index| available_core_ids[index % available_core_ids.len()])
        .collect())
}

#[cfg(test)]
mod tests {
    use super::{resolve_pinned_core_assignment, validate_pinned_assignment};
    use paradencer_core::PinnedCorePolicy;

    #[test]
    fn strict_policy_rejects_oversubscription() {
        let result = validate_pinned_assignment(5, 4, PinnedCorePolicy::Strict);
        assert!(result.is_err());
    }

    #[test]
    fn shared_policy_allows_oversubscription() {
        let result = validate_pinned_assignment(5, 4, PinnedCorePolicy::Shared);
        assert!(result.is_ok());
    }

    #[test]
    fn adaptive_policy_allows_small_oversubscription() {
        let result = validate_pinned_assignment(6, 4, PinnedCorePolicy::Adaptive);
        assert!(result.is_ok());
    }

    #[test]
    fn adaptive_policy_rejects_large_oversubscription() {
        let result = validate_pinned_assignment(9, 4, PinnedCorePolicy::Adaptive);
        assert!(result.is_err());
    }

    #[test]
    fn explicit_pinned_assignment_requires_entry_per_service() {
        let result = resolve_pinned_core_assignment(
            3,
            &[0, 1, 2, 3],
            PinnedCorePolicy::Adaptive,
            Some(&[0, 1]),
        );
        assert!(result.is_err());
    }

    #[test]
    fn explicit_pinned_assignment_rejects_unavailable_core_id() {
        let result =
            resolve_pinned_core_assignment(2, &[0, 1], PinnedCorePolicy::Adaptive, Some(&[0, 4]));
        assert!(result.is_err());
    }

    #[test]
    fn strict_policy_rejects_duplicate_explicit_core_assignment() {
        let result =
            resolve_pinned_core_assignment(2, &[0, 1], PinnedCorePolicy::Strict, Some(&[0, 0]));
        assert!(result.is_err());
    }

    #[test]
    fn shared_policy_allows_duplicate_explicit_core_assignment() {
        let result =
            resolve_pinned_core_assignment(2, &[0, 1], PinnedCorePolicy::Shared, Some(&[0, 0]));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0, 0]);
    }

    #[test]
    fn auto_pinned_assignment_uses_round_robin_core_selection() {
        let assigned =
            resolve_pinned_core_assignment(5, &[0, 1], PinnedCorePolicy::Shared, None).unwrap();
        assert_eq!(assigned, vec![0, 1, 0, 1, 0]);
    }
}
