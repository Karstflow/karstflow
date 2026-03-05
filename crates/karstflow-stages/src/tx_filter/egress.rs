use super::{PendingEgressTransaction, TxFilter};
use karstflow_mesh::DualSendError;
use karstflow_runtime::{RuntimeError, RuntimeResult, Service, ServiceContext};

impl TxFilter {
    pub(super) fn try_send_or_buffer(
        &mut self,
        transaction: crate::SanitizedTransaction,
    ) -> RuntimeResult<()> {
        match self.outgoing_transactions.try_send(transaction.clone()) {
            Ok(()) => Ok(()),
            Err(DualSendError::Full(_) | DualSendError::NoCredits(_)) => {
                if self.pending_egress_transactions.len() >= self.egress_retry_buffer_capacity {
                    self.ingress_filter_stats.increment_drop_reason(
                        karstflow_net::DropReason::DownstreamBackpressure,
                        transaction.source,
                    );
                    return Ok(());
                }
                self.pending_egress_transactions
                    .push_back(PendingEgressTransaction {
                        transaction,
                        wait_ticks: 0,
                    });
                Ok(())
            }
            Err(DualSendError::Closed(_)) => Err(RuntimeError::service_failure(
                self.name(),
                "transaction link closed",
            )),
        }
    }

    pub(super) fn flush_pending_egress(&mut self, context: &ServiceContext) -> RuntimeResult<()> {
        let mut remaining = self.pending_egress_transactions.len();
        while remaining > 0 {
            let Some(mut pending) = self.pending_egress_transactions.pop_front() else {
                break;
            };
            match self
                .outgoing_transactions
                .try_send(pending.transaction.clone())
            {
                Ok(()) => {}
                Err(DualSendError::Full(_) | DualSendError::NoCredits(_)) => {
                    pending.wait_ticks = pending.wait_ticks.saturating_add(1);
                    if pending.wait_ticks >= self.egress_retry_max_wait_ticks {
                        self.ingress_filter_stats.increment_drop_reason(
                            karstflow_net::DropReason::DownstreamBackpressure,
                            pending.transaction.source,
                        );
                    } else {
                        self.pending_egress_transactions.push_back(pending);
                    }
                    break;
                }
                Err(DualSendError::Closed(_)) => {
                    context.shutdown.request_stop();
                    return Err(RuntimeError::service_failure(
                        self.name(),
                        "transaction link closed",
                    ));
                }
            }
            remaining = remaining.saturating_sub(1);
        }
        Ok(())
    }
}
