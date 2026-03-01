use super::BlockAssembler;
use paradencer_mesh::DualReceiveError;
use paradencer_runtime::{RuntimeError, RuntimeResult, Service, ServiceContext};
use std::time::Duration;

impl Service for BlockAssembler {
    fn name(&self) -> &'static str {
        "block-assembler"
    }

    fn tick_interval(&self) -> Duration {
        Duration::from_millis(2)
    }

    fn tick(&mut self, context: &ServiceContext) -> RuntimeResult<()> {
        if self.cooldown_ticks_remaining > 0 {
            self.cooldown_ticks_remaining = self.cooldown_ticks_remaining.saturating_sub(1);
            self.block_assembly_stats
                .increment_execution_health_cooldown_skipped_ticks();
            return Ok(());
        }
        if self.replay_safety_hold_ticks_remaining > 0 {
            self.replay_safety_hold_ticks_remaining =
                self.replay_safety_hold_ticks_remaining.saturating_sub(1);
            self.block_assembly_stats
                .increment_replay_safety_hold_skipped_ticks();
            return Ok(());
        }
        if self.fork_choice_quarantine_ticks_remaining > 0 {
            self.fork_choice_quarantine_ticks_remaining = self
                .fork_choice_quarantine_ticks_remaining
                .saturating_sub(1);
            self.block_assembly_stats
                .increment_fork_choice_quarantine_skipped_ticks();
            return Ok(());
        }

        self.process_pending_retry()?;
        if self.buffered_transactions > 0 {
            self.buffered_ticks = self.buffered_ticks.saturating_add(1);
        }
        self.try_assemble_buffered_fragment()?;

        match self.try_recv_transaction() {
            Ok(Some(transaction)) => {
                if transaction.estimated_cost_units > 0 {
                    self.slot_pipeline.on_transaction_buffered();
                    self.buffered_transactions += 1;
                    self.buffered_cost_units = self
                        .buffered_cost_units
                        .saturating_add(transaction.estimated_cost_units);
                    self.buffered_ticks = 0;
                }
                self.try_assemble_buffered_fragment()?;
                Ok(())
            }
            Ok(None) => Ok(()),
            Err(AllClosed) => {
                context.shutdown.request_stop();
                Err(RuntimeError::service_failure(
                    self.name(),
                    "all input transaction links closed",
                ))
            }
        }
    }
}

/// Sentinel error indicating all incoming transaction inputs are closed.
struct AllClosed;

impl BlockAssembler {
    fn try_recv_transaction(&mut self) -> Result<Option<crate::SanitizedTransaction>, AllClosed> {
        if self.incoming_transactions.is_empty() {
            return Err(AllClosed);
        }
        let input_count = self.incoming_transactions.len();
        for input_offset in 0..input_count {
            let index = (self.next_incoming_transaction_index + input_offset) % input_count;
            if self.closed_incoming_transactions[index] {
                continue;
            }
            match self.incoming_transactions[index].try_recv() {
                Ok(Some(transaction)) => {
                    self.next_incoming_transaction_index = (index + 1) % input_count;
                    return Ok(Some(transaction));
                }
                Ok(None) => continue,
                Err(DualReceiveError::Closed) => {
                    self.closed_incoming_transactions[index] = true;
                    self.closed_incoming_transaction_count =
                        self.closed_incoming_transaction_count.saturating_add(1);
                }
                Err(DualReceiveError::Overrun { .. }) => {
                    // Consumer overrun — lost data. Continue to next input.
                    continue;
                }
            }
        }
        if self.closed_incoming_transaction_count == self.incoming_transactions.len() {
            return Err(AllClosed);
        }
        Ok(None)
    }
}
