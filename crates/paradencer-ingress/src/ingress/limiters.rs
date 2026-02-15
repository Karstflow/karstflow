use super::domain::IngressSource;

#[derive(Default)]
pub struct SourceRateLimiter {
    quic: SourceRateState,
    gossip: SourceRateState,
    bundle: SourceRateState,
    rpc: SourceRateState,
}

#[derive(Default)]
pub struct SourceCostBudgetLimiter {
    quic: SourceCostBudgetState,
    gossip: SourceCostBudgetState,
    bundle: SourceCostBudgetState,
    rpc: SourceCostBudgetState,
}

#[derive(Default)]
struct SourceCostBudgetState {
    window_start_tick: u64,
    window_spent_cost: u64,
    initialized_window: bool,
}

#[derive(Default)]
struct SourceRateState {
    last_accepted_tick: Option<u64>,
    last_refill_tick: u64,
    available_tokens: u64,
    initialized_tokens: bool,
}

impl SourceRateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn try_accept(
        &mut self,
        source: IngressSource,
        current_tick: u64,
        min_gap_ticks: u64,
        burst_capacity: u64,
        burst_refill_ticks: u64,
    ) -> bool {
        let source_state = self.state_mut(source);

        if let Some(last_tick) = source_state.last_accepted_tick {
            if current_tick < last_tick.saturating_add(min_gap_ticks) {
                return false;
            }
        }

        if burst_capacity > 0 {
            let refill_ticks = burst_refill_ticks.max(1);
            if !source_state.initialized_tokens {
                source_state.available_tokens = burst_capacity;
                source_state.last_refill_tick = current_tick;
                source_state.initialized_tokens = true;
            } else {
                let elapsed_ticks = current_tick.saturating_sub(source_state.last_refill_tick);
                let refill_units = elapsed_ticks / refill_ticks;
                if refill_units > 0 {
                    source_state.available_tokens = source_state
                        .available_tokens
                        .saturating_add(refill_units)
                        .min(burst_capacity);
                    source_state.last_refill_tick = source_state
                        .last_refill_tick
                        .saturating_add(refill_units.saturating_mul(refill_ticks));
                }
            }

            if source_state.available_tokens == 0 {
                return false;
            }
            source_state.available_tokens = source_state.available_tokens.saturating_sub(1);
        }

        source_state.last_accepted_tick = Some(current_tick);
        true
    }

    fn state_mut(&mut self, source: IngressSource) -> &mut SourceRateState {
        match source {
            IngressSource::Quic => &mut self.quic,
            IngressSource::Gossip => &mut self.gossip,
            IngressSource::Bundle => &mut self.bundle,
            IngressSource::Rpc => &mut self.rpc,
        }
    }
}

impl SourceCostBudgetLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn try_consume(
        &mut self,
        source: IngressSource,
        current_tick: u64,
        cost_units: u64,
        budget_per_window: u64,
        window_ticks: u64,
    ) -> bool {
        if budget_per_window == 0 {
            return true;
        }

        let state = self.state_mut(source);
        let bounded_window_ticks = window_ticks.max(1);
        if !state.initialized_window {
            state.window_start_tick = current_tick;
            state.window_spent_cost = 0;
            state.initialized_window = true;
        } else if current_tick >= state.window_start_tick.saturating_add(bounded_window_ticks) {
            state.window_start_tick = current_tick;
            state.window_spent_cost = 0;
        }

        let Some(next_spent) = state.window_spent_cost.checked_add(cost_units) else {
            return false;
        };
        if next_spent > budget_per_window {
            return false;
        }
        state.window_spent_cost = next_spent;
        true
    }

    fn state_mut(&mut self, source: IngressSource) -> &mut SourceCostBudgetState {
        match source {
            IngressSource::Quic => &mut self.quic,
            IngressSource::Gossip => &mut self.gossip,
            IngressSource::Bundle => &mut self.bundle,
            IngressSource::Rpc => &mut self.rpc,
        }
    }
}
