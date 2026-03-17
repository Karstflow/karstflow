use super::domain::IngressSource;

#[derive(Default)]
pub struct SourceRateLimiter {
    quic: SourceRateState,
    gossip: SourceRateState,
    bundle: SourceRateState,
    rpc: SourceRateState,
    tvu: SourceRateState,
}

#[derive(Default)]
pub struct SourceCostBudgetLimiter {
    quic: SourceCostBudgetState,
    gossip: SourceCostBudgetState,
    bundle: SourceCostBudgetState,
    rpc: SourceCostBudgetState,
    tvu: SourceCostBudgetState,
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
            IngressSource::Tvu => &mut self.tvu,
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
            IngressSource::Tvu => &mut self.tvu,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- SourceRateLimiter ---

    #[test]
    fn rate_limiter_accepts_first_request() {
        let mut limiter = SourceRateLimiter::new();
        assert!(limiter.try_accept(IngressSource::Quic, 0, 0, 0, 1));
    }

    #[test]
    fn rate_limiter_enforces_min_gap() {
        let mut limiter = SourceRateLimiter::new();
        // Accept at tick 0
        assert!(limiter.try_accept(IngressSource::Quic, 0, 5, 0, 1));
        // Reject at tick 3 (gap=5 not met)
        assert!(!limiter.try_accept(IngressSource::Quic, 3, 5, 0, 1));
        // Accept at tick 5 (gap met)
        assert!(limiter.try_accept(IngressSource::Quic, 5, 5, 0, 1));
    }

    #[test]
    fn rate_limiter_burst_capacity() {
        let mut limiter = SourceRateLimiter::new();
        // Burst capacity = 3, no min gap
        assert!(limiter.try_accept(IngressSource::Quic, 0, 0, 3, 1));
        assert!(limiter.try_accept(IngressSource::Quic, 0, 0, 3, 1));
        assert!(limiter.try_accept(IngressSource::Quic, 0, 0, 3, 1));
        // Burst exhausted
        assert!(!limiter.try_accept(IngressSource::Quic, 0, 0, 3, 1));
    }

    #[test]
    fn rate_limiter_burst_refills() {
        let mut limiter = SourceRateLimiter::new();
        // Burst capacity = 1, refill every 5 ticks
        assert!(limiter.try_accept(IngressSource::Quic, 0, 0, 1, 5));
        assert!(!limiter.try_accept(IngressSource::Quic, 2, 0, 1, 5));
        // After 5 ticks, should refill
        assert!(limiter.try_accept(IngressSource::Quic, 5, 0, 1, 5));
    }

    #[test]
    fn rate_limiter_sources_are_independent() {
        let mut limiter = SourceRateLimiter::new();
        assert!(limiter.try_accept(IngressSource::Quic, 0, 10, 0, 1));
        // Gossip is independent, should accept even though Quic has gap
        assert!(limiter.try_accept(IngressSource::Gossip, 0, 10, 0, 1));
    }

    #[test]
    fn rate_limiter_no_burst_no_gap_always_accepts() {
        let mut limiter = SourceRateLimiter::new();
        for tick in 0..100 {
            assert!(limiter.try_accept(IngressSource::Bundle, tick, 0, 0, 1));
        }
    }

    // --- SourceCostBudgetLimiter ---

    #[test]
    fn cost_budget_zero_budget_always_accepts() {
        let mut limiter = SourceCostBudgetLimiter::new();
        // budget_per_window = 0 means no limit
        assert!(limiter.try_consume(IngressSource::Quic, 0, 9999, 0, 10));
    }

    #[test]
    fn cost_budget_enforces_budget() {
        let mut limiter = SourceCostBudgetLimiter::new();
        // Budget = 100, window = 10 ticks
        assert!(limiter.try_consume(IngressSource::Quic, 0, 60, 100, 10));
        assert!(limiter.try_consume(IngressSource::Quic, 1, 30, 100, 10));
        // Would exceed budget (60+30+20 = 110 > 100)
        assert!(!limiter.try_consume(IngressSource::Quic, 2, 20, 100, 10));
    }

    #[test]
    fn cost_budget_resets_after_window() {
        let mut limiter = SourceCostBudgetLimiter::new();
        // Budget = 50, window = 5 ticks
        assert!(limiter.try_consume(IngressSource::Quic, 0, 50, 50, 5));
        // Exhausted in this window
        assert!(!limiter.try_consume(IngressSource::Quic, 3, 1, 50, 5));
        // New window starts at tick 5
        assert!(limiter.try_consume(IngressSource::Quic, 5, 30, 50, 5));
    }

    #[test]
    fn cost_budget_sources_are_independent() {
        let mut limiter = SourceCostBudgetLimiter::new();
        assert!(limiter.try_consume(IngressSource::Quic, 0, 100, 100, 10));
        // Quic exhausted but Gossip should still work
        assert!(!limiter.try_consume(IngressSource::Quic, 1, 1, 100, 10));
        assert!(limiter.try_consume(IngressSource::Gossip, 1, 50, 100, 10));
    }

    #[test]
    fn cost_budget_exact_budget_accepted() {
        let mut limiter = SourceCostBudgetLimiter::new();
        assert!(limiter.try_consume(IngressSource::Rpc, 0, 100, 100, 10));
        // Exactly at budget, next should fail
        assert!(!limiter.try_consume(IngressSource::Rpc, 1, 1, 100, 10));
    }
}
