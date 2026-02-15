/// Compute budget management for transaction execution.
///
/// Controls computational resource limits for transactions:
/// - Compute units (CU): measures execution cost
/// - Heap size: memory allocation for programs
/// - Loaded accounts data size: limits account data that can be loaded
///
/// These limits prevent DoS attacks and ensure fair resource allocation.
use paradencer_constants::execution::*;

/// Compute budget details for a transaction.
///
/// Tracks requested limits and actual consumption during execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComputeBudget {
    /// Maximum compute units this transaction can consume
    pub compute_unit_limit: u64,
    /// Price per compute unit (for prioritization fees)
    pub compute_unit_price: u64,
    /// Remaining compute units (starts at compute_unit_limit)
    pub compute_meter: u64,
    /// Heap size allocated for VMs (in bytes)
    pub heap_size: u32,
    /// Maximum loaded accounts data size (in bytes)
    pub loaded_accounts_data_size_limit: u64,
}

impl ComputeBudget {
    /// Create a new compute budget with default limits.
    pub fn new() -> Self {
        Self {
            compute_unit_limit: DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT,
            compute_unit_price: 0,
            compute_meter: DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT,
            heap_size: DEFAULT_HEAP_FRAME_BYTES,
            loaded_accounts_data_size_limit: MAX_LOADED_ACCOUNTS_DATA_SIZE,
        }
    }

    /// Create a compute budget for builtin programs (reduced limits).
    pub fn new_builtin() -> Self {
        Self {
            compute_unit_limit: MAX_BUILTIN_ALLOCATION_COMPUTE_UNIT_LIMIT,
            compute_unit_price: 0,
            compute_meter: MAX_BUILTIN_ALLOCATION_COMPUTE_UNIT_LIMIT,
            heap_size: DEFAULT_HEAP_FRAME_BYTES,
            loaded_accounts_data_size_limit: MAX_LOADED_ACCOUNTS_DATA_SIZE,
        }
    }

    /// Create a compute budget with custom limits.
    pub fn with_limits(
        compute_unit_limit: u64,
        compute_unit_price: u64,
        heap_size: u32,
        loaded_accounts_data_size_limit: u64,
    ) -> Result<Self, ComputeBudgetError> {
        // Validate limits
        if compute_unit_limit > MAX_COMPUTE_UNIT_LIMIT {
            return Err(ComputeBudgetError::ComputeUnitLimitExceeded);
        }

        if heap_size > 0 {
            Self::validate_heap_size(heap_size)?;
        }

        if loaded_accounts_data_size_limit == 0 {
            return Err(ComputeBudgetError::InvalidLoadedAccountsDataSizeLimit);
        }

        let heap_size = if heap_size > 0 {
            heap_size
        } else {
            DEFAULT_HEAP_FRAME_BYTES
        };

        let loaded_accounts_data_size_limit = loaded_accounts_data_size_limit
            .min(MAX_LOADED_ACCOUNTS_DATA_SIZE);

        Ok(Self {
            compute_unit_limit,
            compute_unit_price,
            compute_meter: compute_unit_limit,
            heap_size,
            loaded_accounts_data_size_limit,
        })
    }

    /// Validate heap size request.
    fn validate_heap_size(heap_size: u32) -> Result<(), ComputeBudgetError> {
        if heap_size < MIN_HEAP_FRAME_BYTES || heap_size > MAX_HEAP_FRAME_BYTES {
            return Err(ComputeBudgetError::InvalidHeapSize);
        }

        if heap_size % HEAP_FRAME_BYTES_GRANULARITY != 0 {
            return Err(ComputeBudgetError::InvalidHeapSize);
        }

        Ok(())
    }

    /// Set compute unit limit.
    pub fn set_compute_unit_limit(&mut self, limit: u64) -> Result<(), ComputeBudgetError> {
        if limit > MAX_COMPUTE_UNIT_LIMIT {
            return Err(ComputeBudgetError::ComputeUnitLimitExceeded);
        }

        self.compute_unit_limit = limit;
        self.compute_meter = limit;
        Ok(())
    }

    /// Set compute unit price for prioritization.
    pub fn set_compute_unit_price(&mut self, price: u64) {
        self.compute_unit_price = price;
    }

    /// Set heap size.
    pub fn set_heap_size(&mut self, size: u32) -> Result<(), ComputeBudgetError> {
        Self::validate_heap_size(size)?;
        self.heap_size = size;
        Ok(())
    }

    /// Set loaded accounts data size limit.
    pub fn set_loaded_accounts_data_size_limit(
        &mut self,
        limit: u64,
    ) -> Result<(), ComputeBudgetError> {
        if limit == 0 {
            return Err(ComputeBudgetError::InvalidLoadedAccountsDataSizeLimit);
        }

        self.loaded_accounts_data_size_limit = limit.min(MAX_LOADED_ACCOUNTS_DATA_SIZE);
        Ok(())
    }

    /// Consume compute units.
    ///
    /// Returns error if insufficient units remain.
    pub fn consume(&mut self, units: u64) -> Result<(), ComputeBudgetError> {
        if units > self.compute_meter {
            return Err(ComputeBudgetError::ComputeBudgetExceeded);
        }

        self.compute_meter = self.compute_meter.saturating_sub(units);
        Ok(())
    }

    /// Get consumed compute units.
    pub fn consumed(&self) -> u64 {
        self.compute_unit_limit.saturating_sub(self.compute_meter)
    }

    /// Get remaining compute units.
    pub fn remaining(&self) -> u64 {
        self.compute_meter
    }

    /// Check if budget is exhausted.
    pub fn is_exhausted(&self) -> bool {
        self.compute_meter == 0
    }

    /// Calculate prioritization fee based on consumed units and price.
    pub fn calculate_prioritization_fee(&self) -> u64 {
        let consumed = self.consumed();
        consumed.saturating_mul(self.compute_unit_price)
    }
}

impl Default for ComputeBudget {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors that can occur with compute budget operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComputeBudgetError {
    /// Compute unit limit exceeds maximum allowed
    ComputeUnitLimitExceeded,
    /// Heap size is invalid (too small, too large, or not aligned)
    InvalidHeapSize,
    /// Loaded accounts data size limit is zero or invalid
    InvalidLoadedAccountsDataSizeLimit,
    /// Transaction exceeded its compute budget
    ComputeBudgetExceeded,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_budget_creates_with_defaults() {
        let budget = ComputeBudget::new();

        assert_eq!(budget.compute_unit_limit, DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT);
        assert_eq!(budget.compute_meter, DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT);
        assert_eq!(budget.heap_size, DEFAULT_HEAP_FRAME_BYTES);
        assert_eq!(budget.loaded_accounts_data_size_limit, MAX_LOADED_ACCOUNTS_DATA_SIZE);
        assert_eq!(budget.compute_unit_price, 0);
    }

    #[test]
    fn compute_budget_creates_for_builtin() {
        let budget = ComputeBudget::new_builtin();

        assert_eq!(budget.compute_unit_limit, MAX_BUILTIN_ALLOCATION_COMPUTE_UNIT_LIMIT);
        assert_eq!(budget.compute_meter, MAX_BUILTIN_ALLOCATION_COMPUTE_UNIT_LIMIT);
    }

    #[test]
    fn compute_budget_creates_with_custom_limits() {
        let budget = ComputeBudget::with_limits(
            100_000,
            50,
            64 * 1024,
            10 * 1024 * 1024,
        ).unwrap();

        assert_eq!(budget.compute_unit_limit, 100_000);
        assert_eq!(budget.compute_unit_price, 50);
        assert_eq!(budget.heap_size, 64 * 1024);
        assert_eq!(budget.loaded_accounts_data_size_limit, 10 * 1024 * 1024);
    }

    #[test]
    fn compute_budget_rejects_excessive_compute_units() {
        let result = ComputeBudget::with_limits(
            MAX_COMPUTE_UNIT_LIMIT + 1,
            0,
            DEFAULT_HEAP_FRAME_BYTES,
            MAX_LOADED_ACCOUNTS_DATA_SIZE,
        );

        assert_eq!(result, Err(ComputeBudgetError::ComputeUnitLimitExceeded));
    }

    #[test]
    fn compute_budget_rejects_invalid_heap_size() {
        // Too small
        let result = ComputeBudget::with_limits(
            100_000,
            0,
            MIN_HEAP_FRAME_BYTES - 1,
            MAX_LOADED_ACCOUNTS_DATA_SIZE,
        );
        assert_eq!(result, Err(ComputeBudgetError::InvalidHeapSize));

        // Too large
        let result = ComputeBudget::with_limits(
            100_000,
            0,
            MAX_HEAP_FRAME_BYTES + 1,
            MAX_LOADED_ACCOUNTS_DATA_SIZE,
        );
        assert_eq!(result, Err(ComputeBudgetError::InvalidHeapSize));

        // Not aligned
        let result = ComputeBudget::with_limits(
            100_000,
            0,
            MIN_HEAP_FRAME_BYTES + 512, // Not multiple of 1024
            MAX_LOADED_ACCOUNTS_DATA_SIZE,
        );
        assert_eq!(result, Err(ComputeBudgetError::InvalidHeapSize));
    }

    #[test]
    fn compute_budget_rejects_zero_loaded_accounts_limit() {
        let result = ComputeBudget::with_limits(
            100_000,
            0,
            DEFAULT_HEAP_FRAME_BYTES,
            0, // Invalid
        );

        assert_eq!(result, Err(ComputeBudgetError::InvalidLoadedAccountsDataSizeLimit));
    }

    #[test]
    fn compute_budget_consumes_units() {
        let mut budget = ComputeBudget::new();

        budget.consume(1000).unwrap();
        assert_eq!(budget.consumed(), 1000);
        assert_eq!(budget.remaining(), DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT - 1000);

        budget.consume(500).unwrap();
        assert_eq!(budget.consumed(), 1500);
    }

    #[test]
    fn compute_budget_rejects_overconsumption() {
        let mut budget = ComputeBudget::new();

        let result = budget.consume(DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT + 1);
        assert_eq!(result, Err(ComputeBudgetError::ComputeBudgetExceeded));
    }

    #[test]
    fn compute_budget_detects_exhaustion() {
        let mut budget = ComputeBudget::new();

        assert!(!budget.is_exhausted());

        budget.consume(budget.compute_unit_limit).unwrap();
        assert!(budget.is_exhausted());
    }

    #[test]
    fn compute_budget_calculates_prioritization_fee() {
        let mut budget = ComputeBudget::new();
        budget.set_compute_unit_price(100);

        budget.consume(1000).unwrap();

        let fee = budget.calculate_prioritization_fee();
        assert_eq!(fee, 100_000); // 1000 units * 100 price
    }

    #[test]
    fn compute_budget_updates_compute_unit_limit() {
        let mut budget = ComputeBudget::new();

        budget.set_compute_unit_limit(50_000).unwrap();
        assert_eq!(budget.compute_unit_limit, 50_000);
        assert_eq!(budget.compute_meter, 50_000);
    }

    #[test]
    fn compute_budget_updates_heap_size() {
        let mut budget = ComputeBudget::new();

        budget.set_heap_size(128 * 1024).unwrap();
        assert_eq!(budget.heap_size, 128 * 1024);
    }

    #[test]
    fn compute_budget_updates_loaded_accounts_limit() {
        let mut budget = ComputeBudget::new();

        budget.set_loaded_accounts_data_size_limit(32 * 1024 * 1024).unwrap();
        assert_eq!(budget.loaded_accounts_data_size_limit, 32 * 1024 * 1024);
    }

    #[test]
    fn compute_budget_caps_loaded_accounts_limit_at_max() {
        let mut budget = ComputeBudget::new();

        budget.set_loaded_accounts_data_size_limit(MAX_LOADED_ACCOUNTS_DATA_SIZE * 2).unwrap();
        assert_eq!(budget.loaded_accounts_data_size_limit, MAX_LOADED_ACCOUNTS_DATA_SIZE);
    }
}
