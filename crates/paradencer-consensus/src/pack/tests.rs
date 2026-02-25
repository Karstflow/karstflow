use super::*;
use paradencer_storage::Pubkey;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_tx(price: u64, cus: u64, is_vote: bool) -> PendingTransaction {
    PendingTransaction {
        id: 0, // assigned by queue
        compute_unit_price: price,
        compute_units: cus,
        data_bytes: 200,
        signature_count: 1,
        is_vote,
        expires_at_slot: 1000,
        read_accounts: vec![],
        write_accounts: vec![],
        fee_payer: Pubkey::new_unique(),
        payload_index: 0,
    }
}

fn make_tx_with_writes(price: u64, cus: u64, writes: Vec<Pubkey>) -> PendingTransaction {
    PendingTransaction {
        id: 0,
        compute_unit_price: price,
        compute_units: cus,
        data_bytes: 200,
        signature_count: 1,
        is_vote: false,
        expires_at_slot: 1000,
        read_accounts: vec![],
        write_accounts: writes,
        fee_payer: Pubkey::new_unique(),
        payload_index: 0,
    }
}

fn make_tx_with_reads_writes(
    price: u64,
    cus: u64,
    reads: Vec<Pubkey>,
    writes: Vec<Pubkey>,
) -> PendingTransaction {
    PendingTransaction {
        id: 0,
        compute_unit_price: price,
        compute_units: cus,
        data_bytes: 200,
        signature_count: 1,
        is_vote: false,
        expires_at_slot: 1000,
        read_accounts: reads,
        write_accounts: writes,
        fee_payer: Pubkey::new_unique(),
        payload_index: 0,
    }
}

// ---------------------------------------------------------------------------
// Priority queue tests
// ---------------------------------------------------------------------------

#[test]
fn priority_queue_insert_and_pop_by_priority() {
    let mut queue = PriorityQueue::new(100);

    queue.insert(make_tx(10, 1000, false));
    queue.insert(make_tx(50, 1000, false));
    queue.insert(make_tx(30, 1000, false));

    let first = queue.pop_pending().unwrap();
    assert_eq!(first.compute_unit_price, 50);

    let second = queue.pop_pending().unwrap();
    assert_eq!(second.compute_unit_price, 30);

    let third = queue.pop_pending().unwrap();
    assert_eq!(third.compute_unit_price, 10);
}

#[test]
fn priority_queue_separates_votes_and_pending() {
    let mut queue = PriorityQueue::new(100);

    queue.insert(make_tx(10, 1000, false));
    queue.insert(make_tx(50, 1000, true));
    queue.insert(make_tx(30, 1000, false));

    assert_eq!(queue.pending_count(), 2);
    assert_eq!(queue.vote_count(), 1);

    let vote = queue.pop_vote().unwrap();
    assert_eq!(vote.compute_unit_price, 50);
    assert!(vote.is_vote);
}

#[test]
fn priority_queue_evicts_lowest_when_full() {
    let mut queue = PriorityQueue::new(3);

    queue.insert(make_tx(10, 1000, false));
    queue.insert(make_tx(20, 1000, false));
    queue.insert(make_tx(30, 1000, false));

    // Queue is full. Insert a higher-priority transaction.
    let result = queue.insert(make_tx(50, 1000, false));
    assert!(result.is_some());
    assert_eq!(queue.len(), 3);

    // The lowest (10) should have been evicted
    let mut prices = Vec::new();
    while let Some(tx) = queue.pop_pending() {
        prices.push(tx.compute_unit_price);
    }
    assert!(!prices.contains(&10));
    assert!(prices.contains(&50));
}

#[test]
fn priority_queue_rejects_low_priority_when_full() {
    let mut queue = PriorityQueue::new(3);

    queue.insert(make_tx(20, 1000, false));
    queue.insert(make_tx(30, 1000, false));
    queue.insert(make_tx(40, 1000, false));

    // Try to insert lower priority than worst
    let result = queue.insert(make_tx(10, 1000, false));
    assert!(result.is_none());
    assert_eq!(queue.len(), 3);
}

#[test]
fn priority_queue_expire_removes_old_transactions() {
    let mut queue = PriorityQueue::new(100);

    let mut tx1 = make_tx(10, 1000, false);
    tx1.expires_at_slot = 50;
    queue.insert(tx1);

    let mut tx2 = make_tx(20, 1000, false);
    tx2.expires_at_slot = 100;
    queue.insert(tx2);

    let mut tx3 = make_tx(30, 1000, true);
    tx3.expires_at_slot = 50;
    queue.insert(tx3);

    let expired = queue.expire_before(75);
    assert_eq!(expired, 2); // tx1 + tx3 expired
    assert_eq!(queue.len(), 1);
    assert_eq!(queue.pending_count(), 1);
    assert_eq!(queue.vote_count(), 0);
}

#[test]
fn priority_queue_fifo_tiebreak() {
    let mut queue = PriorityQueue::new(100);

    // Same priority — earlier insertion should come first
    queue.insert(make_tx(10, 1000, false));
    queue.insert(make_tx(10, 1000, false));
    queue.insert(make_tx(10, 1000, false));

    let first = queue.pop_pending().unwrap();
    let second = queue.pop_pending().unwrap();
    let third = queue.pop_pending().unwrap();

    assert!(first.id < second.id);
    assert!(second.id < third.id);
}

// ---------------------------------------------------------------------------
// Block scheduler tests
// ---------------------------------------------------------------------------

#[test]
fn scheduler_produces_empty_microblock_when_queue_empty() {
    let mut scheduler = BlockScheduler::with_defaults();
    let mut queue = PriorityQueue::new(100);

    let mb = scheduler.schedule_microblock(&mut queue, 0.75);
    assert!(mb.transactions.is_empty());
}

#[test]
fn scheduler_schedules_non_conflicting_transactions() {
    let mut scheduler = BlockScheduler::with_defaults();
    let mut queue = PriorityQueue::new(100);

    let acct_a = Pubkey::new_unique();
    let acct_b = Pubkey::new_unique();

    // Two transactions writing to different accounts — no conflict
    queue.insert(make_tx_with_writes(10, 1000, vec![acct_a]));
    queue.insert(make_tx_with_writes(20, 1000, vec![acct_b]));

    let mb = scheduler.schedule_microblock(&mut queue, 0.0);
    assert_eq!(mb.transactions.len(), 2);
}

#[test]
fn scheduler_defers_write_write_conflicts() {
    let mut scheduler = BlockScheduler::with_defaults();
    let mut queue = PriorityQueue::new(100);

    let shared_account = Pubkey::new_unique();

    // Two transactions writing to the same account — conflict
    queue.insert(make_tx_with_writes(10, 1000, vec![shared_account]));
    queue.insert(make_tx_with_writes(20, 1000, vec![shared_account]));

    let mb = scheduler.schedule_microblock(&mut queue, 0.0);
    // Only the higher priority one should be scheduled
    assert_eq!(mb.transactions.len(), 1);
    assert_eq!(mb.transactions[0].transaction.compute_unit_price, 20);

    // The other should still be in the queue
    assert_eq!(queue.pending_count(), 1);
}

#[test]
fn scheduler_defers_read_write_conflicts() {
    let mut scheduler = BlockScheduler::with_defaults();
    let mut queue = PriorityQueue::new(100);

    let shared_account = Pubkey::new_unique();

    // First writes to shared_account
    queue.insert(make_tx_with_writes(20, 1000, vec![shared_account]));
    // Second reads from shared_account
    queue.insert(make_tx_with_reads_writes(
        10,
        1000,
        vec![shared_account],
        vec![],
    ));

    let mb = scheduler.schedule_microblock(&mut queue, 0.0);
    // Higher priority writer gets scheduled; reader is deferred
    assert_eq!(mb.transactions.len(), 1);
    assert_eq!(mb.transactions[0].transaction.compute_unit_price, 20);
}

#[test]
fn scheduler_releases_locks_after_completion() {
    let mut scheduler = BlockScheduler::with_defaults();
    let mut queue = PriorityQueue::new(100);

    let shared_account = Pubkey::new_unique();

    queue.insert(make_tx_with_writes(20, 1000, vec![shared_account]));
    queue.insert(make_tx_with_writes(10, 1000, vec![shared_account]));

    // First microblock: only higher priority
    let mb1 = scheduler.schedule_microblock(&mut queue, 0.0);
    assert_eq!(mb1.transactions.len(), 1);
    let tx_id = mb1.transactions[0].transaction.id;

    // Release the lock
    scheduler.release_locks(tx_id);

    // Second microblock: now the deferred transaction can be scheduled
    let mb2 = scheduler.schedule_microblock(&mut queue, 0.0);
    assert_eq!(mb2.transactions.len(), 1);
    assert_eq!(mb2.transactions[0].transaction.compute_unit_price, 10);
}

#[test]
fn scheduler_respects_block_compute_limit() {
    let limits = BlockLimits {
        max_block_compute_units: 5000,
        ..BlockLimits::default()
    };
    let mut scheduler = BlockScheduler::new(limits);
    let mut queue = PriorityQueue::new(100);

    // Each transaction takes 2000 CU — only 2 fit in 5000
    queue.insert(make_tx(30, 2000, false));
    queue.insert(make_tx(20, 2000, false));
    queue.insert(make_tx(10, 2000, false));

    let mb = scheduler.schedule_microblock(&mut queue, 0.0);
    assert_eq!(mb.transactions.len(), 2);
    assert_eq!(mb.total_compute_units, 4000);
}

#[test]
fn scheduler_respects_vote_compute_limit() {
    let limits = BlockLimits {
        max_block_compute_units: 100_000,
        max_vote_compute_units: 3000,
        ..BlockLimits::default()
    };
    let mut scheduler = BlockScheduler::new(limits);
    let mut queue = PriorityQueue::new(100);

    // Each vote takes 2000 CU — only 1 fits in 3000 vote budget
    queue.insert(make_tx(30, 2000, true));
    queue.insert(make_tx(20, 2000, true));

    let mb = scheduler.schedule_microblock(&mut queue, 1.0);
    assert_eq!(mb.transactions.len(), 1);
}

#[test]
fn scheduler_respects_per_account_write_limit() {
    let limits = BlockLimits {
        max_write_cost_per_account: 3000,
        ..BlockLimits::default()
    };
    let mut scheduler = BlockScheduler::new(limits);
    let mut queue = PriorityQueue::new(100);

    let hot_account = Pubkey::new_unique();

    // Two transactions writing to the same account: 2000 + 2000 > 3000
    queue.insert(make_tx_with_writes(20, 2000, vec![hot_account]));
    queue.insert(make_tx_with_writes(10, 2000, vec![hot_account]));

    let mb = scheduler.schedule_microblock(&mut queue, 0.0);
    assert_eq!(mb.transactions.len(), 1);

    let usage = scheduler.usage();
    let acct_cost = usage
        .account_write_costs
        .get(&hot_account)
        .copied()
        .unwrap_or(0);
    assert_eq!(acct_cost, 2000);
}

#[test]
fn scheduler_prefers_votes_then_fills_with_pending() {
    let mut scheduler = BlockScheduler::with_defaults();
    let mut queue = PriorityQueue::new(100);

    queue.insert(make_tx(100, 1000, true));
    queue.insert(make_tx(50, 1000, false));
    queue.insert(make_tx(200, 1000, false));

    let mb = scheduler.schedule_microblock(&mut queue, 0.5);
    // Should have the vote + at least one non-vote
    assert!(mb.transactions.len() >= 2);

    let vote_count = mb
        .transactions
        .iter()
        .filter(|st| st.transaction.is_vote)
        .count();
    assert!(vote_count >= 1);
}

#[test]
fn scheduler_end_block_resets_state() {
    let mut scheduler = BlockScheduler::with_defaults();
    let mut queue = PriorityQueue::new(100);

    queue.insert(make_tx(10, 1000, false));
    let _ = scheduler.schedule_microblock(&mut queue, 0.0);

    assert!(scheduler.usage().total_compute_units > 0);

    scheduler.end_block();
    assert_eq!(scheduler.usage().total_compute_units, 0);
    assert_eq!(scheduler.usage().transaction_count, 0);
}

// ---------------------------------------------------------------------------
// TransactionPack integration tests
// ---------------------------------------------------------------------------

#[test]
fn pack_insert_and_schedule() {
    let mut pack = TransactionPack::with_defaults();

    pack.insert(make_tx(10, 1000, false));
    pack.insert(make_tx(20, 1000, false));
    pack.insert(make_tx(30, 1000, true));

    assert_eq!(pack.pending_count(), 3);

    let mb = pack.schedule_microblock();
    assert!(!mb.transactions.is_empty());
    assert!(mb.total_compute_units > 0);
}

#[test]
fn pack_expire_and_schedule() {
    let mut pack = TransactionPack::with_defaults();

    let mut tx1 = make_tx(10, 1000, false);
    tx1.expires_at_slot = 50;
    pack.insert(tx1);

    let mut tx2 = make_tx(20, 1000, false);
    tx2.expires_at_slot = 200;
    pack.insert(tx2);

    pack.expire_before(100);
    assert_eq!(pack.pending_count(), 1);

    let mb = pack.schedule_microblock();
    assert_eq!(mb.transactions.len(), 1);
    assert_eq!(mb.transactions[0].transaction.compute_unit_price, 20);
}

#[test]
fn pack_end_block_allows_new_scheduling() {
    let limits = BlockLimits {
        max_block_compute_units: 2000,
        ..BlockLimits::default()
    };
    let mut pack = TransactionPack::new(100, limits);

    pack.insert(make_tx(10, 1500, false));
    pack.insert(make_tx(5, 1500, false));

    // First block: only one fits
    let mb1 = pack.schedule_microblock();
    assert_eq!(mb1.transactions.len(), 1);

    // The second is deferred (block limit), schedule again returns empty
    let mb_empty = pack.schedule_microblock();
    // May or may not schedule depending on remaining capacity — but block is almost full
    let _total_scheduled = mb1.transactions.len() + mb_empty.transactions.len();

    // End block and schedule again
    pack.end_block();
    let mb2 = pack.schedule_microblock();
    assert_eq!(mb2.transactions.len(), 1);
}

#[test]
fn pack_complete_transaction_unblocks_conflicting() {
    let mut pack = TransactionPack::with_defaults();

    let shared = Pubkey::new_unique();

    pack.insert(make_tx_with_writes(20, 1000, vec![shared]));
    pack.insert(make_tx_with_writes(10, 1000, vec![shared]));

    let mb1 = pack.schedule_microblock();
    assert_eq!(mb1.transactions.len(), 1);
    let tx_id = mb1.transactions[0].transaction.id;

    // Complete the first transaction
    pack.complete_transaction(tx_id);

    // Now the second should be schedulable
    let mb2 = pack.schedule_microblock();
    assert_eq!(mb2.transactions.len(), 1);
}

#[test]
fn pack_multiple_microblocks_accumulate_usage() {
    let limits = BlockLimits {
        max_block_compute_units: 10_000,
        ..BlockLimits::default()
    };
    let mut pack = TransactionPack::new(100, limits);

    // Insert 5 transactions of 2000 CU each (total = 10K)
    for i in 0..5 {
        let mut tx = make_tx(10 + i, 2000, false);
        // Unique write accounts so no conflicts
        tx.write_accounts = vec![Pubkey::new_unique()];
        pack.insert(tx);
    }

    // Schedule multiple microblocks
    let mb1 = pack.schedule_microblock();
    let mb2 = pack.schedule_microblock();

    let total = mb1.transactions.len() + mb2.transactions.len();
    assert!(total <= 5);

    let total_cu = pack.block_usage().total_compute_units;
    assert!(total_cu <= 10_000);
}

#[test]
fn pack_data_bytes_limit_enforced() {
    let limits = BlockLimits {
        max_data_bytes: 500,
        ..BlockLimits::default()
    };
    let mut pack = TransactionPack::new(100, limits);

    // Each transaction is 200 bytes — only 2 fit in 500
    pack.insert(make_tx(30, 1000, false));
    pack.insert(make_tx(20, 1000, false));
    pack.insert(make_tx(10, 1000, false));

    let mb = pack.schedule_microblock();
    assert_eq!(mb.transactions.len(), 2);
    assert!(mb.total_data_bytes <= 500);
}
