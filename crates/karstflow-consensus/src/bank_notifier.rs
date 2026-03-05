use karstflow_types::{Account, Pubkey};

/// Summary of a transaction execution for notification purposes.
#[derive(Debug)]
pub struct TransactionInfo<'a> {
    pub signature: &'a [u8; 64],
    pub is_vote: bool,
    pub index: usize,
    pub account_keys: &'a [Pubkey],
    pub success: bool,
    pub error: Option<&'a str>,
    pub compute_units_consumed: u64,
    pub fee: u64,
}

/// Callback interface for bank-level state change notifications.
///
/// Components that want to observe account mutations and transaction
/// results implement this trait.  The Bank calls these methods after
/// committing state changes so that external consumers (Geyser plugins,
/// WebSocket subscriptions, indexers) receive real-time updates.
///
/// Implementors must be `Send + Sync` because Banks are shared across
/// threads via `Arc`.
pub trait BankNotifier: Send + Sync + std::fmt::Debug {
    /// Called for each account modified by a transaction or epoch processing.
    ///
    /// `is_startup` is true during initial snapshot restore to distinguish
    /// bulk-loading from runtime updates.
    fn notify_account_update(
        &self,
        slot: u64,
        pubkey: &Pubkey,
        account: &Account,
        txn_signature: Option<&[u8; 64]>,
        is_startup: bool,
    );

    /// Called after a transaction is executed (success or failure).
    fn notify_transaction(&self, slot: u64, info: &TransactionInfo<'_>);
}
