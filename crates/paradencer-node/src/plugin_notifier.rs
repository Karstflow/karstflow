use paradencer_consensus::{BankNotifier, TransactionInfo};
use paradencer_plugin::{AccountUpdate, SharedPluginManager, TransactionNotification};
use paradencer_storage::{Account, Pubkey};
use tracing::warn;

/// Bridges bank-level state change notifications to the Geyser plugin system.
///
/// Wraps a `SharedPluginManager` and translates `BankNotifier` calls into
/// `PluginManager::notify_account_update` and `notify_transaction` calls.
pub struct PluginBankNotifier {
    manager: SharedPluginManager,
}

impl std::fmt::Debug for PluginBankNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginBankNotifier").finish()
    }
}

impl PluginBankNotifier {
    pub fn new(manager: SharedPluginManager) -> Self {
        Self { manager }
    }
}

impl BankNotifier for PluginBankNotifier {
    fn notify_account_update(
        &self,
        slot: u64,
        pubkey: &Pubkey,
        account: &Account,
        txn_signature: Option<&[u8; 64]>,
        is_startup: bool,
    ) {
        let mgr = match self.manager.read() {
            Ok(m) => m,
            Err(e) => {
                warn!("plugin manager lock poisoned in account notification: {e}");
                return;
            }
        };

        if !mgr.account_data_notifications_enabled() {
            return;
        }

        let update = AccountUpdate {
            pubkey: pubkey.as_bytes(),
            lamports: account.meta.lamports,
            owner: account.meta.owner.as_bytes(),
            executable: account.meta.executable,
            rent_epoch: account.meta.rent_epoch,
            data: account.data.as_ref(),
            write_version: 0,
            txn_signature,
        };

        mgr.notify_account_update(&update, slot, is_startup);
    }

    fn notify_transaction(&self, slot: u64, info: &TransactionInfo<'_>) {
        let mgr = match self.manager.read() {
            Ok(m) => m,
            Err(e) => {
                warn!("plugin manager lock poisoned in transaction notification: {e}");
                return;
            }
        };

        if !mgr.transaction_notifications_enabled() {
            return;
        }

        let keys: Vec<[u8; 32]> = info.account_keys.iter().map(|k| *k.as_bytes()).collect();

        let notification = TransactionNotification {
            signature: info.signature,
            is_vote: info.is_vote,
            index: info.index,
            account_keys: &keys,
            message_data: &[],
            success: info.success,
            error: info.error,
            compute_units_consumed: info.compute_units_consumed,
            fee: info.fee,
        };

        mgr.notify_transaction(&notification, slot);
    }
}
