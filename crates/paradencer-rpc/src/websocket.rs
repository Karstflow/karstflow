use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::broadcast;

use crate::state::{RpcCommitment, RpcRuntimeSnapshot};
use paradencer_types::Account;

/// WebSocket subscription manager
#[derive(Clone)]
pub struct SubscriptionManager {
    subscriptions: Arc<DashMap<SubscriptionId, Subscription>>,
    account_subs: Arc<DashMap<String, Vec<SubscriptionId>>>,
    signature_subs: Arc<DashMap<String, Vec<SubscriptionId>>>,
    slot_subs: Arc<RwLock<Vec<SubscriptionId>>>,
    program_subs: Arc<DashMap<String, Vec<SubscriptionId>>>,
    next_id: Arc<RwLock<u64>>,
    broadcast_tx: broadcast::Sender<Notification>,
}

pub type SubscriptionId = u64;

#[derive(Debug, Clone)]
pub struct Subscription {
    pub id: SubscriptionId,
    pub sub_type: SubscriptionType,
    pub commitment: RpcCommitment,
    pub created_at: std::time::Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubscriptionType {
    Account(String),
    Signature(String),
    Slot,
    Program(String),
    Logs(LogsSubscription),
    Root,
    BlockNotification,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogsSubscription {
    pub mentions: Option<Vec<String>>,
    pub all: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Notification {
    pub subscription: SubscriptionId,
    pub result: NotificationResult,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum NotificationResult {
    Account(AccountNotification),
    Signature(SignatureNotification),
    Slot(SlotNotification),
    Program(ProgramNotification),
    Logs(LogsNotification),
    Root(RootNotification),
    Block(BlockNotification),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountNotification {
    pub context: NotificationContext,
    pub value: AccountInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountInfo {
    pub lamports: u64,
    pub owner: String,
    pub data: Vec<String>,
    pub executable: bool,
    pub rent_epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureNotification {
    pub context: NotificationContext,
    pub value: SignatureResult,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureResult {
    pub err: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotNotification {
    pub slot: u64,
    pub parent: u64,
    pub root: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgramNotification {
    pub context: NotificationContext,
    pub value: ProgramAccountUpdate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgramAccountUpdate {
    pub pubkey: String,
    pub account: AccountInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogsNotification {
    pub context: NotificationContext,
    pub value: LogsResult,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogsResult {
    pub signature: String,
    pub err: Option<serde_json::Value>,
    pub logs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootNotification {
    pub root: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockNotification {
    pub context: NotificationContext,
    pub value: BlockUpdate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockUpdate {
    pub slot: u64,
    pub block_hash: String,
    pub block_height: u64,
    pub block_time: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationContext {
    pub slot: u64,
}

impl SubscriptionManager {
    pub fn new() -> Self {
        let (broadcast_tx, _) = broadcast::channel(1000);

        Self {
            subscriptions: Arc::new(DashMap::new()),
            account_subs: Arc::new(DashMap::new()),
            signature_subs: Arc::new(DashMap::new()),
            slot_subs: Arc::new(RwLock::new(Vec::new())),
            program_subs: Arc::new(DashMap::new()),
            next_id: Arc::new(RwLock::new(1)),
            broadcast_tx,
        }
    }

    /// Subscribe to account updates
    pub fn subscribe_account(&self, pubkey: String, commitment: RpcCommitment) -> SubscriptionId {
        let id = self.allocate_id();
        let sub = Subscription {
            id,
            sub_type: SubscriptionType::Account(pubkey.clone()),
            commitment,
            created_at: std::time::Instant::now(),
        };

        self.subscriptions.insert(id, sub);
        self.account_subs.entry(pubkey).or_default().push(id);

        id
    }

    /// Subscribe to signature updates
    pub fn subscribe_signature(
        &self,
        signature: String,
        commitment: RpcCommitment,
    ) -> SubscriptionId {
        let id = self.allocate_id();
        let sub = Subscription {
            id,
            sub_type: SubscriptionType::Signature(signature.clone()),
            commitment,
            created_at: std::time::Instant::now(),
        };

        self.subscriptions.insert(id, sub);
        self.signature_subs.entry(signature).or_default().push(id);

        id
    }

    /// Subscribe to slot updates
    pub fn subscribe_slot(&self, commitment: RpcCommitment) -> SubscriptionId {
        let id = self.allocate_id();
        let sub = Subscription {
            id,
            sub_type: SubscriptionType::Slot,
            commitment,
            created_at: std::time::Instant::now(),
        };

        self.subscriptions.insert(id, sub);
        self.slot_subs.write().push(id);

        id
    }

    /// Subscribe to program account updates
    pub fn subscribe_program(
        &self,
        program_id: String,
        commitment: RpcCommitment,
    ) -> SubscriptionId {
        let id = self.allocate_id();
        let sub = Subscription {
            id,
            sub_type: SubscriptionType::Program(program_id.clone()),
            commitment,
            created_at: std::time::Instant::now(),
        };

        self.subscriptions.insert(id, sub);
        self.program_subs.entry(program_id).or_default().push(id);

        id
    }

    /// Subscribe to logs
    pub fn subscribe_logs(
        &self,
        config: LogsSubscription,
        commitment: RpcCommitment,
    ) -> SubscriptionId {
        let id = self.allocate_id();
        let sub = Subscription {
            id,
            sub_type: SubscriptionType::Logs(config),
            commitment,
            created_at: std::time::Instant::now(),
        };

        self.subscriptions.insert(id, sub);

        id
    }

    /// Unsubscribe from a subscription
    pub fn unsubscribe(&self, id: SubscriptionId) -> bool {
        if let Some((_, sub)) = self.subscriptions.remove(&id) {
            // Remove from type-specific maps
            match &sub.sub_type {
                SubscriptionType::Account(pubkey) => {
                    if let Some(mut subs) = self.account_subs.get_mut(pubkey) {
                        subs.retain(|&sid| sid != id);
                    }
                }
                SubscriptionType::Signature(signature) => {
                    if let Some(mut subs) = self.signature_subs.get_mut(signature) {
                        subs.retain(|&sid| sid != id);
                    }
                }
                SubscriptionType::Slot => {
                    self.slot_subs.write().retain(|&sid| sid != id);
                }
                SubscriptionType::Program(program_id) => {
                    if let Some(mut subs) = self.program_subs.get_mut(program_id) {
                        subs.retain(|&sid| sid != id);
                    }
                }
                _ => {}
            }
            true
        } else {
            false
        }
    }

    /// Notify account update
    pub fn notify_account(&self, pubkey: &str, account: &Account, snapshot: RpcRuntimeSnapshot) {
        if let Some(subs) = self.account_subs.get(pubkey) {
            let notification = Notification {
                subscription: 0, // Will be filled per subscription
                result: NotificationResult::Account(AccountNotification {
                    context: NotificationContext {
                        slot: snapshot.slot,
                    },
                    value: AccountInfo {
                        lamports: account.meta.lamports,
                        owner: account.meta.owner.to_string(),
                        data: vec![
                            bs58::encode(account.data.as_slice()).into_string(),
                            "base58".to_string(),
                        ],
                        executable: account.meta.executable,
                        rent_epoch: account.meta.rent_epoch,
                    },
                }),
            };

            for &sub_id in subs.value().iter() {
                let mut notif = notification.clone();
                notif.subscription = sub_id;
                let _ = self.broadcast_tx.send(notif);
            }
        }
    }

    /// Notify signature confirmation
    pub fn notify_signature(
        &self,
        signature: &str,
        err: Option<String>,
        snapshot: RpcRuntimeSnapshot,
    ) {
        if let Some(subs) = self.signature_subs.get(signature) {
            let notification = Notification {
                subscription: 0,
                result: NotificationResult::Signature(SignatureNotification {
                    context: NotificationContext {
                        slot: snapshot.slot,
                    },
                    value: SignatureResult {
                        err: err.map(|e| serde_json::json!(e)),
                    },
                }),
            };

            for &sub_id in subs.value().iter() {
                let mut notif = notification.clone();
                notif.subscription = sub_id;
                let _ = self.broadcast_tx.send(notif);
            }
        }
    }

    /// Notify slot update
    pub fn notify_slot(&self, snapshot: RpcRuntimeSnapshot) {
        let notification = Notification {
            subscription: 0,
            result: NotificationResult::Slot(SlotNotification {
                slot: snapshot.slot,
                parent: snapshot.slot.saturating_sub(1),
                root: snapshot.slot.saturating_sub(32),
            }),
        };

        for &sub_id in self.slot_subs.read().iter() {
            let mut notif = notification.clone();
            notif.subscription = sub_id;
            let _ = self.broadcast_tx.send(notif);
        }
    }

    /// Notify program account update
    pub fn notify_program(
        &self,
        program_id: &str,
        pubkey: &str,
        account: &Account,
        snapshot: RpcRuntimeSnapshot,
    ) {
        if let Some(subs) = self.program_subs.get(program_id) {
            let notification = Notification {
                subscription: 0,
                result: NotificationResult::Program(ProgramNotification {
                    context: NotificationContext {
                        slot: snapshot.slot,
                    },
                    value: ProgramAccountUpdate {
                        pubkey: pubkey.to_string(),
                        account: AccountInfo {
                            lamports: account.meta.lamports,
                            owner: account.meta.owner.to_string(),
                            data: vec![
                                bs58::encode(account.data.as_slice()).into_string(),
                                "base58".to_string(),
                            ],
                            executable: account.meta.executable,
                            rent_epoch: account.meta.rent_epoch,
                        },
                    },
                }),
            };

            for &sub_id in subs.value().iter() {
                let mut notif = notification.clone();
                notif.subscription = sub_id;
                let _ = self.broadcast_tx.send(notif);
            }
        }
    }

    /// Get subscription receiver
    pub fn subscribe_notifications(&self) -> broadcast::Receiver<Notification> {
        self.broadcast_tx.subscribe()
    }

    /// Get subscription count
    pub fn subscription_count(&self) -> usize {
        self.subscriptions.len()
    }

    /// Get subscription by ID
    pub fn get_subscription(&self, id: SubscriptionId) -> Option<Subscription> {
        self.subscriptions.get(&id).map(|sub| sub.clone())
    }

    /// Allocate new subscription ID
    fn allocate_id(&self) -> SubscriptionId {
        let mut next = self.next_id.write();
        let id = *next;
        *next += 1;
        id
    }

    /// Clean up old subscriptions
    pub fn cleanup_old(&self, max_age: std::time::Duration) {
        let now = std::time::Instant::now();
        let old_ids: Vec<_> = self
            .subscriptions
            .iter()
            .filter(|entry| now.duration_since(entry.value().created_at) > max_age)
            .map(|entry| *entry.key())
            .collect();

        for id in old_ids {
            self.unsubscribe(id);
        }
    }
}

impl Default for SubscriptionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use paradencer_types::Pubkey;

    fn test_snapshot() -> RpcRuntimeSnapshot {
        RpcRuntimeSnapshot {
            slot: 1000,
            block_height: 1000,
            transaction_count: 5000,
            uptime_millis: 100000,
            latest_blockhash_seed: 12345,
        }
    }

    #[test]
    fn test_subscribe_account() {
        let manager = SubscriptionManager::new();
        let id = manager.subscribe_account("test_pubkey".to_string(), RpcCommitment::Confirmed);

        assert_eq!(id, 1);
        assert_eq!(manager.subscription_count(), 1);

        let sub = manager.get_subscription(id).unwrap();
        assert_eq!(sub.commitment, RpcCommitment::Confirmed);
    }

    #[test]
    fn test_subscribe_signature() {
        let manager = SubscriptionManager::new();
        let id = manager.subscribe_signature("test_sig".to_string(), RpcCommitment::Finalized);

        assert_eq!(id, 1);
        assert_eq!(manager.subscription_count(), 1);
    }

    #[test]
    fn test_subscribe_slot() {
        let manager = SubscriptionManager::new();
        let id = manager.subscribe_slot(RpcCommitment::Confirmed);

        assert_eq!(id, 1);
        assert_eq!(manager.subscription_count(), 1);
    }

    #[test]
    fn test_subscribe_program() {
        let manager = SubscriptionManager::new();
        let id = manager.subscribe_program("program_id".to_string(), RpcCommitment::Confirmed);

        assert_eq!(id, 1);
        assert_eq!(manager.subscription_count(), 1);
    }

    #[test]
    fn test_unsubscribe() {
        let manager = SubscriptionManager::new();
        let id = manager.subscribe_account("test_pubkey".to_string(), RpcCommitment::Confirmed);

        assert!(manager.unsubscribe(id));
        assert_eq!(manager.subscription_count(), 0);

        // Unsubscribe again should return false
        assert!(!manager.unsubscribe(id));
    }

    #[test]
    fn test_notify_account() {
        let manager = SubscriptionManager::new();
        let _id = manager.subscribe_account("test_pubkey".to_string(), RpcCommitment::Confirmed);

        // Subscribe to notifications BEFORE sending
        let mut rx = manager.subscribe_notifications();

        let account = Account::new(1000000, vec![1, 2, 3], Pubkey::zeroed());
        let snapshot = test_snapshot();
        manager.notify_account("test_pubkey", &account, snapshot);

        assert!(rx.try_recv().is_ok());
    }

    #[test]
    fn test_notify_signature() {
        let manager = SubscriptionManager::new();
        let _id = manager.subscribe_signature("test_sig".to_string(), RpcCommitment::Confirmed);

        let mut rx = manager.subscribe_notifications();

        let snapshot = test_snapshot();
        manager.notify_signature("test_sig", None, snapshot);

        assert!(rx.try_recv().is_ok());
    }

    #[test]
    fn test_notify_slot() {
        let manager = SubscriptionManager::new();
        let _id = manager.subscribe_slot(RpcCommitment::Confirmed);

        let mut rx = manager.subscribe_notifications();

        let snapshot = test_snapshot();
        manager.notify_slot(snapshot);

        assert!(rx.try_recv().is_ok());
    }

    #[test]
    fn test_multiple_subscriptions() {
        let manager = SubscriptionManager::new();

        let id1 = manager.subscribe_account("acc1".to_string(), RpcCommitment::Confirmed);
        let id2 = manager.subscribe_signature("sig1".to_string(), RpcCommitment::Confirmed);
        let id3 = manager.subscribe_slot(RpcCommitment::Confirmed);

        assert_eq!(manager.subscription_count(), 3);
        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
    }

    #[test]
    fn test_multiple_account_subscriptions() {
        let manager = SubscriptionManager::new();

        let _id1 = manager.subscribe_account("test_pubkey".to_string(), RpcCommitment::Confirmed);
        let _id2 = manager.subscribe_account("test_pubkey".to_string(), RpcCommitment::Finalized);

        assert_eq!(manager.subscription_count(), 2);

        // Subscribe to notifications BEFORE sending
        let mut rx = manager.subscribe_notifications();

        // Notify should send to both subscriptions
        let account = Account::new(1000000, vec![1, 2, 3], Pubkey::zeroed());
        let snapshot = test_snapshot();
        manager.notify_account("test_pubkey", &account, snapshot);

        assert!(rx.try_recv().is_ok());
        assert!(rx.try_recv().is_ok());
    }

    #[test]
    fn test_subscription_id_allocation() {
        let manager = SubscriptionManager::new();

        let id1 = manager.subscribe_account("acc1".to_string(), RpcCommitment::Confirmed);
        let id2 = manager.subscribe_account("acc2".to_string(), RpcCommitment::Confirmed);
        let id3 = manager.subscribe_account("acc3".to_string(), RpcCommitment::Confirmed);

        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(id3, 3);
    }
}
