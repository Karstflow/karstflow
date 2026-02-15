mod loops;
mod params;

use crate::state::{RpcRuntimeSnapshot, RuntimeSnapshotProvider};
use jsonrpsee::core::server::PendingSubscriptionSink;
use jsonrpsee::core::RegisterMethodError;
use jsonrpsee::server::RpcModule;
use jsonrpsee::types::ErrorObjectOwned;
use loops::{
    run_account_subscription_loop, run_block_subscription_loop, run_logs_subscription_loop,
    run_program_subscription_loop, run_root_subscription_loop, run_signature_subscription_loop,
    run_slot_subscription_loop, run_slots_updates_subscription_loop, run_vote_subscription_loop,
};
use paradencer_constants::rpc::{
    WS_SNAPSHOT_FEED_CHANNEL_CAPACITY, WS_SNAPSHOT_FEED_INTERVAL_MILLIS,
};
use params::{
    parse_account_subscribe_params, parse_block_subscribe_params, parse_logs_subscribe_params,
    parse_no_params, parse_optional_commitment_config, parse_program_subscribe_params,
    parse_signature_subscribe_params,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;

const SLOT_SUBSCRIBE_METHOD: &str = "slotSubscribe";
const SLOT_NOTIFICATION_METHOD: &str = "slotNotification";
const SLOT_UNSUBSCRIBE_METHOD: &str = "slotUnsubscribe";
const ROOT_SUBSCRIBE_METHOD: &str = "rootSubscribe";
const ROOT_NOTIFICATION_METHOD: &str = "rootNotification";
const ROOT_UNSUBSCRIBE_METHOD: &str = "rootUnsubscribe";
const ACCOUNT_SUBSCRIBE_METHOD: &str = "accountSubscribe";
const ACCOUNT_NOTIFICATION_METHOD: &str = "accountNotification";
const ACCOUNT_UNSUBSCRIBE_METHOD: &str = "accountUnsubscribe";
const SIGNATURE_SUBSCRIBE_METHOD: &str = "signatureSubscribe";
const SIGNATURE_NOTIFICATION_METHOD: &str = "signatureNotification";
const SIGNATURE_UNSUBSCRIBE_METHOD: &str = "signatureUnsubscribe";
const BLOCK_SUBSCRIBE_METHOD: &str = "blockSubscribe";
const BLOCK_NOTIFICATION_METHOD: &str = "blockNotification";
const BLOCK_UNSUBSCRIBE_METHOD: &str = "blockUnsubscribe";
const LOGS_SUBSCRIBE_METHOD: &str = "logsSubscribe";
const LOGS_NOTIFICATION_METHOD: &str = "logsNotification";
const LOGS_UNSUBSCRIBE_METHOD: &str = "logsUnsubscribe";
const PROGRAM_SUBSCRIBE_METHOD: &str = "programSubscribe";
const PROGRAM_NOTIFICATION_METHOD: &str = "programNotification";
const PROGRAM_UNSUBSCRIBE_METHOD: &str = "programUnsubscribe";
const SLOTS_UPDATES_SUBSCRIBE_METHOD: &str = "slotsUpdatesSubscribe";
const SLOTS_UPDATES_NOTIFICATION_METHOD: &str = "slotsUpdatesNotification";
const SLOTS_UPDATES_UNSUBSCRIBE_METHOD: &str = "slotsUpdatesUnsubscribe";
const VOTE_SUBSCRIBE_METHOD: &str = "voteSubscribe";
const VOTE_NOTIFICATION_METHOD: &str = "voteNotification";
const VOTE_UNSUBSCRIBE_METHOD: &str = "voteUnsubscribe";
#[derive(Clone)]
struct SnapshotFeed {
    sender: broadcast::Sender<RpcRuntimeSnapshot>,
}

impl SnapshotFeed {
    fn start(runtime_snapshot_provider: Option<Arc<dyn RuntimeSnapshotProvider>>) -> Self {
        let (sender, _) = broadcast::channel(WS_SNAPSHOT_FEED_CHANNEL_CAPACITY);
        let publish_sender = sender.clone();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_millis(WS_SNAPSHOT_FEED_INTERVAL_MILLIS));
            loop {
                interval.tick().await;
                let snapshot = current_snapshot(runtime_snapshot_provider.as_ref());
                let _ = publish_sender.send(snapshot);
            }
        });
        Self { sender }
    }

    fn subscribe(&self) -> broadcast::Receiver<RpcRuntimeSnapshot> {
        self.sender.subscribe()
    }
}

pub(super) fn register_subscription_methods(
    module: &mut RpcModule<()>,
    full_api: bool,
    runtime_snapshot_provider: Option<Arc<dyn RuntimeSnapshotProvider>>,
) -> Result<(), RegisterMethodError> {
    let snapshot_feed = SnapshotFeed::start(runtime_snapshot_provider);
    let slot_feed = snapshot_feed.clone();
    module.register_subscription(
        SLOT_SUBSCRIBE_METHOD,
        SLOT_NOTIFICATION_METHOD,
        SLOT_UNSUBSCRIBE_METHOD,
        move |params, pending, _, _| {
            let mut slot_updates = slot_feed.subscribe();
            async move {
                if !full_api {
                    reject_subscription(
                        pending,
                        ErrorObjectOwned::owned(
                            -32601,
                            format!("Method not found: {SLOT_SUBSCRIBE_METHOD}"),
                            None::<()>,
                        ),
                    )
                    .await;
                    return Ok(());
                }
                let raw_params = match params.parse::<serde_json::Value>() {
                    Ok(value) => value,
                    Err(error) => {
                        reject_subscription(pending, ErrorObjectOwned::from(error)).await;
                        return Ok(());
                    }
                };
                let commitment = match parse_optional_commitment_config(&raw_params) {
                    Ok(commitment) => commitment,
                    Err(error) => {
                        reject_subscription(pending, error).await;
                        return Ok(());
                    }
                };
                let sink = pending.accept().await?;
                run_slot_subscription_loop(sink, &mut slot_updates, commitment).await
            }
        },
    )?;

    let root_feed = snapshot_feed.clone();
    module.register_subscription(
        ROOT_SUBSCRIBE_METHOD,
        ROOT_NOTIFICATION_METHOD,
        ROOT_UNSUBSCRIBE_METHOD,
        move |params, pending, _, _| {
            let mut root_updates = root_feed.subscribe();
            async move {
                if !full_api {
                    reject_subscription(
                        pending,
                        ErrorObjectOwned::owned(
                            -32601,
                            format!("Method not found: {ROOT_SUBSCRIBE_METHOD}"),
                            None::<()>,
                        ),
                    )
                    .await;
                    return Ok(());
                }
                let raw_params = match params.parse::<serde_json::Value>() {
                    Ok(value) => value,
                    Err(error) => {
                        reject_subscription(pending, ErrorObjectOwned::from(error)).await;
                        return Ok(());
                    }
                };
                if let Err(error) = parse_no_params(&raw_params) {
                    reject_subscription(pending, error).await;
                    return Ok(());
                }
                let sink = pending.accept().await?;
                run_root_subscription_loop(sink, &mut root_updates).await
            }
        },
    )?;

    let account_feed = snapshot_feed.clone();
    module.register_subscription(
        ACCOUNT_SUBSCRIBE_METHOD,
        ACCOUNT_NOTIFICATION_METHOD,
        ACCOUNT_UNSUBSCRIBE_METHOD,
        move |params, pending, _, _| {
            let mut account_updates = account_feed.subscribe();
            async move {
                if !full_api {
                    reject_subscription(
                        pending,
                        ErrorObjectOwned::owned(
                            -32601,
                            format!("Method not found: {ACCOUNT_SUBSCRIBE_METHOD}"),
                            None::<()>,
                        ),
                    )
                    .await;
                    return Ok(());
                }
                let raw_params = match params.parse::<serde_json::Value>() {
                    Ok(value) => value,
                    Err(error) => {
                        reject_subscription(pending, ErrorObjectOwned::from(error)).await;
                        return Ok(());
                    }
                };
                let (pubkey, account_config) = match parse_account_subscribe_params(&raw_params) {
                    Ok(values) => values,
                    Err(error) => {
                        reject_subscription(pending, error).await;
                        return Ok(());
                    }
                };
                let sink = pending.accept().await?;
                run_account_subscription_loop(sink, &mut account_updates, pubkey, account_config)
                    .await
            }
        },
    )?;

    let signature_feed = snapshot_feed.clone();
    module.register_subscription(
        SIGNATURE_SUBSCRIBE_METHOD,
        SIGNATURE_NOTIFICATION_METHOD,
        SIGNATURE_UNSUBSCRIBE_METHOD,
        move |params, pending, _, _| {
            let mut signature_updates = signature_feed.subscribe();
            async move {
                if !full_api {
                    reject_subscription(
                        pending,
                        ErrorObjectOwned::owned(
                            -32601,
                            format!("Method not found: {SIGNATURE_SUBSCRIBE_METHOD}"),
                            None::<()>,
                        ),
                    )
                    .await;
                    return Ok(());
                }
                let raw_params = match params.parse::<serde_json::Value>() {
                    Ok(value) => value,
                    Err(error) => {
                        reject_subscription(pending, ErrorObjectOwned::from(error)).await;
                        return Ok(());
                    }
                };
                let (signature, signature_config) =
                    match parse_signature_subscribe_params(&raw_params) {
                        Ok(value) => value,
                        Err(error) => {
                            reject_subscription(pending, error).await;
                            return Ok(());
                        }
                    };
                let sink = pending.accept().await?;
                run_signature_subscription_loop(
                    sink,
                    &mut signature_updates,
                    signature,
                    signature_config,
                )
                .await
            }
        },
    )?;

    let block_feed = snapshot_feed.clone();
    module.register_subscription(
        BLOCK_SUBSCRIBE_METHOD,
        BLOCK_NOTIFICATION_METHOD,
        BLOCK_UNSUBSCRIBE_METHOD,
        move |params, pending, _, _| {
            let mut block_updates = block_feed.subscribe();
            async move {
                if !full_api {
                    reject_subscription(
                        pending,
                        ErrorObjectOwned::owned(
                            -32601,
                            format!("Method not found: {BLOCK_SUBSCRIBE_METHOD}"),
                            None::<()>,
                        ),
                    )
                    .await;
                    return Ok(());
                }
                let raw_params = match params.parse::<serde_json::Value>() {
                    Ok(value) => value,
                    Err(error) => {
                        reject_subscription(pending, ErrorObjectOwned::from(error)).await;
                        return Ok(());
                    }
                };
                let (filter, block_config) = match parse_block_subscribe_params(&raw_params) {
                    Ok(values) => values,
                    Err(error) => {
                        reject_subscription(pending, error).await;
                        return Ok(());
                    }
                };
                let sink = pending.accept().await?;
                run_block_subscription_loop(sink, &mut block_updates, filter, block_config).await
            }
        },
    )?;

    let logs_feed = snapshot_feed.clone();
    module.register_subscription(
        LOGS_SUBSCRIBE_METHOD,
        LOGS_NOTIFICATION_METHOD,
        LOGS_UNSUBSCRIBE_METHOD,
        move |params, pending, _, _| {
            let mut logs_updates = logs_feed.subscribe();
            async move {
                if !full_api {
                    reject_subscription(
                        pending,
                        ErrorObjectOwned::owned(
                            -32601,
                            format!("Method not found: {LOGS_SUBSCRIBE_METHOD}"),
                            None::<()>,
                        ),
                    )
                    .await;
                    return Ok(());
                }
                let raw_params = match params.parse::<serde_json::Value>() {
                    Ok(value) => value,
                    Err(error) => {
                        reject_subscription(pending, ErrorObjectOwned::from(error)).await;
                        return Ok(());
                    }
                };
                let (filter, commitment) = match parse_logs_subscribe_params(&raw_params) {
                    Ok(values) => values,
                    Err(error) => {
                        reject_subscription(pending, error).await;
                        return Ok(());
                    }
                };
                let sink = pending.accept().await?;
                run_logs_subscription_loop(sink, &mut logs_updates, filter, commitment).await
            }
        },
    )?;

    let program_feed = snapshot_feed.clone();
    module.register_subscription(
        PROGRAM_SUBSCRIBE_METHOD,
        PROGRAM_NOTIFICATION_METHOD,
        PROGRAM_UNSUBSCRIBE_METHOD,
        move |params, pending, _, _| {
            let mut program_updates = program_feed.subscribe();
            async move {
                if !full_api {
                    reject_subscription(
                        pending,
                        ErrorObjectOwned::owned(
                            -32601,
                            format!("Method not found: {PROGRAM_SUBSCRIBE_METHOD}"),
                            None::<()>,
                        ),
                    )
                    .await;
                    return Ok(());
                }
                let raw_params = match params.parse::<serde_json::Value>() {
                    Ok(value) => value,
                    Err(error) => {
                        reject_subscription(pending, ErrorObjectOwned::from(error)).await;
                        return Ok(());
                    }
                };
                let (program_id, program_config) = match parse_program_subscribe_params(&raw_params)
                {
                    Ok(values) => values,
                    Err(error) => {
                        reject_subscription(pending, error).await;
                        return Ok(());
                    }
                };
                let sink = pending.accept().await?;
                run_program_subscription_loop(
                    sink,
                    &mut program_updates,
                    program_id,
                    program_config,
                )
                .await
            }
        },
    )?;

    let slots_updates_feed = snapshot_feed.clone();
    module.register_subscription(
        SLOTS_UPDATES_SUBSCRIBE_METHOD,
        SLOTS_UPDATES_NOTIFICATION_METHOD,
        SLOTS_UPDATES_UNSUBSCRIBE_METHOD,
        move |params, pending, _, _| {
            let mut slots_updates = slots_updates_feed.subscribe();
            async move {
                if !full_api {
                    reject_subscription(
                        pending,
                        ErrorObjectOwned::owned(
                            -32601,
                            format!("Method not found: {SLOTS_UPDATES_SUBSCRIBE_METHOD}"),
                            None::<()>,
                        ),
                    )
                    .await;
                    return Ok(());
                }
                let raw_params = match params.parse::<serde_json::Value>() {
                    Ok(value) => value,
                    Err(error) => {
                        reject_subscription(pending, ErrorObjectOwned::from(error)).await;
                        return Ok(());
                    }
                };
                if let Err(error) = parse_no_params(&raw_params) {
                    reject_subscription(pending, error).await;
                    return Ok(());
                }
                let sink = pending.accept().await?;
                run_slots_updates_subscription_loop(sink, &mut slots_updates).await
            }
        },
    )?;

    let vote_feed = snapshot_feed;
    module.register_subscription(
        VOTE_SUBSCRIBE_METHOD,
        VOTE_NOTIFICATION_METHOD,
        VOTE_UNSUBSCRIBE_METHOD,
        move |params, pending, _, _| {
            let mut vote_updates = vote_feed.subscribe();
            async move {
                if !full_api {
                    reject_subscription(
                        pending,
                        ErrorObjectOwned::owned(
                            -32601,
                            format!("Method not found: {VOTE_SUBSCRIBE_METHOD}"),
                            None::<()>,
                        ),
                    )
                    .await;
                    return Ok(());
                }
                let raw_params = match params.parse::<serde_json::Value>() {
                    Ok(value) => value,
                    Err(error) => {
                        reject_subscription(pending, ErrorObjectOwned::from(error)).await;
                        return Ok(());
                    }
                };
                let commitment = match parse_optional_commitment_config(&raw_params) {
                    Ok(commitment) => commitment,
                    Err(error) => {
                        reject_subscription(pending, error).await;
                        return Ok(());
                    }
                };
                let sink = pending.accept().await?;
                run_vote_subscription_loop(sink, &mut vote_updates, commitment).await
            }
        },
    )?;

    Ok(())
}

fn current_snapshot(
    runtime_snapshot_provider: Option<&Arc<dyn RuntimeSnapshotProvider>>,
) -> RpcRuntimeSnapshot {
    runtime_snapshot_provider
        .and_then(|provider| provider.latest_snapshot())
        .unwrap_or(RpcRuntimeSnapshot {
            slot: 0,
            block_height: 0,
            transaction_count: 0,
            uptime_millis: 0,
            latest_blockhash_seed: 0,
        })
}

async fn reject_subscription(pending: PendingSubscriptionSink, error: ErrorObjectOwned) {
    let _ = pending.reject(error).await;
}

#[cfg(test)]
mod tests {
    use super::{
        register_subscription_methods, ACCOUNT_SUBSCRIBE_METHOD, BLOCK_SUBSCRIBE_METHOD,
        LOGS_SUBSCRIBE_METHOD, PROGRAM_SUBSCRIBE_METHOD, ROOT_SUBSCRIBE_METHOD,
        SIGNATURE_SUBSCRIBE_METHOD, SLOTS_UPDATES_SUBSCRIBE_METHOD, SLOT_SUBSCRIBE_METHOD,
        VOTE_SUBSCRIBE_METHOD,
    };
    use crate::state::{RpcRuntimeSnapshot, RuntimeSnapshotProvider};
    use jsonrpsee::core::EmptyServerParams;
    use jsonrpsee::server::RpcModule;
    use std::sync::Arc;

    struct FixedSnapshotProvider;

    impl RuntimeSnapshotProvider for FixedSnapshotProvider {
        fn latest_snapshot(&self) -> Option<RpcRuntimeSnapshot> {
            Some(RpcRuntimeSnapshot {
                slot: 88,
                block_height: 88,
                transaction_count: 1000,
                uptime_millis: 1_000,
                latest_blockhash_seed: 77,
            })
        }
    }

    #[tokio::test]
    async fn slot_subscribe_emits_notifications() {
        let mut module = RpcModule::new(());
        register_subscription_methods(&mut module, true, Some(Arc::new(FixedSnapshotProvider)))
            .unwrap();

        let mut subscription = module
            .subscribe_unbounded(SLOT_SUBSCRIBE_METHOD, EmptyServerParams::new())
            .await
            .unwrap();
        let (message, _) = subscription
            .next::<serde_json::Value>()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            message.get("slot").and_then(|value| value.as_u64()),
            Some(56)
        );
        assert_eq!(
            message.get("root").and_then(|value| value.as_u64()),
            Some(56)
        );
    }

    #[tokio::test]
    async fn slot_subscribe_rejects_non_object_config() {
        let mut module = RpcModule::new(());
        register_subscription_methods(&mut module, true, Some(Arc::new(FixedSnapshotProvider)))
            .unwrap();
        let result = module
            .subscribe_unbounded(SLOT_SUBSCRIBE_METHOD, ("processed",))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn slot_subscribe_rejects_extra_params() {
        let mut module = RpcModule::new(());
        register_subscription_methods(&mut module, true, Some(Arc::new(FixedSnapshotProvider)))
            .unwrap();
        let result = module
            .subscribe_unbounded(
                SLOT_SUBSCRIBE_METHOD,
                (
                    serde_json::json!({"commitment": "processed"}),
                    serde_json::json!({"extra": true}),
                ),
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn slot_subscribe_rejects_unknown_config_key() {
        let mut module = RpcModule::new(());
        register_subscription_methods(&mut module, true, Some(Arc::new(FixedSnapshotProvider)))
            .unwrap();
        let result = module
            .subscribe_unbounded(
                SLOT_SUBSCRIBE_METHOD,
                (serde_json::json!({"commitment": "processed", "extra": true}),),
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn account_subscribe_emits_notifications() {
        let mut module = RpcModule::new(());
        register_subscription_methods(&mut module, true, Some(Arc::new(FixedSnapshotProvider)))
            .unwrap();

        let mut subscription = module
            .subscribe_unbounded(
                ACCOUNT_SUBSCRIBE_METHOD,
                (
                    "Vote111111111111111111111111111111111111111",
                    serde_json::json!({"commitment": "processed"}),
                ),
            )
            .await
            .unwrap();
        let (message, _) = subscription
            .next::<serde_json::Value>()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            message
                .get("context")
                .and_then(|context| context.get("slot"))
                .and_then(|value| value.as_u64()),
            Some(88)
        );
        assert!(message.get("value").is_some());
    }

    #[tokio::test]
    async fn account_subscribe_applies_encoding_and_data_slice() {
        let mut module = RpcModule::new(());
        register_subscription_methods(&mut module, true, Some(Arc::new(FixedSnapshotProvider)))
            .unwrap();

        let mut subscription = module
            .subscribe_unbounded(
                ACCOUNT_SUBSCRIBE_METHOD,
                (
                    "Vote111111111111111111111111111111111111111",
                    serde_json::json!({
                        "commitment": "processed",
                        "encoding": "base58",
                        "dataSlice": {"offset": 2, "length": 4}
                    }),
                ),
            )
            .await
            .unwrap();
        let (message, _) = subscription
            .next::<serde_json::Value>()
            .await
            .unwrap()
            .unwrap();
        let data = message
            .get("value")
            .and_then(|value| value.get("data"))
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default();
        assert_eq!(
            data.get(1).and_then(serde_json::Value::as_str),
            Some("base58")
        );
        assert_eq!(
            data.first()
                .and_then(serde_json::Value::as_str)
                .map(str::len),
            Some(4)
        );
    }

    #[tokio::test]
    async fn account_subscribe_rejects_invalid_encoding() {
        let mut module = RpcModule::new(());
        register_subscription_methods(&mut module, true, Some(Arc::new(FixedSnapshotProvider)))
            .unwrap();
        let result = module
            .subscribe_unbounded(
                ACCOUNT_SUBSCRIBE_METHOD,
                (
                    "Vote111111111111111111111111111111111111111",
                    serde_json::json!({"encoding": "gzip"}),
                ),
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn account_subscribe_rejects_invalid_data_slice() {
        let mut module = RpcModule::new(());
        register_subscription_methods(&mut module, true, Some(Arc::new(FixedSnapshotProvider)))
            .unwrap();
        let result = module
            .subscribe_unbounded(
                ACCOUNT_SUBSCRIBE_METHOD,
                (
                    "Vote111111111111111111111111111111111111111",
                    serde_json::json!({"dataSlice": {"offset": "x", "length": 4}}),
                ),
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn account_subscribe_rejects_unknown_config_key() {
        let mut module = RpcModule::new(());
        register_subscription_methods(&mut module, true, Some(Arc::new(FixedSnapshotProvider)))
            .unwrap();
        let result = module
            .subscribe_unbounded(
                ACCOUNT_SUBSCRIBE_METHOD,
                (
                    "Vote111111111111111111111111111111111111111",
                    serde_json::json!({"commitment": "processed", "extra": true}),
                ),
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn account_subscribe_rejects_data_slice_unknown_key() {
        let mut module = RpcModule::new(());
        register_subscription_methods(&mut module, true, Some(Arc::new(FixedSnapshotProvider)))
            .unwrap();
        let result = module
            .subscribe_unbounded(
                ACCOUNT_SUBSCRIBE_METHOD,
                (
                    "Vote111111111111111111111111111111111111111",
                    serde_json::json!({
                        "dataSlice": {"offset": 1, "length": 4, "extra": 9}
                    }),
                ),
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn root_subscribe_emits_notifications() {
        let mut module = RpcModule::new(());
        register_subscription_methods(&mut module, true, Some(Arc::new(FixedSnapshotProvider)))
            .unwrap();

        let mut subscription = module
            .subscribe_unbounded(ROOT_SUBSCRIBE_METHOD, EmptyServerParams::new())
            .await
            .unwrap();
        let (message, _) = subscription.next::<u64>().await.unwrap().unwrap();
        assert_eq!(message, 56);
    }

    #[tokio::test]
    async fn root_subscribe_rejects_unexpected_params() {
        let mut module = RpcModule::new(());
        register_subscription_methods(&mut module, true, Some(Arc::new(FixedSnapshotProvider)))
            .unwrap();
        let result = module
            .subscribe_unbounded(ROOT_SUBSCRIBE_METHOD, ("unexpected",))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn signature_subscribe_emits_notifications() {
        let mut module = RpcModule::new(());
        register_subscription_methods(&mut module, true, Some(Arc::new(FixedSnapshotProvider)))
            .unwrap();

        let mut subscription = module
            .subscribe_unbounded(
                SIGNATURE_SUBSCRIBE_METHOD,
                ("3bxs9v7f5JfWHqK9x2q8f9QkR9nA3eJr7c4D2w1m6pT",),
            )
            .await
            .unwrap();
        let (message, _) = subscription
            .next::<serde_json::Value>()
            .await
            .unwrap()
            .unwrap();
        assert!(message.get("context").is_some());
        assert_eq!(
            message
                .get("value")
                .and_then(|value| value.get("err"))
                .unwrap_or(&serde_json::Value::String("missing".to_string())),
            &serde_json::Value::Null
        );
    }

    #[tokio::test]
    async fn signature_subscribe_supports_received_notification_flag() {
        let mut module = RpcModule::new(());
        register_subscription_methods(&mut module, true, Some(Arc::new(FixedSnapshotProvider)))
            .unwrap();

        let mut subscription = module
            .subscribe_unbounded(
                SIGNATURE_SUBSCRIBE_METHOD,
                (
                    "3bxs9v7f5JfWHqK9x2q8f9QkR9nA3eJr7c4D2w1m6pT",
                    serde_json::json!({
                        "commitment": "processed",
                        "enableReceivedNotification": true
                    }),
                ),
            )
            .await
            .unwrap();
        let (message, _) = subscription
            .next::<serde_json::Value>()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            message.get("value").and_then(serde_json::Value::as_str),
            Some("receivedSignature")
        );
    }

    #[tokio::test]
    async fn signature_subscribe_rejects_invalid_received_notification_flag() {
        let mut module = RpcModule::new(());
        register_subscription_methods(&mut module, true, Some(Arc::new(FixedSnapshotProvider)))
            .unwrap();
        let result = module
            .subscribe_unbounded(
                SIGNATURE_SUBSCRIBE_METHOD,
                (
                    "3bxs9v7f5JfWHqK9x2q8f9QkR9nA3eJr7c4D2w1m6pT",
                    serde_json::json!({"enableReceivedNotification": "yes"}),
                ),
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn signature_subscribe_rejects_unknown_config_key() {
        let mut module = RpcModule::new(());
        register_subscription_methods(&mut module, true, Some(Arc::new(FixedSnapshotProvider)))
            .unwrap();
        let result = module
            .subscribe_unbounded(
                SIGNATURE_SUBSCRIBE_METHOD,
                (
                    "3bxs9v7f5JfWHqK9x2q8f9QkR9nA3eJr7c4D2w1m6pT",
                    serde_json::json!({"commitment": "processed", "extra": true}),
                ),
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn vote_subscribe_emits_notifications() {
        let mut module = RpcModule::new(());
        register_subscription_methods(&mut module, true, Some(Arc::new(FixedSnapshotProvider)))
            .unwrap();

        let mut subscription = module
            .subscribe_unbounded(
                VOTE_SUBSCRIBE_METHOD,
                (serde_json::json!({"commitment": "confirmed"}),),
            )
            .await
            .unwrap();
        let (message, _) = subscription
            .next::<serde_json::Value>()
            .await
            .unwrap()
            .unwrap();
        assert!(message.get("hash").is_some());
        assert_eq!(
            message
                .get("slots")
                .and_then(|value| value.as_array())
                .map(Vec::len),
            Some(3)
        );
    }

    #[tokio::test]
    async fn vote_subscribe_rejects_non_object_config() {
        let mut module = RpcModule::new(());
        register_subscription_methods(&mut module, true, Some(Arc::new(FixedSnapshotProvider)))
            .unwrap();
        let result = module
            .subscribe_unbounded(VOTE_SUBSCRIBE_METHOD, ("confirmed",))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn vote_subscribe_rejects_extra_params() {
        let mut module = RpcModule::new(());
        register_subscription_methods(&mut module, true, Some(Arc::new(FixedSnapshotProvider)))
            .unwrap();
        let result = module
            .subscribe_unbounded(
                VOTE_SUBSCRIBE_METHOD,
                (
                    serde_json::json!({"commitment": "confirmed"}),
                    serde_json::json!({"extra": true}),
                ),
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn vote_subscribe_rejects_unknown_config_key() {
        let mut module = RpcModule::new(());
        register_subscription_methods(&mut module, true, Some(Arc::new(FixedSnapshotProvider)))
            .unwrap();
        let result = module
            .subscribe_unbounded(
                VOTE_SUBSCRIBE_METHOD,
                (serde_json::json!({"commitment": "confirmed", "extra": true}),),
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn block_subscribe_emits_notifications() {
        let mut module = RpcModule::new(());
        register_subscription_methods(&mut module, true, Some(Arc::new(FixedSnapshotProvider)))
            .unwrap();

        let mut subscription = module
            .subscribe_unbounded(
                BLOCK_SUBSCRIBE_METHOD,
                ("all", serde_json::json!({"commitment": "finalized"})),
            )
            .await
            .unwrap();
        let (message, _) = subscription
            .next::<serde_json::Value>()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            message.get("slot").and_then(|value| value.as_u64()),
            Some(56)
        );
        assert!(message
            .get("block")
            .and_then(|value| value.get("blockhash"))
            .is_some());
        assert_eq!(
            message
                .get("block")
                .and_then(|value| value.get("encoding"))
                .and_then(serde_json::Value::as_str),
            Some("base64")
        );
        assert_eq!(
            message.get("filter").and_then(serde_json::Value::as_str),
            Some("all")
        );
    }

    #[tokio::test]
    async fn block_subscribe_applies_config_fields() {
        let mut module = RpcModule::new(());
        register_subscription_methods(&mut module, true, Some(Arc::new(FixedSnapshotProvider)))
            .unwrap();

        let mut subscription = module
            .subscribe_unbounded(
                BLOCK_SUBSCRIBE_METHOD,
                (
                    serde_json::json!({
                        "mentionsAccountOrProgram": "Vote111111111111111111111111111111111111111"
                    }),
                    serde_json::json!({
                        "commitment": "confirmed",
                        "encoding": "jsonParsed",
                        "transactionDetails": "signatures",
                        "showRewards": false,
                        "maxSupportedTransactionVersion": 0
                    }),
                ),
            )
            .await
            .unwrap();
        let (message, _) = subscription
            .next::<serde_json::Value>()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            message
                .get("block")
                .and_then(|value| value.get("encoding"))
                .and_then(serde_json::Value::as_str),
            Some("jsonParsed")
        );
        assert_eq!(
            message
                .get("block")
                .and_then(|value| value.get("transactionDetails"))
                .and_then(serde_json::Value::as_str),
            Some("signatures")
        );
        assert_eq!(
            message
                .get("block")
                .and_then(|value| value.get("rewards"))
                .and_then(serde_json::Value::as_array)
                .map(Vec::len),
            Some(0)
        );
        assert_eq!(
            message
                .get("block")
                .and_then(|value| value.get("maxSupportedTransactionVersion"))
                .and_then(serde_json::Value::as_u64),
            Some(0)
        );
    }

    #[tokio::test]
    async fn logs_subscribe_emits_notifications() {
        let mut module = RpcModule::new(());
        register_subscription_methods(&mut module, true, Some(Arc::new(FixedSnapshotProvider)))
            .unwrap();

        let mut subscription = module
            .subscribe_unbounded(
                LOGS_SUBSCRIBE_METHOD,
                ("all", serde_json::json!({"commitment": "processed"})),
            )
            .await
            .unwrap();
        let (message, _) = subscription
            .next::<serde_json::Value>()
            .await
            .unwrap()
            .unwrap();
        assert!(message
            .get("value")
            .and_then(|value| value.get("signature"))
            .is_some());
        assert!(message
            .get("value")
            .and_then(|value| value.get("logs"))
            .and_then(serde_json::Value::as_array)
            .is_some());
        assert_eq!(
            message
                .get("value")
                .and_then(|value| value.get("logsFilter"))
                .and_then(serde_json::Value::as_str),
            Some("all")
        );
    }

    #[tokio::test]
    async fn program_subscribe_emits_notifications() {
        let mut module = RpcModule::new(());
        register_subscription_methods(&mut module, true, Some(Arc::new(FixedSnapshotProvider)))
            .unwrap();

        let mut subscription = module
            .subscribe_unbounded(
                PROGRAM_SUBSCRIBE_METHOD,
                (
                    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                    serde_json::json!({"commitment": "confirmed"}),
                ),
            )
            .await
            .unwrap();
        let (message, _) = subscription
            .next::<serde_json::Value>()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            message
                .get("context")
                .and_then(|context| context.get("slot"))
                .and_then(|value| value.as_u64()),
            Some(87)
        );
        assert_eq!(
            message
                .get("value")
                .and_then(|value| value.get("filtersApplied"))
                .and_then(serde_json::Value::as_array)
                .map(Vec::len),
            Some(0)
        );
        assert!(message
            .get("value")
            .and_then(|value| value.get("account"))
            .is_some());
    }

    #[tokio::test]
    async fn program_subscribe_applies_config_fields() {
        let mut module = RpcModule::new(());
        register_subscription_methods(&mut module, true, Some(Arc::new(FixedSnapshotProvider)))
            .unwrap();

        let mut subscription = module
            .subscribe_unbounded(
                PROGRAM_SUBSCRIBE_METHOD,
                (
                    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                    serde_json::json!({
                        "commitment": "processed",
                        "encoding": "jsonParsed",
                        "dataSlice": {"offset": 1, "length": 4},
                        "filters": [
                            {"dataSize": 165},
                            {"memcmp": {"offset": 0, "bytes": "Vote111111111111111111111111111111111111111"}}
                        ]
                    }),
                ),
            )
            .await
            .unwrap();
        let (message, _) = subscription
            .next::<serde_json::Value>()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            message
                .get("context")
                .and_then(|context| context.get("slot"))
                .and_then(|value| value.as_u64()),
            Some(88)
        );
        assert_eq!(
            message
                .get("value")
                .and_then(|value| value.get("filtersApplied"))
                .and_then(serde_json::Value::as_array)
                .map(Vec::len),
            Some(2)
        );
        assert_eq!(
            message
                .get("value")
                .and_then(|value| value.get("account"))
                .and_then(|account| account.get("data"))
                .and_then(|data| data.get("program"))
                .and_then(serde_json::Value::as_str),
            Some("spl-token")
        );
    }

    #[tokio::test]
    async fn slots_updates_subscribe_emits_notifications() {
        let mut module = RpcModule::new(());
        register_subscription_methods(&mut module, true, Some(Arc::new(FixedSnapshotProvider)))
            .unwrap();

        let mut subscription = module
            .subscribe_unbounded(SLOTS_UPDATES_SUBSCRIBE_METHOD, EmptyServerParams::new())
            .await
            .unwrap();
        let (message, _) = subscription
            .next::<serde_json::Value>()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            message.get("type").and_then(serde_json::Value::as_str),
            Some("completed")
        );
        assert_eq!(
            message.get("slot").and_then(serde_json::Value::as_u64),
            Some(88)
        );
    }

    #[tokio::test]
    async fn slots_updates_subscribe_rejects_unexpected_params() {
        let mut module = RpcModule::new(());
        register_subscription_methods(&mut module, true, Some(Arc::new(FixedSnapshotProvider)))
            .unwrap();
        let result = module
            .subscribe_unbounded(SLOTS_UPDATES_SUBSCRIBE_METHOD, ("unexpected",))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn block_subscribe_rejects_invalid_filter() {
        let mut module = RpcModule::new(());
        register_subscription_methods(&mut module, true, Some(Arc::new(FixedSnapshotProvider)))
            .unwrap();
        let result = module
            .subscribe_unbounded(BLOCK_SUBSCRIBE_METHOD, ("invalid-filter",))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn block_subscribe_rejects_invalid_encoding() {
        let mut module = RpcModule::new(());
        register_subscription_methods(&mut module, true, Some(Arc::new(FixedSnapshotProvider)))
            .unwrap();
        let result = module
            .subscribe_unbounded(
                BLOCK_SUBSCRIBE_METHOD,
                ("all", serde_json::json!({"encoding": "yaml"})),
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn block_subscribe_rejects_invalid_show_rewards_type() {
        let mut module = RpcModule::new(());
        register_subscription_methods(&mut module, true, Some(Arc::new(FixedSnapshotProvider)))
            .unwrap();
        let result = module
            .subscribe_unbounded(
                BLOCK_SUBSCRIBE_METHOD,
                ("all", serde_json::json!({"showRewards": "yes"})),
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn block_subscribe_rejects_unknown_filter_key() {
        let mut module = RpcModule::new(());
        register_subscription_methods(&mut module, true, Some(Arc::new(FixedSnapshotProvider)))
            .unwrap();
        let result = module
            .subscribe_unbounded(
                BLOCK_SUBSCRIBE_METHOD,
                (serde_json::json!({"mentionsAccountOrProgram": "abc", "extra": 1}),),
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn block_subscribe_rejects_unknown_config_key() {
        let mut module = RpcModule::new(());
        register_subscription_methods(&mut module, true, Some(Arc::new(FixedSnapshotProvider)))
            .unwrap();
        let result = module
            .subscribe_unbounded(
                BLOCK_SUBSCRIBE_METHOD,
                (
                    "all",
                    serde_json::json!({"commitment": "finalized", "extra": 1}),
                ),
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn logs_subscribe_rejects_invalid_mentions_filter() {
        let mut module = RpcModule::new(());
        register_subscription_methods(&mut module, true, Some(Arc::new(FixedSnapshotProvider)))
            .unwrap();
        let result = module
            .subscribe_unbounded(
                LOGS_SUBSCRIBE_METHOD,
                (serde_json::json!({"mentions": []}),),
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn logs_subscribe_rejects_unknown_filter_key() {
        let mut module = RpcModule::new(());
        register_subscription_methods(&mut module, true, Some(Arc::new(FixedSnapshotProvider)))
            .unwrap();
        let result = module
            .subscribe_unbounded(
                LOGS_SUBSCRIBE_METHOD,
                (serde_json::json!({"mentions": ["abc"], "extra": 1}),),
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn logs_subscribe_rejects_unknown_config_key() {
        let mut module = RpcModule::new(());
        register_subscription_methods(&mut module, true, Some(Arc::new(FixedSnapshotProvider)))
            .unwrap();
        let result = module
            .subscribe_unbounded(
                LOGS_SUBSCRIBE_METHOD,
                (
                    "all",
                    serde_json::json!({"commitment": "processed", "extra": 1}),
                ),
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn logs_subscribe_accepts_all_with_votes_filter() {
        let mut module = RpcModule::new(());
        register_subscription_methods(&mut module, true, Some(Arc::new(FixedSnapshotProvider)))
            .unwrap();
        let mut subscription = module
            .subscribe_unbounded(LOGS_SUBSCRIBE_METHOD, ("allWithVotes",))
            .await
            .unwrap();
        let (message, _) = subscription
            .next::<serde_json::Value>()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            message
                .get("value")
                .and_then(|value| value.get("logsFilter"))
                .and_then(serde_json::Value::as_str),
            Some("allWithVotes")
        );
    }

    #[tokio::test]
    async fn logs_subscribe_accepts_single_mention_filter() {
        let mut module = RpcModule::new(());
        register_subscription_methods(&mut module, true, Some(Arc::new(FixedSnapshotProvider)))
            .unwrap();
        let mut subscription = module
            .subscribe_unbounded(
                LOGS_SUBSCRIBE_METHOD,
                (serde_json::json!({"mentions": ["Vote111111111111111111111111111111111111111"]}),),
            )
            .await
            .unwrap();
        let (message, _) = subscription
            .next::<serde_json::Value>()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            message
                .get("value")
                .and_then(|value| value.get("logsFilter"))
                .and_then(serde_json::Value::as_str),
            Some("mentions:Vote111111111111111111111111111111111111111")
        );
    }

    #[tokio::test]
    async fn logs_subscribe_rejects_multiple_mentions() {
        let mut module = RpcModule::new(());
        register_subscription_methods(&mut module, true, Some(Arc::new(FixedSnapshotProvider)))
            .unwrap();
        let result = module
            .subscribe_unbounded(
                LOGS_SUBSCRIBE_METHOD,
                (serde_json::json!({"mentions": ["a", "b"]}),),
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn program_subscribe_rejects_empty_program_id() {
        let mut module = RpcModule::new(());
        register_subscription_methods(&mut module, true, Some(Arc::new(FixedSnapshotProvider)))
            .unwrap();
        let result = module
            .subscribe_unbounded(PROGRAM_SUBSCRIBE_METHOD, ("   ",))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn program_subscribe_rejects_invalid_filters_shape() {
        let mut module = RpcModule::new(());
        register_subscription_methods(&mut module, true, Some(Arc::new(FixedSnapshotProvider)))
            .unwrap();
        let result = module
            .subscribe_unbounded(
                PROGRAM_SUBSCRIBE_METHOD,
                (
                    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                    serde_json::json!({"filters": [{"memcmp": {"offset": 0}}]}),
                ),
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn program_subscribe_rejects_unknown_config_key() {
        let mut module = RpcModule::new(());
        register_subscription_methods(&mut module, true, Some(Arc::new(FixedSnapshotProvider)))
            .unwrap();
        let result = module
            .subscribe_unbounded(
                PROGRAM_SUBSCRIBE_METHOD,
                (
                    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                    serde_json::json!({"commitment": "processed", "extra": 1}),
                ),
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn program_subscribe_rejects_unknown_filter_keys() {
        let mut module = RpcModule::new(());
        register_subscription_methods(&mut module, true, Some(Arc::new(FixedSnapshotProvider)))
            .unwrap();
        let result = module
            .subscribe_unbounded(
                PROGRAM_SUBSCRIBE_METHOD,
                (
                    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                    serde_json::json!({
                        "filters": [
                            {"dataSize": 165, "extra": 1}
                        ]
                    }),
                ),
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn program_subscribe_rejects_unknown_memcmp_keys() {
        let mut module = RpcModule::new(());
        register_subscription_methods(&mut module, true, Some(Arc::new(FixedSnapshotProvider)))
            .unwrap();
        let result = module
            .subscribe_unbounded(
                PROGRAM_SUBSCRIBE_METHOD,
                (
                    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                    serde_json::json!({
                        "filters": [
                            {"memcmp": {"offset": 0, "bytes": "abc", "extra": true}}
                        ]
                    }),
                ),
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn subscriptions_are_hidden_without_full_api() {
        let mut module = RpcModule::new(());
        register_subscription_methods(&mut module, false, None).unwrap();
        let result = module
            .subscribe_unbounded(SLOT_SUBSCRIBE_METHOD, EmptyServerParams::new())
            .await;
        assert!(result.is_err());
        let result = module
            .subscribe_unbounded(ROOT_SUBSCRIBE_METHOD, EmptyServerParams::new())
            .await;
        assert!(result.is_err());
        let result = module
            .subscribe_unbounded(SIGNATURE_SUBSCRIBE_METHOD, ("abc",))
            .await;
        assert!(result.is_err());
        let result = module
            .subscribe_unbounded(VOTE_SUBSCRIBE_METHOD, EmptyServerParams::new())
            .await;
        assert!(result.is_err());
        let result = module
            .subscribe_unbounded(BLOCK_SUBSCRIBE_METHOD, ("all",))
            .await;
        assert!(result.is_err());
        let result = module
            .subscribe_unbounded(LOGS_SUBSCRIBE_METHOD, ("all",))
            .await;
        assert!(result.is_err());
        let result = module
            .subscribe_unbounded(
                PROGRAM_SUBSCRIBE_METHOD,
                ("11111111111111111111111111111111",),
            )
            .await;
        assert!(result.is_err());
        let result = module
            .subscribe_unbounded(SLOTS_UPDATES_SUBSCRIBE_METHOD, EmptyServerParams::new())
            .await;
        assert!(result.is_err());
    }
}
