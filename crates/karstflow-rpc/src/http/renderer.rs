use crate::state::{BankAccessProvider, RpcCommitment, RpcRuntimeSnapshot, TransactionSubmitter};
use serde_json::json;
use std::sync::Arc;

use super::method_error::RpcMethodError;
use super::methods::dispatch_method;
use super::registry::resolve_method_with_dev_mode;

pub(super) fn render_json_rpc_response_with_dev_mode(
    body: &str,
    full_api: bool,
    dev_mode: bool,
    runtime_snapshot: Option<RpcRuntimeSnapshot>,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
    tx_submitter: Option<&Arc<dyn TransactionSubmitter>>,
) -> String {
    let parsed: serde_json::Value = match serde_json::from_str(body) {
        Ok(value) => value,
        Err(_) => {
            return json!({
                "jsonrpc": "2.0",
                "error": {"code": -32700, "message": "Parse error"},
                "id": serde_json::Value::Null
            })
            .to_string();
        }
    };

    let snapshot = runtime_snapshot.unwrap_or(RpcRuntimeSnapshot {
        slot: 0,
        block_height: 0,
        transaction_count: 0,
        uptime_millis: 0,
        latest_blockhash_seed: 0,
    });

    match &parsed {
        serde_json::Value::Array(requests) => {
            if requests.is_empty() {
                return invalid_request_response(serde_json::Value::Null).to_string();
            }
            let mut responses = Vec::new();
            for request in requests {
                if let Some(response) = render_single_request(
                    request,
                    full_api,
                    dev_mode,
                    snapshot,
                    bank_access,
                    tx_submitter,
                ) {
                    responses.push(response);
                }
            }
            if responses.is_empty() {
                String::new()
            } else {
                serde_json::Value::Array(responses).to_string()
            }
        }
        _ => match render_single_request(
            &parsed,
            full_api,
            dev_mode,
            snapshot,
            bank_access,
            tx_submitter,
        ) {
            Some(response) => response.to_string(),
            None => String::new(),
        },
    }
}

fn render_single_request(
    parsed: &serde_json::Value,
    full_api: bool,
    dev_mode: bool,
    snapshot: RpcRuntimeSnapshot,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
    tx_submitter: Option<&Arc<dyn TransactionSubmitter>>,
) -> Option<serde_json::Value> {
    let parsed_object = match parsed.as_object() {
        Some(object) => object,
        None => return Some(invalid_request_response(serde_json::Value::Null)),
    };
    let id_field = parsed_object.get("id");
    if let Some(id_value) = id_field {
        if !is_valid_json_rpc_id(id_value) {
            return Some(invalid_request_response(serde_json::Value::Null));
        }
    }
    let id = id_field.cloned().unwrap_or(serde_json::Value::Null);
    let is_notification = id_field.is_none();

    if parsed_object
        .get("jsonrpc")
        .and_then(serde_json::Value::as_str)
        != Some("2.0")
    {
        return Some(invalid_request_response(serde_json::Value::Null));
    }

    let method = match parsed_object
        .get("method")
        .and_then(serde_json::Value::as_str)
    {
        Some(method) => method,
        None => return Some(invalid_request_response(serde_json::Value::Null)),
    };
    if method.is_empty() || method.starts_with("rpc.") {
        return Some(invalid_request_response(serde_json::Value::Null));
    }

    if let Err(error) = validate_params_shape(parsed) {
        return if is_notification {
            None
        } else {
            Some(json!({
                "jsonrpc": "2.0",
                "error": {"code": error.code(), "message": error.message(method)},
                "id": id
            }))
        };
    }

    let rpc_method = match resolve_method_with_dev_mode(method, full_api, dev_mode) {
        Ok(method) => method,
        Err(_) => {
            return if is_notification {
                None
            } else {
                Some(json!({
                    "jsonrpc": "2.0",
                    "error": {"code": -32601, "message": format!("Method not found: {method}")},
                    "id": id
                }))
            };
        }
    };
    let commitment = match parse_commitment(parsed) {
        Ok(commitment) => commitment.unwrap_or(RpcCommitment::Finalized),
        Err(error) => {
            return if is_notification {
                None
            } else {
                Some(json!({
                    "jsonrpc": "2.0",
                    "error": {"code": error.code(), "message": error.message(method)},
                    "id": id
                }))
            };
        }
    };
    let result = dispatch_method(
        rpc_method,
        parsed,
        snapshot,
        commitment,
        full_api,
        bank_access,
        tx_submitter,
    );

    if is_notification {
        None
    } else {
        Some(match result {
            Ok(result) => json!({"jsonrpc": "2.0", "result": result, "id": id}),
            Err(error) => json!({
                "jsonrpc": "2.0",
                "error": {"code": error.code(), "message": error.message(method)},
                "id": id
            }),
        })
    }
}

fn invalid_request_response(id: serde_json::Value) -> serde_json::Value {
    json!({
        "jsonrpc": "2.0",
        "error": {
            "code": RpcMethodError::InvalidRequest.code(),
            "message": RpcMethodError::InvalidRequest.message("")
        },
        "id": id
    })
}

fn is_valid_json_rpc_id(id: &serde_json::Value) -> bool {
    id.is_string() || id.is_null() || id.as_i64().is_some() || id.as_u64().is_some()
}

fn parse_commitment(request: &serde_json::Value) -> Result<Option<RpcCommitment>, RpcMethodError> {
    let params = match request.get("params") {
        Some(serde_json::Value::Array(params)) => params,
        Some(_) => return Err(RpcMethodError::InvalidParams),
        None => return Ok(None),
    };

    let raw_commitment = params
        .iter()
        .filter_map(serde_json::Value::as_object)
        .find_map(|object| object.get("commitment"));
    let raw_commitment = match raw_commitment {
        Some(raw_commitment) => raw_commitment,
        None => return Ok(None),
    };

    let commitment = raw_commitment
        .as_str()
        .ok_or(RpcMethodError::InvalidParams)?
        .to_ascii_lowercase();
    match commitment.as_str() {
        "processed" => Ok(Some(RpcCommitment::Processed)),
        "confirmed" => Ok(Some(RpcCommitment::Confirmed)),
        "finalized" => Ok(Some(RpcCommitment::Finalized)),
        _ => Err(RpcMethodError::InvalidParams),
    }
}

fn validate_params_shape(request: &serde_json::Value) -> Result<(), RpcMethodError> {
    match request.get("params") {
        Some(serde_json::Value::Array(_)) | None => Ok(()),
        Some(_) => Err(RpcMethodError::InvalidParams),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        render_json_rpc_response_with_dev_mode as render_json_rpc_response_full, RpcRuntimeSnapshot,
    };
    use crate::http::methods::shared::format_blockhash_from_seed;
    use crate::http::registry::resolve_method;
    use crate::state::read_metrics_snapshot_for_test;
    use crate::state::BankAccessProvider;
    use std::fs;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Wrapper that supplies `None` for `tx_submitter` (most tests don't need it).
    fn render_json_rpc_response(
        body: &str,
        full_api: bool,
        snapshot: Option<RpcRuntimeSnapshot>,
        bank_access: Option<&Arc<dyn BankAccessProvider>>,
    ) -> String {
        render_json_rpc_response_full(body, full_api, false, snapshot, bank_access, None)
    }

    fn unique_temp_file(prefix: &str, extension: &str) -> std::path::PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{suffix}.{extension}"))
    }

    #[test]
    fn rpc_response_returns_health_ok() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":1,"method":"getHealth","params":[]}"#,
            false,
            None,
            None,
        );
        assert!(payload.contains(r#""result":"ok""#));
        assert!(payload.contains(r#""id":1"#));
    }

    #[test]
    fn rpc_response_returns_version() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":"a","method":"getVersion","params":[]}"#,
            true,
            None,
            None,
        );
        assert!(payload.contains(r#""karstflow-core":"0.1.0""#));
        assert!(payload.contains(r#""feature-set":"full_api""#));
    }

    #[test]
    fn rpc_response_returns_method_not_found() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":3,"method":"unknownMethod","params":[]}"#,
            false,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32601"#));
        assert!(payload.contains("Method not found"));
    }

    #[test]
    fn rpc_response_returns_parse_error() {
        let payload = render_json_rpc_response("{bad json", false, None, None);
        assert!(payload.contains(r#""code":-32700"#));
        assert!(payload.contains("Parse error"));
    }

    #[test]
    fn rpc_response_notification_returns_no_payload() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","method":"getHealth","params":[]}"#,
            false,
            None,
            None,
        );
        assert!(payload.is_empty());
    }

    #[test]
    fn rpc_response_invalid_request_without_id_still_returns_error() {
        let payload =
            render_json_rpc_response(r#"{"jsonrpc":"2.0","params":[]}"#, false, None, None);
        assert!(payload.contains(r#""code":-32600"#));
        assert!(payload.contains(r#""id":null"#));
    }

    #[test]
    fn rpc_response_invalid_jsonrpc_without_id_still_returns_error() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"1.0","method":"getHealth","params":[]}"#,
            false,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32600"#));
        assert!(payload.contains(r#""id":null"#));
    }

    #[test]
    fn rpc_response_batch_returns_only_non_notification_responses() {
        let payload = render_json_rpc_response(
            r#"[{"jsonrpc":"2.0","id":1,"method":"getHealth","params":[]},{"jsonrpc":"2.0","method":"getHealth","params":[]},{"jsonrpc":"2.0","id":2,"method":"getVersion","params":[]}]"#,
            false,
            None,
            None,
        );
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        let responses = parsed.as_array().expect("batch response array");
        assert_eq!(responses.len(), 2);
    }

    #[test]
    fn rpc_response_empty_batch_returns_invalid_request() {
        let payload = render_json_rpc_response("[]", false, None, None);
        assert!(payload.contains(r#""code":-32600"#));
    }

    #[test]
    fn rpc_response_batch_with_only_notifications_returns_no_payload() {
        let payload = render_json_rpc_response(
            r#"[{"jsonrpc":"2.0","method":"getHealth","params":[]},{"jsonrpc":"2.0","method":"getVersion","params":[]}]"#,
            false,
            None,
            None,
        );
        assert!(payload.is_empty());
    }

    #[test]
    fn rpc_response_rejects_object_id_as_invalid_request() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":{"bad":"id"},"method":"getHealth","params":[]}"#,
            false,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32600"#));
    }

    #[test]
    fn rpc_response_batch_rejects_invalid_id_item_with_null_id() {
        let payload = render_json_rpc_response(
            r#"[{"jsonrpc":"2.0","id":1,"method":"getHealth","params":[]},{"jsonrpc":"2.0","id":{"bad":"id"},"method":"getHealth","params":[]}]"#,
            false,
            None,
            None,
        );
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        let responses = parsed.as_array().expect("batch response array");
        assert_eq!(responses.len(), 2);
        assert!(responses
            .iter()
            .any(|item| item.get("error").is_some()
                && item.get("id") == Some(&serde_json::Value::Null)));
    }

    #[test]
    fn rpc_response_rejects_fractional_numeric_id_as_invalid_request() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":1.5,"method":"getHealth","params":[]}"#,
            false,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32600"#));
        assert!(payload.contains(r#""id":null"#));
    }

    #[test]
    fn rpc_response_batch_rejects_fractional_numeric_id_item() {
        let payload = render_json_rpc_response(
            r#"[{"jsonrpc":"2.0","id":1,"method":"getHealth","params":[]},{"jsonrpc":"2.0","id":2.25,"method":"getHealth","params":[]}]"#,
            false,
            None,
            None,
        );
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        let responses = parsed.as_array().expect("batch response array");
        assert_eq!(responses.len(), 2);
        assert!(responses
            .iter()
            .any(|item| item.get("error").is_some()
                && item.get("id") == Some(&serde_json::Value::Null)));
    }

    #[test]
    fn rpc_response_rejects_non_object_request_as_invalid_request() {
        let payload = render_json_rpc_response(r#"[1,2,3]"#, false, None, None);
        assert!(payload.contains(r#""code":-32600"#));
        assert!(payload.contains("Invalid request"));
    }

    #[test]
    fn rpc_response_rejects_invalid_jsonrpc_version() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"1.0","id":1,"method":"getHealth","params":[]}"#,
            false,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32600"#));
        assert!(payload.contains("Invalid request"));
    }

    #[test]
    fn rpc_response_rejects_non_string_method_as_invalid_request() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":1,"method":123,"params":[]}"#,
            false,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32600"#));
        assert!(payload.contains("Invalid request"));
    }

    #[test]
    fn rpc_response_rejects_empty_method_as_invalid_request() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":1,"method":"","params":[]}"#,
            false,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32600"#));
    }

    #[test]
    fn rpc_response_rejects_reserved_rpc_prefix_method_as_invalid_request() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":1,"method":"rpc.discover","params":[]}"#,
            false,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32600"#));
    }

    #[test]
    fn rpc_response_reads_slot_and_block_height_from_runtime_snapshot() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":11,"method":"getSlot","params":[]}"#,
            false,
            Some(RpcRuntimeSnapshot {
                slot: 42,
                block_height: 42,
                transaction_count: 120,
                uptime_millis: 2_000,
                latest_blockhash_seed: 42,
            }),
            None,
        );
        assert!(payload.contains(r#""result":10"#));

        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":12,"method":"getBlockHeight","params":[]}"#,
            false,
            Some(RpcRuntimeSnapshot {
                slot: 42,
                block_height: 42,
                transaction_count: 120,
                uptime_millis: 2_000,
                latest_blockhash_seed: 42,
            }),
            None,
        );
        assert!(payload.contains(r#""result":10"#));
    }

    #[test]
    fn rpc_response_supports_commitment_in_slot_methods() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":99,"method":"getSlot","params":[{"commitment":"processed"}]}"#,
            false,
            Some(RpcRuntimeSnapshot {
                slot: 42,
                block_height: 42,
                transaction_count: 0,
                uptime_millis: 1_000,
                latest_blockhash_seed: 7,
            }),
            None,
        );
        assert!(payload.contains(r#""result":42"#));
    }

    #[test]
    fn rpc_response_rejects_invalid_commitment_value() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":100,"method":"getSlot","params":[{"commitment":"fast"}]}"#,
            false,
            Some(RpcRuntimeSnapshot {
                slot: 42,
                block_height: 42,
                transaction_count: 0,
                uptime_millis: 1_000,
                latest_blockhash_seed: 7,
            }),
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_rejects_non_string_commitment_value() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":101,"method":"getSlot","params":[{"commitment":1}]}"#,
            false,
            Some(RpcRuntimeSnapshot {
                slot: 42,
                block_height: 42,
                transaction_count: 0,
                uptime_millis: 1_000,
                latest_blockhash_seed: 7,
            }),
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_rejects_non_array_params_shape() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":102,"method":"getHealth","params":{"bad":"shape"}}"#,
            false,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_returns_extended_count_methods() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":21,"method":"getBlockCount","params":[]}"#,
            false,
            Some(RpcRuntimeSnapshot {
                slot: 7,
                block_height: 7,
                transaction_count: 333,
                uptime_millis: 5_000,
                latest_blockhash_seed: 0xABCD,
            }),
            None,
        );
        assert!(payload.contains(r#""result":0"#));

        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":22,"method":"getTransactionCount","params":[]}"#,
            false,
            Some(RpcRuntimeSnapshot {
                slot: 7,
                block_height: 7,
                transaction_count: 333,
                uptime_millis: 5_000,
                latest_blockhash_seed: 0xABCD,
            }),
            None,
        );
        assert!(payload.contains(r#""result":333"#));
    }

    #[test]
    fn rpc_response_returns_genesis_hash_without_full_api() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":23,"method":"getGenesisHash","params":[]}"#,
            false,
            None,
            None,
        );
        assert!(payload.contains(r#""result":"5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp6H6r6Q4QvJf4""#));
    }

    #[test]
    fn rpc_response_rejects_transaction_count_when_min_context_slot_is_too_high() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":24,"method":"getTransactionCount","params":[{"commitment":"finalized","minContextSlot":100}]}"#,
            false,
            Some(RpcRuntimeSnapshot {
                slot: 50,
                block_height: 50,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 1,
            }),
            None,
        );
        assert!(payload.contains(r#""code":-32016"#));
        assert!(payload.contains("Minimum context slot not reached"));
    }

    #[test]
    fn rpc_response_rejects_slot_when_min_context_slot_is_too_high() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":241,"method":"getSlot","params":[{"commitment":"finalized","minContextSlot":100}]}"#,
            false,
            Some(RpcRuntimeSnapshot {
                slot: 50,
                block_height: 50,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 1,
            }),
            None,
        );
        assert!(payload.contains(r#""code":-32016"#));
    }

    #[test]
    fn rpc_response_rejects_block_height_when_min_context_slot_is_too_high() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":242,"method":"getBlockHeight","params":[{"commitment":"finalized","minContextSlot":100}]}"#,
            false,
            Some(RpcRuntimeSnapshot {
                slot: 50,
                block_height: 50,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 1,
            }),
            None,
        );
        assert!(payload.contains(r#""code":-32016"#));
    }

    #[test]
    fn rpc_response_rejects_block_count_when_min_context_slot_is_too_high() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":243,"method":"getBlockCount","params":[{"commitment":"finalized","minContextSlot":100}]}"#,
            false,
            Some(RpcRuntimeSnapshot {
                slot: 50,
                block_height: 50,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 1,
            }),
            None,
        );
        assert!(payload.contains(r#""code":-32016"#));
    }

    #[test]
    fn rpc_response_returns_recent_blockhash_without_full_api() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":25,"method":"getRecentBlockhash","params":[{"commitment":"processed"}]}"#,
            false,
            Some(RpcRuntimeSnapshot {
                slot: 15,
                block_height: 15,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 7,
            }),
            None,
        );
        assert!(payload.contains(r#""lamportsPerSignature":5000"#));
        assert!(payload.contains(r#""slot":15"#));
    }

    #[test]
    fn rpc_response_returns_is_blockhash_valid_true_for_current_blockhash() {
        let expected = format_blockhash_from_seed(0xABCD_u64.wrapping_add(0_u64.rotate_left(7)));
        let payload = render_json_rpc_response(
            &format!(
                r#"{{"jsonrpc":"2.0","id":26,"method":"isBlockhashValid","params":["{expected}"]}}"#
            ),
            false,
            Some(RpcRuntimeSnapshot {
                slot: 32,
                block_height: 32,
                transaction_count: 333,
                uptime_millis: 5_000,
                latest_blockhash_seed: 0xABCD,
            }),
            None,
        );
        assert!(payload.contains(r#""value":true"#));
    }

    #[test]
    fn rpc_response_returns_invalid_params_for_is_blockhash_valid_without_hash() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":27,"method":"isBlockhashValid","params":[]}"#,
            false,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_returns_fee_for_message_without_full_api() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":28,"method":"getFeeForMessage","params":["AQAB"]}"#,
            false,
            Some(RpcRuntimeSnapshot {
                slot: 11,
                block_height: 11,
                transaction_count: 333,
                uptime_millis: 5_000,
                latest_blockhash_seed: 0xABCD,
            }),
            None,
        );
        assert!(payload.contains(r#""value":5040"#));
        assert!(payload.contains(r#""slot":0"#));
    }

    #[test]
    fn rpc_response_returns_fees_without_full_api() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":280,"method":"getFees","params":[{"commitment":"processed"}]}"#,
            false,
            Some(RpcRuntimeSnapshot {
                slot: 11,
                block_height: 11,
                transaction_count: 333,
                uptime_millis: 5_000,
                latest_blockhash_seed: 0xABCD,
            }),
            None,
        );
        assert!(payload.contains(r#""lamportsPerSignature":5000"#));
        assert!(payload.contains(r#""lastValidSlot":161"#));
        assert!(payload.contains(r#""lastValidBlockHeight":161"#));
    }

    #[test]
    fn rpc_response_returns_fee_calculator_for_current_blockhash_without_full_api() {
        let expected = format_blockhash_from_seed(0xABCD_u64.wrapping_add(0_u64.rotate_left(7)));
        let payload = render_json_rpc_response(
            &format!(
                r#"{{"jsonrpc":"2.0","id":282,"method":"getFeeCalculatorForBlockhash","params":["{expected}"]}}"#
            ),
            false,
            Some(RpcRuntimeSnapshot {
                slot: 11,
                block_height: 11,
                transaction_count: 333,
                uptime_millis: 5_000,
                latest_blockhash_seed: 0xABCD,
            }),
            None,
        );
        assert!(payload.contains(r#""lamportsPerSignature":5000"#));
    }

    #[test]
    fn rpc_response_returns_null_fee_calculator_for_unknown_blockhash() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":283,"method":"getFeeCalculatorForBlockhash","params":["unknown-blockhash"]}"#,
            false,
            Some(RpcRuntimeSnapshot {
                slot: 11,
                block_height: 11,
                transaction_count: 333,
                uptime_millis: 5_000,
                latest_blockhash_seed: 0xABCD,
            }),
            None,
        );
        assert!(payload.contains(r#""result":{"context":{"slot":0},"value":null}"#));
    }

    #[test]
    fn rpc_response_returns_invalid_params_for_fee_calculator_without_blockhash() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":284,"method":"getFeeCalculatorForBlockhash","params":[]}"#,
            false,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_rejects_fees_when_min_context_slot_is_too_high() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":281,"method":"getFees","params":[{"minContextSlot":100}]}"#,
            false,
            Some(RpcRuntimeSnapshot {
                slot: 10,
                block_height: 10,
                transaction_count: 333,
                uptime_millis: 5_000,
                latest_blockhash_seed: 0xABCD,
            }),
            None,
        );
        assert!(payload.contains(r#""code":-32016"#));
    }

    #[test]
    fn rpc_response_rejects_fee_calculator_when_min_context_slot_is_too_high() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":285,"method":"getFeeCalculatorForBlockhash","params":["abc",{"minContextSlot":100}]}"#,
            false,
            Some(RpcRuntimeSnapshot {
                slot: 10,
                block_height: 10,
                transaction_count: 333,
                uptime_millis: 5_000,
                latest_blockhash_seed: 0xABCD,
            }),
            None,
        );
        assert!(payload.contains(r#""code":-32016"#));
    }

    #[test]
    fn rpc_response_returns_invalid_params_for_fee_for_message_without_message() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":29,"method":"getFeeForMessage","params":[]}"#,
            false,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_returns_balance_with_context() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":24,"method":"getBalance","params":["9xQeWvG816bUx9EPjHmaT23yvVM1X9vY5zs7j2dAefX5",{"commitment":"processed"}]}"#,
            false,
            Some(RpcRuntimeSnapshot {
                slot: 15,
                block_height: 15,
                transaction_count: 333,
                uptime_millis: 5_000,
                latest_blockhash_seed: 0xABCD,
            }),
            None,
        );
        assert!(payload.contains(r#""result":{"context":{"slot":15},"value":"#));
    }

    #[test]
    fn rpc_response_returns_identity_without_full_api() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":26,"method":"getIdentity","params":[]}"#,
            false,
            None,
            None,
        );
        assert!(payload.contains(r#""identity":"ParaDancer11111111111111111111111111111111""#));
    }

    #[test]
    fn rpc_response_returns_epoch_schedule_without_full_api() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":265,"method":"getEpochSchedule","params":[]}"#,
            false,
            None,
            None,
        );
        assert!(payload.contains(r#""slotsPerEpoch":432000"#));
        assert!(payload.contains(r#""leaderScheduleSlotOffset":432000"#));
        assert!(payload.contains(r#""warmup":false"#));
    }

    #[test]
    fn rpc_response_returns_minimum_balance_for_rent_exemption_without_full_api() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":266,"method":"getMinimumBalanceForRentExemption","params":[165]}"#,
            false,
            None,
            None,
        );
        assert!(payload.contains(r#""result":2039280"#));
    }

    #[test]
    fn rpc_response_returns_invalid_params_for_minimum_balance_without_data_len() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":267,"method":"getMinimumBalanceForRentExemption","params":[]}"#,
            false,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_returns_stake_minimum_delegation_without_full_api() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":268,"method":"getStakeMinimumDelegation","params":[{"commitment":"processed"}]}"#,
            false,
            Some(RpcRuntimeSnapshot {
                slot: 77,
                block_height: 77,
                transaction_count: 0,
                uptime_millis: 1_000,
                latest_blockhash_seed: 1,
            }),
            None,
        );
        assert!(payload.contains(r#""slot":77"#));
        assert!(payload.contains(r#""value":1000000000"#));
    }

    #[test]
    fn rpc_response_rejects_stake_minimum_delegation_when_min_context_slot_is_too_high() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":269,"method":"getStakeMinimumDelegation","params":[{"minContextSlot":100}]}"#,
            false,
            Some(RpcRuntimeSnapshot {
                slot: 10,
                block_height: 10,
                transaction_count: 333,
                uptime_millis: 5_000,
                latest_blockhash_seed: 0xABCD,
            }),
            None,
        );
        assert!(payload.contains(r#""code":-32016"#));
    }

    #[test]
    fn rpc_response_returns_slot_leader_without_full_api() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":260,"method":"getSlotLeader","params":[{"commitment":"processed"}]}"#,
            false,
            Some(RpcRuntimeSnapshot {
                slot: 123,
                block_height: 123,
                transaction_count: 0,
                uptime_millis: 1_000,
                latest_blockhash_seed: 1,
            }),
            None,
        );
        assert!(payload.contains("ParaLeader"));
    }

    #[test]
    fn rpc_response_returns_slot_leaders_without_full_api() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":261,"method":"getSlotLeaders","params":[10,3,{"commitment":"processed"}]}"#,
            false,
            Some(RpcRuntimeSnapshot {
                slot: 100,
                block_height: 100,
                transaction_count: 0,
                uptime_millis: 1_000,
                latest_blockhash_seed: 1,
            }),
            None,
        );
        assert!(payload.contains(r#""result":["ParaLeader"#));
    }

    #[test]
    fn rpc_response_returns_invalid_params_for_slot_leaders_without_args() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":262,"method":"getSlotLeaders","params":[]}"#,
            false,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_returns_invalid_params_for_slot_leaders_limit_above_max() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":263,"method":"getSlotLeaders","params":[1,5001,{"commitment":"processed"}]}"#,
            false,
            Some(RpcRuntimeSnapshot {
                slot: 10_000,
                block_height: 10_000,
                transaction_count: 0,
                uptime_millis: 1_000,
                latest_blockhash_seed: 1,
            }),
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_returns_empty_slot_leaders_for_future_start_slot() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":264,"method":"getSlotLeaders","params":[200,3,{"commitment":"processed"}]}"#,
            false,
            Some(RpcRuntimeSnapshot {
                slot: 100,
                block_height: 100,
                transaction_count: 0,
                uptime_millis: 1_000,
                latest_blockhash_seed: 1,
            }),
            None,
        );
        assert!(payload.contains(r#""result":[]"#));
    }

    #[test]
    fn rpc_response_returns_epoch_info() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":25,"method":"getEpochInfo","params":[]}"#,
            false,
            Some(RpcRuntimeSnapshot {
                slot: 500_000,
                block_height: 500_000,
                transaction_count: 1_000,
                uptime_millis: 10_000,
                latest_blockhash_seed: 9,
            }),
            None,
        );
        assert!(payload.contains(r#""epoch":1"#));
        assert!(payload.contains(r#""slotIndex":67968"#));
        assert!(payload.contains(r#""slotsInEpoch":432000"#));
    }

    #[test]
    fn rpc_response_returns_highest_snapshot_slot_without_full_api() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":251,"method":"getHighestSnapshotSlot","params":[{"commitment":"processed"}]}"#,
            false,
            Some(RpcRuntimeSnapshot {
                slot: 500_000,
                block_height: 500_000,
                transaction_count: 1_000,
                uptime_millis: 10_000,
                latest_blockhash_seed: 9,
            }),
            None,
        );
        assert!(payload.contains(r#""full":500000"#));
        assert!(payload.contains(r#""incremental":499999"#));
    }

    #[test]
    fn rpc_response_returns_max_retransmit_slot_without_full_api() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":252,"method":"getMaxRetransmitSlot","params":[{"commitment":"processed"}]}"#,
            false,
            Some(RpcRuntimeSnapshot {
                slot: 500_000,
                block_height: 500_000,
                transaction_count: 1_000,
                uptime_millis: 10_000,
                latest_blockhash_seed: 9,
            }),
            None,
        );
        assert!(payload.contains(r#""result":500000"#));
    }

    #[test]
    fn rpc_response_returns_latest_blockhash_shape() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":13,"method":"getLatestBlockhash","params":[]}"#,
            false,
            Some(RpcRuntimeSnapshot {
                slot: 7,
                block_height: 7,
                transaction_count: 333,
                uptime_millis: 5_000,
                latest_blockhash_seed: 0xABCD,
            }),
            None,
        );
        assert!(payload.contains(r#""lastValidBlockHeight":150"#));
        assert!(payload.contains(r#""slot":0"#));
        assert!(payload.contains(&format_blockhash_from_seed(
            0xABCD_u64.wrapping_add(0_u64.rotate_left(7))
        )));
    }

    #[test]
    fn rpc_response_rejects_latest_blockhash_when_min_context_slot_is_too_high() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":130,"method":"getLatestBlockhash","params":[{"minContextSlot":100}]}"#,
            false,
            Some(RpcRuntimeSnapshot {
                slot: 10,
                block_height: 10,
                transaction_count: 333,
                uptime_millis: 5_000,
                latest_blockhash_seed: 0xABCD,
            }),
            None,
        );
        assert!(payload.contains(r#""code":-32016"#));
    }

    #[test]
    fn rpc_response_rejects_recent_blockhash_when_min_context_slot_is_too_high() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":131,"method":"getRecentBlockhash","params":[{"minContextSlot":100}]}"#,
            false,
            Some(RpcRuntimeSnapshot {
                slot: 10,
                block_height: 10,
                transaction_count: 333,
                uptime_millis: 5_000,
                latest_blockhash_seed: 0xABCD,
            }),
            None,
        );
        assert!(payload.contains(r#""code":-32016"#));
    }

    #[test]
    fn rpc_response_rejects_blockhash_validity_when_min_context_slot_is_too_high() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":132,"method":"isBlockhashValid","params":["abc",{"minContextSlot":100}]}"#,
            false,
            Some(RpcRuntimeSnapshot {
                slot: 10,
                block_height: 10,
                transaction_count: 333,
                uptime_millis: 5_000,
                latest_blockhash_seed: 0xABCD,
            }),
            None,
        );
        assert!(payload.contains(r#""code":-32016"#));
    }

    #[test]
    fn rpc_response_rejects_fee_for_message_when_min_context_slot_is_too_high() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":133,"method":"getFeeForMessage","params":["AQAB",{"minContextSlot":100}]}"#,
            false,
            Some(RpcRuntimeSnapshot {
                slot: 10,
                block_height: 10,
                transaction_count: 333,
                uptime_millis: 5_000,
                latest_blockhash_seed: 0xABCD,
            }),
            None,
        );
        assert!(payload.contains(r#""code":-32016"#));
    }

    #[test]
    fn rpc_response_returns_recent_performance_samples_when_full_api() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":33,"method":"getRecentPerformanceSamples","params":[2]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 20,
                block_height: 20,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 1,
            }),
            None,
        );
        assert!(payload.contains("numTransactions"));
        assert!(payload.contains("numSlots"));
        assert!(payload.contains("samplePeriodSecs"));
    }

    #[test]
    fn rpc_response_returns_invalid_params_for_recent_performance_samples_with_non_numeric_limit() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":331,"method":"getRecentPerformanceSamples","params":["2"]}"#,
            true,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_returns_invalid_params_for_recent_performance_samples_with_zero_limit() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":332,"method":"getRecentPerformanceSamples","params":[0]}"#,
            true,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_returns_inflation_governor_in_full_api_mode() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":99,"method":"getInflationGovernor","params":[]}"#,
            true,
            None,
            None,
        );
        assert!(payload.contains(r#""initial":0.08"#));
        assert!(payload.contains(r#""terminal":0.015"#));
    }

    #[test]
    fn rpc_response_hides_inflation_governor_when_not_full_api() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":100,"method":"getInflationGovernor","params":[]}"#,
            false,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32601"#));
    }

    #[test]
    fn rpc_response_returns_inflation_rate_in_full_api_mode() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":101,"method":"getInflationRate","params":[]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 500_000,
                block_height: 500_000,
                transaction_count: 1_000,
                uptime_millis: 10_000,
                latest_blockhash_seed: 9,
            }),
            None,
        );
        assert!(payload.contains(r#""epoch":1"#));
        assert!(payload.contains(r#""validator":"#));
    }

    #[test]
    fn rpc_response_hides_inflation_rate_when_not_full_api() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":102,"method":"getInflationRate","params":[]}"#,
            false,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32601"#));
    }

    #[test]
    fn rpc_response_returns_inflation_reward_in_full_api_mode() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":103,"method":"getInflationReward","params":[["Vote111111111111111111111111111111111111111"]]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 55,
                block_height: 55,
                transaction_count: 777,
                uptime_millis: 9_000,
                latest_blockhash_seed: 1,
            }),
            None,
        );
        assert!(payload.contains(r#""effectiveSlot":23"#));
        assert!(payload.contains(r#""commission":5"#));
    }

    #[test]
    fn rpc_response_returns_invalid_params_for_inflation_reward_without_addresses() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":104,"method":"getInflationReward","params":[]}"#,
            true,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_hides_inflation_reward_when_not_full_api() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":105,"method":"getInflationReward","params":[["Vote111111111111111111111111111111111111111"]]}"#,
            false,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32601"#));
    }

    #[test]
    fn rpc_response_returns_signatures_for_address_in_full_api_mode() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":87,"method":"getSignaturesForAddress","params":["Vote111111111111111111111111111111111111111",{"limit":3}]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 55,
                block_height: 55,
                transaction_count: 777,
                uptime_millis: 9_000,
                latest_blockhash_seed: 1,
            }),
            None,
        );
        assert!(
            payload.contains(r#""sourceAddress":"Vote111111111111111111111111111111111111111""#)
        );
        assert!(payload.contains(r#""confirmationStatus":"finalized""#));
    }

    #[test]
    fn rpc_response_rejects_signatures_for_address_when_min_context_slot_is_too_high() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":870,"method":"getSignaturesForAddress","params":["Vote111111111111111111111111111111111111111",{"limit":3,"minContextSlot":999}]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 55,
                block_height: 55,
                transaction_count: 777,
                uptime_millis: 9_000,
                latest_blockhash_seed: 1,
            }),
            None,
        );
        assert!(payload.contains(r#""code":-32016"#));
    }

    #[test]
    fn rpc_response_returns_signatures_for_address_with_before_until_config() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":871,"method":"getSignaturesForAddress","params":["Vote111111111111111111111111111111111111111",{"before":"before-sig","until":"until-sig","limit":3}]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 55,
                block_height: 55,
                transaction_count: 777,
                uptime_millis: 9_000,
                latest_blockhash_seed: 1,
            }),
            None,
        );
        assert!(payload.contains(r#""before":"before-sig""#));
        assert!(payload.contains(r#""until":"until-sig""#));
    }

    #[test]
    fn rpc_response_returns_confirmed_signatures_for_address2_in_full_api_mode() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":872,"method":"getConfirmedSignaturesForAddress2","params":["Vote111111111111111111111111111111111111111",{"limit":2}]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 55,
                block_height: 55,
                transaction_count: 777,
                uptime_millis: 9_000,
                latest_blockhash_seed: 1,
            }),
            None,
        );
        assert!(
            payload.contains(r#""sourceAddress":"Vote111111111111111111111111111111111111111""#)
        );
        assert!(payload.contains(r#""confirmationStatus":"finalized""#));
    }

    #[test]
    fn rpc_response_hides_confirmed_signatures_for_address2_when_not_full_api() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":873,"method":"getConfirmedSignaturesForAddress2","params":["Vote111111111111111111111111111111111111111"]}"#,
            false,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32601"#));
    }

    #[test]
    fn rpc_response_returns_invalid_params_for_signatures_for_address_without_address() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":88,"method":"getSignaturesForAddress","params":[]}"#,
            true,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_hides_signatures_for_address_when_not_full_api() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":89,"method":"getSignaturesForAddress","params":["Vote111111111111111111111111111111111111111"]}"#,
            false,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32601"#));
    }

    #[test]
    fn rpc_response_hides_recent_performance_samples_when_not_full_api() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":34,"method":"getRecentPerformanceSamples","params":[1]}"#,
            false,
            Some(RpcRuntimeSnapshot {
                slot: 20,
                block_height: 20,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 1,
            }),
            None,
        );
        assert!(payload.contains(r#""code":-32601"#));
    }

    #[test]
    fn rpc_response_returns_cluster_nodes_in_full_api_mode() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":83,"method":"getClusterNodes","params":[]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 20,
                block_height: 20,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 1,
            }),
            None,
        );
        assert!(payload.contains(r#""pubkey":"ParaDancer11111111111111111111111111111111""#));
        assert!(payload.contains(r#""version":"0.1.0""#));
    }

    #[test]
    fn rpc_response_hides_cluster_nodes_when_not_full_api() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":84,"method":"getClusterNodes","params":[]}"#,
            false,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32601"#));
    }

    #[test]
    fn rpc_response_returns_vote_accounts_in_full_api_mode() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":85,"method":"getVoteAccounts","params":[]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 55,
                block_height: 55,
                transaction_count: 777,
                uptime_millis: 9_000,
                latest_blockhash_seed: 1,
            }),
            None,
        );
        assert!(payload.contains(r#""votePubkey":"Vote111111111111111111111111111111111111111""#));
        assert!(payload.contains(r#""delinquent":[]"#));
    }

    #[test]
    fn rpc_response_returns_filtered_vote_accounts_in_full_api_mode() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":851,"method":"getVoteAccounts","params":[{"votePubkey":"Vote111111111111111111111111111111111111111"}]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 55,
                block_height: 55,
                transaction_count: 777,
                uptime_millis: 9_000,
                latest_blockhash_seed: 1,
            }),
            None,
        );
        assert!(payload.contains(r#""current":[{"#));
        assert!(payload.contains(r#""votePubkey":"Vote111111111111111111111111111111111111111""#));
    }

    #[test]
    fn rpc_response_returns_empty_vote_accounts_for_unknown_vote_pubkey_filter() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":852,"method":"getVoteAccounts","params":[{"votePubkey":"UnknownVote11111111111111111111111111111111111"}]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 55,
                block_height: 55,
                transaction_count: 777,
                uptime_millis: 9_000,
                latest_blockhash_seed: 1,
            }),
            None,
        );
        assert!(payload.contains(r#""current":[]"#));
    }

    #[test]
    fn rpc_response_returns_delinquent_vote_accounts_when_enabled() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":853,"method":"getVoteAccounts","params":[{"keepUnstakedDelinquents":true,"delinquentSlotDistance":4}]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 55,
                block_height: 55,
                transaction_count: 777,
                uptime_millis: 9_000,
                latest_blockhash_seed: 1,
            }),
            None,
        );
        assert!(payload.contains(r#""delinquent":[{"#));
        assert!(payload.contains(r#""votePubkey":"VoteDelinq11111111111111111111111111111111111""#));
    }

    #[test]
    fn rpc_response_returns_invalid_params_for_vote_accounts_with_invalid_config_types() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":854,"method":"getVoteAccounts","params":[{"keepUnstakedDelinquents":"yes"}]}"#,
            true,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_rejects_vote_accounts_when_min_context_slot_is_too_high() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":855,"method":"getVoteAccounts","params":[{"minContextSlot":999}]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 55,
                block_height: 55,
                transaction_count: 777,
                uptime_millis: 9_000,
                latest_blockhash_seed: 1,
            }),
            None,
        );
        assert!(payload.contains(r#""code":-32016"#));
    }

    #[test]
    fn rpc_response_hides_vote_accounts_when_not_full_api() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":86,"method":"getVoteAccounts","params":[]}"#,
            false,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32601"#));
    }

    #[test]
    fn rpc_response_returns_supply_in_full_api_mode() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":75,"method":"getSupply","params":[]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 55,
                block_height: 55,
                transaction_count: 777,
                uptime_millis: 9_000,
                latest_blockhash_seed: 1,
            }),
            None,
        );
        assert!(payload.contains(r#""context":{"slot":23}"#));
        assert!(payload.contains(r#""nonCirculatingAccounts":[]"#));
    }

    #[test]
    fn rpc_response_returns_supply_without_non_circulating_accounts_when_excluded() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":751,"method":"getSupply","params":[{"excludeNonCirculatingAccountsList":true}]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 55,
                block_height: 55,
                transaction_count: 777,
                uptime_millis: 9_000,
                latest_blockhash_seed: 1,
            }),
            None,
        );
        assert!(payload.contains(r#""nonCirculatingAccounts":[]"#));
    }

    #[test]
    fn rpc_response_rejects_supply_when_min_context_slot_is_too_high() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":752,"method":"getSupply","params":[{"minContextSlot":999}]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 55,
                block_height: 55,
                transaction_count: 777,
                uptime_millis: 9_000,
                latest_blockhash_seed: 1,
            }),
            None,
        );
        assert!(payload.contains(r#""code":-32016"#));
    }

    #[test]
    fn rpc_response_returns_invalid_params_for_supply_with_invalid_exclude_flag() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":753,"method":"getSupply","params":[{"excludeNonCirculatingAccountsList":"true"}]}"#,
            true,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_hides_supply_when_not_full_api() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":76,"method":"getSupply","params":[]}"#,
            false,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32601"#));
    }

    #[test]
    fn rpc_response_returns_token_supply_in_full_api_mode() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":770,"method":"getTokenSupply","params":["So11111111111111111111111111111111111111112"]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 55,
                block_height: 55,
                transaction_count: 777,
                uptime_millis: 9_000,
                latest_blockhash_seed: 1,
            }),
            None,
        );
        assert!(payload.contains(r#""context":{"slot":23}"#));
        assert!(payload.contains(r#""amount":"#));
        assert!(payload.contains(r#""decimals":9"#));
    }

    #[test]
    fn rpc_response_hides_token_supply_when_not_full_api() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":771,"method":"getTokenSupply","params":["So11111111111111111111111111111111111111112"]}"#,
            false,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32601"#));
    }

    #[test]
    fn rpc_response_returns_token_account_balance_in_full_api_mode() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":772,"method":"getTokenAccountBalance","params":["ParaOwnerAcct00111111111111111111111111111111"]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 55,
                block_height: 55,
                transaction_count: 777,
                uptime_millis: 9_000,
                latest_blockhash_seed: 1,
            }),
            None,
        );
        assert!(payload.contains(r#""context":{"slot":23}"#));
        assert!(payload.contains(r#""amount":"#));
        assert!(payload.contains(r#""uiAmountString":"#));
    }

    #[test]
    fn rpc_response_returns_invalid_params_for_token_account_balance_without_account() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":773,"method":"getTokenAccountBalance","params":[]}"#,
            true,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_rejects_token_supply_when_min_context_slot_is_too_high() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":774,"method":"getTokenSupply","params":["So11111111111111111111111111111111111111112",{"minContextSlot":999}]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 55,
                block_height: 55,
                transaction_count: 777,
                uptime_millis: 9_000,
                latest_blockhash_seed: 1,
            }),
            None,
        );
        assert!(payload.contains(r#""code":-32016"#));
    }

    #[test]
    fn rpc_response_hides_token_account_balance_when_not_full_api() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":775,"method":"getTokenAccountBalance","params":["ParaOwnerAcct00111111111111111111111111111111"]}"#,
            false,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32601"#));
    }

    #[test]
    fn rpc_response_returns_largest_accounts_in_full_api_mode() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":77,"method":"getLargestAccounts","params":[{"filter":"circulating"}]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 55,
                block_height: 55,
                transaction_count: 777,
                uptime_millis: 9_000,
                latest_blockhash_seed: 1,
            }),
            None,
        );
        assert!(payload.contains(r#""context":{"slot":23}"#));
        assert!(payload.contains(r#"ParaLargest00"#));
    }

    #[test]
    fn rpc_response_returns_invalid_params_for_largest_accounts_filter() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":78,"method":"getLargestAccounts","params":[{"filter":1}]}"#,
            true,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_hides_largest_accounts_when_not_full_api() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":79,"method":"getLargestAccounts","params":[]}"#,
            false,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32601"#));
    }

    #[test]
    fn rpc_response_returns_token_largest_accounts_in_full_api_mode() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":80,"method":"getTokenLargestAccounts","params":["So11111111111111111111111111111111111111112"]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 55,
                block_height: 55,
                transaction_count: 777,
                uptime_millis: 9_000,
                latest_blockhash_seed: 1,
            }),
            None,
        );
        assert!(payload.contains(r#""mint":"So11111111111111111111111111111111111111112""#));
        assert!(payload.contains(r#"ParaToken00"#));
    }

    #[test]
    fn rpc_response_rejects_token_largest_accounts_when_min_context_slot_is_too_high() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":801,"method":"getTokenLargestAccounts","params":["So11111111111111111111111111111111111111112",{"minContextSlot":999}]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 55,
                block_height: 55,
                transaction_count: 777,
                uptime_millis: 9_000,
                latest_blockhash_seed: 1,
            }),
            None,
        );
        assert!(payload.contains(r#""code":-32016"#));
    }

    #[test]
    fn rpc_response_returns_program_accounts_in_full_api_mode() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":90,"method":"getProgramAccounts","params":["11111111111111111111111111111111",{"withContext":true,"filters":[{"dataSize":165}]}]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 55,
                block_height: 55,
                transaction_count: 777,
                uptime_millis: 9_000,
                latest_blockhash_seed: 1,
            }),
            None,
        );
        assert!(payload.contains(r#""context":{"slot":23}"#));
        assert!(payload.contains(r#"ParaProgAcct00"#));
    }

    #[test]
    fn rpc_response_returns_invalid_params_for_program_accounts_without_program_id() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":91,"method":"getProgramAccounts","params":[]}"#,
            true,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_hides_program_accounts_when_not_full_api() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":92,"method":"getProgramAccounts","params":["11111111111111111111111111111111"]}"#,
            false,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32601"#));
    }

    #[test]
    fn rpc_response_returns_token_accounts_by_owner_in_full_api_mode() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":93,"method":"getTokenAccountsByOwner","params":["Vote111111111111111111111111111111111111111",{"programId":"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"},{"minContextSlot":1}]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 55,
                block_height: 55,
                transaction_count: 777,
                uptime_millis: 9_000,
                latest_blockhash_seed: 1,
            }),
            None,
        );
        assert!(payload.contains(r#""tokenOwner":"Vote111111111111111111111111111111111111111""#));
        assert!(payload
            .contains(r#""selector":"programId:TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA""#));
    }

    #[test]
    fn rpc_response_returns_invalid_params_for_token_accounts_by_owner_without_selector() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":94,"method":"getTokenAccountsByOwner","params":["Vote111111111111111111111111111111111111111"]}"#,
            true,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_hides_token_accounts_by_owner_when_not_full_api() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":95,"method":"getTokenAccountsByOwner","params":["Vote111111111111111111111111111111111111111",{"mint":"So11111111111111111111111111111111111111112"}]}"#,
            false,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32601"#));
    }

    #[test]
    fn rpc_response_returns_token_accounts_by_delegate_in_full_api_mode() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":96,"method":"getTokenAccountsByDelegate","params":["Vote111111111111111111111111111111111111111",{"mint":"So11111111111111111111111111111111111111112"}]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 55,
                block_height: 55,
                transaction_count: 777,
                uptime_millis: 9_000,
                latest_blockhash_seed: 1,
            }),
            None,
        );
        assert!(payload.contains(r#""delegate":"Vote111111111111111111111111111111111111111""#));
        assert!(
            payload.contains(r#""selector":"mint:So11111111111111111111111111111111111111112""#)
        );
    }

    #[test]
    fn rpc_response_returns_invalid_params_for_token_accounts_by_delegate_without_selector() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":97,"method":"getTokenAccountsByDelegate","params":["Vote111111111111111111111111111111111111111"]}"#,
            true,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_hides_token_accounts_by_delegate_when_not_full_api() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":98,"method":"getTokenAccountsByDelegate","params":["Vote111111111111111111111111111111111111111",{"programId":"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"}]}"#,
            false,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32601"#));
    }

    #[test]
    fn rpc_response_returns_invalid_params_for_token_largest_accounts_without_mint() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":81,"method":"getTokenLargestAccounts","params":[]}"#,
            true,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_hides_token_largest_accounts_when_not_full_api() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":82,"method":"getTokenLargestAccounts","params":["So11111111111111111111111111111111111111112"]}"#,
            false,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32601"#));
    }

    #[test]
    fn rpc_response_returns_account_info_in_full_api_mode() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":41,"method":"getAccountInfo","params":["9xQeWvG816bUx9EPjHmaT23yvVM1X9vY5zs7j2dAefX5"]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 55,
                block_height: 55,
                transaction_count: 777,
                uptime_millis: 9_000,
                latest_blockhash_seed: 1,
            }),
            None,
        );
        assert!(payload.contains("lamports"));
        assert!(payload.contains(r#""slot":23"#));
        assert!(payload.contains("11111111111111111111111111111111"));
    }

    #[test]
    fn rpc_response_rejects_account_info_when_min_context_slot_is_too_high() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":141,"method":"getAccountInfo","params":["9xQeWvG816bUx9EPjHmaT23yvVM1X9vY5zs7j2dAefX5",{"commitment":"finalized","minContextSlot":999}]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 55,
                block_height: 55,
                transaction_count: 777,
                uptime_millis: 9_000,
                latest_blockhash_seed: 1,
            }),
            None,
        );
        assert!(payload.contains(r#""code":-32016"#));
        assert!(payload.contains("Minimum context slot not reached"));
    }

    #[test]
    fn rpc_response_returns_multiple_accounts_in_full_api_mode() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":43,"method":"getMultipleAccounts","params":[["9xQeWvG816bUx9EPjHmaT23yvVM1X9vY5zs7j2dAefX5","Vote111111111111111111111111111111111111111"],{"commitment":"processed"}]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 55,
                block_height: 55,
                transaction_count: 777,
                uptime_millis: 9_000,
                latest_blockhash_seed: 1,
            }),
            None,
        );
        assert!(payload.contains(r#""context":{"slot":55}"#));
        assert!(payload.contains(r#""value":["#));
        assert!(payload.contains(r#""lamports":"#));
    }

    #[test]
    fn rpc_response_returns_invalid_params_for_multiple_accounts_without_pubkeys() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":44,"method":"getMultipleAccounts","params":[]}"#,
            true,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_hides_multiple_accounts_when_not_full_api() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":45,"method":"getMultipleAccounts","params":[["11111111111111111111111111111111"]]}"#,
            false,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32601"#));
    }

    #[test]
    fn rpc_response_rejects_token_accounts_by_owner_when_min_context_slot_is_too_high() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":142,"method":"getTokenAccountsByOwner","params":["Owner111111111111111111111111111111111111111",{"programId":"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"},{"minContextSlot":999}]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 55,
                block_height: 55,
                transaction_count: 777,
                uptime_millis: 9_000,
                latest_blockhash_seed: 1,
            }),
            None,
        );
        assert!(payload.contains(r#""code":-32016"#));
        assert!(payload.contains("Minimum context slot not reached"));
    }

    #[test]
    fn rpc_response_returns_first_available_block() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":46,"method":"getFirstAvailableBlock","params":[]}"#,
            false,
            None,
            None,
        );
        assert!(payload.contains(r#""result":0"#));
    }

    #[test]
    fn rpc_response_returns_minimum_ledger_slot() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":69,"method":"minimumLedgerSlot","params":[]}"#,
            false,
            None,
            None,
        );
        assert!(payload.contains(r#""result":0"#));
    }

    #[test]
    fn rpc_response_returns_max_shred_insert_slot() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":70,"method":"getMaxShredInsertSlot","params":[{"commitment":"processed"}]}"#,
            false,
            Some(RpcRuntimeSnapshot {
                slot: 21,
                block_height: 21,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 3,
            }),
            None,
        );
        assert!(payload.contains(r#""result":21"#));
    }

    #[test]
    fn rpc_response_returns_blocks_range_in_full_api_mode() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":47,"method":"getBlocks","params":[3,6,{"commitment":"processed"}]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 20,
                block_height: 20,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 3,
            }),
            None,
        );
        assert!(payload.contains(r#""result":[3,4,5,6]"#));
    }

    #[test]
    fn rpc_response_returns_signature_statuses_in_full_api_mode() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":57,"method":"getSignatureStatuses","params":[["5NfVYAc8T9mPc4QkL9sVwR8CQmTiQ2KX8b6gY6U4Y9JjD2fYg4r6xQxjN5KcV8hM3f2x9pW7qE4nR2mT8yP1zQ7"]]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 100,
                block_height: 100,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 3,
            }),
            None,
        );
        assert!(payload.contains(r#""context":{"slot":68}"#));
        assert!(payload.contains(r#""confirmationStatus":"finalized""#));
    }

    #[test]
    fn rpc_response_returns_null_signature_status_without_history_search() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":571,"method":"getSignatureStatuses","params":[["d"]]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 100,
                block_height: 100,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 3,
            }),
            None,
        );
        assert!(payload.contains(r#""value":[null]"#));
    }

    #[test]
    fn rpc_response_returns_signature_status_with_history_search_enabled() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":572,"method":"getSignatureStatuses","params":[["d"],{"searchTransactionHistory":true}]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 100,
                block_height: 100,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 3,
            }),
            None,
        );
        assert!(payload.contains(r#""confirmationStatus":"finalized""#));
    }

    #[test]
    fn rpc_response_returns_leader_schedule_in_full_api_mode() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":71,"method":"getLeaderSchedule","params":[]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 100,
                block_height: 100,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 3,
            }),
            None,
        );
        assert!(payload.contains(r#"ParaDancer11111111111111111111111111111111"#));
        assert!(payload.contains(r#"ParaDancer22222222222222222222222222222222"#));
    }

    #[test]
    fn rpc_response_returns_filtered_leader_schedule_in_full_api_mode() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":72,"method":"getLeaderSchedule","params":[null,{"identity":"Vote111111111111111111111111111111111111111"}]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 100,
                block_height: 100,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 3,
            }),
            None,
        );
        assert!(payload.contains(r#"Vote111111111111111111111111111111111111111"#));
        assert!(!payload.contains(r#"ParaDancer22222222222222222222222222222222"#));
    }

    #[test]
    fn rpc_response_rejects_leader_schedule_when_min_context_slot_is_too_high() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":721,"method":"getLeaderSchedule","params":[null,{"minContextSlot":999}]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 100,
                block_height: 100,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 3,
            }),
            None,
        );
        assert!(payload.contains(r#""code":-32016"#));
    }

    #[test]
    fn rpc_response_returns_invalid_params_for_leader_schedule_identity() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":73,"method":"getLeaderSchedule","params":[null,{"identity":1}]}"#,
            true,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_hides_leader_schedule_when_not_full_api() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":74,"method":"getLeaderSchedule","params":[]}"#,
            false,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32601"#));
    }

    #[test]
    fn rpc_response_returns_block_production_in_full_api_mode() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":63,"method":"getBlockProduction","params":[{"range":{"firstSlot":12,"lastSlot":15}}]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 100,
                block_height: 100,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 3,
            }),
            None,
        );
        assert!(payload.contains(r#""range":{"firstSlot":12,"lastSlot":15}"#));
        assert!(payload.contains(r#"ParaDancer11111111111111111111111111111111"#));
    }

    #[test]
    fn rpc_response_rejects_block_production_when_min_context_slot_is_too_high() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":631,"method":"getBlockProduction","params":[{"minContextSlot":999}]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 100,
                block_height: 100,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 3,
            }),
            None,
        );
        assert!(payload.contains(r#""code":-32016"#));
    }

    #[test]
    fn rpc_response_returns_invalid_params_for_block_production_range_shape() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":64,"method":"getBlockProduction","params":[{"range":{"firstSlot":"x"}}]}"#,
            true,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_hides_block_production_when_not_full_api() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":65,"method":"getBlockProduction","params":[]}"#,
            false,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32601"#));
    }

    #[test]
    fn rpc_response_returns_recent_prioritization_fees_in_full_api_mode() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":66,"method":"getRecentPrioritizationFees","params":[["11111111111111111111111111111111","Vote111111111111111111111111111111111111111"]]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 100,
                block_height: 100,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 3,
            }),
            None,
        );
        assert!(payload.contains(r#""slot":68"#));
        assert!(payload.contains(r#""prioritizationFee":110"#));
    }

    #[test]
    fn rpc_response_rejects_recent_prioritization_fees_when_min_context_slot_is_too_high() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":661,"method":"getRecentPrioritizationFees","params":[["11111111111111111111111111111111"],{"minContextSlot":999}]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 100,
                block_height: 100,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 3,
            }),
            None,
        );
        assert!(payload.contains(r#""code":-32016"#));
    }

    #[test]
    fn rpc_response_returns_invalid_params_for_recent_prioritization_fees() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":67,"method":"getRecentPrioritizationFees","params":[["",1]]}"#,
            true,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_hides_recent_prioritization_fees_when_not_full_api() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":68,"method":"getRecentPrioritizationFees","params":[]}"#,
            false,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32601"#));
    }

    #[test]
    fn rpc_response_returns_invalid_params_for_signature_statuses_without_signatures() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":58,"method":"getSignatureStatuses","params":[]}"#,
            true,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_returns_invalid_params_for_signature_statuses_with_invalid_search_flag() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":581,"method":"getSignatureStatuses","params":[["abc"],{"searchTransactionHistory":"yes"}]}"#,
            true,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_rejects_signature_statuses_when_min_context_slot_is_too_high() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":582,"method":"getSignatureStatuses","params":[["abc"],{"minContextSlot":999}]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 100,
                block_height: 100,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 3,
            }),
            None,
        );
        assert!(payload.contains(r#""code":-32016"#));
    }

    #[test]
    fn rpc_response_hides_signature_statuses_when_not_full_api() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":59,"method":"getSignatureStatuses","params":[["abc"]]}"#,
            false,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32601"#));
    }

    #[test]
    fn rpc_response_returns_transaction_in_full_api_mode() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":60,"method":"getTransaction","params":["5NfVYAc8T9mPc4QkL9sVwR8CQmTiQ2KX8b6gY6U4Y9JjD2fYg4r6xQxjN5KcV8hM3f2x9pW7qE4nR2mT8yP1zQ7"]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 100,
                block_height: 100,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 3,
            }),
            None,
        );
        assert!(payload.contains(
            r#""transaction":{"message":{"accountKeys":[],"instructions":[],"recentBlockhash":"#
        ));
        assert!(payload.contains(r#""signatures":["5NfVYAc8T9mPc4QkL9sVwR8CQmTiQ2KX8b6gY6U4Y9JjD2fYg4r6xQxjN5KcV8hM3f2x9pW7qE4nR2mT8yP1zQ7"]"#));
        assert!(payload.contains(r#""meta":{"err":null"#));
    }

    #[test]
    fn rpc_response_returns_invalid_params_for_transaction_without_signature() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":61,"method":"getTransaction","params":[]}"#,
            true,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_returns_invalid_params_for_transaction_with_invalid_encoding() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":161,"method":"getTransaction","params":["5NfVYAc8T9mPc4QkL9sVwR8CQmTiQ2KX8b6gY6U4Y9JjD2fYg4r6xQxjN5KcV8hM3f2x9pW7qE4nR2mT8yP1zQ7",{"encoding":"wire"}]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 100,
                block_height: 100,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 3,
            }),
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_returns_invalid_params_for_transaction_with_invalid_version_type() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":162,"method":"getTransaction","params":["5NfVYAc8T9mPc4QkL9sVwR8CQmTiQ2KX8b6gY6U4Y9JjD2fYg4r6xQxjN5KcV8hM3f2x9pW7qE4nR2mT8yP1zQ7",{"maxSupportedTransactionVersion":"0"}]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 100,
                block_height: 100,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 3,
            }),
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_returns_invalid_params_for_transaction_with_unknown_config_key() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":164,"method":"getTransaction","params":["5NfVYAc8T9mPc4QkL9sVwR8CQmTiQ2KX8b6gY6U4Y9JjD2fYg4r6xQxjN5KcV8hM3f2x9pW7qE4nR2mT8yP1zQ7",{"encoding":"json","extra":1}]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 100,
                block_height: 100,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 3,
            }),
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_returns_invalid_params_for_transaction_with_extra_positional_param() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":165,"method":"getTransaction","params":["5NfVYAc8T9mPc4QkL9sVwR8CQmTiQ2KX8b6gY6U4Y9JjD2fYg4r6xQxjN5KcV8hM3f2x9pW7qE4nR2mT8yP1zQ7",{"encoding":"json"},1]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 100,
                block_height: 100,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 3,
            }),
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_returns_base64_transaction_message_when_requested() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":163,"method":"getTransaction","params":["5NfVYAc8T9mPc4QkL9sVwR8CQmTiQ2KX8b6gY6U4Y9JjD2fYg4r6xQxjN5KcV8hM3f2x9pW7qE4nR2mT8yP1zQ7",{"encoding":"base64"}]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 100,
                block_height: 100,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 3,
            }),
            None,
        );
        assert!(payload.contains(r#""message":""#));
        assert!(!payload.contains(r#""accountKeys":"#));
    }

    #[test]
    fn rpc_response_hides_transaction_when_not_full_api() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":62,"method":"getTransaction","params":["abc"]}"#,
            false,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32601"#));
    }

    #[test]
    fn rpc_response_returns_empty_blocks_range_for_future_start_slot() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":48,"method":"getBlocks","params":[99,120]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 20,
                block_height: 20,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 3,
            }),
            None,
        );
        assert!(payload.contains(r#""result":[]"#));
    }

    #[test]
    fn rpc_response_returns_invalid_params_for_blocks_with_misplaced_config_object() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":480,"method":"getBlocks","params":[3,{"commitment":"processed"}]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 20,
                block_height: 20,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 3,
            }),
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_returns_invalid_params_for_blocks_with_misplaced_min_context_object() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":482,"method":"getBlocks","params":[3,{"minContextSlot":900}]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 20,
                block_height: 20,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 3,
            }),
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_returns_invalid_params_for_blocks_with_unknown_config_key() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":481,"method":"getBlocks","params":[3,6,{"extra":true}]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 20,
                block_height: 20,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 3,
            }),
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_returns_blocks_with_limit_range_in_full_api_mode() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":50,"method":"getBlocksWithLimit","params":[5,3,{"commitment":"processed"}]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 20,
                block_height: 20,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 3,
            }),
            None,
        );
        assert!(payload.contains(r#""result":[5,6,7]"#));
    }

    #[test]
    fn rpc_response_returns_block_commitment_in_full_api_mode() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":501,"method":"getBlockCommitment","params":[10,{"commitment":"processed"}]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 50,
                block_height: 50,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 3,
            }),
            None,
        );
        assert!(payload.contains(r#""totalStake":1000000000"#));
        assert!(payload.contains(r#""commitment":["#));
    }

    #[test]
    fn rpc_response_returns_null_for_future_block_commitment_slot() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":502,"method":"getBlockCommitment","params":[999]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 50,
                block_height: 50,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 3,
            }),
            None,
        );
        assert!(payload.contains(r#""result":null"#));
    }

    #[test]
    fn rpc_response_returns_invalid_params_for_block_commitment_without_slot() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":503,"method":"getBlockCommitment","params":[]}"#,
            true,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_hides_block_commitment_when_not_full_api() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":504,"method":"getBlockCommitment","params":[1]}"#,
            false,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32601"#));
    }

    #[test]
    fn rpc_response_returns_invalid_params_for_blocks_with_limit_without_limit() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":51,"method":"getBlocksWithLimit","params":[5]}"#,
            true,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_returns_invalid_params_for_blocks_with_limit_above_max() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":510,"method":"getBlocksWithLimit","params":[5,501]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 800,
                block_height: 800,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 3,
            }),
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_returns_invalid_params_for_blocks_with_limit_unknown_config_key() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":513,"method":"getBlocksWithLimit","params":[5,3,{"extra":1}]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 800,
                block_height: 800,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 3,
            }),
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_rejects_blocks_with_limit_when_min_context_slot_is_too_high() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":511,"method":"getBlocksWithLimit","params":[5,3,{"minContextSlot":900}]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 100,
                block_height: 100,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 3,
            }),
            None,
        );
        assert!(payload.contains(r#""code":-32016"#));
    }

    #[test]
    fn rpc_response_rejects_block_commitment_when_min_context_slot_is_too_high() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":512,"method":"getBlockCommitment","params":[10,{"minContextSlot":900}]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 100,
                block_height: 100,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 3,
            }),
            None,
        );
        assert!(payload.contains(r#""code":-32016"#));
    }

    #[test]
    fn rpc_response_hides_blocks_with_limit_when_not_full_api() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":52,"method":"getBlocksWithLimit","params":[3,4]}"#,
            false,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32601"#));
    }

    #[test]
    fn rpc_response_hides_blocks_when_not_full_api() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":49,"method":"getBlocks","params":[3,6]}"#,
            false,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32601"#));
    }

    #[test]
    fn rpc_response_returns_invalid_params_for_account_info_without_pubkey() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":42,"method":"getAccountInfo","params":[]}"#,
            true,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_returns_block_payload_in_full_api_mode() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":51,"method":"getBlock","params":[10]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 50,
                block_height: 50,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 3,
            }),
            None,
        );
        assert!(payload.contains("blockHeight"));
        assert!(payload.contains("parentSlot"));
        assert!(payload.contains("transactions"));
    }

    #[test]
    fn rpc_response_returns_null_for_future_block_slot() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":52,"method":"getBlock","params":[99]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 20,
                block_height: 20,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 3,
            }),
            None,
        );
        assert!(payload.contains(r#""result":null"#));
    }

    #[test]
    fn rpc_response_returns_invalid_params_for_block_without_slot() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":53,"method":"getBlock","params":[]}"#,
            true,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_returns_invalid_params_for_block_with_invalid_encoding() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":153,"method":"getBlock","params":[10,{"encoding":"bincode"}]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 50,
                block_height: 50,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 3,
            }),
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_returns_invalid_params_for_block_with_invalid_transaction_details_type() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":155,"method":"getBlock","params":[10,{"transactionDetails":true}]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 50,
                block_height: 50,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 3,
            }),
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_returns_invalid_params_for_block_with_invalid_rewards_type() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":156,"method":"getBlock","params":[10,{"rewards":"yes"}]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 50,
                block_height: 50,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 3,
            }),
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_returns_invalid_params_for_block_with_unknown_config_key() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":158,"method":"getBlock","params":[10,{"encoding":"json","extra":"x"}]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 50,
                block_height: 50,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 3,
            }),
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_returns_invalid_params_for_block_with_extra_positional_param() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":159,"method":"getBlock","params":[10,{"encoding":"json"},1]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 50,
                block_height: 50,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 3,
            }),
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_returns_block_without_rewards_when_disabled() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":157,"method":"getBlock","params":[10,{"transactionDetails":"none","rewards":false}]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 50,
                block_height: 50,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 3,
            }),
            None,
        );
        assert!(payload.contains(r#""transactions":[]"#));
        assert!(payload.contains(r#""rewards":null"#));
    }

    #[test]
    fn rpc_response_rejects_block_when_min_context_slot_is_too_high() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":154,"method":"getBlock","params":[10,{"minContextSlot":999}]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 50,
                block_height: 50,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 3,
            }),
            None,
        );
        assert!(payload.contains(r#""code":-32016"#));
        assert!(payload.contains("Minimum context slot not reached"));
    }

    #[test]
    fn rpc_response_returns_block_time_payload_in_full_api_mode() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":54,"method":"getBlockTime","params":[10,{"commitment":"processed"}]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 20,
                block_height: 20,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 3,
            }),
            None,
        );
        assert!(payload.contains(r#""result":1700000020"#));
    }

    #[test]
    fn rpc_response_returns_null_for_future_block_time_slot() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":55,"method":"getBlockTime","params":[99]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 20,
                block_height: 20,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 3,
            }),
            None,
        );
        assert!(payload.contains(r#""result":null"#));
    }

    #[test]
    fn rpc_response_returns_invalid_params_for_block_time_unknown_config_key() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":57,"method":"getBlockTime","params":[10,{"extra":"x"}]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 20,
                block_height: 20,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 3,
            }),
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_hides_block_time_when_not_full_api() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":56,"method":"getBlockTime","params":[10]}"#,
            false,
            Some(RpcRuntimeSnapshot {
                slot: 20,
                block_height: 20,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 3,
            }),
            None,
        );
        assert!(payload.contains(r#""code":-32601"#));
    }

    #[test]
    fn rpc_response_returns_confirmed_block_alias_payload_in_full_api_mode() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":901,"method":"getConfirmedBlock","params":[10]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 50,
                block_height: 50,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 3,
            }),
            None,
        );
        assert!(payload.contains("blockHeight"));
        assert!(payload.contains("transactions"));
    }

    #[test]
    fn rpc_response_returns_confirmed_blocks_alias_payload_in_full_api_mode() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":902,"method":"getConfirmedBlocks","params":[3,6,{"commitment":"processed"}]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 20,
                block_height: 20,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 3,
            }),
            None,
        );
        assert!(payload.contains(r#""result":[3,4,5,6]"#));
    }

    #[test]
    fn rpc_response_returns_confirmed_transaction_alias_payload_in_full_api_mode() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":903,"method":"getConfirmedTransaction","params":["abc123"]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 20,
                block_height: 20,
                transaction_count: 500,
                uptime_millis: 10_000,
                latest_blockhash_seed: 3,
            }),
            None,
        );
        assert!(payload.contains(r#""meta":"#));
        assert!(payload.contains(r#""transaction":"#));
    }

    #[test]
    fn rpc_response_hides_confirmed_aliases_when_not_full_api() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":904,"method":"getConfirmedBlock","params":[10]}"#,
            false,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32601"#));

        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":905,"method":"getConfirmedBlocks","params":[3,6]}"#,
            false,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32601"#));

        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":906,"method":"getConfirmedTransaction","params":["abc123"]}"#,
            false,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32601"#));
    }

    #[test]
    fn rpc_response_returns_send_transaction_signature_in_full_api_mode() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":910,"method":"sendTransaction","params":["dGVzdF90eA==",{"encoding":"base64","skipPreflight":true,"maxRetries":4}]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 42,
                block_height: 42,
                transaction_count: 9_999,
                uptime_millis: 2_000,
                latest_blockhash_seed: 77,
            }),
            None,
        );
        assert!(payload.contains(r#""result":"#));
    }

    #[test]
    fn rpc_response_rejects_send_transaction_invalid_config() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":911,"method":"sendTransaction","params":["dGVzdF90eA==",{"encoding":"json"}]}"#,
            true,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_rejects_send_transaction_unknown_config_key() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":913,"method":"sendTransaction","params":["dGVzdF90eA==",{"encoding":"base64","foo":"bar"}]}"#,
            true,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_rejects_send_transaction_extra_positional_param() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":914,"method":"sendTransaction","params":["dGVzdF90eA==",{"encoding":"base64"},1]}"#,
            true,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_rejects_send_transaction_when_min_context_slot_not_reached() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":912,"method":"sendTransaction","params":["dGVzdF90eA==",{"minContextSlot":999}]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 20,
                block_height: 20,
                transaction_count: 1,
                uptime_millis: 1_000,
                latest_blockhash_seed: 7,
            }),
            None,
        );
        assert!(payload.contains(r#""code":-32016"#));
    }

    #[test]
    fn rpc_response_returns_simulate_transaction_payload_in_full_api_mode() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":920,"method":"simulateTransaction","params":["dGVzdF90eA==",{"encoding":"base64","sigVerify":true,"replaceRecentBlockhash":true,"accounts":{"encoding":"base64","addresses":["11111111111111111111111111111111"]}}]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 42,
                block_height: 42,
                transaction_count: 100,
                uptime_millis: 2_000,
                latest_blockhash_seed: 77,
            }),
            None,
        );
        assert!(payload.contains(r#""unitsConsumed":"#));
        assert!(payload.contains(r#""replacementBlockhash":"#));
    }

    #[test]
    fn rpc_response_rejects_simulate_transaction_invalid_accounts() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":921,"method":"simulateTransaction","params":["dGVzdF90eA==",{"accounts":{"addresses":["",1]}}]}"#,
            true,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_rejects_simulate_transaction_unknown_config_key() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":924,"method":"simulateTransaction","params":["dGVzdF90eA==",{"encoding":"base64","extra":true}]}"#,
            true,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_rejects_simulate_transaction_unknown_accounts_key() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":925,"method":"simulateTransaction","params":["dGVzdF90eA==",{"accounts":{"encoding":"base64","addresses":["11111111111111111111111111111111"],"extra":"x"}}]}"#,
            true,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_rejects_simulate_transaction_extra_positional_param() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":926,"method":"simulateTransaction","params":["dGVzdF90eA==",{"encoding":"base64"},1]}"#,
            true,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32602"#));
    }

    #[test]
    fn rpc_response_hides_submission_methods_when_not_full_api() {
        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":922,"method":"sendTransaction","params":["dGVzdF90eA=="]}"#,
            false,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32601"#));

        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":923,"method":"simulateTransaction","params":["dGVzdF90eA=="]}"#,
            false,
            None,
            None,
        );
        assert!(payload.contains(r#""code":-32601"#));
    }

    #[test]
    fn runtime_snapshot_is_loaded_from_latest_metrics_json_line() {
        let metrics_path = unique_temp_file("karstflow-rpc-metrics", "jsonl");
        fs::write(
            &metrics_path,
            r#"{"event":"mesh_metrics","uptime_millis":2000,"ingress_filter":{"accepted_transactions":77},"block_assembly":{"committed_fragments":9,"replay_window_rewinds":2}}"#,
        )
        .unwrap();
        let snapshot = read_metrics_snapshot_for_test(&metrics_path).unwrap();
        fs::remove_file(&metrics_path).unwrap();

        assert_eq!(snapshot.slot, 9);
        assert_eq!(snapshot.block_height, 9);
        assert_eq!(snapshot.transaction_count, 77);
        assert_eq!(snapshot.uptime_millis, 2_000);
        assert_eq!(snapshot.latest_blockhash_seed, 9 ^ 2_u64.rotate_left(13));
    }

    #[test]
    fn method_allowlist_applies_full_api_gate() {
        let allowed = |name: &str, full_api| resolve_method(name, full_api).is_ok();
        assert!(allowed("getHealth", false));
        assert!(allowed("getBalance", false));
        assert!(allowed("getGenesisHash", false));
        assert!(allowed("getIdentity", false));
        assert!(allowed("getEpochInfo", false));
        assert!(allowed("getFirstAvailableBlock", false));
        assert!(allowed("minimumLedgerSlot", false));
        assert!(allowed("getMaxShredInsertSlot", false));
        assert!(allowed("getHighestSnapshotSlot", false));
        assert!(allowed("getMaxRetransmitSlot", false));
        assert!(allowed("isBlockhashValid", false));
        assert!(allowed("getFeeForMessage", false));
        assert!(allowed("getRecentBlockhash", false));
        assert!(!allowed("getRecentPerformanceSamples", false));
        assert!(!allowed("getInflationGovernor", false));
        assert!(!allowed("getInflationRate", false));
        assert!(!allowed("getInflationReward", false));
        assert!(!allowed("getSignaturesForAddress", false));
        assert!(!allowed("getClusterNodes", false));
        assert!(!allowed("getVoteAccounts", false));
        assert!(!allowed("getSupply", false));
        assert!(!allowed("getTokenSupply", false));
        assert!(!allowed("getTokenAccountBalance", false));
        assert!(!allowed("getLargestAccounts", false));
        assert!(!allowed("getTokenLargestAccounts", false));
        assert!(!allowed("getProgramAccounts", false));
        assert!(!allowed("getTokenAccountsByOwner", false));
        assert!(!allowed("getTokenAccountsByDelegate", false));
        assert!(!allowed("getAccountInfo", false));
        assert!(!allowed("getMultipleAccounts", false));
        assert!(!allowed("getSignatureStatuses", false));
        assert!(!allowed("getLeaderSchedule", false));
        assert!(!allowed("getBlockProduction", false));
        assert!(!allowed("getRecentPrioritizationFees", false));
        assert!(!allowed("getBlocks", false));
        assert!(!allowed("getBlock", false));
        assert!(!allowed("getBlockTime", false));
        assert!(!allowed("getTransaction", false));
        assert!(!allowed("getConfirmedBlocks", false));
        assert!(!allowed("getConfirmedBlock", false));
        assert!(!allowed("getConfirmedTransaction", false));
        assert!(!allowed("sendTransaction", false));
        assert!(!allowed("simulateTransaction", false));
        assert!(allowed("getRecentPerformanceSamples", true));
        assert!(allowed("getInflationGovernor", true));
        assert!(allowed("getInflationRate", true));
        assert!(allowed("getInflationReward", true));
        assert!(allowed("getSignaturesForAddress", true));
        assert!(allowed("getClusterNodes", true));
        assert!(allowed("getVoteAccounts", true));
        assert!(allowed("getAccountInfo", true));
        assert!(allowed("getMultipleAccounts", true));
        assert!(allowed("getSignatureStatuses", true));
        assert!(allowed("getLeaderSchedule", true));
        assert!(allowed("getBlockProduction", true));
        assert!(allowed("getRecentPrioritizationFees", true));
        assert!(allowed("getBlocks", true));
        assert!(allowed("getBlock", true));
        assert!(allowed("getBlockTime", true));
        assert!(allowed("getTransaction", true));
        assert!(allowed("getConfirmedBlocks", true));
        assert!(allowed("getConfirmedBlock", true));
        assert!(allowed("getConfirmedTransaction", true));
        assert!(allowed("sendTransaction", true));
        assert!(allowed("simulateTransaction", true));
        assert!(allowed("getSupply", true));
        assert!(allowed("getTokenSupply", true));
        assert!(allowed("getTokenAccountBalance", true));
        assert!(allowed("getLargestAccounts", true));
        assert!(allowed("getTokenLargestAccounts", true));
        assert!(allowed("getProgramAccounts", true));
        assert!(allowed("getTokenAccountsByOwner", true));
        assert!(allowed("getTokenAccountsByDelegate", true));
    }

    // --- BankAccessProvider integration tests ---

    use std::collections::HashMap;
    use std::sync::Mutex;

    struct MockBankAccess {
        accounts: Mutex<HashMap<karstflow_types::Pubkey, karstflow_types::Account>>,
        slot: u64,
        blockhash: [u8; 32],
        lamports_per_sig: u64,
        transaction_count: u64,
        capitalization: u64,
    }

    impl MockBankAccess {
        fn new() -> Self {
            Self {
                accounts: Mutex::new(HashMap::new()),
                slot: 100,
                blockhash: [0xAB; 32],
                lamports_per_sig: 5000,
                transaction_count: 999,
                capitalization: 500_000_000_000,
            }
        }

        fn with_account(
            self,
            pubkey: karstflow_types::Pubkey,
            account: karstflow_types::Account,
        ) -> Self {
            self.accounts.lock().unwrap().insert(pubkey, account);
            self
        }
    }

    impl BankAccessProvider for MockBankAccess {
        fn get_account(
            &self,
            pubkey: &karstflow_types::Pubkey,
            _commitment: crate::state::RpcCommitment,
        ) -> Option<karstflow_types::Account> {
            self.accounts.lock().unwrap().get(pubkey).cloned()
        }

        fn get_balance(
            &self,
            pubkey: &karstflow_types::Pubkey,
            _commitment: crate::state::RpcCommitment,
        ) -> u64 {
            self.accounts
                .lock()
                .unwrap()
                .get(pubkey)
                .map(|a| a.meta.lamports)
                .unwrap_or(0)
        }

        fn get_slot(&self, _commitment: crate::state::RpcCommitment) -> u64 {
            self.slot
        }

        fn get_block_height(&self, _commitment: crate::state::RpcCommitment) -> u64 {
            self.slot
        }

        fn get_latest_blockhash(&self, _commitment: crate::state::RpcCommitment) -> [u8; 32] {
            self.blockhash
        }

        fn is_blockhash_valid(
            &self,
            blockhash: &[u8; 32],
            _commitment: crate::state::RpcCommitment,
        ) -> bool {
            *blockhash == self.blockhash
        }

        fn get_lamports_per_signature(&self, _commitment: crate::state::RpcCommitment) -> u64 {
            self.lamports_per_sig
        }

        fn get_last_valid_block_height(&self, _commitment: crate::state::RpcCommitment) -> u64 {
            self.slot + 150
        }

        fn get_transaction_count(&self, _commitment: crate::state::RpcCommitment) -> u64 {
            self.transaction_count
        }

        fn get_capitalization(&self, _commitment: crate::state::RpcCommitment) -> u64 {
            self.capitalization
        }

        fn get_accounts_by_owner(
            &self,
            owner: &karstflow_types::Pubkey,
            _commitment: crate::state::RpcCommitment,
        ) -> Vec<(karstflow_types::Pubkey, karstflow_types::Account)> {
            self.accounts
                .lock()
                .unwrap()
                .iter()
                .filter(|(_, account)| account.meta.owner == *owner)
                .map(|(pubkey, account)| (*pubkey, account.clone()))
                .collect()
        }

        fn get_slot_leader(
            &self,
            _slot: u64,
            _commitment: crate::state::RpcCommitment,
        ) -> Option<karstflow_types::Pubkey> {
            None
        }

        fn get_slot_leaders(
            &self,
            start_slot: u64,
            count: u64,
            _commitment: crate::state::RpcCommitment,
        ) -> Vec<(u64, Option<karstflow_types::Pubkey>)> {
            (0..count)
                .map(|i| (start_slot.saturating_add(i), None))
                .collect()
        }

        fn get_leader_schedule(
            &self,
            _slot: u64,
            _commitment: crate::state::RpcCommitment,
        ) -> Option<Vec<(karstflow_types::Pubkey, Vec<u64>)>> {
            None
        }

        fn simulate_transaction(
            &self,
            _raw_tx: &[u8],
            _sig_verify: bool,
            _replace_recent_blockhash: bool,
            _commitment: crate::state::RpcCommitment,
        ) -> crate::state::TransactionSimulationResponse {
            crate::state::TransactionSimulationResponse {
                error: None,
                logs: vec![
                    "Program 11111111111111111111111111111111 invoke [1]".to_string(),
                    "Program 11111111111111111111111111111111 success".to_string(),
                ],
                units_consumed: 150,
                accounts: vec![],
                return_data: None,
            }
        }
    }

    fn test_pubkey_bytes() -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[0] = 1;
        bytes[31] = 1;
        bytes
    }

    fn test_pubkey() -> karstflow_types::Pubkey {
        karstflow_types::Pubkey::new(test_pubkey_bytes())
    }

    fn test_pubkey_base58() -> String {
        bs58::encode(test_pubkey_bytes()).into_string()
    }

    #[test]
    fn bank_access_get_balance_returns_real_lamports() {
        let pubkey = test_pubkey();
        let account = karstflow_types::Account::new(42_000, vec![], pubkey);
        let mock: Arc<dyn BankAccessProvider> =
            Arc::new(MockBankAccess::new().with_account(pubkey, account));

        let payload = render_json_rpc_response(
            &format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"getBalance","params":["{}"]}}"#,
                test_pubkey_base58()
            ),
            false,
            Some(RpcRuntimeSnapshot {
                slot: 10,
                block_height: 10,
                transaction_count: 0,
                uptime_millis: 1_000,
                latest_blockhash_seed: 0,
            }),
            Some(&mock),
        );
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(parsed["result"]["value"], 42_000);
        assert_eq!(parsed["result"]["context"]["slot"], 100);
    }

    #[test]
    fn bank_access_get_balance_returns_zero_for_missing_account() {
        let mock: Arc<dyn BankAccessProvider> = Arc::new(MockBankAccess::new());

        let payload = render_json_rpc_response(
            &format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"getBalance","params":["{}"]}}"#,
                test_pubkey_base58()
            ),
            false,
            Some(RpcRuntimeSnapshot {
                slot: 10,
                block_height: 10,
                transaction_count: 0,
                uptime_millis: 1_000,
                latest_blockhash_seed: 0,
            }),
            Some(&mock),
        );
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(parsed["result"]["value"], 0);
    }

    #[test]
    fn bank_access_get_account_info_returns_real_account() {
        let pubkey = test_pubkey();
        let owner = karstflow_types::Pubkey::new([2u8; 32]);
        let account = karstflow_types::Account::new(100_000, vec![1, 2, 3], owner);
        let mock: Arc<dyn BankAccessProvider> =
            Arc::new(MockBankAccess::new().with_account(pubkey, account));

        let payload = render_json_rpc_response(
            &format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"getAccountInfo","params":["{}"]}}"#,
                test_pubkey_base58()
            ),
            true,
            Some(RpcRuntimeSnapshot {
                slot: 10,
                block_height: 10,
                transaction_count: 0,
                uptime_millis: 1_000,
                latest_blockhash_seed: 0,
            }),
            Some(&mock),
        );
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        let value = &parsed["result"]["value"];
        assert_eq!(value["lamports"], 100_000);
        assert_eq!(value["space"], 3);
        assert!(!value["executable"].as_bool().unwrap());
    }

    #[test]
    fn bank_access_get_account_info_returns_null_for_missing_account() {
        let mock: Arc<dyn BankAccessProvider> = Arc::new(MockBankAccess::new());

        let payload = render_json_rpc_response(
            &format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"getAccountInfo","params":["{}"]}}"#,
                test_pubkey_base58()
            ),
            true,
            Some(RpcRuntimeSnapshot {
                slot: 10,
                block_height: 10,
                transaction_count: 0,
                uptime_millis: 1_000,
                latest_blockhash_seed: 0,
            }),
            Some(&mock),
        );
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert!(parsed["result"]["value"].is_null());
    }

    #[test]
    fn bank_access_get_multiple_accounts_returns_mixed_results() {
        let pubkey1 = test_pubkey();
        let account1 = karstflow_types::Account::new(50_000, vec![], pubkey1);
        let mock: Arc<dyn BankAccessProvider> =
            Arc::new(MockBankAccess::new().with_account(pubkey1, account1));

        let pubkey2 = karstflow_types::Pubkey::new([3u8; 32]);
        let pubkey2_bs58 = bs58::encode(pubkey2.as_bytes()).into_string();

        let payload = render_json_rpc_response(
            &format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"getMultipleAccounts","params":[["{}", "{}"]]}}"#,
                test_pubkey_base58(),
                pubkey2_bs58
            ),
            true,
            Some(RpcRuntimeSnapshot {
                slot: 10,
                block_height: 10,
                transaction_count: 0,
                uptime_millis: 1_000,
                latest_blockhash_seed: 0,
            }),
            Some(&mock),
        );
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        let values = parsed["result"]["value"].as_array().unwrap();
        assert_eq!(values.len(), 2);
        assert_eq!(values[0]["lamports"], 50_000);
        assert!(values[1].is_null());
    }

    #[test]
    fn bank_access_get_latest_blockhash_returns_real_hash() {
        let mock: Arc<dyn BankAccessProvider> = Arc::new(MockBankAccess::new());
        let expected_hash = bs58::encode([0xAB; 32]).into_string();

        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":1,"method":"getLatestBlockhash","params":[]}"#,
            false,
            Some(RpcRuntimeSnapshot {
                slot: 10,
                block_height: 10,
                transaction_count: 0,
                uptime_millis: 1_000,
                latest_blockhash_seed: 0,
            }),
            Some(&mock),
        );
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(parsed["result"]["value"]["blockhash"], expected_hash);
        assert_eq!(parsed["result"]["value"]["lastValidBlockHeight"], 250);
        assert_eq!(parsed["result"]["context"]["slot"], 100);
    }

    #[test]
    fn bank_access_is_blockhash_valid_checks_real_hash() {
        let mock: Arc<dyn BankAccessProvider> = Arc::new(MockBankAccess::new());
        let valid_hash = bs58::encode([0xAB; 32]).into_string();
        let invalid_hash = bs58::encode([0x00; 32]).into_string();

        let payload = render_json_rpc_response(
            &format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"isBlockhashValid","params":["{valid_hash}"]}}"#
            ),
            false,
            Some(RpcRuntimeSnapshot {
                slot: 10,
                block_height: 10,
                transaction_count: 0,
                uptime_millis: 1_000,
                latest_blockhash_seed: 0,
            }),
            Some(&mock),
        );
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(parsed["result"]["value"], true);

        let payload = render_json_rpc_response(
            &format!(
                r#"{{"jsonrpc":"2.0","id":2,"method":"isBlockhashValid","params":["{invalid_hash}"]}}"#
            ),
            false,
            Some(RpcRuntimeSnapshot {
                slot: 10,
                block_height: 10,
                transaction_count: 0,
                uptime_millis: 1_000,
                latest_blockhash_seed: 0,
            }),
            Some(&mock),
        );
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(parsed["result"]["value"], false);
    }

    #[test]
    fn bank_access_get_slot_returns_real_slot() {
        let mock: Arc<dyn BankAccessProvider> = Arc::new(MockBankAccess::new());

        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":1,"method":"getSlot","params":[]}"#,
            false,
            Some(RpcRuntimeSnapshot {
                slot: 10,
                block_height: 10,
                transaction_count: 0,
                uptime_millis: 1_000,
                latest_blockhash_seed: 0,
            }),
            Some(&mock),
        );
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(parsed["result"], 100);
    }

    #[test]
    fn bank_access_get_transaction_count_returns_real_count() {
        let mock: Arc<dyn BankAccessProvider> = Arc::new(MockBankAccess::new());

        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":1,"method":"getTransactionCount","params":[]}"#,
            false,
            Some(RpcRuntimeSnapshot {
                slot: 10,
                block_height: 10,
                transaction_count: 0,
                uptime_millis: 1_000,
                latest_blockhash_seed: 0,
            }),
            Some(&mock),
        );
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(parsed["result"], 999);
    }

    #[test]
    fn bank_access_get_supply_returns_real_capitalization() {
        let mock: Arc<dyn BankAccessProvider> = Arc::new(MockBankAccess::new());

        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":1,"method":"getSupply","params":[]}"#,
            true,
            Some(RpcRuntimeSnapshot {
                slot: 10,
                block_height: 10,
                transaction_count: 0,
                uptime_millis: 1_000,
                latest_blockhash_seed: 0,
            }),
            Some(&mock),
        );
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(parsed["result"]["value"]["total"], 500_000_000_000_u64);
    }

    #[test]
    fn bank_access_get_recent_blockhash_returns_real_hash_and_fee() {
        let mock: Arc<dyn BankAccessProvider> = Arc::new(MockBankAccess::new());
        let expected_hash = bs58::encode([0xAB; 32]).into_string();

        let payload = render_json_rpc_response(
            r#"{"jsonrpc":"2.0","id":1,"method":"getRecentBlockhash","params":[]}"#,
            false,
            Some(RpcRuntimeSnapshot {
                slot: 10,
                block_height: 10,
                transaction_count: 0,
                uptime_millis: 1_000,
                latest_blockhash_seed: 0,
            }),
            Some(&mock),
        );
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(parsed["result"]["value"]["blockhash"], expected_hash);
        assert_eq!(
            parsed["result"]["value"]["feeCalculator"]["lamportsPerSignature"],
            5000
        );
    }

    #[test]
    fn bank_access_fallback_to_synthetic_when_none() {
        let payload = render_json_rpc_response(
            &format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"getBalance","params":["{}"]}}"#,
                test_pubkey_base58()
            ),
            false,
            Some(RpcRuntimeSnapshot {
                slot: 10,
                block_height: 10,
                transaction_count: 100,
                uptime_millis: 1_000,
                latest_blockhash_seed: 0,
            }),
            None,
        );
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        let value = parsed["result"]["value"].as_u64().unwrap();
        assert!(
            value > 0,
            "synthetic fallback should produce non-zero balance"
        );
    }

    #[test]
    fn bank_access_get_program_accounts_returns_real_accounts() {
        let program_id = test_pubkey();
        let acct_bytes = {
            let mut b = [0u8; 32];
            b[0] = 2;
            b[31] = 2;
            b
        };
        let acct_pubkey = karstflow_types::Pubkey::new(acct_bytes);
        let account = karstflow_types::Account::new(77_000, vec![1, 2, 3], program_id);
        let mock: Arc<dyn BankAccessProvider> =
            Arc::new(MockBankAccess::new().with_account(acct_pubkey, account));

        let payload = render_json_rpc_response(
            &format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"getProgramAccounts","params":["{}",{{"withContext":true}}]}}"#,
                test_pubkey_base58()
            ),
            true,
            Some(RpcRuntimeSnapshot {
                slot: 10,
                block_height: 10,
                transaction_count: 0,
                uptime_millis: 1_000,
                latest_blockhash_seed: 0,
            }),
            Some(&mock),
        );
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(parsed["result"]["context"]["slot"], 100);
        let accounts = parsed["result"]["value"].as_array().unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0]["account"]["lamports"], 77_000);
    }

    #[test]
    fn bank_access_get_token_supply_parses_mint() {
        // Build an SPL Mint account (82 bytes):
        // bytes 0..4: mint_authority option tag (0 = None)
        // bytes 4..36: mint_authority pubkey (zeroed for None)
        // bytes 36..44: supply (u64 LE)
        // byte 44: decimals
        // byte 45: is_initialized
        // bytes 46..82: freeze_authority option
        let mut mint_data = vec![0u8; 82];
        let supply: u64 = 1_000_000_000;
        mint_data[36..44].copy_from_slice(&supply.to_le_bytes());
        mint_data[44] = 6; // decimals
        mint_data[45] = 1; // is_initialized

        let mint_pubkey = test_pubkey();
        let mint_account = karstflow_types::Account::new(
            1_000_000,
            mint_data,
            karstflow_types::Pubkey::new([0u8; 32]),
        );
        let mock: Arc<dyn BankAccessProvider> =
            Arc::new(MockBankAccess::new().with_account(mint_pubkey, mint_account));

        let payload = render_json_rpc_response(
            &format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"getTokenSupply","params":["{}"]}}"#,
                test_pubkey_base58()
            ),
            true,
            Some(RpcRuntimeSnapshot {
                slot: 10,
                block_height: 10,
                transaction_count: 0,
                uptime_millis: 1_000,
                latest_blockhash_seed: 0,
            }),
            Some(&mock),
        );
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(parsed["result"]["value"]["amount"], "1000000000");
        assert_eq!(parsed["result"]["value"]["decimals"], 6);
        assert_eq!(parsed["result"]["value"]["uiAmountString"], "1000.000000");
    }

    #[test]
    fn bank_access_get_token_account_balance_parses_account() {
        // Build an SPL Token account (165 bytes):
        // bytes 0..32: mint pubkey
        // bytes 32..64: owner pubkey
        // bytes 64..72: amount (u64 LE)
        // rest: delegate, state, etc.
        let mut token_data = vec![0u8; 165];
        let amount: u64 = 500_000;
        token_data[64..72].copy_from_slice(&amount.to_le_bytes());

        let token_pubkey = test_pubkey();
        let token_account = karstflow_types::Account::new(
            2_039_280,
            token_data,
            karstflow_types::Pubkey::new([0u8; 32]),
        );
        let mock: Arc<dyn BankAccessProvider> =
            Arc::new(MockBankAccess::new().with_account(token_pubkey, token_account));

        let payload = render_json_rpc_response(
            &format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"getTokenAccountBalance","params":["{}"]}}"#,
                test_pubkey_base58()
            ),
            true,
            Some(RpcRuntimeSnapshot {
                slot: 10,
                block_height: 10,
                transaction_count: 0,
                uptime_millis: 1_000,
                latest_blockhash_seed: 0,
            }),
            Some(&mock),
        );
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        // Decimals will be 0 since we don't resolve the mint in the parser
        assert_eq!(parsed["result"]["value"]["amount"], "500000");
        assert_eq!(parsed["result"]["value"]["decimals"], 0);
    }

    #[test]
    fn bank_access_get_token_accounts_by_owner_filters_correctly() {
        // The owner whose token accounts we're looking for
        let owner_bytes = {
            let mut b = [0u8; 32];
            b[0] = 5;
            b
        };
        let _owner_pubkey = karstflow_types::Pubkey::new(owner_bytes);

        // SPL Token program is the account owner in the accounts DB
        let token_program_bytes = bs58::decode("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
            .into_vec()
            .unwrap();
        let mut token_program_arr = [0u8; 32];
        token_program_arr.copy_from_slice(&token_program_bytes);
        let token_program = karstflow_types::Pubkey::new(token_program_arr);

        // Token account 1: owned by our owner (bytes 32..64 match)
        let mut token_data_1 = vec![0u8; 165];
        token_data_1[32..64].copy_from_slice(&owner_bytes);
        let amount1: u64 = 100;
        token_data_1[64..72].copy_from_slice(&amount1.to_le_bytes());
        let token_acct_1_bytes = {
            let mut b = [0u8; 32];
            b[0] = 10;
            b
        };
        let token_acct_1 = karstflow_types::Pubkey::new(token_acct_1_bytes);
        let account_1 = karstflow_types::Account::new(2_039_280, token_data_1, token_program);

        // Token account 2: owned by someone else
        let mut token_data_2 = vec![0u8; 165];
        let other_owner = [0xFFu8; 32];
        token_data_2[32..64].copy_from_slice(&other_owner);
        let token_acct_2_bytes = {
            let mut b = [0u8; 32];
            b[0] = 11;
            b
        };
        let token_acct_2 = karstflow_types::Pubkey::new(token_acct_2_bytes);
        let account_2 = karstflow_types::Account::new(2_039_280, token_data_2, token_program);

        let mock: Arc<dyn BankAccessProvider> = Arc::new(
            MockBankAccess::new()
                .with_account(token_acct_1, account_1)
                .with_account(token_acct_2, account_2),
        );

        let owner_base58 = bs58::encode(owner_bytes).into_string();
        let payload = render_json_rpc_response(
            &format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"getTokenAccountsByOwner","params":["{}",{{"programId":"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"}}]}}"#,
                owner_base58
            ),
            true,
            Some(RpcRuntimeSnapshot {
                slot: 10,
                block_height: 10,
                transaction_count: 0,
                uptime_millis: 1_000,
                latest_blockhash_seed: 0,
            }),
            Some(&mock),
        );
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        let accounts = parsed["result"]["value"].as_array().unwrap();
        // Only account_1 should match (owned by our owner)
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0]["account"]["lamports"], 2_039_280);
    }
}
