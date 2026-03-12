#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcMethodError {
    InvalidRequest,
    InvalidParams,
    MethodNotFound,
    MinimumContextSlotNotReached,
    TransactionSubmissionFailed {
        message: String,
        err: Option<serde_json::Value>,
        logs: Option<Vec<String>>,
    },
    NodeUnhealthy {
        num_slots_behind: Option<u64>,
    },
    Internal,
}

impl RpcMethodError {
    pub fn code(&self) -> i32 {
        match self {
            Self::InvalidRequest => -32600,
            Self::InvalidParams => -32602,
            Self::MethodNotFound => -32601,
            Self::MinimumContextSlotNotReached => -32016,
            Self::TransactionSubmissionFailed { .. } => -32002,
            Self::NodeUnhealthy { .. } => -32005,
            Self::Internal => -32603,
        }
    }

    pub fn message(&self, method: &str) -> String {
        match self {
            Self::InvalidRequest => "Invalid request".to_string(),
            Self::InvalidParams => "Invalid params".to_string(),
            Self::MethodNotFound => format!("Method not found: {method}"),
            Self::MinimumContextSlotNotReached => "Minimum context slot not reached".to_string(),
            Self::TransactionSubmissionFailed { message, .. } => message.clone(),
            Self::NodeUnhealthy { .. } => "Node is behind by too many slots".to_string(),
            Self::Internal => "Internal error".to_string(),
        }
    }

    pub fn data(&self) -> Option<serde_json::Value> {
        match self {
            Self::TransactionSubmissionFailed { err, logs, .. } => Some(serde_json::json!({
                "accounts": null,
                "err": err.clone().unwrap_or(serde_json::json!("BlockhashNotFound")),
                "innerInstructions": null,
                "logs": logs.as_deref().unwrap_or(&[]),
                "returnData": null,
                "unitsConsumed": 0
            })),
            Self::NodeUnhealthy { num_slots_behind } => Some(serde_json::json!({
                "numSlotsBehind": num_slots_behind
            })),
            _ => None,
        }
    }

    /// Create a transaction submission failure with a Solana-standard error format.
    ///
    /// Parses the Debug-formatted `TransactionExecutionError` string and converts
    /// it to a JSON value that solders/solana-py can deserialize as a `TransactionError`.
    pub fn transaction_failed(err: &str) -> Self {
        let err_json = Self::format_send_error(err);
        Self::TransactionSubmissionFailed {
            message: format!("Transaction simulation failed: {err}"),
            err: Some(err_json),
            logs: None,
        }
    }

    /// Convert an internal error string to Solana-compatible JSON TransactionError format.
    fn format_send_error(error: &str) -> serde_json::Value {
        // Top-level transaction errors
        match error {
            "BlockhashNotFound" => return serde_json::json!("BlockhashNotFound"),
            "AccountNotFound" => return serde_json::json!("AccountNotFound"),
            "AlreadyProcessed" => return serde_json::json!("AlreadyProcessed"),
            "DuplicateTransaction" => return serde_json::json!("DuplicateTransaction"),
            _ => {}
        }
        if error.starts_with("InsufficientFundsForFee") {
            return serde_json::json!("InsufficientFundsForFee");
        }

        // Parse Debug-formatted InstructionFailed { index: N, message: "..." }
        if let Some(rest) = error.strip_prefix("InstructionFailed { index: ") {
            let ix_index = rest
                .split(',')
                .next()
                .and_then(|n| n.trim().parse::<u64>().ok())
                .unwrap_or(0);
            let message = rest
                .split("message: \"")
                .nth(1)
                .and_then(|m| m.strip_suffix("\" }"))
                .unwrap_or(error);
            let variant = Self::map_instruction_error_variant(message);
            return serde_json::json!({"InstructionError": [ix_index, variant]});
        }

        // Parse Debug-formatted ComputeBudgetExceeded { ... }
        if error.starts_with("ComputeBudgetExceeded") {
            return serde_json::json!({"InstructionError": [0, "ComputationalBudgetExceeded"]});
        }

        // Parse Display-formatted "instruction N failed: ..."
        if let Some(rest) = error.strip_prefix("instruction ") {
            let ix_index = rest
                .split(' ')
                .next()
                .and_then(|n| n.parse::<u64>().ok())
                .unwrap_or(0);
            let message = rest.split("failed: ").nth(1).unwrap_or(error);
            let variant = Self::map_instruction_error_variant(message);
            return serde_json::json!({"InstructionError": [ix_index, variant]});
        }

        // Generic instruction error fallback
        let variant = Self::map_instruction_error_variant(error);
        serde_json::json!({"InstructionError": [0, variant]})
    }

    /// Map an error message to a Solana-standard InstructionError variant.
    fn map_instruction_error_variant(error: &str) -> serde_json::Value {
        let lower = error.to_lowercase();
        if (lower.contains("insufficient") && lower.contains("lamports"))
            || lower.contains("negative lamports")
            || lower.contains("not enough lamports")
        {
            serde_json::json!("InsufficientFunds")
        } else if lower.contains("missing required signature") || lower.contains("not a signer") {
            serde_json::json!("MissingRequiredSignature")
        } else if lower.contains("invalid account data") {
            serde_json::json!("InvalidAccountData")
        } else if lower.contains("account already in use") || lower.contains("already exists") {
            serde_json::json!("AccountAlreadyInitialized")
        } else if lower.contains("account data too small") || lower.contains("data too short") {
            serde_json::json!("AccountDataTooSmall")
        } else if lower.contains("compute budget exceeded") {
            serde_json::json!("ComputationalBudgetExceeded")
        } else if lower.contains("not rent exempt") {
            serde_json::json!("InsufficientFunds")
        } else if lower.contains("invalid instruction data") {
            serde_json::json!("InvalidInstructionData")
        } else if lower.contains("incorrect program id") {
            serde_json::json!("IncorrectProgramId")
        } else if lower.contains("custom program error") {
            if let Some(code) = error.split("Custom program error: ").nth(1) {
                if let Ok(n) = code.trim().parse::<u32>() {
                    return serde_json::json!({"Custom": n});
                }
            }
            serde_json::json!({"Custom": 0})
        } else {
            serde_json::json!({"Custom": 0})
        }
    }

    pub fn node_unhealthy(slots_behind: Option<u64>) -> Self {
        Self::NodeUnhealthy {
            num_slots_behind: slots_behind,
        }
    }
}

impl From<i32> for RpcMethodError {
    fn from(code: i32) -> Self {
        match code {
            -32600 => Self::InvalidRequest,
            -32602 => Self::InvalidParams,
            -32601 => Self::MethodNotFound,
            -32016 => Self::MinimumContextSlotNotReached,
            _ => Self::Internal,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_are_negative() {
        let errors: Vec<RpcMethodError> = vec![
            RpcMethodError::InvalidRequest,
            RpcMethodError::InvalidParams,
            RpcMethodError::MethodNotFound,
            RpcMethodError::MinimumContextSlotNotReached,
            RpcMethodError::transaction_failed("test"),
            RpcMethodError::node_unhealthy(Some(100)),
            RpcMethodError::Internal,
        ];
        for e in &errors {
            assert!(e.code() < 0);
        }
    }

    #[test]
    fn standard_jsonrpc_codes() {
        assert_eq!(RpcMethodError::InvalidRequest.code(), -32600);
        assert_eq!(RpcMethodError::InvalidParams.code(), -32602);
        assert_eq!(RpcMethodError::MethodNotFound.code(), -32601);
    }

    #[test]
    fn custom_error_codes() {
        assert_eq!(RpcMethodError::MinimumContextSlotNotReached.code(), -32016);
        assert_eq!(RpcMethodError::transaction_failed("x").code(), -32002);
        assert_eq!(RpcMethodError::node_unhealthy(None).code(), -32005);
        assert_eq!(RpcMethodError::Internal.code(), -32603);
    }

    #[test]
    fn message_includes_method_name() {
        let msg = RpcMethodError::MethodNotFound.message("getBalance");
        assert!(msg.contains("getBalance"));
    }

    #[test]
    fn message_static_errors() {
        assert_eq!(RpcMethodError::InvalidParams.message("x"), "Invalid params");
        assert_eq!(
            RpcMethodError::InvalidRequest.message("x"),
            "Invalid request"
        );
        assert_eq!(RpcMethodError::Internal.message("x"), "Internal error");
    }

    #[test]
    fn from_known_code() {
        assert_eq!(RpcMethodError::from(-32600), RpcMethodError::InvalidRequest);
        assert_eq!(RpcMethodError::from(-32602), RpcMethodError::InvalidParams);
        assert_eq!(RpcMethodError::from(-32601), RpcMethodError::MethodNotFound);
        assert_eq!(
            RpcMethodError::from(-32016),
            RpcMethodError::MinimumContextSlotNotReached
        );
    }

    #[test]
    fn from_unknown_code_returns_internal() {
        assert_eq!(RpcMethodError::from(-99999), RpcMethodError::Internal);
        assert_eq!(RpcMethodError::from(0), RpcMethodError::Internal);
    }

    #[test]
    fn roundtrip_code_to_error() {
        let errors = [
            RpcMethodError::InvalidRequest,
            RpcMethodError::InvalidParams,
            RpcMethodError::MethodNotFound,
            RpcMethodError::MinimumContextSlotNotReached,
        ];
        for e in &errors {
            assert_eq!(RpcMethodError::from(e.code()), e.clone());
        }
    }

    #[test]
    fn transaction_failed_has_data() {
        let err = RpcMethodError::transaction_failed("InsufficientFundsForFee");
        assert!(err.data().is_some());
        let data = err.data().unwrap();
        assert_eq!(data["err"], serde_json::json!("InsufficientFundsForFee"));
    }

    #[test]
    fn transaction_failed_instruction_error_format() {
        let err = RpcMethodError::transaction_failed(
            r#"InstructionFailed { index: 1, message: "Program failed: Nonce account data too short" }"#,
        );
        let data = err.data().unwrap();
        let err_val = &data["err"];
        assert!(err_val["InstructionError"].is_array());
        assert_eq!(err_val["InstructionError"][0], 1);
    }

    #[test]
    fn node_unhealthy_has_data() {
        let err = RpcMethodError::node_unhealthy(Some(50));
        assert!(err.data().is_some());
        let data = err.data().unwrap();
        assert_eq!(data["numSlotsBehind"], 50);
    }

    #[test]
    fn simple_errors_have_no_data() {
        assert!(RpcMethodError::InvalidParams.data().is_none());
        assert!(RpcMethodError::Internal.data().is_none());
        assert!(RpcMethodError::MethodNotFound.data().is_none());
    }
}
