#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcMethodError {
    InvalidRequest,
    InvalidParams,
    MethodNotFound,
    MinimumContextSlotNotReached,
    TransactionSubmissionFailed {
        message: String,
        err: Option<String>,
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
                "err": err.as_deref().unwrap_or("BlockhashNotFound"),
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

    /// Create a transaction submission failure with a valid Solana TransactionError variant.
    ///
    /// Valid `err` values include: `AccountInUse`, `AccountNotFound`,
    /// `InsufficientFundsForFee`, `BlockhashNotFound`, `AlreadyProcessed`,
    /// `SignatureFailure`, `SanitizeFailure`, and others from solana TransactionError.
    pub fn transaction_failed(err: &str) -> Self {
        Self::TransactionSubmissionFailed {
            message: format!("Transaction simulation failed: {err}"),
            err: Some(err.to_string()),
            logs: None,
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
        assert_eq!(data["err"], "InsufficientFundsForFee");
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
