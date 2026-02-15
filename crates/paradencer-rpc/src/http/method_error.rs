#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcMethodError {
    InvalidRequest,
    InvalidParams,
    MethodNotFound,
    MinimumContextSlotNotReached,
    Internal,
}

impl RpcMethodError {
    pub fn code(self) -> i32 {
        match self {
            Self::InvalidRequest => -32600,
            Self::InvalidParams => -32602,
            Self::MethodNotFound => -32601,
            Self::MinimumContextSlotNotReached => -32016,
            Self::Internal => -32603,
        }
    }

    pub fn message(self, method: &str) -> String {
        match self {
            Self::InvalidRequest => "Invalid request".to_string(),
            Self::InvalidParams => "Invalid params".to_string(),
            Self::MethodNotFound => format!("Method not found: {method}"),
            Self::MinimumContextSlotNotReached => "Minimum context slot not reached".to_string(),
            Self::Internal => "Internal error".to_string(),
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
