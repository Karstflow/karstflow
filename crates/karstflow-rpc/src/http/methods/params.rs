use serde_json::{Map, Value};

use super::super::method_error::RpcMethodError;

pub(super) fn params_array(request: &Value) -> Result<&[Value], RpcMethodError> {
    request
        .get("params")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or(RpcMethodError::InvalidParams)
}

pub(super) fn params_array_or_empty(request: &Value) -> &[Value] {
    request
        .get("params")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

pub(super) fn first_param_u64(request: &Value) -> Result<u64, RpcMethodError> {
    params_array(request)?
        .first()
        .and_then(Value::as_u64)
        .ok_or(RpcMethodError::InvalidParams)
}

pub(super) fn first_param_non_empty_string(request: &Value) -> Result<String, RpcMethodError> {
    params_array(request)?
        .first()
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or(RpcMethodError::InvalidParams)
}

pub(super) fn first_param_non_empty_string_array(
    request: &Value,
) -> Result<Vec<String>, RpcMethodError> {
    let values = params_array(request)?
        .first()
        .and_then(Value::as_array)
        .ok_or(RpcMethodError::InvalidParams)?;
    if values.is_empty() {
        return Err(RpcMethodError::InvalidParams);
    }

    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .ok_or(RpcMethodError::InvalidParams)
        })
        .collect::<Result<Vec<_>, RpcMethodError>>()
}

pub(super) fn first_config_object(params: &[Value]) -> Option<&Map<String, Value>> {
    params.iter().find_map(Value::as_object)
}

pub(super) fn min_context_slot_from_params(request: &Value) -> Result<Option<u64>, RpcMethodError> {
    let params = params_array_or_empty(request);
    let config_object = first_config_object(params);
    let min_context_slot = config_object
        .and_then(|cfg| cfg.get("minContextSlot"))
        .map(|value| value.as_u64().ok_or(RpcMethodError::InvalidParams))
        .transpose()?;
    Ok(min_context_slot)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn params_array_valid() {
        let req = json!({"params": [1, 2, 3]});
        let arr = params_array(&req).unwrap();
        assert_eq!(arr.len(), 3);
    }

    #[test]
    fn params_array_missing_returns_error() {
        let req = json!({});
        assert!(params_array(&req).is_err());
    }

    #[test]
    fn params_array_not_array_returns_error() {
        let req = json!({"params": "not_an_array"});
        assert!(params_array(&req).is_err());
    }

    #[test]
    fn params_array_or_empty_missing() {
        let req = json!({});
        assert!(params_array_or_empty(&req).is_empty());
    }

    #[test]
    fn params_array_or_empty_present() {
        let req = json!({"params": [42]});
        assert_eq!(params_array_or_empty(&req).len(), 1);
    }

    #[test]
    fn first_param_u64_valid() {
        let req = json!({"params": [99]});
        assert_eq!(first_param_u64(&req).unwrap(), 99);
    }

    #[test]
    fn first_param_u64_not_number() {
        let req = json!({"params": ["hello"]});
        assert!(first_param_u64(&req).is_err());
    }

    #[test]
    fn first_param_u64_empty_params() {
        let req = json!({"params": []});
        assert!(first_param_u64(&req).is_err());
    }

    #[test]
    fn first_param_non_empty_string_valid() {
        let req = json!({"params": ["hello"]});
        assert_eq!(first_param_non_empty_string(&req).unwrap(), "hello");
    }

    #[test]
    fn first_param_non_empty_string_trims_whitespace() {
        let req = json!({"params": ["  hello  "]});
        assert_eq!(first_param_non_empty_string(&req).unwrap(), "hello");
    }

    #[test]
    fn first_param_non_empty_string_rejects_empty() {
        let req = json!({"params": [""]});
        assert!(first_param_non_empty_string(&req).is_err());
    }

    #[test]
    fn first_param_non_empty_string_rejects_whitespace_only() {
        let req = json!({"params": ["   "]});
        assert!(first_param_non_empty_string(&req).is_err());
    }

    #[test]
    fn first_param_non_empty_string_array_valid() {
        let req = json!({"params": [["a", "b", "c"]]});
        let result = first_param_non_empty_string_array(&req).unwrap();
        assert_eq!(result, vec!["a", "b", "c"]);
    }

    #[test]
    fn first_param_non_empty_string_array_rejects_empty_array() {
        let req = json!({"params": [[]]});
        assert!(first_param_non_empty_string_array(&req).is_err());
    }

    #[test]
    fn first_param_non_empty_string_array_rejects_empty_string_element() {
        let req = json!({"params": [["valid", ""]]});
        assert!(first_param_non_empty_string_array(&req).is_err());
    }

    #[test]
    fn first_config_object_finds_object() {
        let params = vec![json!(42), json!({"encoding": "base64"})];
        let obj = first_config_object(&params);
        assert!(obj.is_some());
        assert!(obj.unwrap().contains_key("encoding"));
    }

    #[test]
    fn first_config_object_none_without_object() {
        let params = vec![json!(42), json!("hello")];
        assert!(first_config_object(&params).is_none());
    }

    #[test]
    fn min_context_slot_present() {
        let req = json!({"params": ["addr", {"minContextSlot": 100}]});
        assert_eq!(min_context_slot_from_params(&req).unwrap(), Some(100));
    }

    #[test]
    fn min_context_slot_absent() {
        let req = json!({"params": ["addr", {"encoding": "base64"}]});
        assert_eq!(min_context_slot_from_params(&req).unwrap(), None);
    }

    #[test]
    fn min_context_slot_no_params() {
        let req = json!({});
        assert_eq!(min_context_slot_from_params(&req).unwrap(), None);
    }

    #[test]
    fn min_context_slot_invalid_type() {
        let req = json!({"params": [{"minContextSlot": "not_a_number"}]});
        assert!(min_context_slot_from_params(&req).is_err());
    }
}
