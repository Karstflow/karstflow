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
