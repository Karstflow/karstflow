use crate::state::RpcCommitment;
use jsonrpsee::types::ErrorObjectOwned;

pub(super) enum BlockSubscriptionFilter {
    All,
    MentionsAccountOrProgram(String),
}

#[derive(Clone, Copy)]
pub(super) enum BlockDataEncoding {
    Base64,
    Base58,
    Json,
    JsonParsed,
}

#[derive(Clone, Copy)]
pub(super) enum BlockTransactionDetails {
    Full,
    Signatures,
    None,
}

#[derive(Clone, Copy)]
pub(super) struct BlockSubscriptionConfig {
    pub commitment: RpcCommitment,
    pub encoding: BlockDataEncoding,
    pub transaction_details: BlockTransactionDetails,
    pub show_rewards: bool,
    pub max_supported_transaction_version: Option<u8>,
}

impl BlockSubscriptionConfig {
    pub fn commitment(self) -> RpcCommitment {
        self.commitment
    }

    pub fn encoding(self) -> BlockDataEncoding {
        self.encoding
    }

    pub fn transaction_details(self) -> BlockTransactionDetails {
        self.transaction_details
    }

    pub fn show_rewards(self) -> bool {
        self.show_rewards
    }

    pub fn max_supported_transaction_version(self) -> Option<u8> {
        self.max_supported_transaction_version
    }
}

#[derive(Clone)]
pub(super) enum LogsSubscriptionFilter {
    All,
    AllWithVotes,
    Mentions(String),
}

#[derive(Clone, Copy)]
pub(super) enum AccountDataEncoding {
    Base58,
    Base64,
    Base64Zstd,
    JsonParsed,
}

#[derive(Clone, Copy)]
pub(super) struct DataSlice {
    pub offset: usize,
    pub length: usize,
}

#[derive(Clone, Copy)]
pub(super) struct AccountSubscriptionConfig {
    pub commitment: RpcCommitment,
    pub data_encoding: AccountDataEncoding,
    pub data_slice: Option<DataSlice>,
}

#[derive(Clone, Copy)]
pub(super) struct SignatureSubscriptionConfig {
    pub commitment: RpcCommitment,
    pub enable_received_notification: bool,
}

#[derive(Clone)]
pub(super) enum ProgramAccountFilter {
    DataSize(u64),
    Memcmp { offset: usize, bytes: String },
}

#[derive(Clone)]
pub(super) struct ProgramSubscriptionConfig {
    pub commitment: RpcCommitment,
    pub data_encoding: AccountDataEncoding,
    pub data_slice: Option<DataSlice>,
    pub filters: Vec<ProgramAccountFilter>,
}

impl ProgramSubscriptionConfig {
    pub fn commitment(&self) -> RpcCommitment {
        self.commitment
    }

    pub fn data_encoding(&self) -> AccountDataEncoding {
        self.data_encoding
    }

    pub fn data_slice(&self) -> Option<DataSlice> {
        self.data_slice
    }

    pub fn filters(&self) -> &[ProgramAccountFilter] {
        &self.filters
    }
}

impl SignatureSubscriptionConfig {
    pub fn commitment(self) -> RpcCommitment {
        self.commitment
    }

    pub fn enable_received_notification(self) -> bool {
        self.enable_received_notification
    }
}

impl AccountSubscriptionConfig {
    pub fn commitment(self) -> RpcCommitment {
        self.commitment
    }

    pub fn data_encoding(self) -> AccountDataEncoding {
        self.data_encoding
    }

    pub fn data_slice(self) -> Option<DataSlice> {
        self.data_slice
    }
}

pub(super) fn parse_block_subscribe_params(
    params: &serde_json::Value,
) -> Result<(BlockSubscriptionFilter, BlockSubscriptionConfig), ErrorObjectOwned> {
    let array = params.as_array().ok_or_else(invalid_params_error)?;
    let filter = match array.first() {
        Some(serde_json::Value::String(value)) if value.trim().eq_ignore_ascii_case("all") => {
            BlockSubscriptionFilter::All
        }
        Some(serde_json::Value::Object(object)) => {
            ensure_only_keys(object, &["mentionsAccountOrProgram"])?;
            let mention = object
                .get("mentionsAccountOrProgram")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .ok_or_else(invalid_params_error)?;
            BlockSubscriptionFilter::MentionsAccountOrProgram(mention)
        }
        _ => return Err(invalid_params_error()),
    };
    let config_object = array.get(1).and_then(serde_json::Value::as_object);
    if let Some(config_object) = config_object {
        ensure_only_keys(
            config_object,
            &[
                "commitment",
                "encoding",
                "transactionDetails",
                "showRewards",
                "maxSupportedTransactionVersion",
            ],
        )?;
    }
    let commitment =
        parse_subscription_commitment(config_object.and_then(|object| object.get("commitment")))?;
    let encoding =
        parse_block_data_encoding(config_object.and_then(|object| object.get("encoding")))?;
    let transaction_details = parse_block_transaction_details(
        config_object.and_then(|object| object.get("transactionDetails")),
    )?;
    let show_rewards =
        parse_block_show_rewards(config_object.and_then(|object| object.get("showRewards")))?;
    let max_supported_transaction_version = parse_max_supported_transaction_version(
        config_object.and_then(|object| object.get("maxSupportedTransactionVersion")),
    )?;
    Ok((
        filter,
        BlockSubscriptionConfig {
            commitment,
            encoding,
            transaction_details,
            show_rewards,
            max_supported_transaction_version,
        },
    ))
}

pub(super) fn parse_logs_subscribe_params(
    params: &serde_json::Value,
) -> Result<(LogsSubscriptionFilter, RpcCommitment), ErrorObjectOwned> {
    let array = params.as_array().ok_or_else(invalid_params_error)?;
    let filter = match array.first() {
        Some(serde_json::Value::String(value)) if value.trim().eq_ignore_ascii_case("all") => {
            LogsSubscriptionFilter::All
        }
        Some(serde_json::Value::String(value))
            if value.trim().eq_ignore_ascii_case("allwithvotes") =>
        {
            LogsSubscriptionFilter::AllWithVotes
        }
        Some(serde_json::Value::Object(object)) => {
            ensure_only_keys(object, &["mentions"])?;
            if let Some(mentions) = object.get("mentions").and_then(serde_json::Value::as_array) {
                let values: Vec<&str> = mentions
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .collect();
                if values.len() != 1 {
                    return Err(invalid_params_error());
                }
                LogsSubscriptionFilter::Mentions(values[0].to_string())
            } else {
                return Err(invalid_params_error());
            }
        }
        _ => return Err(invalid_params_error()),
    };
    let config_object = array.get(1).and_then(serde_json::Value::as_object);
    if let Some(config_object) = config_object {
        ensure_only_keys(config_object, &["commitment"])?;
    }
    let commitment =
        parse_subscription_commitment(config_object.and_then(|object| object.get("commitment")))?;
    Ok((filter, commitment))
}

pub(super) fn parse_program_subscribe_params(
    params: &serde_json::Value,
) -> Result<(String, ProgramSubscriptionConfig), ErrorObjectOwned> {
    let array = params.as_array().ok_or_else(invalid_params_error)?;
    let program_id = array
        .first()
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(invalid_params_error)?;
    let config_object = array.get(1).and_then(serde_json::Value::as_object);
    if let Some(config_object) = config_object {
        ensure_only_keys(
            config_object,
            &["commitment", "encoding", "dataSlice", "filters"],
        )?;
    }
    let commitment =
        parse_subscription_commitment(config_object.and_then(|object| object.get("commitment")))?;
    let data_encoding =
        parse_account_data_encoding(config_object.and_then(|object| object.get("encoding")))?;
    let data_slice = parse_data_slice(config_object.and_then(|object| object.get("dataSlice")))?;
    let filters =
        parse_program_account_filters(config_object.and_then(|object| object.get("filters")))?;
    Ok((
        program_id,
        ProgramSubscriptionConfig {
            commitment,
            data_encoding,
            data_slice,
            filters,
        },
    ))
}

pub(super) fn parse_account_subscribe_params(
    params: &serde_json::Value,
) -> Result<(String, AccountSubscriptionConfig), ErrorObjectOwned> {
    let array = params.as_array().ok_or_else(invalid_params_error)?;
    let pubkey = array
        .first()
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(invalid_params_error)?;

    let config_object = array.get(1).and_then(serde_json::Value::as_object);
    if let Some(config_object) = config_object {
        ensure_only_keys(config_object, &["commitment", "encoding", "dataSlice"])?;
    }
    let commitment =
        parse_subscription_commitment(config_object.and_then(|object| object.get("commitment")))?;
    let data_encoding =
        parse_account_data_encoding(config_object.and_then(|object| object.get("encoding")))?;
    let data_slice = parse_data_slice(config_object.and_then(|object| object.get("dataSlice")))?;

    Ok((
        pubkey,
        AccountSubscriptionConfig {
            commitment,
            data_encoding,
            data_slice,
        },
    ))
}

pub(super) fn parse_signature_subscribe_params(
    params: &serde_json::Value,
) -> Result<(String, SignatureSubscriptionConfig), ErrorObjectOwned> {
    let array = params.as_array().ok_or_else(invalid_params_error)?;
    let signature = array
        .first()
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(invalid_params_error)?;
    let config_object = array.get(1).and_then(serde_json::Value::as_object);
    if let Some(config_object) = config_object {
        ensure_only_keys(config_object, &["commitment", "enableReceivedNotification"])?;
    }
    let commitment =
        parse_subscription_commitment(config_object.and_then(|object| object.get("commitment")))?;
    let enable_received_notification = parse_enable_received_notification(
        config_object.and_then(|object| object.get("enableReceivedNotification")),
    )?;
    Ok((
        signature,
        SignatureSubscriptionConfig {
            commitment,
            enable_received_notification,
        },
    ))
}

pub(super) fn parse_subscription_commitment(
    raw_commitment: Option<&serde_json::Value>,
) -> Result<RpcCommitment, ErrorObjectOwned> {
    let Some(commitment) = raw_commitment else {
        return Ok(RpcCommitment::Finalized);
    };
    let commitment = commitment
        .as_str()
        .ok_or_else(invalid_params_error)?
        .to_ascii_lowercase();
    match commitment.as_str() {
        "processed" => Ok(RpcCommitment::Processed),
        "confirmed" => Ok(RpcCommitment::Confirmed),
        "finalized" => Ok(RpcCommitment::Finalized),
        _ => Err(invalid_params_error()),
    }
}

pub(super) fn parse_no_params(params: &serde_json::Value) -> Result<(), ErrorObjectOwned> {
    let array = params.as_array().ok_or_else(invalid_params_error)?;
    if array.is_empty() {
        Ok(())
    } else {
        Err(invalid_params_error())
    }
}

pub(super) fn parse_optional_commitment_config(
    params: &serde_json::Value,
) -> Result<RpcCommitment, ErrorObjectOwned> {
    let array = params.as_array().ok_or_else(invalid_params_error)?;
    if array.len() > 1 {
        return Err(invalid_params_error());
    }
    let raw_commitment = match array.first() {
        None => None,
        Some(serde_json::Value::Object(object)) => {
            ensure_only_keys(object, &["commitment"])?;
            object.get("commitment")
        }
        Some(_) => return Err(invalid_params_error()),
    };
    parse_subscription_commitment(raw_commitment)
}

fn parse_account_data_encoding(
    raw_encoding: Option<&serde_json::Value>,
) -> Result<AccountDataEncoding, ErrorObjectOwned> {
    let Some(raw_encoding) = raw_encoding else {
        return Ok(AccountDataEncoding::Base64);
    };
    let encoding = raw_encoding
        .as_str()
        .ok_or_else(invalid_params_error)?
        .to_ascii_lowercase();
    match encoding.as_str() {
        "base58" => Ok(AccountDataEncoding::Base58),
        "base64" => Ok(AccountDataEncoding::Base64),
        "base64+zstd" => Ok(AccountDataEncoding::Base64Zstd),
        "jsonparsed" => Ok(AccountDataEncoding::JsonParsed),
        _ => Err(invalid_params_error()),
    }
}

fn parse_data_slice(
    raw_data_slice: Option<&serde_json::Value>,
) -> Result<Option<DataSlice>, ErrorObjectOwned> {
    let Some(raw_data_slice) = raw_data_slice else {
        return Ok(None);
    };
    let object = raw_data_slice
        .as_object()
        .ok_or_else(invalid_params_error)?;
    ensure_only_keys(object, &["offset", "length"])?;
    let offset = object
        .get("offset")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(invalid_params_error)? as usize;
    let length = object
        .get("length")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(invalid_params_error)? as usize;
    Ok(Some(DataSlice { offset, length }))
}

fn parse_enable_received_notification(
    raw_flag: Option<&serde_json::Value>,
) -> Result<bool, ErrorObjectOwned> {
    let Some(raw_flag) = raw_flag else {
        return Ok(false);
    };
    raw_flag.as_bool().ok_or_else(invalid_params_error)
}

fn parse_program_account_filters(
    raw_filters: Option<&serde_json::Value>,
) -> Result<Vec<ProgramAccountFilter>, ErrorObjectOwned> {
    let Some(raw_filters) = raw_filters else {
        return Ok(Vec::new());
    };
    let filters_array = raw_filters.as_array().ok_or_else(invalid_params_error)?;
    let mut parsed_filters = Vec::with_capacity(filters_array.len());
    for filter in filters_array {
        let object = filter.as_object().ok_or_else(invalid_params_error)?;
        if let Some(data_size) = object.get("dataSize").and_then(serde_json::Value::as_u64) {
            ensure_only_keys(object, &["dataSize"])?;
            parsed_filters.push(ProgramAccountFilter::DataSize(data_size));
            continue;
        }
        if let Some(memcmp) = object.get("memcmp").and_then(serde_json::Value::as_object) {
            ensure_only_keys(object, &["memcmp"])?;
            ensure_only_keys(memcmp, &["offset", "bytes"])?;
            let offset = memcmp
                .get("offset")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(invalid_params_error)? as usize;
            let bytes = memcmp
                .get("bytes")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .ok_or_else(invalid_params_error)?;
            parsed_filters.push(ProgramAccountFilter::Memcmp { offset, bytes });
            continue;
        }
        return Err(invalid_params_error());
    }
    Ok(parsed_filters)
}

fn ensure_only_keys(
    object: &serde_json::Map<String, serde_json::Value>,
    allowed_keys: &[&str],
) -> Result<(), ErrorObjectOwned> {
    if object
        .keys()
        .all(|key| allowed_keys.iter().any(|allowed| key == allowed))
    {
        Ok(())
    } else {
        Err(invalid_params_error())
    }
}

fn parse_block_data_encoding(
    raw_encoding: Option<&serde_json::Value>,
) -> Result<BlockDataEncoding, ErrorObjectOwned> {
    let Some(raw_encoding) = raw_encoding else {
        return Ok(BlockDataEncoding::Base64);
    };
    let encoding = raw_encoding
        .as_str()
        .ok_or_else(invalid_params_error)?
        .to_ascii_lowercase();
    match encoding.as_str() {
        "base64" => Ok(BlockDataEncoding::Base64),
        "base58" => Ok(BlockDataEncoding::Base58),
        "json" => Ok(BlockDataEncoding::Json),
        "jsonparsed" => Ok(BlockDataEncoding::JsonParsed),
        _ => Err(invalid_params_error()),
    }
}

fn parse_block_transaction_details(
    raw_transaction_details: Option<&serde_json::Value>,
) -> Result<BlockTransactionDetails, ErrorObjectOwned> {
    let Some(raw_transaction_details) = raw_transaction_details else {
        return Ok(BlockTransactionDetails::Full);
    };
    let value = raw_transaction_details
        .as_str()
        .ok_or_else(invalid_params_error)?
        .to_ascii_lowercase();
    match value.as_str() {
        "full" => Ok(BlockTransactionDetails::Full),
        "signatures" => Ok(BlockTransactionDetails::Signatures),
        "none" => Ok(BlockTransactionDetails::None),
        _ => Err(invalid_params_error()),
    }
}

fn parse_block_show_rewards(
    raw_show_rewards: Option<&serde_json::Value>,
) -> Result<bool, ErrorObjectOwned> {
    let Some(raw_show_rewards) = raw_show_rewards else {
        return Ok(true);
    };
    raw_show_rewards.as_bool().ok_or_else(invalid_params_error)
}

fn parse_max_supported_transaction_version(
    raw_version: Option<&serde_json::Value>,
) -> Result<Option<u8>, ErrorObjectOwned> {
    let Some(raw_version) = raw_version else {
        return Ok(None);
    };
    let version = raw_version.as_u64().ok_or_else(invalid_params_error)?;
    if version > u8::MAX as u64 {
        return Err(invalid_params_error());
    }
    Ok(Some(version as u8))
}

fn invalid_params_error() -> ErrorObjectOwned {
    ErrorObjectOwned::owned(-32602, "Invalid params", None::<()>)
}
