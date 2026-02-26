use paradencer_types::Account;
use serde::{Deserialize, Serialize};

/// Filter types for account queries
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RpcFilterType {
    /// Match account data size
    DataSize(u64),
    /// Match bytes at offset
    Memcmp(MemcmpFilter),
    /// Match lamports range
    LamportsRange { min: Option<u64>, max: Option<u64> },
    /// Match owner program
    Owner(String),
    /// Match executable flag
    Executable(bool),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemcmpFilter {
    pub offset: usize,
    pub bytes: MemcmpBytes,
    pub encoding: Option<MemcmpEncoding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MemcmpBytes {
    Bytes(Vec<u8>),
    Base58(String),
    Base64(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MemcmpEncoding {
    Base58,
    Base64,
    Bytes,
}

/// Sort order for account results
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SortOrder {
    LamportsAsc,
    LamportsDesc,
    DataSizeAsc,
    DataSizeDesc,
    PubkeyAsc,
    PubkeyDesc,
}

/// Apply filters to account list
pub fn apply_filters(
    accounts: &[(String, Account)],
    filters: &[RpcFilterType],
) -> Vec<(String, Account)> {
    accounts
        .iter()
        .filter(|(_, account)| matches_all_filters(account, filters))
        .cloned()
        .collect()
}

/// Check if account matches all filters
fn matches_all_filters(account: &Account, filters: &[RpcFilterType]) -> bool {
    filters.iter().all(|filter| matches_filter(account, filter))
}

/// Check if account matches a single filter
fn matches_filter(account: &Account, filter: &RpcFilterType) -> bool {
    match filter {
        RpcFilterType::DataSize(size) => account.data_len() == *size as usize,

        RpcFilterType::Memcmp(memcmp) => {
            let bytes = match &memcmp.bytes {
                MemcmpBytes::Bytes(b) => b.clone(),
                MemcmpBytes::Base58(s) => match bs58::decode(s).into_vec() {
                    Ok(b) => b,
                    Err(_) => return false,
                },
                MemcmpBytes::Base64(s) => match decode_base64(s) {
                    Ok(b) => b,
                    Err(_) => return false,
                },
            };

            if memcmp.offset + bytes.len() > account.data_len() {
                return false;
            }

            let account_slice =
                &account.data.as_slice()[memcmp.offset..memcmp.offset + bytes.len()];
            account_slice == bytes.as_slice()
        }

        RpcFilterType::LamportsRange { min, max } => {
            let lamports = account.meta.lamports;
            let min_ok = min.map(|m| lamports >= m).unwrap_or(true);
            let max_ok = max.map(|m| lamports <= m).unwrap_or(true);
            min_ok && max_ok
        }

        RpcFilterType::Owner(owner_str) => account.meta.owner.to_string() == *owner_str,

        RpcFilterType::Executable(executable) => account.meta.executable == *executable,
    }
}

/// Decode base64 string into raw bytes.
fn decode_base64(s: &str) -> Result<Vec<u8>, String> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    STANDARD
        .decode(s)
        .map_err(|e| format!("invalid base64: {e}"))
}

/// Build filter from JSON
pub fn parse_filter(value: &serde_json::Value) -> Result<RpcFilterType, String> {
    if let Some(data_size) = value.get("dataSize") {
        if let Some(size) = data_size.as_u64() {
            return Ok(RpcFilterType::DataSize(size));
        }
    }

    if let Some(memcmp) = value.get("memcmp") {
        let offset = memcmp
            .get("offset")
            .and_then(|v| v.as_u64())
            .ok_or("memcmp missing offset")? as usize;

        let bytes_value = memcmp.get("bytes").ok_or("memcmp missing bytes")?;
        let encoding = memcmp
            .get("encoding")
            .and_then(|v| v.as_str())
            .map(|s| match s {
                "base58" => MemcmpEncoding::Base58,
                "base64" => MemcmpEncoding::Base64,
                _ => MemcmpEncoding::Bytes,
            });

        let bytes = if let Some(s) = bytes_value.as_str() {
            match encoding {
                Some(MemcmpEncoding::Base58) => MemcmpBytes::Base58(s.to_string()),
                Some(MemcmpEncoding::Base64) => MemcmpBytes::Base64(s.to_string()),
                _ => MemcmpBytes::Base58(s.to_string()), // Default to base58
            }
        } else if let Some(arr) = bytes_value.as_array() {
            let bytes: Result<Vec<u8>, _> = arr
                .iter()
                .map(|v| {
                    v.as_u64()
                        .and_then(|n| u8::try_from(n).ok())
                        .ok_or("invalid byte value")
                })
                .collect();
            MemcmpBytes::Bytes(bytes?)
        } else {
            return Err("invalid bytes format".to_string());
        };

        return Ok(RpcFilterType::Memcmp(MemcmpFilter {
            offset,
            bytes,
            encoding,
        }));
    }

    if let Some(lamports) = value.get("lamportsRange") {
        let min = lamports.get("min").and_then(|v| v.as_u64());
        let max = lamports.get("max").and_then(|v| v.as_u64());
        return Ok(RpcFilterType::LamportsRange { min, max });
    }

    if let Some(owner) = value.get("owner") {
        if let Some(s) = owner.as_str() {
            return Ok(RpcFilterType::Owner(s.to_string()));
        }
    }

    if let Some(executable) = value.get("executable") {
        if let Some(b) = executable.as_bool() {
            return Ok(RpcFilterType::Executable(b));
        }
    }

    Err("unknown filter type".to_string())
}

/// Parse multiple filters from JSON array
pub fn parse_filters(values: &[serde_json::Value]) -> Result<Vec<RpcFilterType>, String> {
    values.iter().map(parse_filter).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use paradencer_types::Pubkey;
    use serde_json::json;

    fn create_test_account(lamports: u64, data: Vec<u8>, executable: bool) -> Account {
        let mut account = Account::new(lamports, data, Pubkey::zeroed());
        account.meta.executable = executable;
        account
    }

    #[test]
    fn test_data_size_filter() {
        let account = create_test_account(1000, vec![1, 2, 3, 4], false);
        let filter = RpcFilterType::DataSize(4);

        assert!(matches_filter(&account, &filter));

        let filter_wrong = RpcFilterType::DataSize(5);
        assert!(!matches_filter(&account, &filter_wrong));
    }

    #[test]
    fn test_memcmp_filter() {
        let account = create_test_account(1000, vec![0, 1, 2, 3, 4, 5], false);
        let filter = RpcFilterType::Memcmp(MemcmpFilter {
            offset: 2,
            bytes: MemcmpBytes::Bytes(vec![2, 3, 4]),
            encoding: None,
        });

        assert!(matches_filter(&account, &filter));

        let filter_wrong = RpcFilterType::Memcmp(MemcmpFilter {
            offset: 2,
            bytes: MemcmpBytes::Bytes(vec![2, 3, 5]),
            encoding: None,
        });
        assert!(!matches_filter(&account, &filter_wrong));
    }

    #[test]
    fn test_lamports_range_filter() {
        let account = create_test_account(5000, vec![], false);

        let filter = RpcFilterType::LamportsRange {
            min: Some(1000),
            max: Some(10000),
        };
        assert!(matches_filter(&account, &filter));

        let filter_too_high = RpcFilterType::LamportsRange {
            min: Some(6000),
            max: None,
        };
        assert!(!matches_filter(&account, &filter_too_high));

        let filter_too_low = RpcFilterType::LamportsRange {
            min: None,
            max: Some(4000),
        };
        assert!(!matches_filter(&account, &filter_too_low));
    }

    #[test]
    fn test_executable_filter() {
        let executable_account = create_test_account(1000, vec![], true);
        let regular_account = create_test_account(1000, vec![], false);

        let filter_true = RpcFilterType::Executable(true);
        assert!(matches_filter(&executable_account, &filter_true));
        assert!(!matches_filter(&regular_account, &filter_true));

        let filter_false = RpcFilterType::Executable(false);
        assert!(!matches_filter(&executable_account, &filter_false));
        assert!(matches_filter(&regular_account, &filter_false));
    }

    #[test]
    fn test_apply_filters() {
        let accounts = vec![
            (
                "acc1".to_string(),
                create_test_account(1000, vec![1, 2], false),
            ),
            (
                "acc2".to_string(),
                create_test_account(5000, vec![1, 2, 3], false),
            ),
            (
                "acc3".to_string(),
                create_test_account(2000, vec![1], false),
            ),
        ];

        let filters = vec![RpcFilterType::LamportsRange {
            min: Some(2000),
            max: None,
        }];

        let filtered = apply_filters(&accounts, &filters);
        assert_eq!(filtered.len(), 2); // acc2 and acc3
    }

    #[test]
    fn test_matches_all_filters() {
        let account = create_test_account(5000, vec![1, 2, 3], false);

        let filters = vec![
            RpcFilterType::DataSize(3),
            RpcFilterType::LamportsRange {
                min: Some(4000),
                max: Some(6000),
            },
        ];

        assert!(matches_all_filters(&account, &filters));

        let filters_with_fail = vec![
            RpcFilterType::DataSize(3),
            RpcFilterType::LamportsRange {
                min: Some(6000),
                max: None,
            },
        ];

        assert!(!matches_all_filters(&account, &filters_with_fail));
    }

    #[test]
    fn test_parse_data_size_filter() {
        let json = json!({ "dataSize": 100 });
        let filter = parse_filter(&json).unwrap();

        match filter {
            RpcFilterType::DataSize(size) => assert_eq!(size, 100),
            _ => panic!("wrong filter type"),
        }
    }

    #[test]
    fn test_parse_memcmp_filter() {
        let json = json!({
            "memcmp": {
                "offset": 10,
                "bytes": [1, 2, 3, 4],
                "encoding": "bytes"
            }
        });

        let filter = parse_filter(&json).unwrap();

        match filter {
            RpcFilterType::Memcmp(memcmp) => {
                assert_eq!(memcmp.offset, 10);
                match memcmp.bytes {
                    MemcmpBytes::Bytes(b) => assert_eq!(b, vec![1, 2, 3, 4]),
                    _ => panic!("wrong bytes type"),
                }
            }
            _ => panic!("wrong filter type"),
        }
    }

    #[test]
    fn test_parse_lamports_range_filter() {
        let json = json!({
            "lamportsRange": {
                "min": 1000,
                "max": 5000
            }
        });

        let filter = parse_filter(&json).unwrap();

        match filter {
            RpcFilterType::LamportsRange { min, max } => {
                assert_eq!(min, Some(1000));
                assert_eq!(max, Some(5000));
            }
            _ => panic!("wrong filter type"),
        }
    }

    #[test]
    fn test_parse_executable_filter() {
        let json = json!({ "executable": true });
        let filter = parse_filter(&json).unwrap();

        match filter {
            RpcFilterType::Executable(b) => assert!(b),
            _ => panic!("wrong filter type"),
        }
    }

    #[test]
    fn test_parse_filters_multiple() {
        let json = vec![json!({ "dataSize": 100 }), json!({ "executable": false })];

        let filters = parse_filters(&json).unwrap();
        assert_eq!(filters.len(), 2);
    }
}
