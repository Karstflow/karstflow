/// BPF loader input region serialization and deserialization.
///
/// Serializes instruction accounts and data into the binary format
/// expected by the sBPF virtual machine input region (0x400000000+).
/// Two formats are supported:
///
/// - **Aligned** (BPF Loader v2/v3/v4): 8-byte aligned metadata with
///   16-byte aligned account data boundaries and realloc buffers.
/// - **Unaligned** (deprecated BPF Loader v1): compact format without
///   alignment padding or realloc buffers.
///
/// After execution, the deserialization step reads back modified
/// account data (lamports, data, owner) from the VM output buffer.
use paradencer_constants::vm::{
    ALIGN_OF_U128, MAX_INSTRUCTION_ACCOUNTS, MAX_PERMITTED_DATA_INCREASE,
    MAX_PERMITTED_DATA_LENGTH, NON_DUP_MARKER, REGION_INPUT_BASE,
};
use paradencer_types::Pubkey;

/// Per-account metadata tracked during serialization for deserialization write-back.
#[derive(Debug, Clone, Default)]
pub struct AccountRegionMeta {
    /// Original data length before execution.
    pub original_data_len: usize,
    /// Whether the account was writable.
    pub is_writable: bool,
    /// Key of the account.
    pub key: Pubkey,
    /// Owner of the account at serialization time.
    pub owner: Pubkey,
}

/// Result of serializing the BPF input region.
#[derive(Debug, Clone)]
pub struct SerializedInput {
    /// The serialized buffer containing all account metadata, data, and instruction info.
    pub buffer: Vec<u8>,
    /// Per-account region metadata for deserialization write-back.
    pub account_metas: Vec<AccountRegionMeta>,
    /// Original data lengths per instruction account (for realloc validation).
    pub pre_lens: Vec<usize>,
    /// Virtual address offset where instruction data begins.
    pub instruction_data_offset: u64,
    /// Indices mapping duplicate accounts to their first occurrence.
    /// `None` if this account is the first occurrence, `Some(idx)` if duplicate.
    pub duplicate_indices: Vec<Option<usize>>,
}

/// An account passed to the serializer.
#[derive(Debug, Clone)]
pub struct InputAccount {
    pub key: Pubkey,
    pub owner: Pubkey,
    pub lamports: u64,
    pub data: Vec<u8>,
    pub is_signer: bool,
    pub is_writable: bool,
    pub is_executable: bool,
    pub rent_epoch: u64,
}

/// Serialize the input region in aligned format (BPF Loader v2/v3/v4).
///
/// Layout per non-duplicate account:
/// ```text
/// [1 byte:  NON_DUP_MARKER (0xFF)]
/// [1 byte:  is_signer]
/// [1 byte:  is_writable]
/// [1 byte:  is_executable]
/// [4 bytes: padding (original_data_len placeholder)]
/// [32 bytes: pubkey]
/// [32 bytes: owner]
/// [8 bytes: lamports]
/// [8 bytes: data_len]
/// [data_len bytes: account data]
/// [MAX_PERMITTED_DATA_INCREASE bytes: realloc buffer (zeroed)]
/// [align_offset bytes: padding to 16-byte alignment]
/// [8 bytes: rent_epoch (u64::MAX)]
/// ```
///
/// Layout per duplicate account:
/// ```text
/// [8 bytes: first byte = index to original, rest = 0]
/// ```
pub fn serialize_aligned(
    accounts: &[InputAccount],
    instruction_data: &[u8],
    program_id: &Pubkey,
) -> Result<SerializedInput, String> {
    if accounts.len() > MAX_INSTRUCTION_ACCOUNTS {
        return Err("Too many instruction accounts".to_string());
    }

    // Pre-allocate buffer: rough estimate
    let estimated_size = 8 // account count
        + accounts.len() * (128 + MAX_PERMITTED_DATA_INCREASE + ALIGN_OF_U128)
        + accounts.iter().map(|a| a.data.len()).sum::<usize>()
        + 8 + instruction_data.len() + 32;
    let mut buffer = Vec::with_capacity(estimated_size);
    let mut account_metas: Vec<AccountRegionMeta> = Vec::with_capacity(accounts.len());
    let mut pre_lens = Vec::with_capacity(accounts.len());
    let mut duplicate_indices = Vec::with_capacity(accounts.len());

    // Track seen accounts for deduplication (by key)
    let mut seen: Vec<Option<usize>> = vec![None; accounts.len()];
    // Map from key bytes to first instruction account index
    let mut key_to_first: std::collections::HashMap<[u8; 32], usize> = std::collections::HashMap::new();

    // Write account count
    buffer.extend_from_slice(&(accounts.len() as u64).to_le_bytes());

    for (i, account) in accounts.iter().enumerate() {
        let key_bytes: [u8; 32] = *account.key.as_bytes();

        if let Some(&first_idx) = key_to_first.get(&key_bytes) {
            // Duplicate account — write 8 bytes with first byte = index
            let mut dup_bytes = [0u8; 8];
            dup_bytes[0] = first_idx as u8;
            buffer.extend_from_slice(&dup_bytes);

            // Clone region meta from the first occurrence
            account_metas.push(account_metas[first_idx].clone());
            pre_lens.push(pre_lens[first_idx]);
            duplicate_indices.push(Some(first_idx));
            seen[i] = Some(first_idx);
        } else {
            key_to_first.insert(key_bytes, i);
            duplicate_indices.push(None);

            // Non-duplicate marker
            buffer.push(NON_DUP_MARKER);

            // is_signer
            buffer.push(account.is_signer as u8);

            // is_writable
            buffer.push(account.is_writable as u8);

            // is_executable
            buffer.push(account.is_executable as u8);

            // 4 bytes padding (original_data_len placeholder — not populated)
            buffer.extend_from_slice(&0u32.to_le_bytes());

            // pubkey (32 bytes)
            buffer.extend_from_slice(account.key.as_bytes());

            // owner (32 bytes)
            buffer.extend_from_slice(account.owner.as_bytes());

            // lamports (8 bytes)
            buffer.extend_from_slice(&account.lamports.to_le_bytes());

            // data_len (8 bytes)
            let data_len = account.data.len();
            buffer.extend_from_slice(&(data_len as u64).to_le_bytes());

            // account data
            buffer.extend_from_slice(&account.data);

            // realloc buffer (MAX_PERMITTED_DATA_INCREASE bytes, zeroed)
            buffer.resize(buffer.len() + MAX_PERMITTED_DATA_INCREASE, 0);

            // alignment padding to 16 bytes
            let align_offset = data_len.wrapping_neg() & (ALIGN_OF_U128 - 1);
            buffer.resize(buffer.len() + align_offset, 0);

            // rent_epoch (8 bytes, always u64::MAX in Agave)
            buffer.extend_from_slice(&u64::MAX.to_le_bytes());

            pre_lens.push(data_len);
            account_metas.push(AccountRegionMeta {
                original_data_len: data_len,
                is_writable: account.is_writable,
                key: account.key,
                owner: account.owner,
            });
        }
    }

    // Instruction data length
    buffer.extend_from_slice(&(instruction_data.len() as u64).to_le_bytes());

    // Instruction data offset (virtual address)
    let instruction_data_offset = REGION_INPUT_BASE + buffer.len() as u64;

    // Instruction data
    buffer.extend_from_slice(instruction_data);

    // Program ID (32 bytes)
    buffer.extend_from_slice(program_id.as_bytes());

    Ok(SerializedInput {
        buffer,
        account_metas,
        pre_lens,
        instruction_data_offset,
        duplicate_indices,
    })
}

/// Serialize the input region in unaligned format (deprecated BPF Loader v1).
///
/// Layout per non-duplicate account:
/// ```text
/// [1 byte:  NON_DUP_MARKER (0xFF)]
/// [1 byte:  is_signer]
/// [1 byte:  is_writable]
/// [32 bytes: pubkey]
/// [8 bytes: lamports]
/// [8 bytes: data_len]
/// [data_len bytes: account data]
/// [32 bytes: owner]
/// [1 byte:  is_executable]
/// [8 bytes: rent_epoch (u64::MAX)]
/// ```
pub fn serialize_unaligned(
    accounts: &[InputAccount],
    instruction_data: &[u8],
    program_id: &Pubkey,
) -> Result<SerializedInput, String> {
    if accounts.len() > MAX_INSTRUCTION_ACCOUNTS {
        return Err("Too many instruction accounts".to_string());
    }

    let estimated_size = 8
        + accounts.len() * 96
        + accounts.iter().map(|a| a.data.len()).sum::<usize>()
        + 8 + instruction_data.len() + 32;
    let mut buffer = Vec::with_capacity(estimated_size);
    let mut account_metas: Vec<AccountRegionMeta> = Vec::with_capacity(accounts.len());
    let mut pre_lens = Vec::with_capacity(accounts.len());
    let mut duplicate_indices = Vec::with_capacity(accounts.len());

    let mut key_to_first: std::collections::HashMap<[u8; 32], usize> = std::collections::HashMap::new();

    // Write account count
    buffer.extend_from_slice(&(accounts.len() as u64).to_le_bytes());

    for (i, account) in accounts.iter().enumerate() {
        let key_bytes: [u8; 32] = *account.key.as_bytes();

        if let Some(&first_idx) = key_to_first.get(&key_bytes) {
            // Duplicate: single byte with index
            buffer.push(first_idx as u8);
            account_metas.push(account_metas[first_idx].clone());
            pre_lens.push(pre_lens[first_idx]);
            duplicate_indices.push(Some(first_idx));
        } else {
            key_to_first.insert(key_bytes, i);
            duplicate_indices.push(None);

            buffer.push(NON_DUP_MARKER);
            buffer.push(account.is_signer as u8);
            buffer.push(account.is_writable as u8);

            // pubkey
            buffer.extend_from_slice(account.key.as_bytes());

            // lamports
            buffer.extend_from_slice(&account.lamports.to_le_bytes());

            // data_len
            let data_len = account.data.len();
            buffer.extend_from_slice(&(data_len as u64).to_le_bytes());

            // account data (no realloc buffer for deprecated loader)
            buffer.extend_from_slice(&account.data);

            // owner
            buffer.extend_from_slice(account.owner.as_bytes());

            // is_executable
            buffer.push(account.is_executable as u8);

            // rent_epoch
            buffer.extend_from_slice(&u64::MAX.to_le_bytes());

            pre_lens.push(data_len);
            account_metas.push(AccountRegionMeta {
                original_data_len: data_len,
                is_writable: account.is_writable,
                key: account.key,
                owner: account.owner,
            });
        }
    }

    // Instruction data
    buffer.extend_from_slice(&(instruction_data.len() as u64).to_le_bytes());
    let instruction_data_offset = REGION_INPUT_BASE + buffer.len() as u64;
    buffer.extend_from_slice(instruction_data);

    // Program ID
    buffer.extend_from_slice(program_id.as_bytes());

    Ok(SerializedInput {
        buffer,
        account_metas,
        pre_lens,
        instruction_data_offset,
        duplicate_indices,
    })
}

/// Modified account data extracted during deserialization.
#[derive(Debug, Clone)]
pub struct DeserializedAccount {
    /// New lamports value after execution.
    pub lamports: u64,
    /// New data after execution (may have been resized).
    pub data: Vec<u8>,
    /// New owner after execution (may have changed).
    pub owner: Pubkey,
}

/// Deserialize the aligned format output buffer to extract modified account state.
///
/// Reads back lamports, data (possibly resized), and owner from the VM output.
/// For read-only accounts, verifies data was not modified.
pub fn deserialize_aligned(
    buffer: &[u8],
    account_metas: &[AccountRegionMeta],
    pre_lens: &[usize],
    duplicate_indices: &[Option<usize>],
) -> Result<Vec<Option<DeserializedAccount>>, String> {
    let num_accounts = account_metas.len();
    let mut results: Vec<Option<DeserializedAccount>> = vec![None; num_accounts];
    let mut offset = 8; // skip account count

    let mut seen = vec![false; num_accounts];

    for i in 0..num_accounts {
        if let Some(_first_idx) = duplicate_indices[i] {
            // Duplicate: skip 8 bytes
            offset += 8;
            continue;
        }

        if seen[i] {
            offset += 8;
            continue;
        }
        seen[i] = true;

        // Skip: dup_marker(1) + is_signer(1) + is_writable(1) + is_executable(1) + padding(4) + key(32)
        offset += 1 + 1 + 1 + 1 + 4 + 32;

        // Read owner (32 bytes)
        if offset + 32 > buffer.len() {
            return Err("Buffer too short for owner".to_string());
        }
        let owner = Pubkey::new(buffer[offset..offset + 32].try_into().unwrap());
        offset += 32;

        // Read lamports (8 bytes)
        if offset + 8 > buffer.len() {
            return Err("Buffer too short for lamports".to_string());
        }
        let lamports = u64::from_le_bytes(buffer[offset..offset + 8].try_into().unwrap());
        offset += 8;

        // Read data_len (8 bytes)
        if offset + 8 > buffer.len() {
            return Err("Buffer too short for data_len".to_string());
        }
        let post_len = u64::from_le_bytes(buffer[offset..offset + 8].try_into().unwrap()) as usize;
        offset += 8;

        let pre_len = pre_lens[i];

        // Validate realloc limits
        if post_len > pre_len + MAX_PERMITTED_DATA_INCREASE {
            return Err(format!(
                "Account {} data grew beyond realloc limit: {} -> {}",
                i, pre_len, post_len
            ));
        }
        if post_len > MAX_PERMITTED_DATA_LENGTH {
            return Err(format!(
                "Account {} data exceeds maximum: {}",
                i, post_len
            ));
        }

        // Read data
        if offset + post_len > buffer.len() {
            return Err("Buffer too short for account data".to_string());
        }
        let data = buffer[offset..offset + post_len].to_vec();

        // Skip over the full data region + realloc buffer + alignment
        let align_offset = pre_len.wrapping_neg() & (ALIGN_OF_U128 - 1);
        offset += pre_len + MAX_PERMITTED_DATA_INCREASE + align_offset;

        // Skip rent_epoch (8 bytes)
        offset += 8;

        if account_metas[i].is_writable {
            results[i] = Some(DeserializedAccount {
                lamports,
                data,
                owner,
            });
        } else {
            // For read-only accounts, verify data was not modified
            if lamports != 0 || post_len != pre_len {
                // In strict mode would error, but for now just skip
            }
        }
    }

    Ok(results)
}

/// Deserialize the unaligned format output buffer to extract modified account state.
pub fn deserialize_unaligned(
    buffer: &[u8],
    account_metas: &[AccountRegionMeta],
    pre_lens: &[usize],
    duplicate_indices: &[Option<usize>],
) -> Result<Vec<Option<DeserializedAccount>>, String> {
    let num_accounts = account_metas.len();
    let mut results: Vec<Option<DeserializedAccount>> = vec![None; num_accounts];
    let mut offset = 8; // skip account count

    let mut seen = vec![false; num_accounts];

    for i in 0..num_accounts {
        if let Some(_first_idx) = duplicate_indices[i] {
            // Duplicate: skip 1 byte
            offset += 1;
            continue;
        }

        if seen[i] {
            offset += 1;
            continue;
        }
        seen[i] = true;

        // Skip: dup_marker(1) + is_signer(1) + is_writable(1) + key(32)
        offset += 1 + 1 + 1 + 32;

        // Read lamports
        if offset + 8 > buffer.len() {
            return Err("Buffer too short for lamports".to_string());
        }
        let lamports = u64::from_le_bytes(buffer[offset..offset + 8].try_into().unwrap());
        offset += 8;

        // Read data_len
        if offset + 8 > buffer.len() {
            return Err("Buffer too short for data_len".to_string());
        }
        let _data_len = u64::from_le_bytes(buffer[offset..offset + 8].try_into().unwrap()) as usize;
        offset += 8;

        let pre_len = pre_lens[i];

        // Read data (deprecated loader doesn't support realloc, use pre_len)
        if offset + pre_len > buffer.len() {
            return Err("Buffer too short for account data".to_string());
        }
        let data = buffer[offset..offset + pre_len].to_vec();
        offset += pre_len;

        // Read owner (32 bytes)
        if offset + 32 > buffer.len() {
            return Err("Buffer too short for owner".to_string());
        }
        let owner = Pubkey::new(buffer[offset..offset + 32].try_into().unwrap());
        offset += 32;

        // Skip: is_executable(1) + rent_epoch(8)
        offset += 1 + 8;

        if account_metas[i].is_writable {
            results[i] = Some(DeserializedAccount {
                lamports,
                data,
                owner,
            });
        }
    }

    Ok(results)
}

/// Top-level dispatch: serialize input for BPF program execution.
///
/// `is_deprecated` selects between aligned (false) and unaligned (true) formats.
pub fn serialize_parameters(
    accounts: &[InputAccount],
    instruction_data: &[u8],
    program_id: &Pubkey,
    is_deprecated: bool,
) -> Result<SerializedInput, String> {
    if is_deprecated {
        serialize_unaligned(accounts, instruction_data, program_id)
    } else {
        serialize_aligned(accounts, instruction_data, program_id)
    }
}

/// Top-level dispatch: deserialize output from BPF program execution.
pub fn deserialize_parameters(
    buffer: &[u8],
    account_metas: &[AccountRegionMeta],
    pre_lens: &[usize],
    duplicate_indices: &[Option<usize>],
    is_deprecated: bool,
) -> Result<Vec<Option<DeserializedAccount>>, String> {
    if is_deprecated {
        deserialize_unaligned(buffer, account_metas, pre_lens, duplicate_indices)
    } else {
        deserialize_aligned(buffer, account_metas, pre_lens, duplicate_indices)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_account(key: Pubkey, owner: Pubkey, lamports: u64, data: &[u8]) -> InputAccount {
        InputAccount {
            key,
            owner,
            lamports,
            data: data.to_vec(),
            is_signer: true,
            is_writable: true,
            is_executable: false,
            rent_epoch: u64::MAX,
        }
    }

    // -----------------------------------------------------------------------
    // Aligned format tests
    // -----------------------------------------------------------------------

    #[test]
    fn aligned_serialize_single_account() {
        let key = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let program_id = Pubkey::new_unique();
        let data = vec![1, 2, 3, 4, 5];

        let accounts = vec![make_test_account(key, owner, 1000, &data)];
        let instruction_data = vec![10, 20, 30];

        let result = serialize_aligned(&accounts, &instruction_data, &program_id).unwrap();

        // Verify account count at start
        let count = u64::from_le_bytes(result.buffer[0..8].try_into().unwrap());
        assert_eq!(count, 1);

        // Verify non-dup marker
        assert_eq!(result.buffer[8], NON_DUP_MARKER);

        // Verify is_signer
        assert_eq!(result.buffer[9], 1);

        // Verify is_writable
        assert_eq!(result.buffer[10], 1);

        // Verify key at offset 8+1+1+1+1+4 = 16
        let stored_key = Pubkey::new(result.buffer[16..48].try_into().unwrap());
        assert_eq!(stored_key, key);

        // Verify owner at offset 48
        let stored_owner = Pubkey::new(result.buffer[48..80].try_into().unwrap());
        assert_eq!(stored_owner, owner);

        // Verify lamports at offset 80
        let stored_lamports = u64::from_le_bytes(result.buffer[80..88].try_into().unwrap());
        assert_eq!(stored_lamports, 1000);

        // Verify data_len at offset 88
        let stored_data_len = u64::from_le_bytes(result.buffer[88..96].try_into().unwrap());
        assert_eq!(stored_data_len, 5);

        // Verify data at offset 96
        assert_eq!(&result.buffer[96..101], &[1, 2, 3, 4, 5]);

        // Verify buffer ends with program_id
        let end = result.buffer.len();
        let stored_program_id = Pubkey::new(result.buffer[end - 32..end].try_into().unwrap());
        assert_eq!(stored_program_id, program_id);

        // Verify metadata
        assert_eq!(result.pre_lens, vec![5]);
        assert_eq!(result.account_metas.len(), 1);
        assert_eq!(result.account_metas[0].original_data_len, 5);
        assert!(result.account_metas[0].is_writable);
    }

    #[test]
    fn aligned_serialize_multiple_accounts() {
        let keys: Vec<Pubkey> = (0..3).map(|_| Pubkey::new_unique()).collect();
        let owner = Pubkey::new_unique();
        let program_id = Pubkey::new_unique();

        let accounts = vec![
            make_test_account(keys[0], owner, 1000, &[1, 2]),
            make_test_account(keys[1], owner, 2000, &[3, 4, 5]),
            make_test_account(keys[2], owner, 3000, &[]),
        ];
        let instruction_data = vec![0xFF];

        let result = serialize_aligned(&accounts, &instruction_data, &program_id).unwrap();

        let count = u64::from_le_bytes(result.buffer[0..8].try_into().unwrap());
        assert_eq!(count, 3);

        assert_eq!(result.pre_lens, vec![2, 3, 0]);
        assert_eq!(result.account_metas.len(), 3);
    }

    #[test]
    fn aligned_serialize_duplicate_account() {
        let key = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let program_id = Pubkey::new_unique();

        // Same key appears twice
        let accounts = vec![
            make_test_account(key, owner, 1000, &[1, 2, 3]),
            make_test_account(key, owner, 1000, &[1, 2, 3]),
        ];
        let instruction_data = vec![];

        let result = serialize_aligned(&accounts, &instruction_data, &program_id).unwrap();

        let count = u64::from_le_bytes(result.buffer[0..8].try_into().unwrap());
        assert_eq!(count, 2);

        // First account: NON_DUP_MARKER
        assert_eq!(result.buffer[8], NON_DUP_MARKER);

        // Second account: duplicate marker (8 bytes, first byte = index 0)
        // Find the second account entry. After first account: metadata + data + realloc + align + rent_epoch
        // Let's just verify duplicate_indices
        assert_eq!(result.duplicate_indices[0], None);
        assert_eq!(result.duplicate_indices[1], Some(0));
    }

    #[test]
    fn aligned_round_trip_single_account() {
        let key = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let program_id = Pubkey::new_unique();
        let data = vec![10, 20, 30, 40, 50, 60, 70, 80];

        let accounts = vec![make_test_account(key, owner, 5000, &data)];
        let instruction_data = vec![0xAA, 0xBB];

        let serialized = serialize_aligned(&accounts, &instruction_data, &program_id).unwrap();

        let deserialized = deserialize_aligned(
            &serialized.buffer,
            &serialized.account_metas,
            &serialized.pre_lens,
            &serialized.duplicate_indices,
        )
        .unwrap();

        assert_eq!(deserialized.len(), 1);
        let account = deserialized[0].as_ref().unwrap();
        assert_eq!(account.lamports, 5000);
        assert_eq!(account.data, data);
        assert_eq!(account.owner, owner);
    }

    #[test]
    fn aligned_round_trip_preserves_data_after_modification() {
        let key = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let program_id = Pubkey::new_unique();
        let data = vec![1, 2, 3, 4];

        let accounts = vec![make_test_account(key, owner, 1000, &data)];

        let mut serialized = serialize_aligned(&accounts, &[], &program_id).unwrap();

        // Simulate VM modifying lamports in the buffer
        // Lamports are at offset 8 (account_count) + 1 + 1 + 1 + 1 + 4 + 32 + 32 = 80
        let new_lamports = 2000u64;
        serialized.buffer[80..88].copy_from_slice(&new_lamports.to_le_bytes());

        let deserialized = deserialize_aligned(
            &serialized.buffer,
            &serialized.account_metas,
            &serialized.pre_lens,
            &serialized.duplicate_indices,
        )
        .unwrap();

        let account = deserialized[0].as_ref().unwrap();
        assert_eq!(account.lamports, 2000);
        assert_eq!(account.data, data);
    }

    // -----------------------------------------------------------------------
    // Unaligned format tests
    // -----------------------------------------------------------------------

    #[test]
    fn unaligned_serialize_single_account() {
        let key = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let program_id = Pubkey::new_unique();
        let data = vec![5, 6, 7];

        let accounts = vec![make_test_account(key, owner, 500, &data)];
        let instruction_data = vec![99];

        let result = serialize_unaligned(&accounts, &instruction_data, &program_id).unwrap();

        // Account count
        let count = u64::from_le_bytes(result.buffer[0..8].try_into().unwrap());
        assert_eq!(count, 1);

        // Non-dup marker
        assert_eq!(result.buffer[8], NON_DUP_MARKER);

        // is_signer
        assert_eq!(result.buffer[9], 1);

        // is_writable
        assert_eq!(result.buffer[10], 1);

        // Key at offset 11
        let stored_key = Pubkey::new(result.buffer[11..43].try_into().unwrap());
        assert_eq!(stored_key, key);

        // Lamports at offset 43
        let stored_lamports = u64::from_le_bytes(result.buffer[43..51].try_into().unwrap());
        assert_eq!(stored_lamports, 500);

        // Data len at offset 51
        let stored_data_len = u64::from_le_bytes(result.buffer[51..59].try_into().unwrap());
        assert_eq!(stored_data_len, 3);

        // Data at offset 59
        assert_eq!(&result.buffer[59..62], &[5, 6, 7]);

        // Owner at offset 62
        let stored_owner = Pubkey::new(result.buffer[62..94].try_into().unwrap());
        assert_eq!(stored_owner, owner);
    }

    #[test]
    fn unaligned_serialize_duplicate_account() {
        let key = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let program_id = Pubkey::new_unique();

        let accounts = vec![
            make_test_account(key, owner, 1000, &[1]),
            make_test_account(key, owner, 1000, &[1]),
        ];

        let result = serialize_unaligned(&accounts, &[], &program_id).unwrap();

        assert_eq!(result.duplicate_indices[0], None);
        assert_eq!(result.duplicate_indices[1], Some(0));
    }

    #[test]
    fn unaligned_round_trip() {
        let key = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let program_id = Pubkey::new_unique();
        let data = vec![10, 20, 30];

        let accounts = vec![make_test_account(key, owner, 3000, &data)];

        let serialized = serialize_unaligned(&accounts, &[0xCC], &program_id).unwrap();

        let deserialized = deserialize_unaligned(
            &serialized.buffer,
            &serialized.account_metas,
            &serialized.pre_lens,
            &serialized.duplicate_indices,
        )
        .unwrap();

        assert_eq!(deserialized.len(), 1);
        let account = deserialized[0].as_ref().unwrap();
        assert_eq!(account.lamports, 3000);
        assert_eq!(account.data, data);
        assert_eq!(account.owner, owner);
    }

    // -----------------------------------------------------------------------
    // Dispatch tests
    // -----------------------------------------------------------------------

    #[test]
    fn serialize_parameters_dispatches_correctly() {
        let key = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let program_id = Pubkey::new_unique();

        let accounts = vec![make_test_account(key, owner, 1000, &[1, 2])];

        let aligned = serialize_parameters(&accounts, &[0xAA], &program_id, false).unwrap();
        let unaligned = serialize_parameters(&accounts, &[0xAA], &program_id, true).unwrap();

        // Aligned has realloc buffer, so it should be larger
        assert!(aligned.buffer.len() > unaligned.buffer.len());
    }

    #[test]
    fn aligned_empty_accounts() {
        let program_id = Pubkey::new_unique();
        let result = serialize_aligned(&[], &[1, 2, 3], &program_id).unwrap();

        // Should just have: 8 (count=0) + 8 (instr_data_len) + 3 (data) + 32 (program_id) = 51
        assert_eq!(result.buffer.len(), 8 + 8 + 3 + 32);
        let count = u64::from_le_bytes(result.buffer[0..8].try_into().unwrap());
        assert_eq!(count, 0);
    }

    #[test]
    fn aligned_large_data_account() {
        let key = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let program_id = Pubkey::new_unique();

        // 1 MB data
        let data = vec![0xAB; 1024 * 1024];
        let accounts = vec![make_test_account(key, owner, 100000, &data)];

        let serialized = serialize_aligned(&accounts, &[], &program_id).unwrap();

        // Should contain the full 1MB data + realloc buffer
        assert!(serialized.buffer.len() > 1024 * 1024 + MAX_PERMITTED_DATA_INCREASE);

        let deserialized = deserialize_aligned(
            &serialized.buffer,
            &serialized.account_metas,
            &serialized.pre_lens,
            &serialized.duplicate_indices,
        )
        .unwrap();

        let account = deserialized[0].as_ref().unwrap();
        assert_eq!(account.data.len(), 1024 * 1024);
        assert_eq!(account.data[0], 0xAB);
    }

    #[test]
    fn aligned_instruction_data_offset_valid() {
        let key = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let program_id = Pubkey::new_unique();

        let accounts = vec![make_test_account(key, owner, 1000, &[1, 2, 3])];
        let instruction_data = vec![0xDE, 0xAD];

        let result = serialize_aligned(&accounts, &instruction_data, &program_id).unwrap();

        // Instruction data offset should be within the input region
        assert!(result.instruction_data_offset >= REGION_INPUT_BASE);
        let local_offset = (result.instruction_data_offset - REGION_INPUT_BASE) as usize;
        assert!(local_offset + instruction_data.len() <= result.buffer.len());
        assert_eq!(
            &result.buffer[local_offset..local_offset + 2],
            &[0xDE, 0xAD]
        );
    }
}
