use crate::pubkey::Pubkey;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountMeta {
    pub lamports: u64,
    pub owner: Pubkey,
    pub executable: bool,
    pub rent_epoch: u64,
}

impl AccountMeta {
    pub const fn new(lamports: u64, owner: Pubkey, executable: bool, rent_epoch: u64) -> Self {
        Self {
            lamports,
            owner,
            executable,
            rent_epoch,
        }
    }

    pub const fn zeroed() -> Self {
        Self {
            lamports: 0,
            owner: Pubkey::zeroed(),
            executable: false,
            rent_epoch: 0,
        }
    }
}

impl Default for AccountMeta {
    fn default() -> Self {
        Self::zeroed()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountData {
    data: Vec<u8>,
}

impl AccountData {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn empty() -> Self {
        Self { data: Vec::new() }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
        }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.data.clone()
    }

    pub fn resize(&mut self, new_len: usize, value: u8) {
        self.data.resize(new_len, value);
    }

    pub fn extend_from_slice(&mut self, slice: &[u8]) {
        self.data.extend_from_slice(slice);
    }
}

impl Default for AccountData {
    fn default() -> Self {
        Self::empty()
    }
}

impl From<Vec<u8>> for AccountData {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl AsRef<[u8]> for AccountData {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub meta: AccountMeta,
    pub data: AccountData,
}

impl Account {
    pub fn new(lamports: u64, data: Vec<u8>, owner: Pubkey) -> Self {
        Self {
            meta: AccountMeta::new(lamports, owner, false, 0),
            data: AccountData::new(data),
        }
    }

    pub fn new_with_meta(meta: AccountMeta, data: Vec<u8>) -> Self {
        Self {
            meta,
            data: AccountData::new(data),
        }
    }

    pub fn zeroed() -> Self {
        Self {
            meta: AccountMeta::zeroed(),
            data: AccountData::empty(),
        }
    }

    pub fn data_len(&self) -> usize {
        self.data.len()
    }
}

impl Default for Account {
    fn default() -> Self {
        Self::zeroed()
    }
}
