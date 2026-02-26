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

#[cfg(test)]
mod tests {
    use super::*;

    fn owner() -> Pubkey {
        Pubkey::new([1u8; 32])
    }

    // --- AccountMeta ---

    #[test]
    fn account_meta_new() {
        let meta = AccountMeta::new(1000, owner(), true, 42);
        assert_eq!(meta.lamports, 1000);
        assert_eq!(meta.owner, owner());
        assert!(meta.executable);
        assert_eq!(meta.rent_epoch, 42);
    }

    #[test]
    fn account_meta_zeroed() {
        let meta = AccountMeta::zeroed();
        assert_eq!(meta.lamports, 0);
        assert_eq!(meta.owner, Pubkey::zeroed());
        assert!(!meta.executable);
        assert_eq!(meta.rent_epoch, 0);
    }

    #[test]
    fn account_meta_default_is_zeroed() {
        assert_eq!(AccountMeta::default(), AccountMeta::zeroed());
    }

    // --- AccountData ---

    #[test]
    fn account_data_new() {
        let data = AccountData::new(vec![1, 2, 3]);
        assert_eq!(data.len(), 3);
        assert_eq!(data.as_slice(), &[1, 2, 3]);
    }

    #[test]
    fn account_data_empty() {
        let data = AccountData::empty();
        assert!(data.is_empty());
        assert_eq!(data.len(), 0);
    }

    #[test]
    fn account_data_resize() {
        let mut data = AccountData::new(vec![1, 2]);
        data.resize(5, 0);
        assert_eq!(data.len(), 5);
        assert_eq!(data.as_slice(), &[1, 2, 0, 0, 0]);
    }

    #[test]
    fn account_data_extend() {
        let mut data = AccountData::new(vec![1]);
        data.extend_from_slice(&[2, 3]);
        assert_eq!(data.as_slice(), &[1, 2, 3]);
    }

    #[test]
    fn account_data_mut_slice() {
        let mut data = AccountData::new(vec![0, 0, 0]);
        data.as_mut_slice()[1] = 42;
        assert_eq!(data.as_slice(), &[0, 42, 0]);
    }

    #[test]
    fn account_data_to_vec() {
        let data = AccountData::new(vec![5, 6, 7]);
        assert_eq!(data.to_vec(), vec![5, 6, 7]);
    }

    #[test]
    fn account_data_from_vec() {
        let data: AccountData = vec![10, 20].into();
        assert_eq!(data.len(), 2);
        assert_eq!(data.as_slice(), &[10, 20]);
    }

    #[test]
    fn account_data_as_ref() {
        let data = AccountData::new(vec![1, 2, 3]);
        let slice: &[u8] = data.as_ref();
        assert_eq!(slice, &[1, 2, 3]);
    }

    #[test]
    fn account_data_default_is_empty() {
        let data = AccountData::default();
        assert!(data.is_empty());
    }

    // --- Account ---

    #[test]
    fn account_new() {
        let acct = Account::new(500, vec![1, 2, 3], owner());
        assert_eq!(acct.meta.lamports, 500);
        assert_eq!(acct.data.len(), 3);
        assert_eq!(acct.meta.owner, owner());
        assert!(!acct.meta.executable);
    }

    #[test]
    fn account_new_with_meta() {
        let meta = AccountMeta::new(100, owner(), true, 10);
        let acct = Account::new_with_meta(meta.clone(), vec![0xAB]);
        assert_eq!(acct.meta, meta);
        assert_eq!(acct.data_len(), 1);
    }

    #[test]
    fn account_zeroed() {
        let acct = Account::zeroed();
        assert_eq!(acct.meta.lamports, 0);
        assert!(acct.data.is_empty());
    }

    #[test]
    fn account_default_is_zeroed() {
        assert_eq!(Account::default(), Account::zeroed());
    }

    #[test]
    fn account_data_len() {
        let acct = Account::new(0, vec![1, 2, 3, 4, 5], owner());
        assert_eq!(acct.data_len(), 5);
    }
}
