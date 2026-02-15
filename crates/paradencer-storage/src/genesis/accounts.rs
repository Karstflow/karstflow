//! Initial account creation from genesis config.

use super::{GenesisAccount, GenesisConfig};
use paradencer_types::{Account, AccountData, AccountMeta};

/// Create the set of initial accounts from genesis config.
/// Includes genesis accounts plus rewards pool accounts.
pub fn create_initial_accounts(config: &GenesisConfig) -> Vec<(paradencer_types::Pubkey, Account)> {
    let capacity = config.accounts.len() + config.rewards_pool_accounts.len();
    let mut accounts = Vec::with_capacity(capacity);

    for (pubkey, genesis_account) in &config.accounts {
        accounts.push((*pubkey, genesis_account_to_runtime(genesis_account)));
    }

    for (pubkey, genesis_account) in &config.rewards_pool_accounts {
        accounts.push((*pubkey, genesis_account_to_runtime(genesis_account)));
    }

    accounts
}

/// Convert a genesis account representation to a runtime Account.
pub fn genesis_account_to_runtime(genesis: &GenesisAccount) -> Account {
    Account {
        meta: AccountMeta::new(
            genesis.lamports,
            genesis.owner,
            genesis.executable,
            genesis.rent_epoch,
        ),
        data: AccountData::new(genesis.data.clone()),
    }
}
