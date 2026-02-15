use super::state::VoteState;
use crate::{ExecutionContext, ExecutionOutcome};
use paradencer_constants::vote_program::{
    COMPUTE_COST_BASE_INSTRUCTION, COMPUTE_COST_INITIALIZE, COMPUTE_COST_UPDATE_COMMISSION,
    COMPUTE_COST_VOTE, COMPUTE_COST_WITHDRAW, INSTRUCTION_AUTHORIZE, INSTRUCTION_INITIALIZE,
    INSTRUCTION_UPDATE_COMMISSION, INSTRUCTION_UPDATE_VALIDATOR_IDENTITY, INSTRUCTION_VOTE,
    INSTRUCTION_WITHDRAW,
};
use paradencer_types::{Account, AccountData, Pubkey};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct VoteProgramExecutor {
    base_cost: u64,
}

impl VoteProgramExecutor {
    pub fn new(base_cost: u64) -> Self {
        Self { base_cost }
    }

    pub fn execute(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        if context.instruction_data.is_empty() {
            return Err("Vote instruction data is empty".to_string());
        }

        let instruction_type = u32::from_le_bytes(
            context.instruction_data[0..4.min(context.instruction_data.len())]
                .try_into()
                .unwrap_or([0; 4]),
        );

        let mut compute_used = self.base_cost.saturating_add(COMPUTE_COST_BASE_INSTRUCTION);
        let mut modified_accounts = HashMap::new();
        let mut logs = Vec::new();

        match instruction_type {
            INSTRUCTION_INITIALIZE => {
                self.execute_initialize(
                    context,
                    &mut modified_accounts,
                    &mut logs,
                    &mut compute_used,
                )?;
            }
            INSTRUCTION_VOTE => {
                self.execute_vote(
                    context,
                    &mut modified_accounts,
                    &mut logs,
                    &mut compute_used,
                )?;
            }
            INSTRUCTION_WITHDRAW => {
                self.execute_withdraw(
                    context,
                    &mut modified_accounts,
                    &mut logs,
                    &mut compute_used,
                )?;
            }
            INSTRUCTION_UPDATE_VALIDATOR_IDENTITY => {
                logs.push("Vote: UpdateValidatorIdentity (not implemented)".to_string());
                compute_used = compute_used.saturating_add(100);
            }
            INSTRUCTION_UPDATE_COMMISSION => {
                self.execute_update_commission(
                    context,
                    &mut modified_accounts,
                    &mut logs,
                    &mut compute_used,
                )?;
            }
            INSTRUCTION_AUTHORIZE => {
                logs.push("Vote: Authorize (not implemented)".to_string());
                compute_used = compute_used.saturating_add(100);
            }
            _ => {
                logs.push(format!(
                    "Vote: Unknown instruction type {}",
                    instruction_type
                ));
                compute_used = compute_used.saturating_add(50);
            }
        }

        Ok(ExecutionOutcome {
            success: true,
            compute_units_consumed: compute_used,
            modified_accounts,
            logs,
            return_data: None,
        })
    }

    fn execute_initialize(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
        compute_used: &mut u64,
    ) -> Result<(), String> {
        logs.push("Vote: Initialize".to_string());

        if context.accounts.is_empty() {
            return Err("Initialize requires at least 1 account".to_string());
        }

        if context.instruction_data.len() < 101 {
            return Err("Initialize instruction data too short".to_string());
        }

        let node_pubkey = Pubkey::new_from_array(
            context.instruction_data[4..36]
                .try_into()
                .map_err(|_| "Failed to parse node pubkey")?,
        );
        let authorized_voter = Pubkey::new_from_array(
            context.instruction_data[36..68]
                .try_into()
                .map_err(|_| "Failed to parse authorized voter")?,
        );
        let authorized_withdrawer = Pubkey::new_from_array(
            context.instruction_data[68..100]
                .try_into()
                .map_err(|_| "Failed to parse authorized withdrawer")?,
        );
        let commission = context.instruction_data[100];

        let (vote_pubkey, mut vote_account, writable) = context.accounts[0].clone();

        if !writable {
            return Err("Vote account must be writable".to_string());
        }

        if !vote_account.data.as_ref().is_empty() {
            return Err("Vote account already initialized".to_string());
        }

        let vote_state = VoteState::new(
            node_pubkey,
            authorized_voter,
            authorized_withdrawer,
            commission,
        );
        vote_account.data = AccountData::new(vote_state.serialize());

        modified_accounts.insert(vote_pubkey, vote_account);

        *compute_used = compute_used.saturating_add(COMPUTE_COST_INITIALIZE);

        Ok(())
    }

    fn execute_vote(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
        compute_used: &mut u64,
    ) -> Result<(), String> {
        logs.push("Vote: Vote".to_string());

        if context.accounts.is_empty() {
            return Err("Vote requires at least 1 account".to_string());
        }

        if context.instruction_data.len() < 44 {
            return Err("Vote instruction data too short".to_string());
        }

        let slot = u64::from_le_bytes(
            context.instruction_data[4..12]
                .try_into()
                .map_err(|_| "Failed to parse slot")?,
        );
        let hash: [u8; 32] = context.instruction_data[12..44]
            .try_into()
            .map_err(|_| "Failed to parse hash")?;

        let (vote_pubkey, mut vote_account, writable) = context.accounts[0].clone();

        if !writable {
            return Err("Vote account must be writable".to_string());
        }

        let mut vote_state = VoteState::deserialize(vote_account.data.as_ref())
            .map_err(|e| format!("Failed to deserialize vote state: {:?}", e))?;

        vote_state
            .process_vote(slot, hash)
            .map_err(|e| format!("Vote processing failed: {:?}", e))?;

        vote_account.data = AccountData::new(vote_state.serialize());
        modified_accounts.insert(vote_pubkey, vote_account);

        *compute_used = compute_used.saturating_add(COMPUTE_COST_VOTE);

        Ok(())
    }

    fn execute_withdraw(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
        compute_used: &mut u64,
    ) -> Result<(), String> {
        logs.push("Vote: Withdraw".to_string());

        if context.accounts.len() < 2 {
            return Err("Withdraw requires at least 2 accounts".to_string());
        }

        if context.instruction_data.len() < 12 {
            return Err("Withdraw instruction data too short".to_string());
        }

        let lamports = u64::from_le_bytes(
            context.instruction_data[4..12]
                .try_into()
                .map_err(|_| "Failed to parse lamports")?,
        );

        let (vote_pubkey, mut vote_account, vote_writable) = context.accounts[0].clone();
        let (to_pubkey, mut to_account, to_writable) = context.accounts[1].clone();

        if !vote_writable || !to_writable {
            return Err("Both accounts must be writable".to_string());
        }

        if vote_account.meta.lamports < lamports {
            return Err(format!(
                "Insufficient lamports in vote account: {} < {}",
                vote_account.meta.lamports, lamports
            ));
        }

        vote_account.meta.lamports = vote_account.meta.lamports.saturating_sub(lamports);
        to_account.meta.lamports = to_account.meta.lamports.saturating_add(lamports);

        modified_accounts.insert(vote_pubkey, vote_account);
        modified_accounts.insert(to_pubkey, to_account);

        *compute_used = compute_used.saturating_add(COMPUTE_COST_WITHDRAW);

        Ok(())
    }

    fn execute_update_commission(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
        compute_used: &mut u64,
    ) -> Result<(), String> {
        logs.push("Vote: UpdateCommission".to_string());

        if context.accounts.is_empty() {
            return Err("UpdateCommission requires at least 1 account".to_string());
        }

        if context.instruction_data.len() < 5 {
            return Err("UpdateCommission instruction data too short".to_string());
        }

        let new_commission = context.instruction_data[4];

        let (vote_pubkey, mut vote_account, writable) = context.accounts[0].clone();

        if !writable {
            return Err("Vote account must be writable".to_string());
        }

        let mut vote_state = VoteState::deserialize(vote_account.data.as_ref())
            .map_err(|e| format!("Failed to deserialize vote state: {:?}", e))?;

        vote_state.commission = new_commission;

        vote_account.data = AccountData::new(vote_state.serialize());
        modified_accounts.insert(vote_pubkey, vote_account);

        *compute_used = compute_used.saturating_add(COMPUTE_COST_UPDATE_COMMISSION);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use paradencer_types::AccountMeta;

    #[test]
    fn vote_program_initialize_success() {
        let executor = VoteProgramExecutor::new(150);

        let vote_account = Account::zeroed();
        let node_pubkey = Pubkey::new_unique();
        let authorized_voter = Pubkey::new_unique();
        let authorized_withdrawer = Pubkey::new_unique();

        let mut instruction_data = vec![0, 0, 0, 0];
        instruction_data.extend_from_slice(node_pubkey.as_bytes());
        instruction_data.extend_from_slice(authorized_voter.as_bytes());
        instruction_data.extend_from_slice(authorized_withdrawer.as_bytes());
        instruction_data.push(10);

        let context = ExecutionContext::new(
            Pubkey::new_unique(),
            vec![(Pubkey::new_unique(), vote_account, true)],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);
        assert_eq!(outcome.modified_accounts.len(), 1);
    }

    #[test]
    fn vote_program_vote_success() {
        let executor = VoteProgramExecutor::new(150);

        let node_pubkey = Pubkey::new_unique();
        let authorized_voter = Pubkey::new_unique();
        let authorized_withdrawer = Pubkey::new_unique();
        let vote_state = VoteState::new(node_pubkey, authorized_voter, authorized_withdrawer, 5);

        let vote_account = Account {
            meta: AccountMeta {
                lamports: 1000,
                owner: Pubkey::new_unique(),
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::new(vote_state.serialize()),
        };

        let mut instruction_data = vec![2, 0, 0, 0];
        instruction_data.extend_from_slice(&100u64.to_le_bytes());
        instruction_data.extend_from_slice(&[1u8; 32]);

        let context = ExecutionContext::new(
            Pubkey::new_unique(),
            vec![(Pubkey::new_unique(), vote_account, true)],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);
        assert_eq!(outcome.modified_accounts.len(), 1);

        let modified = outcome.modified_accounts.values().next().unwrap();
        let updated_state = VoteState::deserialize(modified.data.as_ref()).unwrap();
        assert_eq!(updated_state.votes.len(), 1);
        assert_eq!(updated_state.votes[0].slot, 100);
    }

    #[test]
    fn vote_program_withdraw_success() {
        let executor = VoteProgramExecutor::new(150);

        let vote_state = VoteState::new(
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            5,
        );

        let vote_account = Account {
            meta: AccountMeta {
                lamports: 10_000,
                owner: Pubkey::new_unique(),
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::new(vote_state.serialize()),
        };

        let to_account = Account::zeroed();

        let mut instruction_data = vec![3, 0, 0, 0];
        instruction_data.extend_from_slice(&5_000u64.to_le_bytes());

        let vote_pubkey = Pubkey::new_unique();
        let to_pubkey = Pubkey::new_unique();

        let context = ExecutionContext::new(
            Pubkey::new_unique(),
            vec![
                (vote_pubkey, vote_account, true),
                (to_pubkey, to_account, true),
            ],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);
        assert_eq!(outcome.modified_accounts.len(), 2);

        let vote_modified = outcome.modified_accounts.get(&vote_pubkey).unwrap();
        assert_eq!(vote_modified.meta.lamports, 5_000);

        let to_modified = outcome.modified_accounts.get(&to_pubkey).unwrap();
        assert_eq!(to_modified.meta.lamports, 5_000);
    }

    #[test]
    fn vote_program_withdraw_insufficient_lamports() {
        let executor = VoteProgramExecutor::new(150);

        let vote_state = VoteState::new(
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            5,
        );

        let vote_account = Account {
            meta: AccountMeta {
                lamports: 1_000,
                owner: Pubkey::new_unique(),
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::new(vote_state.serialize()),
        };

        let to_account = Account::zeroed();

        let mut instruction_data = vec![3, 0, 0, 0];
        instruction_data.extend_from_slice(&5_000u64.to_le_bytes());

        let context = ExecutionContext::new(
            Pubkey::new_unique(),
            vec![
                (Pubkey::new_unique(), vote_account, true),
                (Pubkey::new_unique(), to_account, true),
            ],
            instruction_data,
        );

        let result = executor.execute(&context);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Insufficient lamports"));
    }

    #[test]
    fn vote_program_update_commission_success() {
        let executor = VoteProgramExecutor::new(150);

        let vote_state = VoteState::new(
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            5,
        );

        let vote_account = Account {
            meta: AccountMeta {
                lamports: 1_000,
                owner: Pubkey::new_unique(),
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::new(vote_state.serialize()),
        };

        let mut instruction_data = vec![5, 0, 0, 0];
        instruction_data.push(15);

        let context = ExecutionContext::new(
            Pubkey::new_unique(),
            vec![(Pubkey::new_unique(), vote_account, true)],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);

        let modified = outcome.modified_accounts.values().next().unwrap();
        let updated_state = VoteState::deserialize(modified.data.as_ref()).unwrap();
        assert_eq!(updated_state.commission, 15);
    }
}
