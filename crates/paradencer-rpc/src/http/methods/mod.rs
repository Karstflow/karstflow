mod accounts;
mod basic;
mod cluster;
mod history;
mod inflation;
mod ledger;
mod params;
pub(super) mod shared;
mod transactions;

use crate::state::{BankAccessProvider, RpcCommitment, RpcRuntimeSnapshot, TransactionSubmitter};
use std::sync::Arc;

use super::method_error::RpcMethodError;
use super::registry::RpcMethod;

pub(super) fn dispatch_method(
    method: RpcMethod,
    request: &serde_json::Value,
    snapshot: RpcRuntimeSnapshot,
    commitment: RpcCommitment,
    full_api: bool,
    bank_access: Option<&Arc<dyn BankAccessProvider>>,
    tx_submitter: Option<&Arc<dyn TransactionSubmitter>>,
) -> Result<serde_json::Value, RpcMethodError> {
    match method {
        RpcMethod::GetHealth
        | RpcMethod::GetVersion
        | RpcMethod::GetGenesisHash
        | RpcMethod::GetIdentity
        | RpcMethod::GetEpochSchedule
        | RpcMethod::GetMinimumBalanceForRentExemption
        | RpcMethod::GetStakeMinimumDelegation
        | RpcMethod::GetEpochInfo
        | RpcMethod::GetFirstAvailableBlock
        | RpcMethod::MinimumLedgerSlot
        | RpcMethod::GetMaxShredInsertSlot
        | RpcMethod::GetHighestSnapshotSlot
        | RpcMethod::GetMaxRetransmitSlot => {
            basic::handle(method, request, snapshot, commitment, full_api, bank_access)
        }

        RpcMethod::GetSlot
        | RpcMethod::GetBlockHeight
        | RpcMethod::GetBlockCount
        | RpcMethod::GetTransactionCount
        | RpcMethod::IsBlockhashValid
        | RpcMethod::GetFeeForMessage
        | RpcMethod::GetFees
        | RpcMethod::GetFeeCalculatorForBlockhash
        | RpcMethod::GetRecentBlockhash
        | RpcMethod::GetLatestBlockhash
        | RpcMethod::GetRecentPerformanceSamples => {
            ledger::handle(method, request, snapshot, commitment, bank_access)
        }

        RpcMethod::GetInflationGovernor
        | RpcMethod::GetInflationRate
        | RpcMethod::GetInflationReward => {
            inflation::handle(method, request, snapshot, commitment, bank_access)
        }

        RpcMethod::GetBalance
        | RpcMethod::GetSupply
        | RpcMethod::GetTokenSupply
        | RpcMethod::GetTokenAccountBalance
        | RpcMethod::GetLargestAccounts
        | RpcMethod::GetTokenLargestAccounts
        | RpcMethod::GetProgramAccounts
        | RpcMethod::GetTokenAccountsByOwner
        | RpcMethod::GetTokenAccountsByDelegate
        | RpcMethod::GetAccountInfo
        | RpcMethod::GetMultipleAccounts
        | RpcMethod::GetSignatureStatuses => {
            accounts::handle(method, request, snapshot, commitment, bank_access)
        }

        RpcMethod::GetSignaturesForAddress
        | RpcMethod::GetConfirmedSignaturesForAddress2
        | RpcMethod::GetClusterNodes
        | RpcMethod::GetVoteAccounts
        | RpcMethod::GetSlotLeader
        | RpcMethod::GetSlotLeaders
        | RpcMethod::GetLeaderSchedule
        | RpcMethod::GetBlockProduction
        | RpcMethod::GetRecentPrioritizationFees => {
            cluster::handle(method, request, snapshot, commitment, bank_access)
        }

        RpcMethod::GetBlocks
        | RpcMethod::GetBlocksWithLimit
        | RpcMethod::GetBlockCommitment
        | RpcMethod::GetBlock
        | RpcMethod::GetConfirmedBlocks
        | RpcMethod::GetConfirmedBlock
        | RpcMethod::GetBlockTime
        | RpcMethod::GetTransaction
        | RpcMethod::GetConfirmedTransaction => {
            history::handle(method, request, snapshot, commitment, bank_access)
        }

        RpcMethod::SendTransaction | RpcMethod::SimulateTransaction => transactions::handle(
            method,
            request,
            snapshot,
            commitment,
            bank_access,
            tx_submitter,
        ),
    }
}
