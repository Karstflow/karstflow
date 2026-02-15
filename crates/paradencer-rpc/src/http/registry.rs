use super::method_error::RpcMethodError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcMethod {
    GetHealth,
    GetVersion,
    GetSlot,
    GetBlockHeight,
    GetBlockCount,
    GetTransactionCount,
    GetBalance,
    GetGenesisHash,
    GetIdentity,
    GetEpochSchedule,
    GetMinimumBalanceForRentExemption,
    GetStakeMinimumDelegation,
    GetSlotLeader,
    GetSlotLeaders,
    GetEpochInfo,
    GetFirstAvailableBlock,
    MinimumLedgerSlot,
    GetMaxShredInsertSlot,
    GetHighestSnapshotSlot,
    GetMaxRetransmitSlot,
    IsBlockhashValid,
    GetFeeForMessage,
    GetFees,
    GetFeeCalculatorForBlockhash,
    GetRecentBlockhash,
    GetLatestBlockhash,
    GetRecentPerformanceSamples,
    GetInflationGovernor,
    GetInflationRate,
    GetInflationReward,
    GetSignaturesForAddress,
    GetConfirmedSignaturesForAddress2,
    GetClusterNodes,
    GetVoteAccounts,
    GetSupply,
    GetTokenSupply,
    GetTokenAccountBalance,
    GetLargestAccounts,
    GetTokenLargestAccounts,
    GetProgramAccounts,
    GetTokenAccountsByOwner,
    GetTokenAccountsByDelegate,
    GetAccountInfo,
    GetMultipleAccounts,
    GetSignatureStatuses,
    GetLeaderSchedule,
    GetBlockProduction,
    GetRecentPrioritizationFees,
    GetBlocks,
    GetBlocksWithLimit,
    GetBlockCommitment,
    GetBlock,
    GetConfirmedBlocks,
    GetConfirmedBlock,
    GetBlockTime,
    GetTransaction,
    GetConfirmedTransaction,
    SendTransaction,
    SimulateTransaction,
}

pub const REGISTERED_RPC_METHODS: &[RpcMethod] = &[
    RpcMethod::GetHealth,
    RpcMethod::GetVersion,
    RpcMethod::GetSlot,
    RpcMethod::GetBlockHeight,
    RpcMethod::GetBlockCount,
    RpcMethod::GetTransactionCount,
    RpcMethod::GetBalance,
    RpcMethod::GetGenesisHash,
    RpcMethod::GetIdentity,
    RpcMethod::GetEpochSchedule,
    RpcMethod::GetMinimumBalanceForRentExemption,
    RpcMethod::GetStakeMinimumDelegation,
    RpcMethod::GetSlotLeader,
    RpcMethod::GetSlotLeaders,
    RpcMethod::GetEpochInfo,
    RpcMethod::GetFirstAvailableBlock,
    RpcMethod::MinimumLedgerSlot,
    RpcMethod::GetMaxShredInsertSlot,
    RpcMethod::GetHighestSnapshotSlot,
    RpcMethod::GetMaxRetransmitSlot,
    RpcMethod::IsBlockhashValid,
    RpcMethod::GetFeeForMessage,
    RpcMethod::GetFees,
    RpcMethod::GetFeeCalculatorForBlockhash,
    RpcMethod::GetRecentBlockhash,
    RpcMethod::GetLatestBlockhash,
    RpcMethod::GetRecentPerformanceSamples,
    RpcMethod::GetInflationGovernor,
    RpcMethod::GetInflationRate,
    RpcMethod::GetInflationReward,
    RpcMethod::GetSignaturesForAddress,
    RpcMethod::GetConfirmedSignaturesForAddress2,
    RpcMethod::GetClusterNodes,
    RpcMethod::GetVoteAccounts,
    RpcMethod::GetSupply,
    RpcMethod::GetTokenSupply,
    RpcMethod::GetTokenAccountBalance,
    RpcMethod::GetLargestAccounts,
    RpcMethod::GetTokenLargestAccounts,
    RpcMethod::GetProgramAccounts,
    RpcMethod::GetTokenAccountsByOwner,
    RpcMethod::GetTokenAccountsByDelegate,
    RpcMethod::GetAccountInfo,
    RpcMethod::GetMultipleAccounts,
    RpcMethod::GetSignatureStatuses,
    RpcMethod::GetLeaderSchedule,
    RpcMethod::GetBlockProduction,
    RpcMethod::GetRecentPrioritizationFees,
    RpcMethod::GetBlocks,
    RpcMethod::GetBlocksWithLimit,
    RpcMethod::GetBlockCommitment,
    RpcMethod::GetBlock,
    RpcMethod::GetConfirmedBlocks,
    RpcMethod::GetConfirmedBlock,
    RpcMethod::GetBlockTime,
    RpcMethod::GetTransaction,
    RpcMethod::GetConfirmedTransaction,
    RpcMethod::SendTransaction,
    RpcMethod::SimulateTransaction,
];

impl RpcMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GetHealth => "getHealth",
            Self::GetVersion => "getVersion",
            Self::GetSlot => "getSlot",
            Self::GetBlockHeight => "getBlockHeight",
            Self::GetBlockCount => "getBlockCount",
            Self::GetTransactionCount => "getTransactionCount",
            Self::GetBalance => "getBalance",
            Self::GetGenesisHash => "getGenesisHash",
            Self::GetIdentity => "getIdentity",
            Self::GetEpochSchedule => "getEpochSchedule",
            Self::GetMinimumBalanceForRentExemption => "getMinimumBalanceForRentExemption",
            Self::GetStakeMinimumDelegation => "getStakeMinimumDelegation",
            Self::GetSlotLeader => "getSlotLeader",
            Self::GetSlotLeaders => "getSlotLeaders",
            Self::GetEpochInfo => "getEpochInfo",
            Self::GetFirstAvailableBlock => "getFirstAvailableBlock",
            Self::MinimumLedgerSlot => "minimumLedgerSlot",
            Self::GetMaxShredInsertSlot => "getMaxShredInsertSlot",
            Self::GetHighestSnapshotSlot => "getHighestSnapshotSlot",
            Self::GetMaxRetransmitSlot => "getMaxRetransmitSlot",
            Self::IsBlockhashValid => "isBlockhashValid",
            Self::GetFeeForMessage => "getFeeForMessage",
            Self::GetFees => "getFees",
            Self::GetFeeCalculatorForBlockhash => "getFeeCalculatorForBlockhash",
            Self::GetRecentBlockhash => "getRecentBlockhash",
            Self::GetLatestBlockhash => "getLatestBlockhash",
            Self::GetRecentPerformanceSamples => "getRecentPerformanceSamples",
            Self::GetInflationGovernor => "getInflationGovernor",
            Self::GetInflationRate => "getInflationRate",
            Self::GetInflationReward => "getInflationReward",
            Self::GetSignaturesForAddress => "getSignaturesForAddress",
            Self::GetConfirmedSignaturesForAddress2 => "getConfirmedSignaturesForAddress2",
            Self::GetClusterNodes => "getClusterNodes",
            Self::GetVoteAccounts => "getVoteAccounts",
            Self::GetSupply => "getSupply",
            Self::GetTokenSupply => "getTokenSupply",
            Self::GetTokenAccountBalance => "getTokenAccountBalance",
            Self::GetLargestAccounts => "getLargestAccounts",
            Self::GetTokenLargestAccounts => "getTokenLargestAccounts",
            Self::GetProgramAccounts => "getProgramAccounts",
            Self::GetTokenAccountsByOwner => "getTokenAccountsByOwner",
            Self::GetTokenAccountsByDelegate => "getTokenAccountsByDelegate",
            Self::GetAccountInfo => "getAccountInfo",
            Self::GetMultipleAccounts => "getMultipleAccounts",
            Self::GetSignatureStatuses => "getSignatureStatuses",
            Self::GetLeaderSchedule => "getLeaderSchedule",
            Self::GetBlockProduction => "getBlockProduction",
            Self::GetRecentPrioritizationFees => "getRecentPrioritizationFees",
            Self::GetBlocks => "getBlocks",
            Self::GetBlocksWithLimit => "getBlocksWithLimit",
            Self::GetBlockCommitment => "getBlockCommitment",
            Self::GetBlock => "getBlock",
            Self::GetConfirmedBlocks => "getConfirmedBlocks",
            Self::GetConfirmedBlock => "getConfirmedBlock",
            Self::GetBlockTime => "getBlockTime",
            Self::GetTransaction => "getTransaction",
            Self::GetConfirmedTransaction => "getConfirmedTransaction",
            Self::SendTransaction => "sendTransaction",
            Self::SimulateTransaction => "simulateTransaction",
        }
    }

    pub fn requires_full_api(self) -> bool {
        matches!(
            self,
            Self::GetRecentPerformanceSamples
                | Self::GetInflationGovernor
                | Self::GetInflationRate
                | Self::GetInflationReward
                | Self::GetSignaturesForAddress
                | Self::GetConfirmedSignaturesForAddress2
                | Self::GetClusterNodes
                | Self::GetVoteAccounts
                | Self::GetSupply
                | Self::GetTokenSupply
                | Self::GetTokenAccountBalance
                | Self::GetLargestAccounts
                | Self::GetTokenLargestAccounts
                | Self::GetProgramAccounts
                | Self::GetTokenAccountsByOwner
                | Self::GetTokenAccountsByDelegate
                | Self::GetAccountInfo
                | Self::GetMultipleAccounts
                | Self::GetSignatureStatuses
                | Self::GetLeaderSchedule
                | Self::GetBlockProduction
                | Self::GetRecentPrioritizationFees
                | Self::GetBlocks
                | Self::GetBlocksWithLimit
                | Self::GetBlockCommitment
                | Self::GetBlock
                | Self::GetConfirmedBlocks
                | Self::GetConfirmedBlock
                | Self::GetBlockTime
                | Self::GetTransaction
                | Self::GetConfirmedTransaction
                | Self::SendTransaction
                | Self::SimulateTransaction
        )
    }
}

pub fn resolve_method(method_name: &str, full_api: bool) -> Result<RpcMethod, RpcMethodError> {
    let method = match method_name {
        "getHealth" => RpcMethod::GetHealth,
        "getVersion" => RpcMethod::GetVersion,
        "getSlot" => RpcMethod::GetSlot,
        "getBlockHeight" => RpcMethod::GetBlockHeight,
        "getBlockCount" => RpcMethod::GetBlockCount,
        "getTransactionCount" => RpcMethod::GetTransactionCount,
        "getBalance" => RpcMethod::GetBalance,
        "getGenesisHash" => RpcMethod::GetGenesisHash,
        "getIdentity" => RpcMethod::GetIdentity,
        "getEpochSchedule" => RpcMethod::GetEpochSchedule,
        "getMinimumBalanceForRentExemption" => RpcMethod::GetMinimumBalanceForRentExemption,
        "getStakeMinimumDelegation" => RpcMethod::GetStakeMinimumDelegation,
        "getSlotLeader" => RpcMethod::GetSlotLeader,
        "getSlotLeaders" => RpcMethod::GetSlotLeaders,
        "getEpochInfo" => RpcMethod::GetEpochInfo,
        "getFirstAvailableBlock" => RpcMethod::GetFirstAvailableBlock,
        "minimumLedgerSlot" => RpcMethod::MinimumLedgerSlot,
        "getMaxShredInsertSlot" => RpcMethod::GetMaxShredInsertSlot,
        "getHighestSnapshotSlot" => RpcMethod::GetHighestSnapshotSlot,
        "getMaxRetransmitSlot" => RpcMethod::GetMaxRetransmitSlot,
        "isBlockhashValid" => RpcMethod::IsBlockhashValid,
        "getFeeForMessage" => RpcMethod::GetFeeForMessage,
        "getFees" => RpcMethod::GetFees,
        "getFeeCalculatorForBlockhash" => RpcMethod::GetFeeCalculatorForBlockhash,
        "getRecentBlockhash" => RpcMethod::GetRecentBlockhash,
        "getLatestBlockhash" => RpcMethod::GetLatestBlockhash,
        "getRecentPerformanceSamples" => RpcMethod::GetRecentPerformanceSamples,
        "getInflationGovernor" => RpcMethod::GetInflationGovernor,
        "getInflationRate" => RpcMethod::GetInflationRate,
        "getInflationReward" => RpcMethod::GetInflationReward,
        "getSignaturesForAddress" => RpcMethod::GetSignaturesForAddress,
        "getConfirmedSignaturesForAddress2" => RpcMethod::GetConfirmedSignaturesForAddress2,
        "getClusterNodes" => RpcMethod::GetClusterNodes,
        "getVoteAccounts" => RpcMethod::GetVoteAccounts,
        "getSupply" => RpcMethod::GetSupply,
        "getTokenSupply" => RpcMethod::GetTokenSupply,
        "getTokenAccountBalance" => RpcMethod::GetTokenAccountBalance,
        "getLargestAccounts" => RpcMethod::GetLargestAccounts,
        "getTokenLargestAccounts" => RpcMethod::GetTokenLargestAccounts,
        "getProgramAccounts" => RpcMethod::GetProgramAccounts,
        "getTokenAccountsByOwner" => RpcMethod::GetTokenAccountsByOwner,
        "getTokenAccountsByDelegate" => RpcMethod::GetTokenAccountsByDelegate,
        "getAccountInfo" => RpcMethod::GetAccountInfo,
        "getMultipleAccounts" => RpcMethod::GetMultipleAccounts,
        "getSignatureStatuses" => RpcMethod::GetSignatureStatuses,
        "getLeaderSchedule" => RpcMethod::GetLeaderSchedule,
        "getBlockProduction" => RpcMethod::GetBlockProduction,
        "getRecentPrioritizationFees" => RpcMethod::GetRecentPrioritizationFees,
        "getBlocks" => RpcMethod::GetBlocks,
        "getBlocksWithLimit" => RpcMethod::GetBlocksWithLimit,
        "getBlockCommitment" => RpcMethod::GetBlockCommitment,
        "getBlock" => RpcMethod::GetBlock,
        "getConfirmedBlocks" => RpcMethod::GetConfirmedBlocks,
        "getConfirmedBlock" => RpcMethod::GetConfirmedBlock,
        "getBlockTime" => RpcMethod::GetBlockTime,
        "getTransaction" => RpcMethod::GetTransaction,
        "getConfirmedTransaction" => RpcMethod::GetConfirmedTransaction,
        "sendTransaction" => RpcMethod::SendTransaction,
        "simulateTransaction" => RpcMethod::SimulateTransaction,
        _ => return Err(RpcMethodError::MethodNotFound),
    };

    if method.requires_full_api() && !full_api {
        return Err(RpcMethodError::MethodNotFound);
    }

    Ok(method)
}

#[cfg(test)]
mod tests {
    use super::{resolve_method, RpcMethod, REGISTERED_RPC_METHODS};

    #[test]
    fn registered_methods_are_resolvable_with_full_api() {
        for method in REGISTERED_RPC_METHODS {
            let resolved =
                resolve_method(method.as_str(), true).expect("registered method resolves");
            assert_eq!(resolved, *method);
        }
    }

    #[test]
    fn full_api_gate_blocks_only_full_api_methods() {
        for method in REGISTERED_RPC_METHODS {
            let resolved = resolve_method(method.as_str(), false);
            if method.requires_full_api() {
                assert!(resolved.is_err(), "{} should be gated", method.as_str());
            } else {
                assert_eq!(resolved.ok(), Some(*method));
            }
        }
    }

    #[test]
    fn unknown_method_is_rejected() {
        assert!(resolve_method("unknownMethod", true).is_err());
        assert!(resolve_method("unknownMethod", false).is_err());
    }

    #[test]
    fn method_name_roundtrip_is_stable() {
        let methods = [
            RpcMethod::GetHealth,
            RpcMethod::GetVersion,
            RpcMethod::GetTransaction,
        ];
        for method in methods {
            let resolved = resolve_method(method.as_str(), true).expect("roundtrip");
            assert_eq!(resolved, method);
        }
    }
}
