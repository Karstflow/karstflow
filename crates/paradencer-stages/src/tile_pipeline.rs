/// Transaction pipeline tiles with zero-copy IPC.
///
/// Implements tile adapters that wrap existing stage logic (VerifyStage,
/// ResolvStage, PackScheduler, ExecStage) with the TileStem/StemInput
/// zero-copy IPC system. Each tile runs in a poll-driven service loop:
///
///   QuicTile → VerifyTile → DedupTile → ResolvTile → PackTile → ExecTile → PoH
///
/// Raw transaction bytes flow through DataRegion shared memory with
/// zero copies on the hot path. Fragment metadata carries sequence
/// numbers and control bits for flow control and dedup.
use paradencer_mesh::fragment::{ctl_pack, FragmentMeta};
use paradencer_mesh::stem::{InputResult, StemInput, StemOutputConfig, TileStem};
use paradencer_mesh::tile::Tile;
use std::sync::Arc;

use crate::dedup_stage::TransactionCache;
use crate::exec_stage::{ExecStage, ExecutionEngine, MockExecutionEngine};
use crate::pack_stage::{PackScheduler, PackedTransaction};
use crate::resolv_stage::{
    Blockhash, ResolvOutcome, ResolvStage, ResolvStats, ResolvedTransaction,
};
use crate::verify_stage::{
    TransactionSource, UnverifiedTransaction, VerifyOutcome, VerifyStage, VerifyStats,
};

// ---------------------------------------------------------------------------
// Wire format helpers
// ---------------------------------------------------------------------------

/// Pack a transaction source into the fragment control field's origin bits.
fn source_to_origin(source: TransactionSource) -> u16 {
    match source {
        TransactionSource::Quic => 0,
        TransactionSource::Gossip => 1,
        TransactionSource::Bundle => 2,
        TransactionSource::Forwarded => 3,
    }
}

/// Unpack a transaction source from the fragment control field's origin bits.
fn origin_to_source(origin: u16) -> TransactionSource {
    match origin {
        1 => TransactionSource::Gossip,
        2 => TransactionSource::Bundle,
        3 => TransactionSource::Forwarded,
        _ => TransactionSource::Quic,
    }
}

/// Extract the first 8 bytes of a transaction payload as a signature
/// fingerprint for the fragment sig field.
fn payload_sig(payload: &[u8]) -> u64 {
    if payload.len() >= 8 {
        u64::from_le_bytes(payload[..8].try_into().unwrap())
    } else {
        let mut buf = [0u8; 8];
        buf[..payload.len()].copy_from_slice(payload);
        u64::from_le_bytes(buf)
    }
}

// ---------------------------------------------------------------------------
// VerifyTile
// ---------------------------------------------------------------------------

/// Signature verification tile.
///
/// Consumes raw transaction packets from an upstream tile (typically QUIC),
/// verifies Ed25519 signatures in batches, and publishes verified
/// transaction bytes to the downstream resolv tile.
///
/// The fragment metadata carries:
/// - `sig`: first 8 bytes of the transaction signature (dedup fingerprint)
/// - `ctl`: source origin in origin bits, SOM+EOM set (single-fragment)
/// - Payload: raw transaction bytes (same as input, zero-copy forwarded)
pub struct VerifyTile {
    stage: VerifyStage,
    input: StemInput,
    output: TileStem,
    /// Scratch buffer for building UnverifiedTransaction from raw bytes.
    /// Avoids allocation per fragment.
    batch_results: Vec<(Vec<u8>, TransactionSource)>,
}

impl VerifyTile {
    /// Create a new verify tile.
    ///
    /// # Safety
    ///
    /// The upstream stem that owns the input's resources must outlive
    /// this tile. The caller must ensure SPSC access patterns.
    pub unsafe fn new(
        stage: VerifyStage,
        input: StemInput,
        output_config: StemOutputConfig,
    ) -> Self {
        Self {
            stage,
            input,
            output: TileStem::new(&[output_config]),
            batch_results: Vec::with_capacity(128),
        }
    }

    /// Access the output stem (for wiring downstream consumers).
    pub fn output_stem(&self) -> &TileStem {
        &self.output
    }

    /// Get a shared reference to the verify stage statistics.
    pub fn stats(&self) -> Arc<VerifyStats> {
        self.stage.stats()
    }
}

impl Tile for VerifyTile {
    fn name(&self) -> &str {
        "verify"
    }

    fn service(&mut self) -> usize {
        let mut processed = 0usize;

        // Refresh output credits from downstream consumer progress.
        self.output.refresh_all_credits();

        // Poll input for available fragments.
        loop {
            if !self.output.has_credits() {
                break;
            }

            match self.input.receive(1) {
                InputResult::Ready { meta, payload } => {
                    let source = origin_to_source(paradencer_mesh::fragment::ctl_origin(meta.ctl));
                    let sig_bytes = payload_sig(payload);

                    // Build an UnverifiedTransaction from raw bytes.
                    // In a full implementation, this would parse the wire
                    // format to extract signature offsets. For now, we
                    // use a simplified layout.
                    let unverified = parse_unverified_transaction(payload, source);

                    let outcome = self.stage.submit(unverified);
                    if outcome == VerifyOutcome::Malformed || outcome == VerifyOutcome::Filtered {
                        processed += 1;
                        continue;
                    }

                    // Batch is filling up — check if we should flush.
                    if self.stage.should_flush() {
                        let results = self.stage.flush();
                        for (verified, outcome) in results {
                            if outcome == VerifyOutcome::Valid {
                                let ctl =
                                    ctl_pack(source_to_origin(verified.source), true, true, false);
                                let sig = payload_sig(&verified.payload);
                                self.output.publish(0, sig, &verified.payload, ctl, 0, 0);
                            }
                        }
                    }

                    processed += 1;
                }
                InputResult::Overrun { recover_seq: _ } => {
                    // Lost fragments — clear pending batch and continue.
                    let _ = self.stage.flush();
                    processed += 1;
                }
                InputResult::Empty => break,
            }
        }

        // Flush any remaining pending transactions.
        if self.stage.pending_count() > 0 {
            let results = self.stage.flush();
            for (verified, outcome) in results {
                if outcome == VerifyOutcome::Valid {
                    let ctl = ctl_pack(source_to_origin(verified.source), true, true, false);
                    let sig = payload_sig(&verified.payload);
                    self.output.publish(0, sig, &verified.payload, ctl, 0, 0);
                }
            }
        }

        processed
    }
}

// ---------------------------------------------------------------------------
// DedupTile
// ---------------------------------------------------------------------------

/// Deduplication tile that filters duplicate transactions between
/// signature verification and blockhash resolution.
///
/// Uses `TransactionCache` (ring buffer + open-addressing hash map) for
/// O(1) amortized duplicate detection. Transactions are identified by
/// their signature fingerprint (first 8 bytes of signature), carried in
/// the fragment's `sig` field.
///
/// Duplicate fragments are silently dropped. Unique fragments are
/// forwarded to the downstream resolv tile with metadata preserved.
pub struct DedupTile {
    cache: TransactionCache,
    input: StemInput,
    output: TileStem,
    /// Total fragments processed.
    total_processed: u64,
    /// Fragments dropped as duplicates.
    duplicates_dropped: u64,
}

impl DedupTile {
    /// Create a new dedup tile.
    ///
    /// # Safety
    ///
    /// The upstream stem that owns the input's resources must outlive
    /// this tile. The caller must ensure SPSC access patterns.
    pub unsafe fn new(depth: usize, input: StemInput, output_config: StemOutputConfig) -> Self {
        Self {
            cache: TransactionCache::new(depth),
            input,
            output: TileStem::new(&[output_config]),
            total_processed: 0,
            duplicates_dropped: 0,
        }
    }

    /// Access the output stem (for wiring downstream consumers).
    pub fn output_stem(&self) -> &TileStem {
        &self.output
    }

    /// Number of fragments processed.
    pub fn total_processed(&self) -> u64 {
        self.total_processed
    }

    /// Number of duplicate fragments dropped.
    pub fn duplicates_dropped(&self) -> u64 {
        self.duplicates_dropped
    }

    /// Reset the dedup cache (e.g. at epoch boundary).
    pub fn reset_cache(&mut self) {
        self.cache.reset();
    }
}

impl Tile for DedupTile {
    fn name(&self) -> &str {
        "dedup"
    }

    fn service(&mut self) -> usize {
        let mut processed = 0usize;

        self.output.refresh_all_credits();

        loop {
            if !self.output.has_credits() {
                break;
            }

            match self.input.receive(1) {
                InputResult::Ready { meta, payload } => {
                    self.total_processed += 1;

                    // Use the sig field as the dedup tag
                    let tag = meta.sig;

                    if self.cache.insert(tag) {
                        // Duplicate — drop
                        self.duplicates_dropped += 1;
                    } else {
                        // Unique — forward with same metadata
                        self.output.publish(
                            0,
                            meta.sig,
                            payload,
                            meta.ctl,
                            meta.sz.into(),
                            meta.chunk,
                        );
                    }

                    processed += 1;
                }
                InputResult::Overrun { .. } => {
                    processed += 1;
                }
                InputResult::Empty => break,
            }
        }

        processed
    }
}

// ---------------------------------------------------------------------------
// ResolvTile
// ---------------------------------------------------------------------------

/// Blockhash resolution tile.
///
/// Consumes verified transactions from the verify tile, resolves their
/// blockhashes, and publishes resolved transactions to the pack tile.
///
/// Fragment metadata follows the same convention as VerifyTile.
/// Transactions with unknown blockhashes are stashed internally.
pub struct ResolvTile {
    stage: ResolvStage,
    input: StemInput,
    output: TileStem,
}

impl ResolvTile {
    /// Create a new resolv tile.
    ///
    /// # Safety
    ///
    /// The upstream stem that owns the input's resources must outlive
    /// this tile.
    pub unsafe fn new(
        stage: ResolvStage,
        input: StemInput,
        output_config: StemOutputConfig,
    ) -> Self {
        Self {
            stage,
            input,
            output: TileStem::new(&[output_config]),
        }
    }

    /// Access the output stem (for wiring downstream consumers).
    pub fn output_stem(&self) -> &TileStem {
        &self.output
    }

    /// Get a shared reference to the resolv stage statistics.
    pub fn stats(&self) -> Arc<ResolvStats> {
        self.stage.stats()
    }

    /// Register a new blockhash. Unstashed transactions that match are
    /// published to the output.
    pub fn register_blockhash(&mut self, hash: Blockhash, slot: u64) {
        let unstashed = self.stage.register_blockhash(hash, slot);
        for (resolved, _expires_at) in unstashed {
            self.publish_resolved(&resolved);
        }
    }

    /// Advance the current slot for expiry tracking.
    pub fn advance_slot(&mut self, slot: u64) {
        self.stage.advance_slot(slot);
    }

    fn publish_resolved(&mut self, resolved: &ResolvedTransaction) {
        let ctl = ctl_pack(0, true, true, resolved.is_vote);
        let sig = payload_sig(&resolved.payload);
        self.output.publish(0, sig, &resolved.payload, ctl, 0, 0);
    }
}

impl Tile for ResolvTile {
    fn name(&self) -> &str {
        "resolv"
    }

    fn service(&mut self) -> usize {
        let mut processed = 0usize;

        self.output.refresh_all_credits();

        loop {
            if !self.output.has_credits() {
                break;
            }

            match self.input.receive(1) {
                InputResult::Ready { meta, payload } => {
                    // Build a ResolvedTransaction from the verified bytes.
                    let resolved = parse_resolved_transaction(payload);

                    match self.stage.resolve(resolved.clone()) {
                        ResolvOutcome::Valid { .. } => {
                            self.publish_resolved(&resolved);
                        }
                        ResolvOutcome::Stashed
                        | ResolvOutcome::Expired
                        | ResolvOutcome::StashFull => {
                            // Stashed or dropped — no output.
                        }
                    }

                    processed += 1;
                }
                InputResult::Overrun { .. } => {
                    processed += 1;
                }
                InputResult::Empty => break,
            }
        }

        processed
    }
}

// ---------------------------------------------------------------------------
// Transaction wire-format parsing helpers
// ---------------------------------------------------------------------------

/// Parse raw transaction bytes into an UnverifiedTransaction.
///
/// The wire format for Solana transactions:
/// - First byte(s): compact-u16 number of signatures
/// - Then: N * 64-byte signatures
/// - Then: message (header + account keys + blockhash + instructions)
///
/// This is a simplified parser that extracts just enough to feed the
/// verification stage. Production implementation would use the full
/// transaction parser from paradencer-types.
fn parse_unverified_transaction(
    payload: &[u8],
    source: TransactionSource,
) -> UnverifiedTransaction {
    // Minimal bounds check.
    if payload.len() < 97 {
        // Too short for even 1 signature + 1 pubkey + message header
        return UnverifiedTransaction {
            payload: payload.to_vec(),
            source,
            num_signatures: 0,
            signature_offset: 0,
            message_offset: 0,
            signer_offsets: vec![],
        };
    }

    // Read number of signatures (compact-u16 at byte 0).
    let (num_sigs, sigs_offset) = read_compact_u16(payload);
    if num_sigs == 0 || sigs_offset + (num_sigs as usize) * 64 > payload.len() {
        return UnverifiedTransaction {
            payload: payload.to_vec(),
            source,
            num_signatures: 0,
            signature_offset: 0,
            message_offset: 0,
            signer_offsets: vec![],
        };
    }

    let signature_offset = sigs_offset;
    let message_offset = sigs_offset + (num_sigs as usize) * 64;

    // Message header: [num_required_sigs, num_readonly_signed,
    //                  num_readonly_unsigned]
    // Followed by compact-u16 number of account keys, then 32-byte keys.
    let msg = &payload[message_offset..];
    if msg.len() < 4 {
        return UnverifiedTransaction {
            payload: payload.to_vec(),
            source,
            num_signatures: num_sigs,
            signature_offset,
            message_offset,
            signer_offsets: vec![],
        };
    }

    let _num_required = msg[0];
    let (num_accounts, accounts_offset) = read_compact_u16(&msg[3..]);
    let keys_start = message_offset + 3 + accounts_offset;

    let signer_offsets: Vec<usize> = (0..num_sigs as usize)
        .map(|i| keys_start + i * 32)
        .filter(|&off| off + 32 <= payload.len())
        .collect();

    UnverifiedTransaction {
        payload: payload.to_vec(),
        source,
        num_signatures: num_sigs,
        signature_offset,
        message_offset,
        signer_offsets,
    }
}

/// Parse verified transaction bytes into a ResolvedTransaction.
///
/// Extracts the blockhash from the transaction message for resolution.
/// Priority fee and compute units are set to defaults (the pack stage
/// will compute accurate values from the parsed instructions).
fn parse_resolved_transaction(payload: &[u8]) -> ResolvedTransaction {
    let blockhash = extract_blockhash(payload);

    ResolvedTransaction {
        payload: payload.to_vec(),
        blockhash,
        priority_fee: 0,
        compute_units: paradencer_constants::execution::MAX_COMPUTE_UNITS,
        is_vote: false,
    }
}

/// Extract the 32-byte blockhash from a raw transaction payload.
///
/// The blockhash is located in the message after the account keys:
///   message_offset + 3 (header) + accounts_size → 32-byte blockhash
fn extract_blockhash(payload: &[u8]) -> Blockhash {
    if payload.len() < 97 {
        return [0u8; 32];
    }

    let (num_sigs, sigs_offset) = read_compact_u16(payload);
    let message_offset = sigs_offset + (num_sigs as usize) * 64;
    let msg = &payload[message_offset..];

    if msg.len() < 4 {
        return [0u8; 32];
    }

    let (num_accounts, accounts_offset) = read_compact_u16(&msg[3..]);
    let keys_end = 3 + accounts_offset + (num_accounts as usize) * 32;

    if msg.len() < keys_end + 32 {
        return [0u8; 32];
    }

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&msg[keys_end..keys_end + 32]);
    hash
}

/// Read a compact-u16 from the start of a byte slice.
/// Returns (value, bytes_consumed).
fn read_compact_u16(data: &[u8]) -> (u16, usize) {
    if data.is_empty() {
        return (0, 0);
    }

    let first = data[0] as u16;
    if first < 0x80 {
        return (first, 1);
    }

    if data.len() < 2 {
        return (0, 0);
    }

    let second = data[1] as u16;
    if second < 0x80 {
        return ((first & 0x7F) | (second << 7), 2);
    }

    if data.len() < 3 {
        return (0, 0);
    }

    let third = data[2] as u16;
    ((first & 0x7F) | ((second & 0x7F) << 7) | (third << 14), 3)
}

// ---------------------------------------------------------------------------
// TransactionPipeline — wires tiles together
// ---------------------------------------------------------------------------

/// Configuration for the transaction pipeline.
#[derive(Debug, Clone)]
pub struct PipelineConfig {
    /// MTU for inter-tile links (max transaction size).
    pub link_mtu: usize,
    /// Ring depth for inter-tile links.
    pub link_depth: usize,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            link_mtu: paradencer_constants::ipc::DATA_REGION_DEFAULT_MTU,
            link_depth: paradencer_constants::ipc::META_RING_DEFAULT_DEPTH,
        }
    }
}

/// Wired transaction pipeline: Verify → Dedup → Resolv → Pack.
///
/// Owns the tile stems and provides a unified `service()` method that
/// drives all tiles in sequence. Transactions enter via `ingest()` and
/// exit as PackedTransactions ready for the execution stage.
///
/// The pipeline uses zero-copy IPC between tiles: raw transaction bytes
/// flow through shared DataRegion memory without copying. The DedupTile
/// sits between Verify and Resolv, filtering duplicate transactions
/// before they consume resolv resources.
pub struct TransactionPipeline {
    /// Ingress stem: external producers publish raw transactions here.
    ingress: TileStem,
    /// Verify tile: consumes from ingress, publishes verified txns.
    verify: VerifyTile,
    /// Dedup tile: consumes from verify, filters duplicates.
    dedup: DedupTile,
    /// Resolv tile: consumes from dedup, publishes resolved txns.
    resolv: ResolvTile,
    /// Resolved transaction consumer: reads from resolv output.
    resolv_output: StemInput,
}

impl TransactionPipeline {
    /// Create a new transaction pipeline with default configuration.
    pub fn new() -> Self {
        Self::with_config(PipelineConfig::default())
    }

    /// Create a new transaction pipeline with the given configuration.
    pub fn with_config(config: PipelineConfig) -> Self {
        use paradencer_constants::dedup::DEFAULT_CACHE_DEPTH;

        let link_config = StemOutputConfig {
            mtu: config.link_mtu,
            depth: config.link_depth,
            initial_seq: 0,
        };

        // Ingress stem: 1 output for feeding the verify tile.
        let ingress = TileStem::new(std::slice::from_ref(&link_config));

        // Verify tile: consumes from ingress output 0.
        // SAFETY: ingress outlives verify (both owned by this struct).
        let verify_input = unsafe { ingress.create_input(0, 0) };
        let verify =
            unsafe { VerifyTile::new(VerifyStage::new(), verify_input, link_config.clone()) };

        // Dedup tile: consumes from verify's output 0, filters duplicates.
        // SAFETY: verify's stem outlives dedup (both owned by this struct).
        let dedup_input = unsafe { verify.output_stem().create_input(0, 0) };
        let dedup =
            unsafe { DedupTile::new(DEFAULT_CACHE_DEPTH, dedup_input, link_config.clone()) };

        // Resolv tile: consumes from dedup's output 0.
        // SAFETY: dedup's stem outlives resolv (both owned by this struct).
        let resolv_input = unsafe { dedup.output_stem().create_input(0, 0) };
        let resolv =
            unsafe { ResolvTile::new(ResolvStage::new(), resolv_input, link_config.clone()) };

        // Output consumer: reads resolved transactions from resolv's output.
        // SAFETY: resolv's stem outlives resolv_output (both owned by this struct).
        let resolv_output = unsafe { resolv.output_stem().create_input(0, 0) };

        Self {
            ingress,
            verify,
            dedup,
            resolv,
            resolv_output,
        }
    }

    /// Ingest a raw transaction packet into the pipeline.
    ///
    /// Returns `true` if the transaction was accepted (ingress has credits),
    /// `false` if backpressure prevented ingestion.
    pub fn ingest(&mut self, payload: &[u8], source: TransactionSource) -> bool {
        self.ingress.refresh_all_credits();
        if !self.ingress.has_credits() {
            return false;
        }

        let sig = payload_sig(payload);
        let ctl = ctl_pack(source_to_origin(source), true, true, false);
        self.ingress.publish(0, sig, payload, ctl, 0, 0).is_some()
    }

    /// Register a blockhash with the resolv tile.
    pub fn register_blockhash(&mut self, hash: Blockhash, slot: u64) {
        self.resolv.register_blockhash(hash, slot);
    }

    /// Advance the current slot for transaction expiry.
    pub fn advance_slot(&mut self, slot: u64) {
        self.resolv.advance_slot(slot);
    }

    /// Service one iteration of all pipeline tiles.
    ///
    /// Returns the total fragments processed across all tiles.
    pub fn service(&mut self) -> usize {
        let mut total = 0;

        // Service verify: consume from ingress, publish to verify output.
        total += self.verify.service();

        // Service dedup: consume from verify output, filter duplicates.
        total += self.dedup.service();

        // Service resolv: consume from dedup output, publish to resolv output.
        total += self.resolv.service();

        total
    }

    /// Drain resolved transactions from the pipeline output.
    ///
    /// Returns raw transaction payloads that have passed both signature
    /// verification and blockhash resolution. These are ready for the
    /// pack scheduler.
    pub fn drain_resolved(&mut self) -> Vec<Vec<u8>> {
        let mut resolved = Vec::new();

        loop {
            match self.resolv_output.receive(1) {
                InputResult::Ready { payload, .. } => {
                    resolved.push(payload.to_vec());
                }
                InputResult::Overrun { .. } => continue,
                InputResult::Empty => break,
            }
        }

        resolved
    }

    /// Get a shared reference to the verify stage statistics.
    pub fn verify_stats(&self) -> Arc<VerifyStats> {
        self.verify.stats()
    }

    /// Get a shared reference to the resolv stage statistics.
    pub fn resolv_stats(&self) -> Arc<ResolvStats> {
        self.resolv.stats()
    }
}

// ---------------------------------------------------------------------------
// Resolved-to-packed transaction conversion
// ---------------------------------------------------------------------------

/// Convert raw resolved transaction bytes into a PackedTransaction for
/// the pack scheduler.
///
/// Parses the wire-format transaction to extract account keys (for lock
/// detection), blockhash, and metadata. Uses the consensus cost model to
/// compute accurate compute unit estimates and priority fees. If parsing
/// fails, the transaction is still packable with default metadata (the
/// execution engine will handle the parse failure gracefully).
fn resolved_to_packed(payload: Vec<u8>) -> PackedTransaction {
    let blockhash = extract_blockhash(&payload);

    // Parse the full transaction to extract account keys.
    match paradencer_types::parse_transaction(&payload) {
        Ok(parsed) => {
            let header = &parsed.message.header;

            // Writable accounts: first N keys where N = num_required_signatures - num_readonly_signed
            // Plus unsigned writable accounts.
            let total_keys = parsed.message.account_keys.len();
            let num_writable_signed = header.num_writable_signed();
            let num_writable_unsigned = header.num_writable_unsigned(total_keys);

            let mut write_accounts = Vec::new();
            let mut read_accounts = Vec::new();

            for (i, key) in parsed.message.account_keys.iter().enumerate() {
                let is_writable = if i < header.num_required_signatures as usize {
                    i < num_writable_signed
                } else {
                    let unsigned_idx = i - header.num_required_signatures as usize;
                    unsigned_idx < num_writable_unsigned
                };

                if is_writable {
                    write_accounts.push(key.to_bytes());
                } else {
                    read_accounts.push(key.to_bytes());
                }
            }

            // Detect vote transactions by checking for the vote program ID
            // in any instruction's program account.
            let is_vote = parsed.message.instructions.iter().any(|ix| {
                let idx = ix.program_id_index as usize;
                idx < parsed.message.account_keys.len()
                    && parsed.message.account_keys[idx] == paradencer_ids::VOTE_PROGRAM_ID
            });

            // Build instruction views for the cost model.
            let instruction_views: Vec<
                paradencer_consensus::pack::cost_model::InstructionView<'_>,
            > = parsed
                .message
                .instructions
                .iter()
                .filter_map(|ix| {
                    let idx = ix.program_id_index as usize;
                    if idx < parsed.message.account_keys.len() {
                        Some(paradencer_consensus::pack::cost_model::InstructionView {
                            program_id: &parsed.message.account_keys[idx],
                            data: &ix.data,
                        })
                    } else {
                        None
                    }
                })
                .collect();

            // Compute consensus-accurate transaction cost.
            let cost = paradencer_consensus::pack::cost_model::compute_transaction_cost(
                &instruction_views,
                header.num_required_signatures as u64,
                write_accounts.len(),
                is_vote,
            );

            let data_size = payload.len();

            PackedTransaction {
                payload,
                blockhash,
                priority_fee: cost.compute_unit_price,
                compute_units: cost.execution_cost,
                total_cost: cost.total_cost,
                is_vote,
                expires_at_slot: u64::MAX,
                write_accounts,
                read_accounts,
                data_size,
                insertion_order: 0,
            }
        }
        Err(_) => {
            // Unparseable — submit with empty locks; execution will fail.
            PackedTransaction {
                data_size: payload.len(),
                payload,
                blockhash,
                priority_fee: 0,
                compute_units: paradencer_constants::execution::MAX_COMPUTE_UNITS,
                total_cost: 0,
                is_vote: false,
                expires_at_slot: u64::MAX,
                write_accounts: vec![],
                read_accounts: vec![],
                insertion_order: 0,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ValidatorPipeline — full end-to-end: Ingress → Verify → Resolv → Pack → Exec → PoH
// ---------------------------------------------------------------------------

/// Full validator transaction pipeline from ingress to block production.
///
/// Combines zero-copy IPC for the hot path (Ingress → Verify → Dedup →
/// Resolv) with the LeaderPipeline for block production (Pack → Exec → PoH).
/// Resolved transactions are automatically converted to PackedTransactions
/// and fed to the pack scheduler.
///
/// ```text
///   QuicTile → [IPC] → VerifyTile → [IPC] → DedupTile → [IPC] →
///     → ResolvTile → [IPC] → resolved_to_packed() → PackScheduler → ExecStage → PoH
/// ```
pub struct ValidatorPipeline {
    /// IPC pipeline: ingress → verify → resolv.
    txn_pipeline: TransactionPipeline,
    /// Block production: pack → exec → PoH.
    leader: crate::leader_pipeline::LeaderPipeline,
}

impl ValidatorPipeline {
    /// Create a new validator pipeline.
    pub fn new(
        pipeline_config: PipelineConfig,
        leader: crate::leader_pipeline::LeaderPipeline,
    ) -> Self {
        Self {
            txn_pipeline: TransactionPipeline::with_config(pipeline_config),
            leader,
        }
    }

    /// Ingest a raw transaction packet.
    ///
    /// Returns `true` if accepted, `false` if backpressure prevented ingestion.
    pub fn ingest(&mut self, payload: &[u8], source: TransactionSource) -> bool {
        self.txn_pipeline.ingest(payload, source)
    }

    /// Register a blockhash for resolv.
    pub fn register_blockhash(&mut self, hash: Blockhash, slot: u64) {
        self.txn_pipeline.register_blockhash(hash, slot);
    }

    /// Advance the resolv slot for expiry tracking.
    pub fn advance_slot(&mut self, slot: u64) {
        self.txn_pipeline.advance_slot(slot);
    }

    /// Start a new leader slot. Resets pack limits and configures PoH.
    pub fn begin_slot(&mut self, slot: u64) {
        self.leader.begin_slot(slot);
    }

    /// Service one iteration of the full pipeline.
    ///
    /// 1. Services the IPC pipeline (Verify + Resolv tiles)
    /// 2. Drains resolved transactions and feeds them to the pack scheduler
    /// 3. Steps the leader pipeline (Pack → Exec → PoH) once
    ///
    /// Returns the total fragments processed plus leader step outcome.
    pub fn service(&mut self) -> ValidatorPipelineResult {
        // Step 1: Service IPC tiles.
        let ipc_processed = self.txn_pipeline.service();

        // Step 2: Drain resolved transactions → pack scheduler.
        let resolved = self.txn_pipeline.drain_resolved();
        let resolved_count = resolved.len();
        for payload in resolved {
            let packed = resolved_to_packed(payload);
            self.leader.submit_transaction(packed);
        }

        // Step 3: Step leader pipeline (produces microblock if available).
        let leader_step = self.leader.step();

        ValidatorPipelineResult {
            ipc_fragments_processed: ipc_processed,
            transactions_resolved: resolved_count,
            leader_step,
        }
    }

    /// Advance PoH ticks.
    pub fn advance_poh(&mut self, target_hashes: u64) {
        self.leader.advance_poh(target_hashes);
    }

    /// Finish the current slot and get accumulated entries.
    pub fn finish_slot(&mut self) -> Vec<crate::block_producer::Entry> {
        self.leader.finish_slot()
    }

    /// Number of queued transactions in the pack scheduler.
    pub fn queue_depth(&self) -> usize {
        self.leader.queue_depth()
    }

    /// Number of microblocks executed in the current slot.
    pub fn microblocks_executed(&self) -> u64 {
        self.leader.microblocks_executed()
    }

    /// Whether the leader pipeline is in Leading state.
    pub fn is_leading(&self) -> bool {
        self.leader.is_leading()
    }

    /// Access the underlying TransactionPipeline.
    pub fn txn_pipeline(&self) -> &TransactionPipeline {
        &self.txn_pipeline
    }

    /// Access the underlying LeaderPipeline.
    pub fn leader_pipeline(&self) -> &crate::leader_pipeline::LeaderPipeline {
        &self.leader
    }

    /// Mutable access to the LeaderPipeline.
    pub fn leader_pipeline_mut(&mut self) -> &mut crate::leader_pipeline::LeaderPipeline {
        &mut self.leader
    }

    /// Get a shared reference to the verify stage statistics.
    pub fn verify_stats(&self) -> Arc<VerifyStats> {
        self.txn_pipeline.verify_stats()
    }

    /// Get a shared reference to the resolv stage statistics.
    pub fn resolv_stats(&self) -> Arc<ResolvStats> {
        self.txn_pipeline.resolv_stats()
    }
}

/// Result of one ValidatorPipeline service iteration.
#[derive(Debug)]
pub struct ValidatorPipelineResult {
    /// Fragments processed by IPC tiles (verify + resolv).
    pub ipc_fragments_processed: usize,
    /// Transactions that passed resolv and were submitted to pack.
    pub transactions_resolved: usize,
    /// Result of the leader pipeline step (None if no microblock produced).
    pub leader_step: Option<crate::leader_pipeline::PipelineStepResult>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    /// Build a minimal signed transaction payload in Solana wire format.
    fn make_signed_transaction(key: &SigningKey) -> Vec<u8> {
        // Transaction wire format:
        // [1 byte: num_signatures (compact-u16)]
        // [64 bytes: signature]
        // [message: header + account keys + blockhash + instructions]

        // Message format:
        // [1 byte: num_required_signatures]
        // [1 byte: num_readonly_signed]
        // [1 byte: num_readonly_unsigned]
        // [compact-u16: num_accounts]
        // [32 bytes * num_accounts: account keys]
        // [32 bytes: recent blockhash]
        // [compact-u16: num_instructions]
        // [instruction data...]

        let pubkey = key.verifying_key().to_bytes();
        let blockhash = [0xBB; 32]; // test blockhash

        // Build the message first (we need to sign it).
        // [header: num_required_sigs, num_readonly_signed, num_readonly_unsigned]
        // [compact-u16: num_accounts] [account keys] [blockhash] [compact-u16: num_instructions]
        let mut message = vec![1u8, 0, 0, 1];
        message.extend_from_slice(&pubkey); // account key
        message.extend_from_slice(&blockhash); // recent blockhash
        message.push(0); // num_instructions (compact-u16, 0 = no instructions)

        // Sign the message.
        let signature = key.sign(&message);

        // Build the full transaction.
        let mut payload = Vec::new();
        payload.push(1); // num_signatures (compact-u16, 1 byte)
        payload.extend_from_slice(&signature.to_bytes()); // 64 bytes
        payload.extend_from_slice(&message);

        payload
    }

    #[test]
    fn compact_u16_parsing() {
        assert_eq!(read_compact_u16(&[0]), (0, 1));
        assert_eq!(read_compact_u16(&[1]), (1, 1));
        assert_eq!(read_compact_u16(&[127]), (127, 1));
        assert_eq!(read_compact_u16(&[0x80, 0x01]), (128, 2));
    }

    #[test]
    fn payload_sig_extraction() {
        let data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let sig = payload_sig(&data);
        assert_eq!(sig, u64::from_le_bytes([1, 2, 3, 4, 5, 6, 7, 8]));
    }

    #[test]
    fn pipeline_ingest_service_drain() {
        let mut pipeline = TransactionPipeline::new();
        let key = SigningKey::from_bytes(&[42u8; 32]);

        // Register the blockhash used in the test transaction.
        let blockhash = [0xBB; 32];
        pipeline.register_blockhash(blockhash, 100);

        // Ingest a signed transaction.
        let payload = make_signed_transaction(&key);
        assert!(pipeline.ingest(&payload, TransactionSource::Quic));

        // Service the pipeline (verify + resolv).
        pipeline.service();

        // Drain resolved transactions.
        let resolved = pipeline.drain_resolved();

        // The transaction should have passed verification and resolution.
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0], payload);
    }

    #[test]
    fn pipeline_multiple_transactions() {
        let mut pipeline = TransactionPipeline::new();

        let blockhash = [0xBB; 32];
        pipeline.register_blockhash(blockhash, 100);

        let keys: Vec<SigningKey> = (0..5u8)
            .map(|i| SigningKey::from_bytes(&[10 + i; 32]))
            .collect();

        for key in &keys {
            let payload = make_signed_transaction(key);
            assert!(pipeline.ingest(&payload, TransactionSource::Quic));
        }

        // May need multiple service rounds for batching.
        for _ in 0..3 {
            pipeline.service();
        }

        let resolved = pipeline.drain_resolved();
        assert_eq!(resolved.len(), 5);
    }

    #[test]
    fn pipeline_unknown_blockhash_stashed() {
        let mut pipeline = TransactionPipeline::new();
        let key = SigningKey::from_bytes(&[1u8; 32]);

        // Don't register the blockhash — transaction should be stashed.
        let payload = make_signed_transaction(&key);
        pipeline.ingest(&payload, TransactionSource::Quic);
        pipeline.service();

        let resolved = pipeline.drain_resolved();
        assert_eq!(resolved.len(), 0); // stashed, not resolved

        // Now register the blockhash — should unstash.
        let blockhash = [0xBB; 32];
        pipeline.register_blockhash(blockhash, 200);

        // Unstashed transactions are published during register_blockhash.
        let resolved = pipeline.drain_resolved();
        assert_eq!(resolved.len(), 1);
    }

    #[test]
    fn pipeline_backpressure() {
        let config = PipelineConfig {
            link_mtu: 1280,
            link_depth: 4, // Small depth for testing.
        };
        let mut pipeline = TransactionPipeline::with_config(config);
        let key = SigningKey::from_bytes(&[2u8; 32]);

        // Ingest more than depth transactions without servicing.
        let payload = make_signed_transaction(&key);
        let mut accepted = 0;
        for _ in 0..10 {
            if pipeline.ingest(&payload, TransactionSource::Quic) {
                accepted += 1;
            }
        }

        // Should be limited by ingress depth.
        assert!(accepted <= 4);
        assert!(accepted > 0);
    }

    #[test]
    fn source_origin_roundtrip() {
        for source in [
            TransactionSource::Quic,
            TransactionSource::Gossip,
            TransactionSource::Bundle,
            TransactionSource::Forwarded,
        ] {
            let origin = source_to_origin(source);
            let back = origin_to_source(origin);
            assert_eq!(back, source);
        }
    }

    #[test]
    fn resolved_to_packed_extracts_accounts() {
        let key = SigningKey::from_bytes(&[42u8; 32]);
        let payload = make_signed_transaction(&key);
        let packed = resolved_to_packed(payload.clone());

        assert_eq!(packed.payload, payload);
        assert_eq!(packed.blockhash, [0xBB; 32]);
        // The signer should be a write account.
        assert_eq!(packed.write_accounts.len(), 1);
        assert_eq!(packed.write_accounts[0], key.verifying_key().to_bytes());
    }

    #[test]
    fn resolved_to_packed_handles_malformed() {
        let packed = resolved_to_packed(vec![0xFF, 0xFF]);
        // Should still produce a PackedTransaction with empty locks.
        assert_eq!(packed.payload, vec![0xFF, 0xFF]);
        assert!(packed.write_accounts.is_empty());
        assert!(packed.read_accounts.is_empty());
    }

    #[test]
    fn validator_pipeline_end_to_end() {
        use crate::block_producer::PohService;
        use crate::exec_stage::MockExecutionEngine;
        use crate::leader_pipeline::LeaderPipeline;
        use crate::pack_stage::PackScheduler;
        use paradencer_types::Hash;

        // Build leader pipeline.
        let pack = PackScheduler::new();
        let engine = MockExecutionEngine::new(50_000);
        let exec = ExecStage::new(Box::new(engine));
        let poh = PohService::new(Hash::default());
        let leader = LeaderPipeline::new(pack, exec, poh);

        // Build full pipeline.
        let mut pipeline = ValidatorPipeline::new(PipelineConfig::default(), leader);

        // Start a leader slot.
        pipeline.begin_slot(1);

        // Register blockhash.
        let blockhash = [0xBB; 32];
        pipeline.register_blockhash(blockhash, 100);

        // Ingest a signed transaction.
        let key = SigningKey::from_bytes(&[42u8; 32]);
        let payload = make_signed_transaction(&key);
        assert!(pipeline.ingest(&payload, TransactionSource::Quic));

        // Service multiple rounds to move through verify → resolv → pack.
        for _ in 0..5 {
            pipeline.service();
        }

        // The transaction should have been verified, resolved, packed, and executed.
        assert!(pipeline.microblocks_executed() >= 1);
    }

    /// Build a signed vote transaction payload in Solana wire format.
    fn make_vote_transaction(key: &SigningKey) -> Vec<u8> {
        let pubkey = key.verifying_key().to_bytes();
        let blockhash = [0xBB; 32];

        // Message with vote program instruction.
        // header: 1 required sig, 0 readonly signed, 1 readonly unsigned
        // accounts: [signer, vote_program_id]
        // 1 instruction targeting program index 1 (vote program)
        let mut message = vec![
            1, // num_required_signatures
            0, // num_readonly_signed_accounts
            1, // num_readonly_unsigned_accounts (vote program is readonly)
            2, // num_accounts (compact-u16)
        ];
        message.extend_from_slice(&pubkey); // account 0: signer (writable)
        message.extend_from_slice(&paradencer_ids::VOTE_PROGRAM_ID.to_bytes()); // account 1: vote program
        message.extend_from_slice(&blockhash); // recent blockhash
        message.push(1); // num_instructions (compact-u16)
                         // Instruction: program_id_index=1, 1 account, 4 bytes data
        message.push(1); // program_id_index
        message.push(1); // num_accounts in instruction (compact-u16)
        message.push(0); // account index 0 (signer)
        message.push(4); // data length (compact-u16)
        message.extend_from_slice(&[2, 0, 0, 0]); // vote instruction type 2

        let signature = key.sign(&message);

        let mut payload = Vec::new();
        payload.push(1); // num_signatures (compact-u16)
        payload.extend_from_slice(&signature.to_bytes());
        payload.extend_from_slice(&message);
        payload
    }

    /// Build a signed transaction with ComputeBudget instructions.
    fn make_transaction_with_compute_budget(key: &SigningKey) -> Vec<u8> {
        let pubkey = key.verifying_key().to_bytes();
        let blockhash = [0xBB; 32];

        // header: 1 required sig, 0 readonly signed, 2 readonly unsigned
        // accounts: [signer, compute_budget_program, system_program]
        // 2 instructions: SetComputeUnitLimit + SetComputeUnitPrice on compute budget
        let mut message = vec![
            1, // num_required_signatures
            0, // num_readonly_signed_accounts
            2, // num_readonly_unsigned_accounts
            3, // num_accounts (compact-u16)
        ];
        message.extend_from_slice(&pubkey); // account 0: signer
        message.extend_from_slice(&paradencer_ids::COMPUTE_BUDGET_PROGRAM_ID.to_bytes()); // account 1
        message.extend_from_slice(&paradencer_ids::SYSTEM_PROGRAM_ID.to_bytes()); // account 2
        message.extend_from_slice(&blockhash);
        message.push(3); // num_instructions

        // Instruction 1: SetComputeUnitLimit(300_000) on ComputeBudget program
        message.push(1); // program_id_index = 1 (compute budget)
        message.push(0); // num_accounts = 0
        message.push(5); // data length
        message
            .push(paradencer_constants::compute_budget_program::INSTRUCTION_SET_COMPUTE_UNIT_LIMIT);
        message.extend_from_slice(&300_000u32.to_le_bytes());

        // Instruction 2: SetComputeUnitPrice(5000) on ComputeBudget program
        message.push(1); // program_id_index = 1
        message.push(0); // num_accounts = 0
        message.push(9); // data length
        message
            .push(paradencer_constants::compute_budget_program::INSTRUCTION_SET_COMPUTE_UNIT_PRICE);
        message.extend_from_slice(&5000u64.to_le_bytes());

        // Instruction 3: System program transfer
        message.push(2); // program_id_index = 2 (system program)
        message.push(1); // num_accounts = 1
        message.push(0); // account 0
        message.push(4); // data length
        message.extend_from_slice(&[0, 0, 0, 0]);

        let signature = key.sign(&message);

        let mut payload = Vec::new();
        payload.push(1);
        payload.extend_from_slice(&signature.to_bytes());
        payload.extend_from_slice(&message);
        payload
    }

    #[test]
    fn resolved_to_packed_detects_vote_transaction() {
        let key = SigningKey::from_bytes(&[42u8; 32]);
        let payload = make_vote_transaction(&key);
        let packed = resolved_to_packed(payload);

        assert!(packed.is_vote, "Vote transaction should be detected");
    }

    #[test]
    fn resolved_to_packed_non_vote_not_flagged() {
        let key = SigningKey::from_bytes(&[42u8; 32]);
        let payload = make_signed_transaction(&key);
        let packed = resolved_to_packed(payload);

        assert!(
            !packed.is_vote,
            "Non-vote transaction should not be flagged"
        );
    }

    #[test]
    fn resolved_to_packed_parses_compute_budget() {
        let key = SigningKey::from_bytes(&[42u8; 32]);
        let payload = make_transaction_with_compute_budget(&key);
        let packed = resolved_to_packed(payload);

        // ComputeBudget sets CU limit to 300_000 and price to 5000.
        assert_eq!(packed.compute_units, 300_000);
        assert_eq!(packed.priority_fee, 5000);
        assert!(!packed.is_vote);
    }
}
