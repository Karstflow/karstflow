//! Decoded shapes of the upstream instruction fixture schema.
//!
//! Field numbers below are the schema's, not this crate's: they are fixed by
//! the published `.proto` definitions the fixture corpus is generated from, so
//! they are written as literals with the field name in a comment rather than
//! being derived from anything local.
//!
//! Unknown field numbers are skipped by wire type. That is deliberate: the
//! schema gains fields between releases, and a fixture carrying a field this
//! decoder has never seen must still decode the fields it does know.

use super::wire::{packed_fixed64, Reader, WireError};

/// One account's complete state, excluding its address's role in the call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcctState {
    /// Account address.
    pub address: [u8; 32],
    /// Balance in lamports.
    pub lamports: u64,
    /// Raw account data.
    pub data: Vec<u8>,
    /// Whether the account holds a loadable program.
    pub executable: bool,
    /// Owning program's address.
    pub owner: [u8; 32],
}

/// A reference from the instruction into the context's account list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstrAcct {
    /// Index into [`InstrContext::accounts`].
    pub index: u32,
    /// Whether the instruction may modify the account.
    pub is_writable: bool,
    /// Whether the account signed the transaction.
    pub is_signer: bool,
}

/// Everything needed to replay one instruction independently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstrContext {
    /// Program being invoked.
    pub program_id: [u8; 32],
    /// Every account the instruction may touch, including sysvars.
    pub accounts: Vec<AcctState>,
    /// The instruction's account access list.
    pub instr_accounts: Vec<InstrAcct>,
    /// Instruction data passed to the program.
    pub data: Vec<u8>,
    /// Compute units available to the invocation.
    pub cu_avail: u64,
    /// Active features, each the first 8 bytes of a feature id as a
    /// little-endian integer.
    pub features: Vec<u64>,
}

/// The observable outcome of replaying an [`InstrContext`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstrEffects {
    /// Zero on success, otherwise an error code. Not consensus-relevant.
    pub result: i32,
    /// Program-defined error code, stable across implementations.
    pub custom_err: u32,
    /// Accounts whose state changed. Order is arbitrary.
    pub modified_accounts: Vec<AcctState>,
    /// Compute units left after execution.
    pub cu_avail: u64,
    /// Data the program returned.
    pub return_data: Vec<u8>,
}

/// A complete fixture: an input context and the effects it must produce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstrFixture {
    /// The harness entry point the fixture was generated for.
    pub entrypoint: String,
    /// Pre-state and invocation.
    pub input: InstrContext,
    /// Expected post-state.
    pub output: InstrEffects,
    /// Whether the fixture actually carried an effects message.
    ///
    /// An absent effects message and a success-with-no-changes effects message
    /// both decode to the same default value, but they mean opposite things:
    /// the first says the invocation was expected to produce nothing at all,
    /// the second says it was expected to succeed. Only the presence flag can
    /// tell them apart, so it is carried rather than reconstructed.
    pub output_present: bool,
}

fn decode_acct_state(buf: &[u8]) -> Result<AcctState, WireError> {
    let mut out = AcctState {
        address: [0u8; 32],
        lamports: 0,
        data: Vec::new(),
        executable: false,
        owner: [0u8; 32],
    };
    let mut reader = Reader::new(buf);
    while let Some((field, value)) = reader.next_field()? {
        match field {
            1 => out.address = value.as_key32()?,      // address
            2 => out.lamports = value.as_u64(),        // lamports
            3 => out.data = value.as_bytes().to_vec(), // data
            4 => out.executable = value.as_bool(),     // executable
            6 => out.owner = value.as_key32()?,        // owner
            _ => {}
        }
    }
    Ok(out)
}

fn decode_instr_acct(buf: &[u8]) -> Result<InstrAcct, WireError> {
    let mut out = InstrAcct {
        index: 0,
        is_writable: false,
        is_signer: false,
    };
    let mut reader = Reader::new(buf);
    while let Some((field, value)) = reader.next_field()? {
        match field {
            1 => out.index = value.as_u64() as u32, // index
            2 => out.is_writable = value.as_bool(), // is_writable
            3 => out.is_signer = value.as_bool(),   // is_signer
            _ => {}
        }
    }
    Ok(out)
}

fn decode_feature_set(buf: &[u8]) -> Result<Vec<u64>, WireError> {
    let mut out = Vec::new();
    let mut reader = Reader::new(buf);
    while let Some((field, value)) = reader.next_field()? {
        if field == 1 {
            // features — packed when written by a conforming encoder, but a
            // repeated fixed64 is also legal unpacked, so accept both.
            match value {
                super::wire::Value::Bytes(bytes) => out.extend(packed_fixed64(bytes)?),
                other => out.push(other.as_u64()),
            }
        }
    }
    Ok(out)
}

fn decode_instr_context(buf: &[u8]) -> Result<InstrContext, WireError> {
    let mut out = InstrContext {
        program_id: [0u8; 32],
        accounts: Vec::new(),
        instr_accounts: Vec::new(),
        data: Vec::new(),
        cu_avail: 0,
        features: Vec::new(),
    };
    let mut reader = Reader::new(buf);
    while let Some((field, value)) = reader.next_field()? {
        match field {
            1 => out.program_id = value.as_key32()?, // program_id
            3 => out.accounts.push(decode_acct_state(value.as_bytes())?), // accounts
            4 => out
                .instr_accounts
                .push(decode_instr_acct(value.as_bytes())?), // instr_accounts
            5 => out.data = value.as_bytes().to_vec(), // data
            6 => out.cu_avail = value.as_u64(),      // cu_avail
            10 => out.features = decode_feature_set(value.as_bytes())?, // features
            _ => {}
        }
    }
    Ok(out)
}

fn decode_instr_effects(buf: &[u8]) -> Result<InstrEffects, WireError> {
    let mut out = InstrEffects {
        result: 0,
        custom_err: 0,
        modified_accounts: Vec::new(),
        cu_avail: 0,
        return_data: Vec::new(),
    };
    let mut reader = Reader::new(buf);
    while let Some((field, value)) = reader.next_field()? {
        match field {
            1 => out.result = value.as_i32(),            // result
            2 => out.custom_err = value.as_u64() as u32, // custom_err
            3 => out
                .modified_accounts
                .push(decode_acct_state(value.as_bytes())?), // modified_accounts
            4 => out.cu_avail = value.as_u64(),          // cu_avail
            5 => out.return_data = value.as_bytes().to_vec(), // return_data
            _ => {}
        }
    }
    Ok(out)
}

/// Decode one fixture file's bytes.
pub fn decode_instr_fixture(buf: &[u8]) -> Result<InstrFixture, WireError> {
    let mut entrypoint = String::new();
    let mut input = None;
    let mut output = None;
    let mut reader = Reader::new(buf);
    while let Some((field, value)) = reader.next_field()? {
        match field {
            1 => {
                // metadata — a single string field, which is not worth its own
                // decoder while it stays one field.
                let mut meta = Reader::new(value.as_bytes());
                while let Some((meta_field, meta_value)) = meta.next_field()? {
                    if meta_field == 1 {
                        entrypoint = String::from_utf8_lossy(meta_value.as_bytes()).into_owned();
                    }
                }
            }
            2 => input = Some(decode_instr_context(value.as_bytes())?), // input
            3 => output = Some(decode_instr_effects(value.as_bytes())?), // output
            _ => {}
        }
    }
    Ok(InstrFixture {
        entrypoint,
        output_present: output.is_some(),
        // A fixture with no input or no output is degenerate rather than
        // malformed; it decodes to empty and the runner reports it as skipped.
        input: input.unwrap_or(InstrContext {
            program_id: [0u8; 32],
            accounts: Vec::new(),
            instr_accounts: Vec::new(),
            data: Vec::new(),
            cu_avail: 0,
            features: Vec::new(),
        }),
        output: output.unwrap_or(InstrEffects {
            result: 0,
            custom_err: 0,
            modified_accounts: Vec::new(),
            cu_avail: 0,
            return_data: Vec::new(),
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn varint(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (value & 0x7F) as u8;
            value >>= 7;
            if value == 0 {
                out.push(byte);
                return out;
            }
            out.push(byte | 0x80);
        }
    }

    fn tag(field: u32, wire: u8) -> Vec<u8> {
        varint((u64::from(field) << 3) | u64::from(wire))
    }

    fn embed(field: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = tag(field, 2);
        out.extend(varint(payload.len() as u64));
        out.extend_from_slice(payload);
        out
    }

    fn scalar(field: u32, value: u64) -> Vec<u8> {
        let mut out = tag(field, 0);
        out.extend(varint(value));
        out
    }

    /// Build a fixture the way the corpus encodes one, so decoding is tested
    /// against bytes assembled from the schema rather than from this decoder.
    fn sample_fixture() -> Vec<u8> {
        let account = {
            let mut a = embed(1, &[9u8; 32]); // address
            a.extend(scalar(2, 1_000_000)); // lamports
            a.extend(embed(3, b"payload")); // data
            a.extend(scalar(4, 1)); // executable
            a.extend(embed(6, &[3u8; 32])); // owner
            a
        };
        let instr_acct = {
            let mut a = scalar(1, 0); // index
            a.extend(scalar(2, 1)); // is_writable
            a.extend(scalar(3, 1)); // is_signer
            a
        };
        let features = {
            let mut packed = Vec::new();
            packed.extend_from_slice(&0xAABB_CCDD_1122_3344u64.to_le_bytes());
            packed.extend_from_slice(&7u64.to_le_bytes());
            embed(1, &packed)
        };
        let context = {
            let mut c = embed(1, &[1u8; 32]); // program_id
            c.extend(embed(3, &account)); // accounts
            c.extend(embed(4, &instr_acct)); // instr_accounts
            c.extend(embed(5, &[0xDE, 0xAD])); // data
            c.extend(scalar(6, 200_000)); // cu_avail
            c.extend(embed(10, &features)); // features
            c
        };
        let effects = {
            let mut e = scalar(1, 0); // result
            e.extend(scalar(2, 42)); // custom_err
            e.extend(embed(3, &account)); // modified_accounts
            e.extend(scalar(4, 199_000)); // cu_avail
            e.extend(embed(5, b"ret")); // return_data
            e
        };
        let metadata = embed(1, b"sol_compat_instr_execute_v1");

        let mut fixture = embed(1, &metadata);
        fixture.extend(embed(2, &context));
        fixture.extend(embed(3, &effects));
        fixture
    }

    #[test]
    fn decodes_every_field_of_a_complete_fixture() {
        let decoded = decode_instr_fixture(&sample_fixture()).unwrap();

        assert_eq!(decoded.entrypoint, "sol_compat_instr_execute_v1");
        assert_eq!(decoded.input.program_id, [1u8; 32]);
        assert_eq!(decoded.input.data, vec![0xDE, 0xAD]);
        assert_eq!(decoded.input.cu_avail, 200_000);
        assert_eq!(decoded.input.features, vec![0xAABB_CCDD_1122_3344, 7]);

        assert_eq!(decoded.input.accounts.len(), 1);
        let account = &decoded.input.accounts[0];
        assert_eq!(account.address, [9u8; 32]);
        assert_eq!(account.lamports, 1_000_000);
        assert_eq!(account.data, b"payload");
        assert!(account.executable);
        assert_eq!(account.owner, [3u8; 32]);

        assert_eq!(
            decoded.input.instr_accounts,
            vec![InstrAcct {
                index: 0,
                is_writable: true,
                is_signer: true,
            }]
        );

        assert_eq!(decoded.output.result, 0);
        assert_eq!(decoded.output.custom_err, 42);
        assert_eq!(decoded.output.cu_avail, 199_000);
        assert_eq!(decoded.output.return_data, b"ret");
        assert_eq!(decoded.output.modified_accounts.len(), 1);
    }

    #[test]
    fn omitted_proto3_defaults_decode_to_zero_values() {
        // Proto3 writes nothing for a default-valued field, so an empty
        // message must still decode into a usable fixture.
        let decoded = decode_instr_fixture(&[]).unwrap();
        assert_eq!(decoded.input.program_id, [0u8; 32]);
        assert!(decoded.input.accounts.is_empty());
        assert_eq!(decoded.output.result, 0);
        assert!(decoded.output.return_data.is_empty());
        // An absent effects message must stay distinguishable from an
        // expected-success one, which decodes to the same default values.
        assert!(!decoded.output_present);
        assert!(
            decode_instr_fixture(&sample_fixture())
                .unwrap()
                .output_present
        );
    }

    #[test]
    fn a_field_the_schema_gained_later_is_skipped_not_misread() {
        // Splice an unknown field 47 in front of the real context fields.
        let mut context = embed(47, &[0xFFu8; 9]);
        context.extend(embed(1, &[5u8; 32]));
        context.extend(scalar(6, 1_400_000));
        let fixture = embed(2, &context);

        let decoded = decode_instr_fixture(&fixture).unwrap();
        assert_eq!(decoded.input.program_id, [5u8; 32]);
        assert_eq!(decoded.input.cu_avail, 1_400_000);
    }

    #[test]
    fn a_truncated_fixture_is_an_error_not_a_panic() {
        let full = sample_fixture();
        // Every prefix must either decode or error; none may panic.
        for cut in 1..full.len().min(400) {
            let _ = decode_instr_fixture(&full[..cut]);
        }
        assert!(decode_instr_fixture(&full[..full.len() - 1]).is_err());
    }

    #[test]
    fn a_negative_result_code_round_trips() {
        let mut effects = tag(1, 0);
        effects.extend(varint((-14i32) as u32 as u64 | 0xFFFF_FFFF_0000_0000));
        let fixture = embed(3, &effects);
        assert_eq!(decode_instr_fixture(&fixture).unwrap().output.result, -14);
    }
}
