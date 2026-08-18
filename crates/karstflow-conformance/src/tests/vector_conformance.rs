//! Replays of the upstream conformance-vector corpus.
//!
//! These tests need the corpus, which lives outside the repository because it
//! is several gigabytes. Set `KARSTFLOW_TEST_VECTORS` to its root and run
//! `just conformance-vectors`. Without it every test here reports a skip and
//! passes, so a checkout without the corpus still builds and tests clean.
//!
//! The tests report; they do not assert a pass rate. A pass rate is only
//! meaningful once each failure has been attributed to a cause — an unported
//! surface, a genuine defect, or a gap in this harness — and that attribution
//! is analysis work, not something a threshold can stand in for.

use crate::vectors::{collect_fixtures, instr_fixture_dir, instr_groups, run_corpus, CORPUS_ENV};

/// Default fixtures replayed per group. The corpus holds tens of thousands; a
/// bounded sample keeps a run to minutes while still covering every group, and
/// the bound is printed so a partial run is never mistaken for a full one.
const DEFAULT_SAMPLE_PER_GROUP: usize = 250;

/// Environment variable raising or lowering the per-group sample.
const SAMPLE_ENV: &str = "KARSTFLOW_VECTOR_SAMPLE";

fn sample_per_group() -> usize {
    std::env::var(SAMPLE_ENV)
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(DEFAULT_SAMPLE_PER_GROUP)
}

fn skip_notice() {
    println!("SKIP: {CORPUS_ENV} is unset or does not point at a corpus directory");
}

#[test]
#[ignore = "requires the upstream vector corpus"]
fn instruction_corpus_decodes_completely() {
    let Some(dir) = instr_fixture_dir(None) else {
        skip_notice();
        return;
    };
    let paths = collect_fixtures(&dir, Some(2_000));
    println!("decoding {} fixtures from {}", paths.len(), dir.display());

    let mut decoded = 0usize;
    let mut failures = Vec::new();
    for path in &paths {
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        match crate::vectors::model::decode_instr_fixture(&bytes) {
            Ok(_) => decoded += 1,
            Err(error) => failures.push(format!("{}: {error:?}", path.display())),
        }
    }

    println!("decoded={decoded} failed={}", failures.len());
    for failure in failures.iter().take(10) {
        println!("  {failure}");
    }

    // Decoding is this crate's own responsibility, so unlike the replay
    // verdicts it IS asserted: a fixture that fails to decode is a defect in
    // the decoder, never a finding about the runtime.
    assert!(
        failures.is_empty(),
        "{} fixture(s) failed to decode",
        failures.len()
    );
}

#[test]
#[ignore = "requires the upstream vector corpus"]
fn instruction_corpus_replay_report() {
    if instr_fixture_dir(None).is_none() {
        skip_notice();
        return;
    }

    let bound = sample_per_group();
    println!("sample bound: {bound} fixtures per group ({SAMPLE_ENV} to change)");
    for group in instr_groups() {
        let Some(dir) = instr_fixture_dir(Some(&group)) else {
            println!("--- {group}: absent from this corpus");
            continue;
        };
        let paths = collect_fixtures(&dir, Some(bound));
        let summary = run_corpus(&paths);

        println!("--- {group}");
        println!("{}", summary.headline());
        print!("{}", summary.breakdown());
        for (path, mismatches) in summary.sample_mismatches.iter().take(3) {
            println!(
                "  e.g. {}: {}",
                path.file_name().unwrap_or_default().to_string_lossy(),
                mismatches.join(", ")
            );
        }
    }
}
