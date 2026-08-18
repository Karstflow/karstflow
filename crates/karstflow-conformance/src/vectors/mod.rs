//! Ingestion of the upstream conformance-vector corpus.
//!
//! The corpus is a large set of binary fixtures published alongside the
//! reference implementation. Each fixture pins one instruction invocation and
//! the exact effects it must produce, which makes it an *external* oracle:
//! until this module existed, karstflow's execution could only be checked
//! against expectations karstflow itself wrote down.
//!
//! The corpus is measured in gigabytes and therefore lives outside the
//! repository. Point `KARSTFLOW_TEST_VECTORS` at the directory that contains
//! the `instr/fixtures/...` tree. When the variable is unset, every entry point
//! here reports an empty corpus and the tests skip — a machine without the
//! vectors must not fail its build over their absence.

pub mod model;
pub mod runner;
pub mod wire;

use runner::{SkipReason, Verdict};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Environment variable naming the corpus root.
pub const CORPUS_ENV: &str = "KARSTFLOW_TEST_VECTORS";

/// Corpus root, when one is configured and present on disk.
pub fn corpus_root() -> Option<PathBuf> {
    let raw = std::env::var(CORPUS_ENV).ok()?;
    let path = PathBuf::from(raw);
    path.is_dir().then_some(path)
}

/// Directory holding instruction fixtures, when the corpus is available.
///
/// `group` selects one program's subdirectory (`system`, `vote`, …); `None`
/// takes every group.
pub fn instr_fixture_dir(group: Option<&str>) -> Option<PathBuf> {
    let mut path = corpus_root()?.join("instr").join("fixtures");
    if let Some(group) = group {
        path = path.join(group);
    }
    path.is_dir().then_some(path)
}

/// Names of the per-program fixture groups the corpus actually contains.
///
/// Discovered rather than hardcoded, so a group added upstream is surveyed
/// automatically instead of being silently skipped by a stale list.
pub fn instr_groups() -> Vec<String> {
    let Some(root) = instr_fixture_dir(None) else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    let mut groups: Vec<String> = entries
        .flatten()
        .filter(|entry| entry.path().is_dir())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    groups.sort();
    groups
}

/// Collect fixture file paths beneath `dir`, in sorted order so that a run is
/// reproducible and a truncated run always covers the same prefix.
pub fn collect_fixtures(dir: &Path, limit: Option<usize>) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        let mut level: Vec<PathBuf> = entries.flatten().map(|entry| entry.path()).collect();
        level.sort();
        for path in level {
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "fix") {
                found.push(path);
            }
        }
    }
    found.sort();
    if let Some(limit) = limit {
        found.truncate(limit);
    }
    found
}

/// Aggregated outcome of replaying a set of fixtures.
#[derive(Debug, Default, Clone)]
pub struct CorpusSummary {
    /// Fixtures attempted.
    pub total: usize,
    /// Fixtures whose every compared field agreed.
    pub passed: usize,
    /// Fixtures with at least one disagreement.
    pub mismatched: usize,
    /// Fixtures that could not be graded.
    pub skipped: usize,
    /// Fixtures whose execution panicked.
    pub panicked: usize,
    /// Fixtures that would pass if compute-unit accounting were disregarded.
    ///
    /// Compute metering is one mechanism, so a class that appears in nearly
    /// every fixture is far more likely to be one systematic gap than a crowd
    /// of independent defects. This counter distinguishes the two, which is
    /// what decides whether the fix is one change or a programme of them.
    pub passed_ignoring_compute_units: usize,
    /// How many fixtures panicked at each distinct source location.
    pub by_panic_site: BTreeMap<String, usize>,
    /// How many fixtures exhibited each mismatch class. A fixture with several
    /// disagreements contributes to several classes.
    pub by_mismatch_class: BTreeMap<&'static str, usize>,
    /// How many fixtures were skipped for each reason.
    pub by_skip_reason: BTreeMap<&'static str, usize>,
    /// Feature prefixes no known feature matched, across the whole run.
    pub unknown_feature_prefixes: usize,
    /// Up to a handful of mismatching paths, kept for diagnosis.
    pub sample_mismatches: Vec<(PathBuf, Vec<String>)>,
    /// How many replays failed for each distinct reason.
    ///
    /// A fixture that expected an error and got one grades as agreement, so
    /// the reason our own replay failed never reaches the mismatch classes.
    /// Without this, a group can sit at `actual: 0` across a thousand fixtures
    /// with nothing to say what refused to run.
    pub by_failure_reason: BTreeMap<String, usize>,
}

impl CorpusSummary {
    /// Share of graded fixtures that passed, as a percentage.
    ///
    /// A panic counts against the rate. It is a worse outcome than a wrong
    /// answer, so excluding it would make the number improve as the failures
    /// got more severe.
    pub fn pass_rate(&self) -> f64 {
        let graded = self.passed + self.mismatched + self.panicked;
        if graded == 0 {
            return 0.0;
        }
        (self.passed as f64) * 100.0 / (graded as f64)
    }

    /// One-line summary suitable for use as completion evidence.
    pub fn headline(&self) -> String {
        format!(
            "total={} passed={} mismatched={} panicked={} skipped={} pass-rate={:.1}%",
            self.total,
            self.passed,
            self.mismatched,
            self.panicked,
            self.skipped,
            self.pass_rate()
        )
    }

    /// Multi-line breakdown by mismatch class and skip reason.
    pub fn breakdown(&self) -> String {
        let mut out = String::new();
        out.push_str("mismatch classes:\n");
        if self.by_mismatch_class.is_empty() {
            out.push_str("  (none)\n");
        }
        for (class, count) in &self.by_mismatch_class {
            out.push_str(&format!("  {class:<26} {count}\n"));
        }
        out.push_str("skip reasons:\n");
        if self.by_skip_reason.is_empty() {
            out.push_str("  (none)\n");
        }
        for (reason, count) in &self.by_skip_reason {
            out.push_str(&format!("  {reason:<26} {count}\n"));
        }
        if !self.by_failure_reason.is_empty() {
            let mut reasons: Vec<_> = self.by_failure_reason.iter().collect();
            reasons.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
            out.push_str("replay failure reasons:\n");
            for (reason, count) in reasons.iter().take(8) {
                out.push_str(&format!("  {count:>5}  {reason}\n"));
            }
            if reasons.len() > 8 {
                out.push_str(&format!(
                    "  ... {} more distinct reasons\n",
                    reasons.len() - 8
                ));
            }
        }
        if !self.by_panic_site.is_empty() {
            out.push_str("panic sites:\n");
            for (site, count) in &self.by_panic_site {
                out.push_str(&format!("  {count:>5}  {site}\n"));
            }
        }
        out.push_str(&format!(
            "would pass if compute units were disregarded: {} (rate {:.1}%)\n",
            self.passed_ignoring_compute_units,
            {
                let graded = self.passed + self.mismatched + self.panicked;
                if graded == 0 {
                    0.0
                } else {
                    ((self.passed + self.passed_ignoring_compute_units) as f64) * 100.0
                        / (graded as f64)
                }
            }
        ));
        out.push_str(&format!(
            "unresolved feature prefixes: {}\n",
            self.unknown_feature_prefixes
        ));
        out
    }
}

/// Replay every fixture in `paths` and aggregate the verdicts.
/// Collapse a failure message to its stable prefix so that reasons group.
///
/// Messages embed addresses, sizes and program ids, which would otherwise make
/// every failure its own category and defeat the point of counting them.
fn normalize_failure_reason(reason: &str) -> String {
    // Wrappers that say only "something went wrong underneath" are stripped,
    // or every distinct cause lands in one bucket named after the wrapper.
    const WRAPPERS: [&str; 3] = [
        "Program failed: ",
        "BPF execution failed: ",
        "execution failed: ",
    ];
    let mut trimmed = reason;
    while let Some(rest) = WRAPPERS.iter().find_map(|w| trimmed.strip_prefix(w)) {
        trimmed = rest;
    }
    let head: String = trimmed.chars().take(72).collect();
    match head.split_once(&[':', '('][..]) {
        Some((prefix, _)) if prefix.len() >= 8 => prefix.trim().to_string(),
        _ => head.trim().to_string(),
    }
}

pub fn run_corpus(paths: &[PathBuf]) -> CorpusSummary {
    runner::install_quiet_panic_hook();
    let backend = karstflow_stages::SbpfExecutionAdapter::with_defaults();
    let mut summary = CorpusSummary::default();

    for path in paths {
        summary.total += 1;
        let Ok(bytes) = std::fs::read(path) else {
            summary.skipped += 1;
            *summary.by_skip_reason.entry("unreadable").or_default() += 1;
            continue;
        };
        let fixture = match model::decode_instr_fixture(&bytes) {
            Ok(fixture) => fixture,
            Err(error) => {
                summary.skipped += 1;
                *summary
                    .by_skip_reason
                    .entry(SkipReason::DecodeFailed(String::new()).class())
                    .or_default() += 1;
                if summary.sample_mismatches.len() < 10 {
                    summary
                        .sample_mismatches
                        .push((path.clone(), vec![format!("decode: {error:?}")]));
                }
                continue;
            }
        };

        let (_, unknown) = runner::resolve_features(&fixture.input.features);
        summary.unknown_feature_prefixes += unknown;

        let replay = runner::run_fixture(&fixture, &backend);
        if let Some(reason) = replay.failure_reason.as_deref() {
            *summary
                .by_failure_reason
                .entry(normalize_failure_reason(reason))
                .or_default() += 1;
        }

        match replay.verdict {
            Verdict::Pass => summary.passed += 1,
            Verdict::Skipped(reason) => {
                summary.skipped += 1;
                *summary.by_skip_reason.entry(reason.class()).or_default() += 1;
            }
            Verdict::Panicked(site) => {
                summary.panicked += 1;
                *summary.by_panic_site.entry(site).or_default() += 1;
            }
            Verdict::Mismatch(mismatches) => {
                summary.mismatched += 1;
                if mismatches
                    .iter()
                    .all(|item| matches!(item, runner::Mismatch::ComputeUnits { .. }))
                {
                    summary.passed_ignoring_compute_units += 1;
                }
                let mut classes: Vec<&'static str> =
                    mismatches.iter().map(|item| item.class()).collect();
                classes.sort_unstable();
                classes.dedup();
                for class in classes {
                    *summary.by_mismatch_class.entry(class).or_default() += 1;
                }
                if summary.sample_mismatches.len() < 10 {
                    summary.sample_mismatches.push((
                        path.clone(),
                        mismatches.iter().map(|item| format!("{item:?}")).collect(),
                    ));
                }
            }
        }
    }

    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absent_corpus_yields_no_paths_rather_than_an_error() {
        // The build must not depend on multi-gigabyte fixtures being present.
        let missing = Path::new("/nonexistent/karstflow/vectors");
        assert!(collect_fixtures(missing, None).is_empty());
    }

    #[test]
    fn summary_reports_a_zero_pass_rate_when_nothing_was_graded() {
        let summary = CorpusSummary::default();
        assert_eq!(summary.pass_rate(), 0.0);
        assert!(summary.headline().contains("total=0"));
        assert!(summary.breakdown().contains("(none)"));
    }

    #[test]
    fn known_feature_prefixes_resolve_and_unknown_ones_are_counted() {
        let (name, id) = karstflow_consensus::features::known_features::FEATURE_REGISTRY[0];
        let mut prefix = [0u8; 8];
        prefix.copy_from_slice(&id[..8]);
        let known = u64::from_le_bytes(prefix);

        let (resolved, unknown) = runner::resolve_features(&[known, 0xDEAD_BEEF_DEAD_BEEF]);
        assert!(
            resolved.contains(&id),
            "{name} should resolve from its prefix"
        );
        assert_eq!(resolved.len(), 1);
        assert_eq!(unknown, 1);
    }
}
