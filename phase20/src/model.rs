use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One frozen Phase 19 case and its balanced labels.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseSpec {
    /// Opaque case identity.
    pub case_id: String,
    /// Opaque pair identity.
    pub pair_id: String,
    /// Vulnerable or control expectation.
    pub classification: String,
    /// Taxonomy family.
    pub family: String,
    /// Framework label.
    pub framework: String,
    /// Source-format label.
    pub source_format: String,
    /// Topology label.
    pub topology: String,
    /// Repository-relative fixture root.
    pub fixture_path: String,
}

/// Explicit lifecycle state; unavailable states are never numeric results.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionState {
    /// Eligible execution completed with adapter-valid evidence.
    Completed,
    /// Eligible execution or adaptation failed.
    Failed,
    /// Frozen contract explicitly does not support this lane.
    Unsupported,
    /// Eligible lane was intentionally not run.
    NotRun,
    /// Result is unavailable for another explicit reason.
    Unavailable,
}

/// One scanner/lane/case process observation with raw-evidence identities.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    /// Contiguous global attempt sequence.
    pub attempt_sequence: u64,
    /// Scanner identity.
    pub scanner: String,
    /// Native or capability-normalized lane.
    pub lane: String,
    /// Opaque case identity.
    pub case_id: String,
    /// Explicit completion/failure state.
    pub state: ExecutionState,
    /// Separate process-policy decision.
    pub process_decision: String,
    /// Normal exit code when available.
    pub exit_code: Option<i32>,
    /// Whether timeout dominated the attempt.
    pub timed_out: bool,
    /// Wall-clock duration in milliseconds.
    pub duration_ms: u64,
    /// Attempt start time.
    pub started_at_unix_ms: u128,
    /// Full instantiated command digest.
    pub command_sha256: String,
    /// Exact wrapper and scanner argument vector.
    pub command: Vec<String>,
    /// Exact cleared, fixed environment entries.
    pub environment: Vec<String>,
    /// Cleared fixed environment digest.
    pub environment_sha256: String,
    /// Captured stdout digest.
    pub stdout_sha256: String,
    /// Captured stderr digest.
    pub stderr_sha256: String,
    /// Raw report digest when present.
    pub raw_output_sha256: Option<String>,
    /// Adapter-valid finding count; absent on failure.
    pub finding_count: Option<u64>,
    /// Repository-relative raw report path.
    pub raw_output_path: Option<String>,
    /// Repository-relative stdout path.
    pub stdout_path: String,
    /// Repository-relative stderr path.
    pub stderr_path: String,
    /// Explicit failure description.
    pub failure: Option<String>,
}

/// Visible rational metric.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Ratio {
    /// Exact numerator.
    pub numerator: u64,
    /// Exact denominator.
    pub denominator: u64,
    /// Six-decimal display value.
    pub decimal: String,
}

/// Confusion matrix and requested metrics.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Metrics {
    /// True positives.
    pub tp: u64,
    /// False positives.
    pub fp: u64,
    /// True negatives.
    pub tn: u64,
    /// False negatives.
    pub fn_count: u64,
    /// Precision, null for a zero denominator.
    pub precision: Option<Ratio>,
    /// Recall, null for a zero denominator.
    pub recall: Option<Ratio>,
    /// Specificity, null for a zero denominator.
    pub specificity: Option<Ratio>,
    /// F1, null for a zero denominator.
    pub f1: Option<Ratio>,
    /// Balanced accuracy, null for a zero denominator.
    pub balanced_accuracy: Option<Ratio>,
}

/// One completed binary case decision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseDecision {
    /// Case identity.
    pub case_id: String,
    /// Pair identity.
    pub pair_id: String,
    /// Frozen expectation.
    pub expected: String,
    /// Adapter-valid finding count.
    pub finding_count: u64,
    /// Whether at least one finding was emitted.
    pub predicted_positive: bool,
    /// TP, FP, TN, or FN.
    pub outcome: String,
    /// Taxonomy family.
    pub family: String,
    /// Framework.
    pub framework: String,
    /// Source format.
    pub source_format: String,
    /// Topology.
    pub topology: String,
}

/// One vulnerable/control pair decision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PairDecision {
    /// Pair identity.
    pub pair_id: String,
    /// Vulnerable member.
    pub vulnerable_case_id: String,
    /// Control member.
    pub control_case_id: String,
    /// Vulnerable member flag.
    pub vulnerable_flagged: bool,
    /// Control member flag.
    pub control_flagged: bool,
    /// Flagged vulnerable and clean control.
    pub pair_exact: bool,
}

/// Complete result for one scanner and one lane.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LaneResult {
    /// Scanner identity.
    pub scanner: String,
    /// Lane identity.
    pub lane: String,
    /// Explicit lifecycle state.
    pub state: ExecutionState,
    /// Reason for non-completed state.
    pub reason: Option<String>,
    /// Process attempts.
    pub process_attempts: u64,
    /// Completed attempts.
    pub completed_attempts: u64,
    /// Failed attempts.
    pub failed_attempts: u64,
    /// Total wall-clock duration.
    pub total_duration_ms: u64,
    /// Overall metrics, absent unless the entire lane completed.
    pub metrics: Option<Metrics>,
    /// Case decisions.
    pub cases: Vec<CaseDecision>,
    /// Pair decisions.
    pub pairs: Vec<PairDecision>,
    /// Family metrics.
    pub by_family: BTreeMap<String, Metrics>,
    /// Framework metrics.
    pub by_framework: BTreeMap<String, Metrics>,
    /// Source-format metrics.
    pub by_source_format: BTreeMap<String, Metrics>,
    /// Topology metrics.
    pub by_topology: BTreeMap<String, Metrics>,
}

/// Paired or explicitly unavailable comparison.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Comparison {
    /// Left scanner/lane.
    pub left: String,
    /// Right scanner/lane.
    pub right: String,
    /// Same-lane or unavailable comparability state.
    pub comparability: String,
    /// Equal binary predictions.
    pub agreements: Option<u64>,
    /// Cases only left classified correctly.
    pub left_only_correct: Option<u64>,
    /// Cases only right classified correctly.
    pub right_only_correct: Option<u64>,
    /// Absolute requested metric differences.
    pub absolute_metric_differences: Option<BTreeMap<String, Ratio>>,
    /// Explicit reason for unavailable comparison.
    pub reason: Option<String>,
}

/// Canonical Phase 20 neutral results.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Results {
    /// Schema identity.
    pub schema_version: String,
    /// Exact Phase 19 commit.
    pub phase19_commit: String,
    /// Aggregate corpus identity.
    pub aggregate_corpus_sha256: String,
    /// Evidence-contract Merkle root.
    pub contract_merkle_root: String,
    /// Lane-separated results.
    pub lanes: Vec<LaneResult>,
    /// Paired and explicitly unavailable comparisons.
    pub comparisons: Vec<Comparison>,
    /// Exact total process attempts.
    pub total_scanner_process_attempts: u64,
    /// Whether any scanner/lane/case key repeated.
    pub repeated_attempts: bool,
}
