use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One opaque planned scanner/case key, frozen before corpus opening.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanAttempt {
    /// Contiguous global sequence.
    pub sequence: u64,
    /// Qualified scanner identity.
    pub scanner: String,
    /// Always capability-normalized.
    pub lane: String,
    /// Opaque Phase 19 case ID.
    pub case_id: String,
}

/// Canonical frozen execution plan.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionPlan {
    /// Plan schema identity.
    pub schema_version: String,
    /// Required methodological label.
    pub study: String,
    /// Expected total recovery attempts.
    pub total_attempts: u64,
    /// Frozen retry count.
    pub retries: u64,
    /// Explicit Secure Engine exclusion.
    pub secure_engine_attempts: u64,
    /// Ordered unique attempt keys.
    pub attempts: Vec<PlanAttempt>,
}

/// Post-open case metadata used for scoring.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseSpec {
    /// Opaque case identity.
    pub case_id: String,
    /// Opaque vulnerable/control pair identity.
    pub pair_id: String,
    /// Vulnerable or control.
    pub classification: String,
    /// SE1001–SE1007.
    pub family: String,
    /// Framework stratum.
    pub framework: String,
    /// Source-format stratum.
    pub source_format: String,
    /// Topology stratum.
    pub topology: String,
    /// Optional adversarial variant.
    pub adversarial_variant: Option<String>,
    /// Repository-relative fixture root.
    pub fixture_path: String,
}

/// Explicit attempt lifecycle state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptState {
    /// Adapter-valid completed report.
    Completed,
    /// Spawn, process, or adapter failure.
    Failed,
    /// Wall-clock timeout.
    Timeout,
    /// Output was not valid scanner JSON.
    Malformed,
    /// Contract does not support the lane.
    Unsupported,
    /// Evidence is explicitly unavailable.
    Unavailable,
}

/// One preserved recovery process observation.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    /// Contiguous sequence from the frozen plan.
    pub sequence: u64,
    /// Scanner identity.
    pub scanner: String,
    /// Capability-normalized lane.
    pub lane: String,
    /// Opaque case ID.
    pub case_id: String,
    /// Explicit lifecycle state.
    pub state: AttemptState,
    /// Separate process-policy decision.
    pub process_decision: String,
    /// Normal process exit code when available.
    pub exit_code: Option<i32>,
    /// Whether the watchdog killed the PID namespace.
    pub timed_out: bool,
    /// Wall-clock duration.
    pub duration_ms: u64,
    /// Full bubblewrap and scanner argument vector.
    pub command: Vec<String>,
    /// Command-vector hash.
    pub command_sha256: String,
    /// Exact cleared environment.
    pub environment: Vec<String>,
    /// Environment-vector hash.
    pub environment_sha256: String,
    /// Standard-output evidence path.
    pub stdout_path: String,
    /// Standard-output hash.
    pub stdout_sha256: String,
    /// Standard-error evidence path.
    pub stderr_path: String,
    /// Standard-error hash.
    pub stderr_sha256: String,
    /// Raw output path when present.
    pub raw_output_path: Option<String>,
    /// Raw output hash when present.
    pub raw_output_sha256: Option<String>,
    /// Adapter-valid finding count.
    pub finding_count: Option<u64>,
    /// Failure reason, never converted to a numeric result.
    pub failure: Option<String>,
}

/// Visible exact ratio with a stable decimal projection.
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
    /// Precision.
    pub precision: Option<Ratio>,
    /// Recall.
    pub recall: Option<Ratio>,
    /// Specificity.
    pub specificity: Option<Ratio>,
    /// F1.
    pub f1: Option<Ratio>,
    /// Balanced accuracy.
    pub balanced_accuracy: Option<Ratio>,
}

/// One case-level decision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseDecision {
    /// Case identity.
    pub case_id: String,
    /// Pair identity.
    pub pair_id: String,
    /// Frozen expectation.
    pub expected: String,
    /// Finding count.
    pub finding_count: u64,
    /// Binary scanner prediction.
    pub predicted_positive: bool,
    /// TP, FP, TN, or FN.
    pub outcome: String,
    /// Family.
    pub family: String,
    /// Framework.
    pub framework: String,
    /// Source format.
    pub source_format: String,
    /// Topology.
    pub topology: String,
    /// Adversarial variant or `none`.
    pub adversarial_variant: String,
}

/// One vulnerable/control pair result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PairDecision {
    /// Pair identity.
    pub pair_id: String,
    /// Vulnerable case ID.
    pub vulnerable_case_id: String,
    /// Control case ID.
    pub control_case_id: String,
    /// Vulnerable member prediction.
    pub vulnerable_flagged: bool,
    /// Control member prediction.
    pub control_flagged: bool,
    /// Exact pair success.
    pub pair_exact: bool,
}

/// Separate operational and duration summary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Operations {
    /// Planned processes.
    pub attempts: u64,
    /// Adapter-valid completions.
    pub completed: u64,
    /// Failed processes/adapters.
    pub failed: u64,
    /// Timed-out processes.
    pub timeouts: u64,
    /// Malformed reports.
    pub malformed: u64,
    /// Contract-unsupported observations.
    pub unsupported: u64,
    /// Missing or unavailable evidence.
    pub unavailable: u64,
    /// Total duration.
    pub total_duration_ms: u64,
    /// Minimum duration.
    pub min_duration_ms: Option<u64>,
    /// Median duration.
    pub median_duration_ms: Option<u64>,
    /// 95th percentile duration.
    pub p95_duration_ms: Option<u64>,
    /// Maximum duration.
    pub max_duration_ms: Option<u64>,
}

/// Complete lane result with separated quality and operations.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LaneResult {
    /// Scanner identity.
    pub scanner: String,
    /// Capability-normalized lane.
    pub lane: String,
    /// completed, partial, or failed.
    pub state: String,
    /// Operations and performance.
    pub operations: Operations,
    /// Overall metrics only for a complete lane.
    pub metrics: Option<Metrics>,
    /// Case decisions only for completed observations.
    pub cases: Vec<CaseDecision>,
    /// Pair decisions only for a complete lane.
    pub pairs: Vec<PairDecision>,
    /// Metrics by family.
    pub by_family: BTreeMap<String, Metrics>,
    /// Metrics by framework.
    pub by_framework: BTreeMap<String, Metrics>,
    /// Metrics by source format.
    pub by_source_format: BTreeMap<String, Metrics>,
    /// Metrics by topology.
    pub by_topology: BTreeMap<String, Metrics>,
    /// Metrics by adversarial variant.
    pub by_adversarial_variant: BTreeMap<String, Metrics>,
    /// Metrics by vulnerable/control classification.
    pub by_classification: BTreeMap<String, Metrics>,
}

/// One paired scanner disagreement.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Disagreement {
    /// Case identity.
    pub case_id: String,
    /// Expected class.
    pub expected: String,
    /// OpenGrep prediction.
    pub opengrep_positive: bool,
    /// Semgrep prediction.
    pub semgrep_positive: bool,
    /// OpenGrep finding count.
    pub opengrep_findings: u64,
    /// Semgrep finding count.
    pub semgrep_findings: u64,
    /// OpenGrep outcome.
    pub opengrep_outcome: String,
    /// Semgrep outcome.
    pub semgrep_outcome: String,
    /// Family.
    pub family: String,
    /// Framework.
    pub framework: String,
    /// Source format.
    pub source_format: String,
    /// Topology.
    pub topology: String,
    /// Adversarial variant.
    pub adversarial_variant: String,
}

/// Paired normalized-lane comparison.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Comparison {
    /// Comparability state.
    pub state: String,
    /// Shared lane.
    pub lane: String,
    /// Equal predictions.
    pub agreements: Option<u64>,
    /// Cases only OpenGrep classified correctly.
    pub opengrep_only_correct: Option<u64>,
    /// Cases only Semgrep classified correctly.
    pub semgrep_only_correct: Option<u64>,
    /// Cases both classified incorrectly.
    pub both_incorrect: Option<u64>,
    /// Absolute metric differences.
    pub absolute_metric_differences: BTreeMap<String, Ratio>,
    /// Explicit disagreement table.
    pub disagreements: Vec<Disagreement>,
    /// Reason when unavailable.
    pub reason: Option<String>,
}

/// Historical row kept separate from Phase 22 metrics.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalRow {
    /// Phase identity.
    pub phase: String,
    /// Study identity.
    pub study: String,
    /// Scanner identity.
    pub scanner: String,
    /// Lane identity.
    pub lane: String,
    /// Historical or recovery state.
    pub state: String,
    /// Process attempts in that phase row.
    pub attempts: u64,
    /// Explicit non-merging note.
    pub note: String,
}

/// Canonical Phase 22 results.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Results {
    /// Results schema identity.
    pub schema_version: String,
    /// Required study label.
    pub study: String,
    /// Exact Phase 21 base.
    pub phase21_commit: String,
    /// Recovery attempt total.
    pub total_recovery_attempts: u64,
    /// Retry total.
    pub retries: u64,
    /// Secure Engine attempt total.
    pub secure_engine_attempts: u64,
    /// Whether any key repeated.
    pub repeated_attempts: bool,
    /// Scanner lane results.
    pub lanes: Vec<LaneResult>,
    /// Paired normalized comparison.
    pub comparison: Comparison,
    /// Cross-phase rows without metric merging.
    pub historical: Vec<HistoricalRow>,
}

/// Hash-chained execution ledger entry.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerEntry {
    /// Schema identity.
    pub schema_version: String,
    /// Contiguous sequence.
    pub sequence: u64,
    /// Event class.
    pub event: String,
    /// Observation hash.
    pub payload_sha256: String,
    /// Previous entry hash.
    pub previous_entry_hash: String,
    /// Complete entry hash.
    pub entry_hash: String,
}
