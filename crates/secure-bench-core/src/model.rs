//! Versioned benchmark, result, failure, and provenance models.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The Phase 0 suite schema identifier.
pub const SUITE_SCHEMA_V1: &str = "secure-bench-suite-v1";
/// The Phase 1 first-party corpus schema identifier.
pub const SUITE_SCHEMA_V2: &str = "secure-bench-suite-v2";
/// The Phase 0 recorded run schema identifier.
pub const RUN_SCHEMA_V1: &str = "secure-bench-run-v1";
/// The Phase 0 result schema identifier.
pub const RESULT_SCHEMA_V1: &str = "secure-bench-result-v1";
/// The Phase 1 result schema identifier.
pub const RESULT_SCHEMA_V2: &str = "secure-bench-result-v2";

/// A benchmark suite loaded only by the matcher after report normalization.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BenchmarkSuite {
    /// Versioned schema identifier.
    pub schema_version: String,
    /// Stable suite identifier.
    pub suite_id: String,
    /// Human-readable title.
    pub title: String,
    /// Scope and limitations.
    pub description: String,
    /// Published methodology revision.
    pub methodology_version: String,
    /// Aggregate fingerprint of all scanner-visible fixture content.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub corpus_fingerprint: Option<String>,
    /// Suite-level fixture provenance.
    pub provenance: FixtureProvenance,
    /// Vulnerable cases and safe controls.
    pub cases: Vec<BenchmarkCase>,
}

/// One independently scored benchmark case.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BenchmarkCase {
    /// Stable case identifier.
    pub case_id: String,
    /// Whether this case is vulnerable or a negative control.
    pub kind: CaseKind,
    /// Source language.
    pub language: String,
    /// Optional framework name.
    pub framework: Option<String>,
    /// Neutral vulnerability category.
    pub category: String,
    /// Violated invariant for vulnerable cases.
    pub invariant: Option<String>,
    /// Repository-relative fixture directory.
    pub fixture_path: String,
    /// Fingerprint of scanner-visible files in this case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_fingerprint: Option<String>,
    /// Eligibility declared before evaluation.
    pub eligibility: Eligibility,
    /// Per-case resource limits for black-box runners.
    pub resource_budget: ResourceBudget,
    /// Expected findings; empty for safe controls.
    #[serde(default)]
    pub expected_findings: Vec<ExpectedFinding>,
    /// Case-level provenance and license data.
    pub provenance: FixtureProvenance,
}

/// Case labels are never merged during scoring.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseKind {
    /// A case with at least one declared security invariant violation.
    Vulnerable,
    /// A negative control that must remain separately visible.
    SafeControl,
}

/// Predeclared eligibility requirements.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Eligibility {
    /// Scanner capabilities required for this case.
    #[serde(default)]
    pub required_capabilities: Vec<String>,
    /// Report formats able to carry the necessary evidence.
    pub supported_report_formats: Vec<String>,
    /// Pre-execution eligibility rationale.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
}

/// Execution bounds declared before a scanner is run.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceBudget {
    /// Wall-clock timeout.
    pub timeout_ms: u64,
    /// Maximum resident memory.
    pub memory_bytes: u64,
    /// Maximum accepted report size.
    pub output_bytes: u64,
    /// Declared network policy.
    pub network: NetworkPolicy,
}

/// Future runner network policy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPolicy {
    /// No network access is permitted.
    Disabled,
    /// A future suite version may explicitly permit and record network access.
    ExplicitlyAllowed,
}

/// A labeled finding consumed only after adapter normalization.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedFinding {
    /// Stable expectation identifier.
    pub expectation_id: String,
    /// Prospective canonical taxonomy coordinates; absent from immutable Phase 0 and Phase 1 data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub taxonomy: Option<TaxonomyCoordinates>,
    /// Violated security invariant.
    pub invariant: String,
    /// Neutral category.
    pub category: String,
    /// Expected severity for calibration only, never detection credit.
    pub severity: Severity,
    /// Expected confidence for calibration only, never detection credit.
    pub confidence: Confidence,
    /// Required or alternative source locations.
    pub source: LocationConstraint,
    /// Required or alternative sink locations.
    pub sink: LocationConstraint,
    /// Evidence-path requirements.
    pub evidence: EvidenceConstraint,
}

/// Complete canonical coordinates used by prospective taxonomy-aware expectations.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaxonomyCoordinates {
    /// Frozen taxonomy version.
    pub taxonomy_version: String,
    /// Stable neutral category identifier.
    pub category_id: String,
    /// Stable neutral security invariant identifier.
    pub invariant_id: String,
}

/// Scanner-reported taxonomy metadata before neutral resolution.
#[derive(Clone, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReportedTaxonomyMetadata {
    /// Reported taxonomy version, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub taxonomy_version: Option<String>,
    /// Reported canonical category identifier, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category_id: Option<String>,
    /// Reported canonical invariant identifier, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invariant_id: Option<String>,
}

/// One required location with optional equivalent variants.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocationConstraint {
    /// Primary repository-relative path.
    pub path: String,
    /// Optional exact line.
    pub line: Option<u32>,
    /// Declared equivalent locations.
    #[serde(default)]
    pub alternatives: Vec<LocationVariant>,
}

/// An allowed equivalent location.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocationVariant {
    /// Repository-relative path.
    pub path: String,
    /// Optional exact line.
    pub line: Option<u32>,
}

/// Expected source-to-sink evidence shape.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceConstraint {
    /// Minimum number of normalized hops, including endpoints.
    pub minimum_hops: u32,
    /// Ordered hop kinds that must appear as a subsequence.
    #[serde(default)]
    pub required_kinds: Vec<String>,
}

/// Fixture origin, license, and history.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureProvenance {
    /// Origin of the fixture.
    pub origin: String,
    /// SPDX license expression.
    pub license: String,
    /// Source revision or `original`.
    pub revision: String,
    /// Modifications made for this suite.
    pub modifications: String,
    /// Fixture authors or accountable organization.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authors: Vec<String>,
}

/// A committed description of a mock tool run; it never executes the command.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedRun {
    /// Versioned schema identifier.
    pub schema_version: String,
    /// Stable run identifier.
    pub run_id: String,
    /// Adapter identifier.
    pub adapter: ReportFormat,
    /// Report path relative to the run manifest.
    pub report_path: String,
    /// Recorded public tool information.
    pub tool: ToolProvenance,
    /// Sanitized host metadata.
    pub host: HostProvenance,
    /// Predeclared per-case outcomes.
    pub case_executions: Vec<CaseExecution>,
}

/// Supported mock report formats.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReportFormat {
    /// Secure JSON v1 is treated as a public native contract.
    SecureJsonV1,
    /// SARIF 2.1.0 with evidence-bearing properties.
    Sarif210,
    /// A deliberately unsupported committed format.
    Unsupported,
}

impl ReportFormat {
    /// Stable adapter identifier used in provenance.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SecureJsonV1 => "secure-json-v1",
            Self::Sarif210 => "sarif-2.1.0",
            Self::Unsupported => "unsupported",
        }
    }
}

/// Public tool provenance recorded without importing tool internals.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolProvenance {
    /// Tool display name.
    pub name: String,
    /// Tool version.
    pub version: String,
    /// Explicit command and arguments, recorded as public provenance.
    pub command: Vec<String>,
    /// SHA-256 fingerprint of public configuration.
    pub configuration_fingerprint: String,
    /// Native output schema identifier.
    pub report_schema: String,
    /// SHA-256 of the external executable, when a live runner is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binary_fingerprint: Option<String>,
}

/// Sanitized, reproducibility-oriented host metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostProvenance {
    /// Operating-system family.
    pub os: String,
    /// CPU architecture.
    pub architecture: String,
    /// Logical processor count, if recorded.
    pub logical_cpus: Option<u32>,
    /// Memory total, if recorded.
    pub memory_bytes: Option<u64>,
    /// Kernel release, if recorded without host identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel_release: Option<String>,
}

/// A case-level attempt and its resource measurements.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseExecution {
    /// Case identifier from the suite.
    pub case_id: String,
    /// Outcome that cannot be interpreted as an empty clean report.
    pub status: ExecutionStatus,
    /// Cold duration when recorded.
    pub cold_duration_ms: Option<u64>,
    /// Warm duration when recorded.
    pub warm_duration_ms: Option<u64>,
    /// Peak resident memory when recorded.
    pub peak_memory_bytes: Option<u64>,
    /// Native report contribution when recorded.
    pub output_bytes: Option<u64>,
}

/// Explicit execution or adapter outcomes.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    /// The committed report contains this case's completed scan.
    Success,
    /// The scanner process crashed.
    Crash,
    /// The scanner exceeded its time budget.
    Timeout,
    /// The tool declared the case unsupported before execution.
    Unsupported,
    /// No scan artifact exists for an eligible case.
    Missing,
    /// The adapter could not parse or validate the report.
    ParseFailure,
    /// A bounded report existed but failed live output validation.
    InvalidOutput,
    /// The binary could not be started or monitored.
    ExecutionFailure,
    /// The user cancelled execution.
    Cancelled,
}

/// A normalized, tool-independent finding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizedFinding {
    /// Content-derived identifier, independent of native rule IDs.
    pub finding_id: String,
    /// Case receiving the finding.
    pub case_id: String,
    /// Native rule identifier retained only for traceability.
    pub native_rule_id: String,
    /// Prospective reported taxonomy metadata; absent means explicitly unresolved by adapters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub taxonomy: Option<ReportedTaxonomyMetadata>,
    /// Neutral category.
    pub category: String,
    /// Reported invariant.
    pub invariant: String,
    /// Normalized severity.
    pub severity: Severity,
    /// Normalized confidence.
    pub confidence: Confidence,
    /// Source location.
    pub source: SourceLocation,
    /// Sink location.
    pub sink: SourceLocation,
    /// Ordered evidence path.
    pub evidence_path: Vec<EvidenceHop>,
    /// Link to the unembedded raw artifact.
    pub provenance: FindingProvenance,
}

/// Neutral severity, which does not affect detection credit.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Informational observation.
    Info,
    /// Low severity.
    Low,
    /// Medium severity.
    Medium,
    /// High severity.
    High,
    /// Critical severity.
    Critical,
}

/// Neutral confidence, scored separately from detection.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// Low confidence.
    Low,
    /// Medium confidence.
    Medium,
    /// High confidence.
    High,
}

/// A repository-relative source coordinate.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceLocation {
    /// Slash-separated repository-relative path.
    pub path: String,
    /// One-based line.
    pub line: u32,
    /// One-based column, when supplied.
    pub column: Option<u32>,
}

/// One evidence-path hop.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceHop {
    /// Neutral hop kind.
    pub kind: String,
    /// Hop coordinate.
    pub location: SourceLocation,
}

/// Raw-artifact linkage without embedding scanner messages or source code.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FindingProvenance {
    /// Adapter identifier.
    pub adapter: String,
    /// SHA-256 report fingerprint.
    pub report_fingerprint: String,
    /// Zero-based native result index.
    pub raw_index: u64,
}

/// Expected-to-observed matching output.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MatchingReport {
    /// One decision for every expectation.
    pub expectations: Vec<ExpectationDecision>,
    /// One disposition for every normalized finding.
    pub findings: Vec<FindingDecision>,
}

/// An inspectable expectation decision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectationDecision {
    /// Case identifier.
    pub case_id: String,
    /// Expectation identifier.
    pub expectation_id: String,
    /// Match outcome.
    pub outcome: MatchOutcome,
    /// Deterministically selected finding, if any.
    pub selected_finding_id: Option<String>,
    /// Other valid candidates, ordered by identifier.
    pub ambiguous_finding_ids: Vec<String>,
    /// Atomic criteria explaining the decision.
    pub criteria: MatchCriteria,
}

/// Match status that distinguishes failures and unsupported cases from misses.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchOutcome {
    /// One unambiguous finding matched.
    Matched,
    /// Multiple distinct findings satisfied the expectation.
    Ambiguous,
    /// A successful attempt produced no valid match.
    Missed,
    /// The case did not complete successfully.
    NotAttempted,
    /// The tool declared the case unsupported.
    Unsupported,
}

/// Per-criterion match evidence.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::struct_excessive_bools)]
#[serde(deny_unknown_fields)]
pub struct MatchCriteria {
    /// Category equality.
    pub category: bool,
    /// Invariant equality.
    pub invariant: bool,
    /// Source constraint satisfaction.
    pub source: bool,
    /// Sink constraint satisfaction.
    pub sink: bool,
    /// Evidence-path satisfaction.
    pub evidence_path: bool,
}

/// Disposition of an observed finding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FindingDecision {
    /// Finding identifier.
    pub finding_id: String,
    /// Case identifier.
    pub case_id: String,
    /// Neutral disposition.
    pub disposition: FindingDisposition,
    /// Related expectation or canonical finding identifier.
    pub related_id: Option<String>,
}

/// Finding accounting categories.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingDisposition {
    /// Selected for an expectation.
    Matched,
    /// Additional byte-equivalent normalized alert.
    Duplicate,
    /// Distinct additional candidate for an expectation.
    AmbiguousCandidate,
    /// Alert in a safe control.
    SafeControlFalsePositive,
    /// Alert in a vulnerable case that matched no expectation.
    Unmatched,
    /// Finding ignored because the case did not complete.
    IneligibleRunOutput,
}

/// An exact rational metric with an optional integer rate.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RatioMetric {
    /// Favorable or counted outcomes.
    pub numerator: u64,
    /// Explicit population denominator.
    pub denominator: u64,
    /// Rate in basis points; absent for a zero denominator.
    pub basis_points: Option<u32>,
}

/// Separate, non-composite quality and operational metrics.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScoreCard {
    /// Detection over all eligible vulnerable expectations; failures receive no credit.
    pub vulnerable_recall: RatioMetric,
    /// Detection over successfully attempted vulnerable expectations.
    pub attempted_vulnerable_recall: RatioMetric,
    /// Safe controls with any alert over successfully attempted safe controls.
    pub safe_control_false_positive_rate: RatioMetric,
    /// Successfully clean safe controls over all eligible safe controls.
    pub safe_control_clean_coverage: RatioMetric,
    /// Correct evidence paths over detected expectations.
    pub evidence_path_accuracy: RatioMetric,
    /// Correct source locations over detected expectations.
    pub source_localization_accuracy: RatioMetric,
    /// Correct sink locations over detected expectations.
    pub sink_localization_accuracy: RatioMetric,
    /// Correct severity labels over detected expectations.
    pub severity_calibration_accuracy: RatioMetric,
    /// Correct confidence labels over detected expectations.
    pub confidence_calibration_accuracy: RatioMetric,
    /// Duplicate alerts over normalized alerts from successful cases.
    pub duplicate_rate: RatioMetric,
    /// Counts and explicit denominators used by all metrics.
    pub counts: ScoreCounts,
    /// Failure accounting by outcome.
    pub failures: FailureCounts,
    /// Performance measurements, never folded into quality.
    pub performance: PerformanceMetrics,
}

/// Raw populations supporting the score card.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScoreCounts {
    /// Vulnerable cases in the suite.
    pub vulnerable_cases: u64,
    /// Safe controls in the suite.
    pub safe_control_cases: u64,
    /// Successfully attempted vulnerable cases.
    pub attempted_vulnerable_cases: u64,
    /// Successfully attempted safe controls.
    pub attempted_safe_control_cases: u64,
    /// Expected vulnerable findings in eligible cases.
    pub eligible_expectations: u64,
    /// Expectations in successful cases.
    pub attempted_expectations: u64,
    /// Matched or ambiguous expectations.
    pub detected_expectations: u64,
    /// Missed expectations in successful cases.
    pub missed_expectations: u64,
    /// Safe controls with at least one false positive.
    pub false_positive_safe_controls: u64,
    /// Successfully attempted clean safe controls.
    pub clean_safe_controls: u64,
    /// Normalized findings retained for successful cases.
    pub normalized_findings: u64,
    /// Duplicate normalized findings.
    pub duplicate_findings: u64,
    /// Distinct unmatched findings.
    pub unmatched_findings: u64,
    /// Ambiguous expectation decisions.
    pub ambiguous_expectations: u64,
}

/// Operational outcomes that can never appear as clean scans.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FailureCounts {
    /// Crashed cases.
    pub crashes: u64,
    /// Timed-out cases.
    pub timeouts: u64,
    /// Cases absent from an otherwise recorded run.
    pub missing: u64,
    /// Unsupported cases.
    pub unsupported: u64,
    /// Cases invalidated by adapter parse failure.
    pub parse_failures: u64,
    /// Bounded reports that failed live output validation.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub invalid_outputs: u64,
    /// Cases whose external process could not be executed.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub execution_failures: u64,
    /// Cases cancelled by the user.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub cancellations: u64,
}

/// Separate resource metrics with explicit sample counts.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PerformanceMetrics {
    /// Sum and sample count for cold durations.
    pub cold_duration: MeasurementTotal,
    /// Sum and sample count for warm durations.
    pub warm_duration: MeasurementTotal,
    /// Maximum peak memory and sample count.
    pub peak_memory: MeasurementMaximum,
    /// Sum and sample count for output sizes.
    pub output_size: MeasurementTotal,
}

/// A summed measurement with no implicit denominator.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MeasurementTotal {
    /// Total value.
    pub total: u64,
    /// Number of recorded samples.
    pub samples: u64,
}

/// A maximum measurement with a sample count.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MeasurementMaximum {
    /// Maximum value, absent without samples.
    pub maximum: Option<u64>,
    /// Number of recorded samples.
    pub samples: u64,
}

/// A sanitized evaluation error.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BenchmarkError {
    /// Stable machine-readable code.
    pub code: String,
    /// Pipeline stage.
    pub stage: ErrorStage,
    /// Professional message without raw report contents.
    pub message: String,
}

/// Failure stage.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorStage {
    /// Manifest loading or validation.
    Contract,
    /// Report normalization.
    Adapter,
    /// Matching.
    Matcher,
    /// Scoring.
    Scorer,
    /// External black-box execution.
    Runner,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero(value: &u64) -> bool {
    *value == 0
}

/// Fingerprints and public execution metadata supporting reproducibility.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResultProvenance {
    /// Suite file fingerprint.
    pub suite_fingerprint: String,
    /// Recorded run manifest fingerprint.
    pub run_manifest_fingerprint: String,
    /// Raw report fingerprint.
    pub report_fingerprint: String,
    /// Tool public provenance.
    pub tool: ToolProvenance,
    /// Sanitized host metadata.
    pub host: HostProvenance,
    /// Schema versions participating in this result.
    pub schemas: BTreeMap<String, String>,
}

/// Stable, machine-readable benchmark result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BenchmarkResult {
    /// Versioned result schema identifier.
    pub schema_version: String,
    /// Suite identifier.
    pub suite_id: String,
    /// Run identifier.
    pub run_id: String,
    /// Normalized findings ordered by stable content.
    pub normalized_findings: Vec<NormalizedFinding>,
    /// Complete matching decisions.
    pub matching: MatchingReport,
    /// Separate quality, failure, and performance metrics.
    pub score: ScoreCard,
    /// Structured failures.
    pub errors: Vec<BenchmarkError>,
    /// Reproducibility metadata.
    pub provenance: ResultProvenance,
}
