//! Prospective taxonomy evaluation and repeat-run comparison for Secure Bench Phase 2.

use crate::adapter::fingerprint;
use crate::model::{
    BenchmarkResult, BenchmarkSuite, CaseKind, FindingDisposition, HostProvenance, MatchOutcome,
    NormalizedFinding, RatioMetric, ReportedTaxonomyMetadata, TaxonomyCoordinates,
};
use crate::pipeline::{LiveEvaluationInput, evaluate_live_run, load_suite};
use crate::runner::{
    DEFAULT_SECURE_ENGINE_ARGUMENTS, LiveCaseStatus, LiveRun, LiveRunStatus, VersionProbeStatus,
    load_live_run,
};
use crate::taxonomy::{
    FrozenTaxonomy, TaxonomyMatchCriteria, TaxonomyResolution, UnmappedReason, load_taxonomy,
    match_taxonomy_finding, resolve_reported_taxonomy,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

/// Schema identifier for the prospective expectation taxonomy profile.
pub const TAXONOMY_PROFILE_SCHEMA_V1: &str = "secure-bench-taxonomy-profile-v1";
/// Schema identifier for a Linux network-namespace attestation.
pub const NETWORK_ISOLATION_SCHEMA_V1: &str = "secure-bench-network-isolation-v1";
/// Schema identifier for the Phase 2 prospective evaluation result.
pub const PHASE2_RESULT_SCHEMA_V1: &str = "secure-bench-phase2-result-v1";

const EXPECTED_PROFILE_ID: &str = "phase-1-corpus-taxonomy-v1";
const EXPECTED_SUITE_ID: &str = "phase-1-javascript-typescript";
const EXPECTED_TOOL_VERSION: &str = "secure 0.1.1";
const EXPECTED_NETWORK_MECHANISM: &str = "bwrap-unshare-net";
const EXPECTED_NETWORK_SCOPE: &str = "version-probe-and-all-scanner-processes";

/// Frozen prospective taxonomy coordinates for the immutable Phase 1 expectations.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaxonomyProfile {
    /// Profile contract version.
    pub schema_version: String,
    /// Stable profile identity.
    pub profile_id: String,
    /// Frozen taxonomy schema identity.
    pub taxonomy_schema: String,
    /// Frozen taxonomy semantic version.
    pub taxonomy_version: String,
    /// Frozen taxonomy canonical content hash.
    pub taxonomy_content_hash: String,
    /// Immutable suite identity.
    pub suite_id: String,
    /// SHA-256 of the immutable suite manifest bytes.
    pub suite_fingerprint: String,
    /// Aggregate scanner-visible corpus fingerprint.
    pub corpus_fingerprint: String,
    /// Sorted expectation-to-taxonomy assignments established before execution.
    pub assignments: Vec<TaxonomyAssignment>,
}

/// One prospective expected taxonomy assignment.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaxonomyAssignment {
    /// Vulnerable case identity.
    pub case_id: String,
    /// Immutable expectation identity.
    pub expectation_id: String,
    /// Canonical frozen category identifier.
    pub category_id: String,
    /// Canonical frozen invariant identifier.
    pub invariant_id: String,
}

/// Machine-readable proof collected inside the scanner's network namespace.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkIsolationAttestation {
    /// Attestation schema identity.
    pub schema_version: String,
    /// Isolation mechanism selected by the benchmark operator.
    pub mechanism: String,
    /// Declared process scope covered by the same wrapper.
    pub scope: String,
    /// Interfaces visible through `/proc/net/dev` inside the namespace.
    pub interfaces: Vec<String>,
    /// Result of a bounded non-loopback TCP connection attempt.
    pub outbound_connectivity: String,
    /// Fixed probe target used only to establish that routing is unavailable.
    pub probe_target: String,
}

/// Raw inputs for one primary and one repeat prospective evaluation.
#[derive(Debug)]
pub struct Phase2EvaluationInput<'a> {
    /// Immutable Phase 1 suite bytes.
    pub suite: &'a [u8],
    /// Frozen taxonomy bytes.
    pub taxonomy: &'a [u8],
    /// Pre-execution taxonomy profile bytes.
    pub profile: &'a [u8],
    /// Network-isolation attestation bytes.
    pub network_attestation: &'a [u8],
    /// Immutable Phase 1 evaluated result bytes.
    pub phase1_result: &'a [u8],
    /// Primary live-run manifest bytes.
    pub primary_run: &'a [u8],
    /// Primary raw reports keyed by bundle-relative path.
    pub primary_reports: &'a BTreeMap<String, Vec<u8>>,
    /// Repeat live-run manifest bytes.
    pub repeat_run: &'a [u8],
    /// Repeat raw reports keyed by bundle-relative path.
    pub repeat_reports: &'a BTreeMap<String, Vec<u8>>,
    /// Expected external black-box binary SHA-256.
    pub binary_fingerprint: &'a str,
    /// User-supplied source RPM SHA-256.
    pub source_rpm_fingerprint: &'a str,
}

/// Complete deterministic Phase 2 result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase2Result {
    /// Phase 2 result contract identity.
    pub schema_version: String,
    /// Immutable evaluated suite identity.
    pub suite_id: String,
    /// Frozen taxonomy version.
    pub taxonomy_version: String,
    /// Primary and repeat run identities.
    pub run_ids: Vec<String>,
    /// One decision for every vulnerable expectation and safe control.
    pub cases: Vec<Phase2CaseDecision>,
    /// Stable privacy-safe finding records for the primary run.
    pub findings: Vec<Phase2FindingRecord>,
    /// Exact quality and agreement metrics.
    pub metrics: Phase2Metrics,
    /// Primary process and resource measurements.
    pub primary_measurement: Phase2RunMeasurement,
    /// Repeat process and resource measurements.
    pub repeat_measurement: Phase2RunMeasurement,
    /// Determinism and fingerprint comparison.
    pub stability: Phase2Stability,
    /// Explicit comparison with the immutable Phase 1 result.
    pub comparison: Phase2Comparison,
    /// Binary, corpus, taxonomy, environment, and artifact provenance.
    pub provenance: Phase2Provenance,
}

/// Prospective case outcome.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase2Outcome {
    /// Canonical taxonomy and every evidence constraint matched.
    ExactCanonicalDetection,
    /// At least one frozen taxonomy or evidence dimension matched, but not all.
    PartialMatch,
    /// A successful eligible scan produced no matching dimension.
    Missed,
    /// The public report schema was unsupported.
    OutOfScope,
    /// The case failed operationally and cannot be interpreted as clean.
    NotAttempted,
    /// A safe control produced one or more distinct findings.
    SafeControlFlagged,
    /// A successfully scanned safe control produced no findings.
    SafeControlClean,
}

/// Atomic prospective agreement dimensions.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::struct_excessive_bools)]
#[serde(deny_unknown_fields)]
pub struct Phase2Criteria {
    /// Reported taxonomy metadata resolved to one frozen pair.
    pub taxonomy_mapped: bool,
    /// Canonical category identifier agreement.
    pub category: bool,
    /// Canonical invariant identifier agreement.
    pub invariant: bool,
    /// The resolved pair carries the expected primary CWE association.
    pub cwe: bool,
    /// Expected source constraint agreement.
    pub source: bool,
    /// Expected sink constraint agreement.
    pub sink: bool,
    /// Expected ordered evidence-path agreement.
    pub evidence_path: bool,
}

impl Phase2Criteria {
    fn is_exact(&self) -> bool {
        self.taxonomy_mapped
            && self.category
            && self.invariant
            && self.cwe
            && self.source
            && self.sink
            && self.evidence_path
    }

    fn partial_score(&self) -> u8 {
        u8::from(self.category && self.invariant && self.cwe)
            + u8::from(self.source)
            + u8::from(self.sink)
            + u8::from(self.evidence_path)
    }
}

/// One vulnerable expectation or safe-control decision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase2CaseDecision {
    /// Case identifier.
    pub case_id: String,
    /// Immutable case label.
    pub kind: CaseKind,
    /// Expected finding identifier for vulnerable cases.
    pub expectation_id: Option<String>,
    /// Prospective outcome.
    pub outcome: Phase2Outcome,
    /// Black-box execution status.
    pub execution_status: LiveCaseStatus,
    /// Deterministically selected candidate finding.
    pub selected_finding_id: Option<String>,
    /// Pre-execution expected taxonomy coordinates.
    pub expected_taxonomy: Option<TaxonomyCoordinates>,
    /// Expected primary CWE association.
    pub primary_cwe: Option<String>,
    /// Atomic agreement for the selected candidate.
    pub criteria: Option<Phase2Criteria>,
    /// Normalized findings observed in this case.
    pub finding_count: u64,
    /// Findings with duplicate semantic fingerprints in this case.
    pub duplicate_findings: u64,
}

/// Stable record linking a normalized finding to raw provenance without report prose.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase2FindingRecord {
    /// Content-derived normalized finding identifier.
    pub finding_id: String,
    /// Case containing the finding.
    pub case_id: String,
    /// Stable semantic fingerprint excluding raw timestamps and report provenance.
    pub semantic_fingerprint: String,
    /// Canonical earlier finding when this record is a duplicate.
    pub duplicate_of: Option<String>,
    /// Resolved canonical taxonomy coordinates, when available.
    pub resolved_taxonomy: Option<TaxonomyCoordinates>,
    /// Explicit reason taxonomy metadata remained unmapped.
    pub unmapped_reason: Option<UnmappedReason>,
    /// SHA-256 of the raw report containing the finding.
    pub report_fingerprint: String,
}

/// Phase 2 raw counts supporting every ratio.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase2Counts {
    /// Eligible vulnerable expectations.
    pub eligible_expectations: u64,
    /// Exact canonical detections.
    pub exact_detections: u64,
    /// Partial matches receiving no exact-detection credit.
    pub partial_matches: u64,
    /// Successful scans with no matching dimension.
    pub misses: u64,
    /// Unsupported-schema vulnerable cases.
    pub out_of_scope: u64,
    /// Operationally failed vulnerable cases.
    pub not_attempted: u64,
    /// Safe controls producing findings.
    pub safe_controls_flagged: u64,
    /// Successfully clean safe controls.
    pub clean_safe_controls: u64,
    /// Safe controls that did not complete.
    pub safe_controls_not_attempted: u64,
    /// All normalized findings in completed cases.
    pub normalized_findings: u64,
    /// Semantically duplicate findings.
    pub duplicate_findings: u64,
    /// Distinct findings not selected for exact detection credit.
    pub false_positive_findings: u64,
}

/// Exact Phase 2 ratios and agreement rates.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase2Metrics {
    /// Raw supporting populations.
    pub counts: Phase2Counts,
    /// Exact finding-level precision.
    pub precision: RatioMetric,
    /// Exact expectation-level recall.
    pub recall: RatioMetric,
    /// Harmonic mean represented as an exact ratio.
    pub f1: RatioMetric,
    /// Canonical category agreement over all eligible expectations.
    pub category_agreement: RatioMetric,
    /// Canonical invariant agreement over all eligible expectations.
    pub invariant_agreement: RatioMetric,
    /// Frozen primary CWE association agreement over all eligible expectations.
    pub cwe_agreement: RatioMetric,
    /// Source agreement over all eligible expectations.
    pub source_agreement: RatioMetric,
    /// Sink agreement over all eligible expectations.
    pub sink_agreement: RatioMetric,
    /// Evidence-path agreement over all eligible expectations.
    pub evidence_path_agreement: RatioMetric,
}

/// Per-run process, output, failure, and resource measurements.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase2RunMeasurement {
    /// Stable run identifier.
    pub run_id: String,
    /// Aggregate live-run status.
    pub status: LiveRunStatus,
    /// Number of suite cases.
    pub cases: u64,
    /// Completed adapter-valid cases.
    pub completed_cases: u64,
    /// Cases with retained findings.
    pub findings_cases: u64,
    /// Total measured case duration.
    pub total_duration_ms: u64,
    /// Maximum sampled direct-process RSS.
    pub peak_rss_bytes: Option<u64>,
    /// Total retained report bytes.
    pub total_output_bytes: u64,
    /// Explicit status counts.
    pub status_counts: BTreeMap<String, u64>,
    /// Per-case process exit codes; null means forced or unavailable.
    pub exit_codes: BTreeMap<String, Option<i32>>,
}

/// Repeat-run equality and fingerprint stability.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::struct_excessive_bools)]
#[serde(deny_unknown_fields)]
pub struct Phase2Stability {
    /// Finding identifiers were identical across both runs.
    pub finding_ids_equal: bool,
    /// Semantic finding fingerprints were identical across both runs.
    pub semantic_findings_equal: bool,
    /// All case outcomes and criteria were identical.
    pub case_decisions_equal: bool,
    /// All quality and agreement metrics were identical.
    pub metrics_equal: bool,
    /// Complete deterministic semantic evaluation equality.
    pub deterministic_evaluation_equal: bool,
    /// Raw reports were byte-identical, including volatile report metadata.
    pub raw_reports_equal: bool,
    /// Case identifiers whose raw report bytes differed.
    pub raw_report_differences: Vec<String>,
    /// Primary fingerprints also present in the repeat run.
    pub fingerprint_stability: RatioMetric,
    /// Primary semantic result SHA-256.
    pub primary_semantic_fingerprint: String,
    /// Repeat semantic result SHA-256.
    pub repeat_semantic_fingerprint: String,
}

/// Explicit Phase 1 versus Phase 2 outcome separation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase2Comparison {
    /// Phase 1 exact detections under its immutable methodology.
    pub phase1_exact_detections: u64,
    /// Phase 2 exact detections under taxonomy 1.0.0.
    pub phase2_exact_detections: u64,
    /// Phase 2 exact cases whose Phase 1 evidence already matched except vocabulary.
    pub taxonomy_alignment_improvements: Vec<String>,
    /// Phase 2 exact cases without a Phase 1 taxonomy-alignment opportunity.
    pub newly_detected_vulnerabilities: Vec<String>,
    /// Phase 1 flagged controls that became clean.
    pub resolved_safe_control_flags: Vec<String>,
    /// Vulnerable cases still lacking exact Phase 2 credit.
    pub remaining_misses: Vec<String>,
    /// Controls flagged in both phases.
    pub remaining_safe_control_flags: Vec<String>,
    /// Phase 1 detections lost in Phase 2.
    pub detection_regressions: Vec<String>,
    /// Previously clean controls newly flagged in Phase 2.
    pub false_positive_regressions: Vec<String>,
}

/// Complete public Phase 2 provenance.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase2Provenance {
    /// External binary SHA-256.
    pub binary_fingerprint: String,
    /// User-supplied source RPM SHA-256.
    pub source_rpm_fingerprint: String,
    /// Immutable suite manifest SHA-256.
    pub suite_fingerprint: String,
    /// Scanner-visible aggregate corpus fingerprint.
    pub corpus_fingerprint: String,
    /// Frozen taxonomy artifact SHA-256.
    pub taxonomy_artifact_fingerprint: String,
    /// Frozen taxonomy canonical content hash.
    pub taxonomy_content_hash: String,
    /// Pre-execution profile artifact SHA-256.
    pub taxonomy_profile_fingerprint: String,
    /// Network-isolation attestation SHA-256.
    pub network_attestation_fingerprint: String,
    /// Immutable Phase 1 result SHA-256.
    pub phase1_result_fingerprint: String,
    /// Primary live-run manifest SHA-256.
    pub primary_run_fingerprint: String,
    /// Repeat live-run manifest SHA-256.
    pub repeat_run_fingerprint: String,
    /// Aggregate primary raw-report fingerprint.
    pub primary_report_fingerprint: String,
    /// Aggregate repeat raw-report fingerprint.
    pub repeat_report_fingerprint: String,
    /// Tool-reported public version.
    pub tool_version: String,
    /// Exact public scanner argument template.
    pub command_template: Vec<String>,
    /// Requested public report schema.
    pub report_schema: String,
    /// Explicit empty configuration SHA-256.
    pub configuration_fingerprint: String,
    /// AI validation state.
    pub ai_validation: String,
    /// Kernel-enforced network isolation mechanism.
    pub network_isolation: String,
    /// Sanitized primary host information.
    pub primary_host: HostProvenance,
    /// Sanitized repeat host information.
    pub repeat_host: HostProvenance,
    /// Participating versioned schemas.
    pub schemas: BTreeMap<String, String>,
}

/// Phase 2 contract or evaluation failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum Phase2Error {
    /// Typed JSON input was malformed.
    #[error("invalid {contract} JSON at line {line}")]
    InvalidJson {
        /// Contract label.
        contract: &'static str,
        /// One-based parser line.
        line: usize,
    },
    /// A contract failed schema or semantic validation.
    #[error("invalid Phase 2 contract: {0}")]
    InvalidContract(String),
    /// A reused Phase 1 live evaluator rejected a bundle.
    #[error("invalid live-run bundle: {0}")]
    InvalidLiveRun(String),
    /// Deterministic output serialization failed.
    #[error("could not serialize deterministic Phase 2 data")]
    Serialization,
}

#[derive(Serialize)]
struct StableFindingView<'a> {
    case_id: &'a str,
    taxonomy: &'a Option<ReportedTaxonomyMetadata>,
    category: &'a str,
    invariant: &'a str,
    source: &'a crate::model::SourceLocation,
    sink: &'a crate::model::SourceLocation,
    evidence_path: &'a [crate::model::EvidenceHop],
}

struct EvaluatedRun {
    decisions: Vec<Phase2CaseDecision>,
    records: Vec<Phase2FindingRecord>,
    metrics: Phase2Metrics,
}

/// Loads and validates a pre-execution taxonomy profile.
///
/// # Errors
///
/// Returns [`Phase2Error`] for JSON, schema, suite-linkage, ordering, or taxonomy failures.
pub fn load_taxonomy_profile(
    bytes: &[u8],
    suite_bytes: &[u8],
    taxonomy: &FrozenTaxonomy,
) -> Result<TaxonomyProfile, Phase2Error> {
    let profile: TaxonomyProfile =
        serde_json::from_slice(bytes).map_err(|error| Phase2Error::InvalidJson {
            contract: "taxonomy profile",
            line: error.line(),
        })?;
    crate::schema::validate_taxonomy_profile(&profile)
        .map_err(|error| Phase2Error::InvalidContract(error.to_string()))?;
    let suite =
        load_suite(suite_bytes).map_err(|error| Phase2Error::InvalidContract(error.to_string()))?;
    validate_profile_semantics(&profile, &suite, suite_bytes, taxonomy)?;
    Ok(profile)
}

/// Loads and validates an isolation attestation generated inside the scanner namespace.
///
/// # Errors
///
/// Returns [`Phase2Error`] for malformed, invalid, or non-isolated evidence.
pub fn load_network_attestation(bytes: &[u8]) -> Result<NetworkIsolationAttestation, Phase2Error> {
    let attestation: NetworkIsolationAttestation =
        serde_json::from_slice(bytes).map_err(|error| Phase2Error::InvalidJson {
            contract: "network isolation attestation",
            line: error.line(),
        })?;
    crate::schema::validate_network_attestation(&attestation)
        .map_err(|error| Phase2Error::InvalidContract(error.to_string()))?;
    if attestation.schema_version != NETWORK_ISOLATION_SCHEMA_V1
        || attestation.mechanism != EXPECTED_NETWORK_MECHANISM
        || attestation.scope != EXPECTED_NETWORK_SCOPE
        || attestation.interfaces != ["lo"]
        || attestation.outbound_connectivity != "blocked"
        || attestation.probe_target != "1.1.1.1:53"
    {
        return Err(Phase2Error::InvalidContract(
            "network attestation does not prove a loopback-only blocked namespace".to_owned(),
        ));
    }
    Ok(attestation)
}

/// Evaluates two retained runs under the frozen taxonomy and compares Phase 1 without mutation.
///
/// # Errors
///
/// Returns [`Phase2Error`] when any versioned input, provenance link, or generated result fails.
#[allow(clippy::too_many_lines)]
pub fn evaluate_phase2(input: &Phase2EvaluationInput<'_>) -> Result<Phase2Result, Phase2Error> {
    let taxonomy = load_taxonomy(input.taxonomy)
        .map_err(|error| Phase2Error::InvalidContract(error.to_string()))?;
    let mut suite =
        load_suite(input.suite).map_err(|error| Phase2Error::InvalidContract(error.to_string()))?;
    let profile = load_taxonomy_profile(input.profile, input.suite, &taxonomy)?;
    let _attestation = load_network_attestation(input.network_attestation)?;
    if !is_sha256(input.binary_fingerprint) || !is_sha256(input.source_rpm_fingerprint) {
        return Err(Phase2Error::InvalidContract(
            "binary and source RPM fingerprints must be lowercase SHA-256".to_owned(),
        ));
    }
    apply_profile(&mut suite, &profile)?;

    let primary_result = evaluate_live_run(&LiveEvaluationInput {
        suite: input.suite,
        run_manifest: input.primary_run,
        reports: input.primary_reports,
    })
    .map_err(|error| Phase2Error::InvalidLiveRun(error.to_string()))?;
    let repeat_result = evaluate_live_run(&LiveEvaluationInput {
        suite: input.suite,
        run_manifest: input.repeat_run,
        reports: input.repeat_reports,
    })
    .map_err(|error| Phase2Error::InvalidLiveRun(error.to_string()))?;
    let primary_run = load_live_run(input.primary_run)
        .map_err(|error| Phase2Error::InvalidLiveRun(error.to_string()))?;
    let repeat_run = load_live_run(input.repeat_run)
        .map_err(|error| Phase2Error::InvalidLiveRun(error.to_string()))?;
    validate_run_pair(&primary_run, &repeat_run, input.binary_fingerprint)?;

    let primary = evaluate_taxonomy_run(
        &suite,
        &taxonomy,
        &primary_result.normalized_findings,
        &primary_run,
    )?;
    let repeat = evaluate_taxonomy_run(
        &suite,
        &taxonomy,
        &repeat_result.normalized_findings,
        &repeat_run,
    )?;
    let stability = build_stability(
        &primary,
        &repeat,
        input.primary_reports,
        input.repeat_reports,
    )?;
    let phase1: BenchmarkResult =
        serde_json::from_slice(input.phase1_result).map_err(|error| Phase2Error::InvalidJson {
            contract: "Phase 1 result",
            line: error.line(),
        })?;
    let comparison = compare_phase1(&suite, &phase1, &primary.decisions);
    let schemas = BTreeMap::from([
        (
            "live_run".to_owned(),
            crate::runner::LIVE_RUN_SCHEMA_V1.to_owned(),
        ),
        (
            "phase1_result".to_owned(),
            crate::model::RESULT_SCHEMA_V2.to_owned(),
        ),
        (
            "phase2_result".to_owned(),
            PHASE2_RESULT_SCHEMA_V1.to_owned(),
        ),
        ("suite".to_owned(), crate::model::SUITE_SCHEMA_V2.to_owned()),
        ("taxonomy".to_owned(), taxonomy.schema_version.clone()),
        (
            "taxonomy_profile".to_owned(),
            profile.schema_version.clone(),
        ),
        (
            "tool_report".to_owned(),
            primary_run.tool.report_schema.clone(),
        ),
    ]);
    let result = Phase2Result {
        schema_version: PHASE2_RESULT_SCHEMA_V1.to_owned(),
        suite_id: suite.suite_id.clone(),
        taxonomy_version: taxonomy.taxonomy_version.clone(),
        run_ids: vec![primary_run.run_id.clone(), repeat_run.run_id.clone()],
        cases: primary.decisions,
        findings: primary.records,
        metrics: primary.metrics,
        primary_measurement: run_measurement(&primary_run),
        repeat_measurement: run_measurement(&repeat_run),
        stability,
        comparison,
        provenance: Phase2Provenance {
            binary_fingerprint: input.binary_fingerprint.to_owned(),
            source_rpm_fingerprint: input.source_rpm_fingerprint.to_owned(),
            suite_fingerprint: fingerprint(input.suite),
            corpus_fingerprint: profile.corpus_fingerprint,
            taxonomy_artifact_fingerprint: fingerprint(input.taxonomy),
            taxonomy_content_hash: taxonomy.content_hash,
            taxonomy_profile_fingerprint: fingerprint(input.profile),
            network_attestation_fingerprint: fingerprint(input.network_attestation),
            phase1_result_fingerprint: fingerprint(input.phase1_result),
            primary_run_fingerprint: fingerprint(input.primary_run),
            repeat_run_fingerprint: fingerprint(input.repeat_run),
            primary_report_fingerprint: primary_result.provenance.report_fingerprint,
            repeat_report_fingerprint: repeat_result.provenance.report_fingerprint,
            tool_version: primary_run.tool.reported_version.clone(),
            command_template: primary_run.tool.argument_template.clone(),
            report_schema: primary_run.tool.report_schema.clone(),
            configuration_fingerprint: primary_run.tool.configuration_fingerprint.clone(),
            ai_validation: "disabled".to_owned(),
            network_isolation: EXPECTED_NETWORK_MECHANISM.to_owned(),
            primary_host: primary_run.host,
            repeat_host: repeat_run.host,
            schemas,
        },
    };
    crate::schema::validate_phase2_result(&result)
        .map_err(|error| Phase2Error::InvalidContract(error.to_string()))?;
    Ok(result)
}

/// Returns deterministic pretty JSON with one trailing newline.
///
/// # Errors
///
/// Returns [`Phase2Error::Serialization`] if serialization fails.
pub fn canonical_phase2_json(result: &Phase2Result) -> Result<Vec<u8>, Phase2Error> {
    let mut bytes = serde_json::to_vec_pretty(result).map_err(|_| Phase2Error::Serialization)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn validate_profile_semantics(
    profile: &TaxonomyProfile,
    suite: &BenchmarkSuite,
    suite_bytes: &[u8],
    taxonomy: &FrozenTaxonomy,
) -> Result<(), Phase2Error> {
    if profile.schema_version != TAXONOMY_PROFILE_SCHEMA_V1
        || profile.profile_id != EXPECTED_PROFILE_ID
        || profile.taxonomy_schema != taxonomy.schema_version
        || profile.taxonomy_version != taxonomy.taxonomy_version
        || profile.taxonomy_content_hash != taxonomy.content_hash
        || profile.suite_id != EXPECTED_SUITE_ID
        || profile.suite_id != suite.suite_id
        || profile.suite_fingerprint != fingerprint(suite_bytes)
        || Some(profile.corpus_fingerprint.as_str()) != suite.corpus_fingerprint.as_deref()
    {
        return Err(Phase2Error::InvalidContract(
            "taxonomy profile does not link exactly to the frozen suite and taxonomy".to_owned(),
        ));
    }
    if !profile
        .assignments
        .windows(2)
        .all(|window| window[0] < window[1])
    {
        return Err(Phase2Error::InvalidContract(
            "taxonomy assignments must be strictly sorted and unique".to_owned(),
        ));
    }
    let expected = suite
        .cases
        .iter()
        .filter(|case| case.kind == CaseKind::Vulnerable)
        .flat_map(|case| {
            case.expected_findings
                .iter()
                .map(move |finding| (case.case_id.as_str(), finding.expectation_id.as_str()))
        })
        .collect::<BTreeSet<_>>();
    let assigned = profile
        .assignments
        .iter()
        .map(|assignment| {
            (
                assignment.case_id.as_str(),
                assignment.expectation_id.as_str(),
            )
        })
        .collect::<BTreeSet<_>>();
    if expected != assigned || profile.assignments.len() != expected.len() {
        return Err(Phase2Error::InvalidContract(
            "taxonomy profile must assign every immutable vulnerable expectation exactly once"
                .to_owned(),
        ));
    }
    for assignment in &profile.assignments {
        let reported = ReportedTaxonomyMetadata {
            taxonomy_version: Some(profile.taxonomy_version.clone()),
            category_id: Some(assignment.category_id.clone()),
            invariant_id: Some(assignment.invariant_id.clone()),
        };
        if !matches!(
            resolve_reported_taxonomy(taxonomy, Some(&reported)),
            TaxonomyResolution::Mapped { .. }
        ) {
            return Err(Phase2Error::InvalidContract(format!(
                "expectation `{}` does not name one frozen taxonomy pair",
                assignment.expectation_id
            )));
        }
    }
    Ok(())
}

fn apply_profile(suite: &mut BenchmarkSuite, profile: &TaxonomyProfile) -> Result<(), Phase2Error> {
    let assignments = profile
        .assignments
        .iter()
        .map(|assignment| (assignment.expectation_id.as_str(), assignment))
        .collect::<BTreeMap<_, _>>();
    for expected in suite
        .cases
        .iter_mut()
        .flat_map(|case| &mut case.expected_findings)
    {
        let assignment = assignments
            .get(expected.expectation_id.as_str())
            .ok_or_else(|| {
                Phase2Error::InvalidContract(format!(
                    "missing taxonomy assignment for `{}`",
                    expected.expectation_id
                ))
            })?;
        expected.taxonomy = Some(TaxonomyCoordinates {
            taxonomy_version: profile.taxonomy_version.clone(),
            category_id: assignment.category_id.clone(),
            invariant_id: assignment.invariant_id.clone(),
        });
    }
    Ok(())
}

fn validate_run_pair(
    primary: &LiveRun,
    repeat: &LiveRun,
    expected_binary: &str,
) -> Result<(), Phase2Error> {
    let expected_arguments = DEFAULT_SECURE_ENGINE_ARGUMENTS.map(str::to_owned).to_vec();
    let empty = fingerprint(&[]);
    if primary.run_id == repeat.run_id
        || primary.tool != repeat.tool
        || primary.tool.binary_fingerprint != expected_binary
        || primary.tool.reported_version != EXPECTED_TOOL_VERSION
        || primary.tool.report_schema != "secure-json-v1"
        || primary.tool.argument_template != expected_arguments
        || primary.tool.configuration_fingerprint != empty
        || primary.tool.version_probe_status != VersionProbeStatus::Success
    {
        return Err(Phase2Error::InvalidContract(
            "run pair differs in tool identity, command, empty configuration, or version"
                .to_owned(),
        ));
    }
    Ok(())
}

fn evaluate_taxonomy_run(
    suite: &BenchmarkSuite,
    taxonomy: &FrozenTaxonomy,
    findings: &[NormalizedFinding],
    run: &LiveRun,
) -> Result<EvaluatedRun, Phase2Error> {
    let records = finding_records(taxonomy, findings)?;
    let duplicate_ids = records
        .iter()
        .filter(|record| record.duplicate_of.is_some())
        .map(|record| record.finding_id.as_str())
        .collect::<BTreeSet<_>>();
    let run_cases = run
        .cases
        .iter()
        .map(|case| (case.case_id.as_str(), case))
        .collect::<BTreeMap<_, _>>();
    let mut cases = suite.cases.iter().collect::<Vec<_>>();
    cases.sort_by(|left, right| left.case_id.cmp(&right.case_id));
    let mut decisions = Vec::with_capacity(cases.len());
    for case in cases {
        let execution = run_cases.get(case.case_id.as_str()).ok_or_else(|| {
            Phase2Error::InvalidContract(format!("run omitted case `{}`", case.case_id))
        })?;
        let case_findings = findings
            .iter()
            .filter(|finding| finding.case_id == case.case_id)
            .collect::<Vec<_>>();
        let duplicate_findings = case_findings
            .iter()
            .filter(|finding| duplicate_ids.contains(finding.finding_id.as_str()))
            .count()
            .try_into()
            .unwrap_or(u64::MAX);
        if case.kind == CaseKind::SafeControl {
            let outcome = case_outcome_for_control(execution.status, case_findings.len());
            decisions.push(Phase2CaseDecision {
                case_id: case.case_id.clone(),
                kind: case.kind,
                expectation_id: None,
                outcome,
                execution_status: execution.status,
                selected_finding_id: None,
                expected_taxonomy: None,
                primary_cwe: None,
                criteria: None,
                finding_count: case_findings.len().try_into().unwrap_or(u64::MAX),
                duplicate_findings,
            });
            continue;
        }
        for expected in &case.expected_findings {
            let coordinates = expected.taxonomy.clone().ok_or_else(|| {
                Phase2Error::InvalidContract(format!(
                    "expectation `{}` lacks prospective taxonomy coordinates",
                    expected.expectation_id
                ))
            })?;
            let primary_cwe = taxonomy
                .categories
                .iter()
                .find(|category| {
                    category.category_id == coordinates.category_id
                        && category.invariant_id == coordinates.invariant_id
                })
                .map(|category| category.primary_cwe.id.clone())
                .ok_or_else(|| {
                    Phase2Error::InvalidContract(format!(
                        "expectation `{}` taxonomy pair is absent",
                        expected.expectation_id
                    ))
                })?;
            let (outcome, selected, criteria) = if execution.status.is_success() {
                select_candidate(
                    taxonomy,
                    expected,
                    &primary_cwe,
                    &case_findings,
                    &duplicate_ids,
                )?
            } else if execution.status == LiveCaseStatus::UnsupportedSchema {
                (Phase2Outcome::OutOfScope, None, None)
            } else {
                (Phase2Outcome::NotAttempted, None, None)
            };
            decisions.push(Phase2CaseDecision {
                case_id: case.case_id.clone(),
                kind: case.kind,
                expectation_id: Some(expected.expectation_id.clone()),
                outcome,
                execution_status: execution.status,
                selected_finding_id: selected,
                expected_taxonomy: Some(coordinates),
                primary_cwe: Some(primary_cwe),
                criteria,
                finding_count: case_findings.len().try_into().unwrap_or(u64::MAX),
                duplicate_findings,
            });
        }
    }
    let metrics = phase2_metrics(&decisions, &records);
    Ok(EvaluatedRun {
        decisions,
        records,
        metrics,
    })
}

fn case_outcome_for_control(status: LiveCaseStatus, findings: usize) -> Phase2Outcome {
    if status.is_success() {
        if findings == 0 {
            Phase2Outcome::SafeControlClean
        } else {
            Phase2Outcome::SafeControlFlagged
        }
    } else if status == LiveCaseStatus::UnsupportedSchema {
        Phase2Outcome::OutOfScope
    } else {
        Phase2Outcome::NotAttempted
    }
}

fn select_candidate(
    taxonomy: &FrozenTaxonomy,
    expected: &crate::model::ExpectedFinding,
    expected_cwe: &str,
    findings: &[&NormalizedFinding],
    duplicates: &BTreeSet<&str>,
) -> Result<(Phase2Outcome, Option<String>, Option<Phase2Criteria>), Phase2Error> {
    let mut candidates = Vec::new();
    for finding in findings
        .iter()
        .copied()
        .filter(|finding| !duplicates.contains(finding.finding_id.as_str()))
    {
        let decision = match_taxonomy_finding(taxonomy, expected, finding)
            .map_err(|error| Phase2Error::InvalidContract(error.to_string()))?;
        let cwe = match &decision.resolution {
            TaxonomyResolution::Mapped { coordinates } => taxonomy.categories.iter().any(|entry| {
                entry.category_id == coordinates.category_id
                    && entry.invariant_id == coordinates.invariant_id
                    && entry.primary_cwe.id == expected_cwe
            }),
            TaxonomyResolution::Unmapped { .. } => false,
        };
        let criteria = criteria_from_taxonomy(&decision.criteria, &decision.resolution, cwe);
        candidates.push((finding, criteria));
    }
    candidates.sort_by(|(left_finding, left), (right_finding, right)| {
        right
            .partial_score()
            .cmp(&left.partial_score())
            .then_with(|| left_finding.finding_id.cmp(&right_finding.finding_id))
    });
    let Some((finding, criteria)) = candidates.first() else {
        return Ok((Phase2Outcome::Missed, None, None));
    };
    let outcome = if criteria.is_exact() {
        Phase2Outcome::ExactCanonicalDetection
    } else if criteria.partial_score() > 0 {
        Phase2Outcome::PartialMatch
    } else {
        Phase2Outcome::Missed
    };
    Ok((
        outcome,
        Some(finding.finding_id.clone()),
        Some(criteria.clone()),
    ))
}

fn criteria_from_taxonomy(
    criteria: &TaxonomyMatchCriteria,
    resolution: &TaxonomyResolution,
    cwe: bool,
) -> Phase2Criteria {
    Phase2Criteria {
        taxonomy_mapped: matches!(resolution, TaxonomyResolution::Mapped { .. }),
        category: criteria.category_id,
        invariant: criteria.invariant_id,
        cwe,
        source: criteria.source,
        sink: criteria.sink,
        evidence_path: criteria.evidence_path,
    }
}

fn finding_records(
    taxonomy: &FrozenTaxonomy,
    findings: &[NormalizedFinding],
) -> Result<Vec<Phase2FindingRecord>, Phase2Error> {
    let mut ordered = findings.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
    let mut canonical_by_semantic = BTreeMap::<String, String>::new();
    let mut records = Vec::with_capacity(ordered.len());
    for finding in ordered {
        let semantic_fingerprint = semantic_finding_fingerprint(finding)?;
        let duplicate_of = canonical_by_semantic.get(&semantic_fingerprint).cloned();
        canonical_by_semantic
            .entry(semantic_fingerprint.clone())
            .or_insert_with(|| finding.finding_id.clone());
        let (resolved_taxonomy, unmapped_reason) =
            match resolve_reported_taxonomy(taxonomy, finding.taxonomy.as_ref()) {
                TaxonomyResolution::Mapped { coordinates } => (Some(coordinates), None),
                TaxonomyResolution::Unmapped { reason } => (None, Some(reason)),
            };
        records.push(Phase2FindingRecord {
            finding_id: finding.finding_id.clone(),
            case_id: finding.case_id.clone(),
            semantic_fingerprint,
            duplicate_of,
            resolved_taxonomy,
            unmapped_reason,
            report_fingerprint: finding.provenance.report_fingerprint.clone(),
        });
    }
    Ok(records)
}

fn semantic_finding_fingerprint(finding: &NormalizedFinding) -> Result<String, Phase2Error> {
    fingerprint_value(&StableFindingView {
        case_id: &finding.case_id,
        taxonomy: &finding.taxonomy,
        category: &finding.category,
        invariant: &finding.invariant,
        source: &finding.source,
        sink: &finding.sink,
        evidence_path: &finding.evidence_path,
    })
}

fn phase2_metrics(
    decisions: &[Phase2CaseDecision],
    records: &[Phase2FindingRecord],
) -> Phase2Metrics {
    let mut counts = Phase2Counts::default();
    let mut category = 0;
    let mut invariant = 0;
    let mut cwe = 0;
    let mut source = 0;
    let mut sink = 0;
    let mut evidence = 0;
    let mut selected_exact = BTreeSet::new();
    for decision in decisions {
        if decision.kind == CaseKind::Vulnerable {
            counts.eligible_expectations += 1;
            match decision.outcome {
                Phase2Outcome::ExactCanonicalDetection => {
                    counts.exact_detections += 1;
                    if let Some(id) = &decision.selected_finding_id {
                        selected_exact.insert(id.as_str());
                    }
                }
                Phase2Outcome::PartialMatch => counts.partial_matches += 1,
                Phase2Outcome::Missed => counts.misses += 1,
                Phase2Outcome::OutOfScope => counts.out_of_scope += 1,
                Phase2Outcome::NotAttempted => counts.not_attempted += 1,
                Phase2Outcome::SafeControlFlagged | Phase2Outcome::SafeControlClean => {}
            }
            if let Some(criteria) = &decision.criteria {
                category += u64::from(criteria.category);
                invariant += u64::from(criteria.invariant);
                cwe += u64::from(criteria.cwe);
                source += u64::from(criteria.source);
                sink += u64::from(criteria.sink);
                evidence += u64::from(criteria.evidence_path);
            }
        } else {
            match decision.outcome {
                Phase2Outcome::SafeControlFlagged => counts.safe_controls_flagged += 1,
                Phase2Outcome::SafeControlClean => counts.clean_safe_controls += 1,
                Phase2Outcome::NotAttempted | Phase2Outcome::OutOfScope => {
                    counts.safe_controls_not_attempted += 1;
                }
                Phase2Outcome::ExactCanonicalDetection
                | Phase2Outcome::PartialMatch
                | Phase2Outcome::Missed => {}
            }
        }
    }
    counts.normalized_findings = records.len().try_into().unwrap_or(u64::MAX);
    counts.duplicate_findings = records
        .iter()
        .filter(|record| record.duplicate_of.is_some())
        .count()
        .try_into()
        .unwrap_or(u64::MAX);
    let distinct = counts
        .normalized_findings
        .saturating_sub(counts.duplicate_findings);
    counts.false_positive_findings = distinct.saturating_sub(counts.exact_detections);
    let false_negatives = counts
        .eligible_expectations
        .saturating_sub(counts.exact_detections);
    Phase2Metrics {
        precision: ratio(counts.exact_detections, distinct),
        recall: ratio(counts.exact_detections, counts.eligible_expectations),
        f1: ratio(
            counts.exact_detections.saturating_mul(2),
            counts
                .exact_detections
                .saturating_mul(2)
                .saturating_add(counts.false_positive_findings)
                .saturating_add(false_negatives),
        ),
        category_agreement: ratio(category, counts.eligible_expectations),
        invariant_agreement: ratio(invariant, counts.eligible_expectations),
        cwe_agreement: ratio(cwe, counts.eligible_expectations),
        source_agreement: ratio(source, counts.eligible_expectations),
        sink_agreement: ratio(sink, counts.eligible_expectations),
        evidence_path_agreement: ratio(evidence, counts.eligible_expectations),
        counts,
    }
}

fn build_stability(
    primary: &EvaluatedRun,
    repeat: &EvaluatedRun,
    primary_reports: &BTreeMap<String, Vec<u8>>,
    repeat_reports: &BTreeMap<String, Vec<u8>>,
) -> Result<Phase2Stability, Phase2Error> {
    let primary_ids = primary
        .records
        .iter()
        .map(|record| record.finding_id.as_str())
        .collect::<BTreeSet<_>>();
    let repeat_ids = repeat
        .records
        .iter()
        .map(|record| record.finding_id.as_str())
        .collect::<BTreeSet<_>>();
    let primary_semantic = primary
        .records
        .iter()
        .map(|record| record.semantic_fingerprint.as_str())
        .collect::<BTreeSet<_>>();
    let repeat_semantic = repeat
        .records
        .iter()
        .map(|record| record.semantic_fingerprint.as_str())
        .collect::<BTreeSet<_>>();
    let stable = primary_semantic.intersection(&repeat_semantic).count();
    let raw_report_differences = primary_reports
        .keys()
        .chain(repeat_reports.keys())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|path| primary_reports.get(*path) != repeat_reports.get(*path))
        .filter_map(|path| {
            path.strip_prefix("reports/")
                .and_then(|value| value.strip_suffix(".json"))
                .map(str::to_owned)
        })
        .collect::<Vec<_>>();
    let primary_semantic_fingerprint =
        fingerprint_value(&(&primary_semantic, &primary.decisions, &primary.metrics))?;
    let repeat_semantic_fingerprint =
        fingerprint_value(&(&repeat_semantic, &repeat.decisions, &repeat.metrics))?;
    let finding_ids_equal = primary_ids == repeat_ids;
    let semantic_findings_equal = primary_semantic == repeat_semantic;
    let case_decisions_equal = primary.decisions == repeat.decisions;
    let metrics_equal = primary.metrics == repeat.metrics;
    Ok(Phase2Stability {
        finding_ids_equal,
        semantic_findings_equal,
        case_decisions_equal,
        metrics_equal,
        deterministic_evaluation_equal: finding_ids_equal
            && semantic_findings_equal
            && case_decisions_equal
            && metrics_equal
            && primary_semantic_fingerprint == repeat_semantic_fingerprint,
        raw_reports_equal: raw_report_differences.is_empty(),
        raw_report_differences,
        fingerprint_stability: ratio(
            stable.try_into().unwrap_or(u64::MAX),
            primary_semantic.len().try_into().unwrap_or(u64::MAX),
        ),
        primary_semantic_fingerprint,
        repeat_semantic_fingerprint,
    })
}

fn compare_phase1(
    suite: &BenchmarkSuite,
    phase1: &BenchmarkResult,
    phase2: &[Phase2CaseDecision],
) -> Phase2Comparison {
    let phase1_exact = phase1
        .matching
        .expectations
        .iter()
        .filter(|decision| {
            matches!(
                decision.outcome,
                MatchOutcome::Matched | MatchOutcome::Ambiguous
            )
        })
        .map(|decision| decision.case_id.clone())
        .collect::<BTreeSet<_>>();
    let phase1_alignment = phase1
        .matching
        .expectations
        .iter()
        .filter(|decision| {
            !decision.criteria.category
                && !decision.criteria.invariant
                && decision.criteria.source
                && decision.criteria.sink
                && decision.criteria.evidence_path
        })
        .map(|decision| decision.case_id.clone())
        .collect::<BTreeSet<_>>();
    let safe_cases = suite
        .cases
        .iter()
        .filter(|case| case.kind == CaseKind::SafeControl)
        .map(|case| case.case_id.clone())
        .collect::<BTreeSet<_>>();
    let vulnerable_cases = suite
        .cases
        .iter()
        .filter(|case| case.kind == CaseKind::Vulnerable)
        .map(|case| case.case_id.clone())
        .collect::<BTreeSet<_>>();
    let phase1_flagged = phase1
        .matching
        .findings
        .iter()
        .filter(|decision| safe_cases.contains(&decision.case_id))
        .filter(|decision| {
            matches!(
                decision.disposition,
                FindingDisposition::SafeControlFalsePositive
                    | FindingDisposition::Duplicate
                    | FindingDisposition::AmbiguousCandidate
            )
        })
        .map(|decision| decision.case_id.clone())
        .collect::<BTreeSet<_>>();
    let phase2_exact = phase2
        .iter()
        .filter(|decision| decision.outcome == Phase2Outcome::ExactCanonicalDetection)
        .map(|decision| decision.case_id.clone())
        .collect::<BTreeSet<_>>();
    let phase2_flagged = phase2
        .iter()
        .filter(|decision| decision.outcome == Phase2Outcome::SafeControlFlagged)
        .map(|decision| decision.case_id.clone())
        .collect::<BTreeSet<_>>();
    let taxonomy_alignment_improvements = phase2_exact
        .intersection(&phase1_alignment)
        .filter(|case| !phase1_exact.contains(*case))
        .cloned()
        .collect::<Vec<_>>();
    let aligned = taxonomy_alignment_improvements
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    Phase2Comparison {
        phase1_exact_detections: phase1_exact.len().try_into().unwrap_or(u64::MAX),
        phase2_exact_detections: phase2_exact.len().try_into().unwrap_or(u64::MAX),
        taxonomy_alignment_improvements,
        newly_detected_vulnerabilities: phase2_exact
            .difference(&phase1_exact)
            .filter(|case| !aligned.contains(*case))
            .cloned()
            .collect(),
        resolved_safe_control_flags: phase1_flagged
            .difference(&phase2_flagged)
            .cloned()
            .collect(),
        remaining_misses: vulnerable_cases
            .difference(&phase2_exact)
            .cloned()
            .collect(),
        remaining_safe_control_flags: phase1_flagged
            .intersection(&phase2_flagged)
            .cloned()
            .collect(),
        detection_regressions: phase1_exact.difference(&phase2_exact).cloned().collect(),
        false_positive_regressions: phase2_flagged
            .difference(&phase1_flagged)
            .cloned()
            .collect(),
    }
}

fn run_measurement(run: &LiveRun) -> Phase2RunMeasurement {
    let mut status_counts = BTreeMap::new();
    let mut exit_codes = BTreeMap::new();
    let mut completed_cases = 0_u64;
    let mut findings_cases = 0_u64;
    let mut total_duration_ms = 0_u64;
    let mut peak_rss_bytes = None;
    let mut total_output_bytes = 0_u64;
    for case in &run.cases {
        *status_counts
            .entry(status_name(case.status).to_owned())
            .or_insert(0) += 1;
        completed_cases += u64::from(case.status.is_success());
        findings_cases += u64::from(case.status == LiveCaseStatus::Findings);
        total_duration_ms = total_duration_ms.saturating_add(case.duration_ms);
        peak_rss_bytes = maximum_option(peak_rss_bytes, case.peak_memory_bytes);
        total_output_bytes =
            total_output_bytes.saturating_add(case.output_bytes.unwrap_or_default());
        exit_codes.insert(case.case_id.clone(), case.process_exit_code);
    }
    Phase2RunMeasurement {
        run_id: run.run_id.clone(),
        status: run.status,
        cases: run.cases.len().try_into().unwrap_or(u64::MAX),
        completed_cases,
        findings_cases,
        total_duration_ms,
        peak_rss_bytes,
        total_output_bytes,
        status_counts,
        exit_codes,
    }
}

fn status_name(status: LiveCaseStatus) -> &'static str {
    match status {
        LiveCaseStatus::Success => "success",
        LiveCaseStatus::Findings => "findings",
        LiveCaseStatus::Crash => "crash",
        LiveCaseStatus::Timeout => "timeout",
        LiveCaseStatus::InvalidOutput => "invalid_output",
        LiveCaseStatus::UnsupportedSchema => "unsupported_schema",
        LiveCaseStatus::ExecutionFailure => "execution_failure",
        LiveCaseStatus::Cancelled => "cancelled",
    }
}

fn ratio(numerator: u64, denominator: u64) -> RatioMetric {
    RatioMetric {
        numerator,
        denominator,
        basis_points: if denominator == 0 {
            None
        } else {
            let scaled = u128::from(numerator) * 10_000 / u128::from(denominator);
            Some(u32::try_from(scaled).unwrap_or(u32::MAX))
        },
    }
}

fn fingerprint_value<T: Serialize>(value: &T) -> Result<String, Phase2Error> {
    let bytes = serde_json::to_vec(value).map_err(|_| Phase2Error::Serialization)?;
    Ok(hex_digest(&Sha256::digest(bytes)))
}

fn maximum_option(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}
