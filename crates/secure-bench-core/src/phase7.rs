//! One-shot Phase 7 execution and evidence-contract v2 evaluation.

use crate::adapter::fingerprint;
use crate::model::{CaseKind, HostProvenance, RatioMetric, ReportedTaxonomyMetadata};
use crate::phase5::{
    CanonicalFindingV2, EvidenceContractV2, EvidenceEffectV2, EvidenceExpectationV2,
    EvidenceMatchV2, EvidenceNodeV2, EvidenceRoleV2, EvidenceSpanV2, Phase5Case, Phase5CaseKind,
    Phase5CommitmentIndex, Phase5Framework, Phase5LedgerEntry, Phase5Manifest, Phase5Topology,
    SinkSemanticKind, SourceSemanticKind, evidence_fingerprint_v2, match_evidence_v2,
    validate_phase5,
};
use crate::runner::{
    LiveCaseRun, LiveCaseStatus, LiveRunStatus, RunnerError, aggregate_status, atomic_write,
    copy_fixture, execute_process, fingerprint_file, host_provenance, millis_u64, unix_millis,
    validate_binary,
};
use crate::taxonomy::{FrozenTaxonomy, load_taxonomy};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tempfile::Builder;
use thiserror::Error;

/// Phase 7 pre-execution contract schema identity.
pub const PHASE7_PRE_EXECUTION_SCHEMA_V1: &str = "secure-bench-phase7-pre-execution-v1";
/// Phase 7 retained run schema identity.
pub const PHASE7_RUN_SCHEMA_V1: &str = "secure-bench-phase7-run-v1";
/// Phase 7 deterministic result schema identity.
pub const PHASE7_RESULT_SCHEMA_V1: &str = "secure-bench-phase7-result-v1";
/// Phase 7 artifact index schema identity.
pub const PHASE7_ARTIFACTS_SCHEMA_V1: &str = "secure-bench-phase7-artifacts-v1";
/// Phase 7 append-only ledger schema identity.
pub const PHASE7_LEDGER_SCHEMA_V1: &str = "secure-bench-phase7-ledger-entry-v1";

/// Sole permitted Phase 7 run identity.
pub const PHASE7_RUN_ID: &str = "secure-engine-0-1-3-orthogonal-holdout-once";
/// Exact external binary fingerprint.
pub const PHASE7_BINARY_SHA256: &str =
    "8678666b532380187d38968628908363970c960078c63489d26af35d31840902";
/// Exact source RPM fingerprint.
pub const PHASE7_RPM_SHA256: &str =
    "ceb9ce77feee5df9a1a5766e72fd610504f67cdd1a2a958753c75e4001501d8d";
/// Exact immutable main commit.
pub const PHASE7_GIT_BASE: &str = "e7b9576a5cd65746a9309310406ba4e49454d006";
/// Required Phase 7 branch.
pub const PHASE7_BRANCH: &str = "codex/phase-7-secure-engine-0-1-3-orthogonal-holdout";
/// Exact Phase 5 freeze commit used for the read-only evaluator projection.
pub const PHASE5_FREEZE_COMMIT: &str = "ac85c6f09f48057e4bcebb7249e2487fe43e1902";
/// Exact Phase 5 manifest fingerprint.
pub const PHASE7_MANIFEST_SHA256: &str =
    "0bf17f093146c99bdc128fd39513b490f9774b427a252bc5fa508b4444c05827";
/// Exact evidence contract v2 fingerprint.
pub const PHASE7_EVIDENCE_CONTRACT_SHA256: &str =
    "142c7f31c6c584cc808410130fa7db8451427e87504e72e64868c9cbc6564c42";
/// Exact scanner-visible corpus aggregate.
pub const PHASE7_CORPUS_SHA256: &str =
    "8f5f43e497e953be79cfb23891e2d3059392c2a24b3143b136e7dc9609cc3b04";
/// Exact case-contract Merkle root.
pub const PHASE7_MERKLE_ROOT: &str =
    "f21b545b942beeb3f37232f39da7adecc1eb1f7694c24ea37a981c8ac20110cb";
/// Exact frozen Phase 5 evaluator aggregate.
pub const PHASE7_FROZEN_EVALUATOR_SHA256: &str =
    "363db2f0201ceb681134687e87313359ad7db83bec767ac99473201fde8b2b7a";
/// Exact genesis-only ledger fingerprint.
pub const PHASE7_GENESIS_LEDGER_SHA256: &str =
    "dee6f5be204c4d4b7758c3afbbdd52997eaac090f636b6b15df7f7aabe7a1704";
/// Exact report argument template.
pub const PHASE7_ARGUMENTS: [&str; 6] = [
    "scan",
    "{fixture}",
    "--format",
    "secure-json-v1",
    "--output",
    "{report}",
];

const TAXONOMY_SHA256: &str = "059fe22d7707cf8d17f2c1621fdae9819787a1958ba2ef0421eca4e4ec858452";
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const EXPECTED_CASES: usize = 112;
const EXPECTED_PAIRS: usize = 56;
const CASE_TIMEOUT_MS: u64 = 60_000;
const CASE_MEMORY_BYTES: u64 = 1_073_741_824;
const CASE_OUTPUT_BYTES: u64 = 10 * 1024 * 1024;
const REPORT_PATH: &str = "/output/report.json";
const ISOLATION_PATH: &str = "/output/isolation.json";
const PROBE_TARGET: &str = "1.1.1.1:53";

const PHASE7_EVALUATOR_FILES: [&str; 19] = [
    "Cargo.lock",
    "apps/secure-bench-cli/src/main.rs",
    "crates/secure-bench-core/src/lib.rs",
    "crates/secure-bench-core/src/phase5.rs",
    "crates/secure-bench-core/src/phase7.rs",
    "crates/secure-bench-core/src/runner.rs",
    "crates/secure-bench-core/src/schema.rs",
    "crates/secure-bench-core/src/taxonomy.rs",
    "crates/secure-bench-core/tests/phase7_holdout.rs",
    "schemas/evidence-contract-v2.schema.json",
    "schemas/phase5-commitments-v1.schema.json",
    "schemas/phase5-contract-tests-v1.schema.json",
    "schemas/phase5-holdout-v2.schema.json",
    "schemas/phase5-ledger-entry-v1.schema.json",
    "schemas/phase7-artifacts-v1.schema.json",
    "schemas/phase7-ledger-entry-v1.schema.json",
    "schemas/phase7-pre-execution-v1.schema.json",
    "schemas/phase7-result-v1.schema.json",
    "schemas/phase7-run-v1.schema.json",
];

const HISTORICAL_ROOTS: [&str; 4] = [
    "baselines/phase-1-secure-engine-phase6",
    "baselines/phase-2-secure-engine-0-1-1",
    "artifacts/phase-4-secure-engine-0-1-2",
    "diagnostics/phase-6",
];

/// Complete pre-execution contract frozen before reservation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase7PreExecutionContract {
    /// Schema identity.
    pub schema_version: String,
    /// UTC freeze time.
    pub frozen_at_utc: String,
    /// Immutable main commit.
    pub git_base: String,
    /// Dedicated branch.
    pub branch: String,
    /// Sole run identity.
    pub run_id: String,
    /// Git prerequisite attestation.
    pub git: Phase7GitContract,
    /// External black-box contract.
    pub scanner: Phase7ScannerContract,
    /// Frozen holdout contract.
    pub holdout: Phase7HoldoutContract,
    /// Frozen-evaluator binding.
    pub frozen_evaluator: Phase7FrozenEvaluatorContract,
    /// Fixed per-case resource policy.
    pub resources: Phase7ResourceContract,
    /// Host and isolation contract.
    pub environment: Phase7EnvironmentContract,
    /// Release benchmark executable SHA-256.
    pub benchmark_binary_sha256: String,
    /// Files defining the Phase 7 adapter, scorer, runner, and schemas.
    pub phase7_evaluator_files: BTreeMap<String, String>,
    /// Byte-stable historical artifact tree hashes.
    pub historical_artifacts: BTreeMap<String, String>,
}

/// Git prerequisite attestation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase7GitContract {
    /// Main reference.
    pub main_commit: String,
    /// Current branch head.
    pub head_commit: String,
    /// Verified current branch.
    pub current_branch: String,
    /// Git object integrity result.
    pub object_integrity: String,
    /// Signed commit validation results.
    pub signatures: BTreeMap<String, String>,
    /// DCO validation results.
    pub dco_signoffs: BTreeMap<String, String>,
}

/// External scanner contract without an absolute path or credentials.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase7ScannerContract {
    /// User-declared artifact identity.
    pub declared_version: String,
    /// External binary SHA-256.
    pub binary_sha256: String,
    /// Source RPM SHA-256.
    pub source_rpm_sha256: String,
    /// Exact portable argument template.
    pub command_template: Vec<String>,
    /// Requested public report schema.
    pub report_schema: String,
    /// Empty configuration fingerprint.
    pub configuration_sha256: String,
    /// AI state.
    pub ai_validation: String,
    /// Version probe policy.
    pub version_probe: String,
    /// Environment clearing policy.
    pub environment_clear: bool,
}

/// Frozen holdout hashes and counts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase7HoldoutContract {
    /// Holdout identity.
    pub holdout_id: String,
    /// Manifest artifact SHA-256.
    pub manifest_sha256: String,
    /// Evidence-contract artifact SHA-256.
    pub evidence_contract_sha256: String,
    /// Genesis ledger SHA-256.
    pub ledger_before_sha256: String,
    /// Aggregate corpus SHA-256.
    pub aggregate_corpus_sha256: String,
    /// Contract Merkle root.
    pub contract_merkle_root: String,
    /// Taxonomy artifact SHA-256.
    pub taxonomy_artifact_sha256: String,
    /// Taxonomy content hash.
    pub taxonomy_content_hash: String,
    /// Pair count.
    pub pairs: u64,
    /// Case count.
    pub cases: u64,
    /// Vulnerable case count.
    pub vulnerable_cases: u64,
    /// Safe-control count.
    pub safe_controls: u64,
    /// Hash of every Phase 5 file except the mutable ledger and future result directory.
    pub frozen_tree_sha256: String,
    /// Confirmation that no prior execution artifact exists.
    pub prior_execution: String,
}

/// Binding to the exact Phase 5 evaluator projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase7FrozenEvaluatorContract {
    /// Git commit supplying the read-only projection.
    pub source_commit: String,
    /// Frozen aggregate evaluator SHA-256.
    pub evaluator_sha256: String,
    /// Exact evaluator file hashes.
    pub files: BTreeMap<String, String>,
    /// Current integration-only wrapper differences.
    pub integration_wrapper_drift: BTreeMap<String, Phase7EvaluatorDrift>,
    /// Projection validation state.
    pub projection_validation: String,
}

/// One explicitly classified current-wrapper difference.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase7EvaluatorDrift {
    /// Frozen Phase 5 file hash.
    pub frozen_sha256: String,
    /// Current Phase 7 file hash.
    pub current_sha256: String,
    /// Non-scoring classification.
    pub classification: String,
}

/// Fixed resource limits.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase7ResourceContract {
    /// Wall-clock timeout per scanner process.
    pub timeout_ms: u64,
    /// Maximum sampled process RSS.
    pub memory_bytes: u64,
    /// Maximum retained report bytes.
    pub output_bytes: u64,
    /// Network policy.
    pub network: String,
    /// Namespace lifecycle.
    pub namespace_scope: String,
}

/// Sanitized environment and isolation provenance.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase7EnvironmentContract {
    /// Operating-system family.
    pub os: String,
    /// CPU architecture.
    pub architecture: String,
    /// Kernel release.
    pub kernel_release: String,
    /// Rust toolchain contract.
    pub rust_toolchain: String,
    /// Bubblewrap SHA-256.
    pub bwrap_sha256: String,
    /// Isolation mechanism.
    pub isolation: String,
    /// Expected interfaces in every fresh namespace.
    pub expected_interfaces: Vec<String>,
    /// Outbound probe target.
    pub probe_target: String,
}

/// Proof written inside one fresh scanner namespace before scanner execution.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase7IsolationAttestation {
    /// Isolation mechanism.
    pub mechanism: String,
    /// Namespace lifecycle.
    pub namespace_scope: String,
    /// Interfaces visible in the namespace.
    pub interfaces: Vec<String>,
    /// Outbound connectivity state.
    pub outbound_connectivity: String,
    /// Fixed probe target.
    pub probe_target: String,
    /// Scanner is invoked only after this proof succeeds.
    pub scanner_invoked_after_probe: bool,
}

/// One retained case execution and its fresh-namespace proof.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase7CaseRun {
    /// Black-box process and output record.
    pub execution: LiveCaseRun,
    /// Isolation proof, absent only when infrastructure failed before it could be written.
    pub isolation: Option<Phase7IsolationAttestation>,
}

/// Complete retained one-shot run.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase7Run {
    /// Schema identity.
    pub schema_version: String,
    /// Run identity.
    pub run_id: String,
    /// Holdout identity.
    pub holdout_id: String,
    /// Pre-execution contract SHA-256.
    pub pre_execution_contract_sha256: String,
    /// External binary SHA-256.
    pub binary_sha256: String,
    /// Source RPM SHA-256.
    pub source_rpm_sha256: String,
    /// Exact portable command template.
    pub command_template: Vec<String>,
    /// AI state.
    pub ai_validation: String,
    /// Version probe execution state.
    pub version_probe_executed: bool,
    /// Sanitized host provenance.
    pub host: HostProvenance,
    /// Start time.
    pub started_unix_ms: u64,
    /// Finish time.
    pub finished_unix_ms: u64,
    /// Aggregate execution state.
    pub status: LiveRunStatus,
    /// Append-only case journal SHA-256.
    pub case_journal_sha256: String,
    /// One outcome per frozen case.
    pub cases: Vec<Phase7CaseRun>,
}

/// Phase 7 outcome under strict evidence-contract v2 scoring.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase7Outcome {
    /// Exact evidence-contract v2 detection.
    ExactDetection,
    /// Contract-defined partial evidence, with no exact credit.
    PartialMatch,
    /// Completed scan without an exact or partial contract match.
    Missed,
    /// Unsupported public report schema.
    OutOfScope,
    /// Operational failure prevented scoring.
    NotAttempted,
    /// Safe control emitted at least one distinct finding.
    SafeControlFlagged,
    /// Safe control completed without findings.
    SafeControlClean,
}

/// Atomic agreement dimensions for one selected candidate.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::struct_excessive_bools)]
#[serde(deny_unknown_fields)]
pub struct Phase7Criteria {
    /// Taxonomy version, category, and invariant jointly agree.
    pub taxonomy: bool,
    /// Category identifier agrees.
    pub category: bool,
    /// Invariant identifier agrees.
    pub invariant: bool,
    /// Primary CWE agrees.
    pub cwe: bool,
    /// Source semantics and span agree.
    pub source: bool,
    /// Sink semantics and span agree.
    pub sink: bool,
    /// Ordered evidence path agrees.
    pub evidence_path: bool,
}

impl Phase7Criteria {
    fn score(&self) -> u8 {
        u8::from(self.taxonomy)
            + u8::from(self.category)
            + u8::from(self.invariant)
            + u8::from(self.cwe)
            + u8::from(self.source)
            + u8::from(self.sink)
            + u8::from(self.evidence_path)
    }
}

/// One vulnerable expectation or safe-control decision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase7CaseDecision {
    /// Frozen case identifier.
    pub case_id: String,
    /// Frozen label.
    pub kind: CaseKind,
    /// Vulnerable expectation identifier.
    pub expectation_id: Option<String>,
    /// Strict outcome.
    pub outcome: Phase7Outcome,
    /// Process/report status.
    pub execution_status: LiveCaseStatus,
    /// Deterministically selected finding.
    pub selected_finding_id: Option<String>,
    /// Selected contract match state.
    pub evidence_match: Option<EvidenceMatchV2>,
    /// Atomic agreement dimensions.
    pub criteria: Option<Phase7Criteria>,
    /// Distinct findings in the case.
    pub distinct_findings: u64,
    /// Duplicate findings in the case.
    pub duplicate_findings: u64,
    /// Findings with neither exact nor partial contract agreement.
    pub unrelated_findings: u64,
}

/// Adapter mapping state retained without prose or source code.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase7AdapterState {
    /// All endpoint semantic identities were canonical.
    Canonical,
    /// One or more semantic identities were unavailable or non-canonical.
    UnmappedSemantics,
}

/// Privacy-safe finding provenance.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase7FindingRecord {
    /// Content-derived finding identifier.
    pub finding_id: String,
    /// Frozen case identifier.
    pub case_id: String,
    /// Evidence-contract semantic fingerprint.
    pub semantic_fingerprint: String,
    /// Earlier equivalent finding, when duplicated.
    pub duplicate_of: Option<String>,
    /// Adapter semantic mapping state.
    pub adapter_state: Phase7AdapterState,
    /// Scanner-reported canonical taxonomy metadata.
    pub reported_taxonomy: Option<ReportedTaxonomyMetadata>,
    /// Scanner-reported primary CWE.
    pub primary_cwe: Option<String>,
    /// Raw report SHA-256.
    pub report_sha256: String,
}

/// Raw counts supporting all Phase 7 metrics.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase7Counts {
    /// Vulnerable expectations.
    pub vulnerable_expectations: u64,
    /// Exact detections.
    pub exact_detections: u64,
    /// Partial matches.
    pub partial_matches: u64,
    /// Completed misses.
    pub misses: u64,
    /// Unsupported cases.
    pub out_of_scope: u64,
    /// Operationally unavailable vulnerable cases.
    pub not_attempted: u64,
    /// Safe controls.
    pub safe_controls: u64,
    /// Flagged safe controls.
    pub safe_controls_flagged: u64,
    /// Clean safe controls.
    pub clean_safe_controls: u64,
    /// Operationally unavailable controls.
    pub safe_controls_not_attempted: u64,
    /// All findings in completed cases.
    pub findings: u64,
    /// Distinct findings in completed cases.
    pub distinct_findings: u64,
    /// Duplicate semantic findings.
    pub duplicate_findings: u64,
    /// Findings unrelated to an exact or partial expectation.
    pub unrelated_findings: u64,
    /// Strict non-exact findings used in the precision denominator.
    pub strict_false_positive_findings: u64,
}

/// Exact strict metrics and agreement rates.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase7Metrics {
    /// Raw supporting counts.
    pub counts: Phase7Counts,
    /// Exact finding-level precision.
    pub precision: RatioMetric,
    /// Exact expectation-level recall.
    pub recall: RatioMetric,
    /// Exact F1.
    pub f1: RatioMetric,
    /// Full taxonomy agreement.
    pub taxonomy_agreement: RatioMetric,
    /// Category agreement.
    pub category_agreement: RatioMetric,
    /// Invariant agreement.
    pub invariant_agreement: RatioMetric,
    /// CWE agreement.
    pub cwe_agreement: RatioMetric,
    /// Source agreement.
    pub source_agreement: RatioMetric,
    /// Sink agreement.
    pub sink_agreement: RatioMetric,
    /// Ordered evidence-path agreement.
    pub evidence_path_agreement: RatioMetric,
}

/// Metrics for one preregistered stratum.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase7GroupMetrics {
    /// Vulnerable cases.
    pub vulnerable: u64,
    /// Exact detections.
    pub exact: u64,
    /// Partial matches.
    pub partial: u64,
    /// Misses.
    pub missed: u64,
    /// Out-of-scope cases.
    pub out_of_scope: u64,
    /// Operational failures.
    pub not_attempted: u64,
    /// Safe controls.
    pub controls: u64,
    /// Flagged controls.
    pub flagged_controls: u64,
    /// Clean controls.
    pub clean_controls: u64,
    /// Operationally unavailable controls.
    pub controls_not_attempted: u64,
    /// Distinct findings.
    pub distinct_findings: u64,
    /// Duplicate findings.
    pub duplicate_findings: u64,
    /// Unrelated findings.
    pub unrelated_findings: u64,
    /// Strict precision.
    pub precision: RatioMetric,
    /// Strict recall.
    pub recall: RatioMetric,
    /// Strict F1.
    pub f1: RatioMetric,
}

/// All balanced Phase 5 factor and crossed-stratum breakdowns.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase7Breakdowns {
    /// Seven taxonomy families.
    pub taxonomy_family: BTreeMap<String, Phase7GroupMetrics>,
    /// Frameworks.
    pub framework: BTreeMap<String, Phase7GroupMetrics>,
    /// Languages.
    pub language: BTreeMap<String, Phase7GroupMetrics>,
    /// Topologies.
    pub topology: BTreeMap<String, Phase7GroupMetrics>,
    /// Framework by language.
    pub framework_language: BTreeMap<String, Phase7GroupMetrics>,
    /// Topology by language.
    pub topology_language: BTreeMap<String, Phase7GroupMetrics>,
    /// Framework by topology.
    pub framework_topology: BTreeMap<String, Phase7GroupMetrics>,
}

/// Runtime, resource, output, and failure measurements.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase7Measurement {
    /// Run identity.
    pub run_id: String,
    /// Aggregate run status.
    pub status: LiveRunStatus,
    /// Total cases.
    pub cases: u64,
    /// Adapter-valid completed cases.
    pub completed_cases: u64,
    /// Total case wall time.
    pub total_duration_ms: u64,
    /// End-to-end runner wall time.
    pub runner_duration_ms: u64,
    /// Maximum sampled process RSS.
    pub peak_rss_bytes: Option<u64>,
    /// Total retained output bytes.
    pub total_output_bytes: u64,
    /// Explicit status counts.
    pub status_counts: BTreeMap<String, u64>,
    /// Process exit codes by case.
    pub exit_codes: BTreeMap<String, Option<i32>>,
    /// Nonzero exits.
    pub nonzero_exits: u64,
    /// All non-success case statuses.
    pub failures: u64,
    /// Crashes.
    pub crashes: u64,
    /// Timeouts.
    pub timeouts: u64,
    /// Malformed reports.
    pub malformed_reports: u64,
    /// Missing reports.
    pub missing_reports: u64,
}

/// Complete Phase 7 provenance.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase7Provenance {
    /// External binary SHA-256.
    pub binary_sha256: String,
    /// Source RPM SHA-256.
    pub source_rpm_sha256: String,
    /// Manifest SHA-256.
    pub manifest_sha256: String,
    /// Evidence contract SHA-256.
    pub evidence_contract_sha256: String,
    /// Aggregate corpus SHA-256.
    pub aggregate_corpus_sha256: String,
    /// Contract Merkle root.
    pub contract_merkle_root: String,
    /// Taxonomy artifact SHA-256.
    pub taxonomy_artifact_sha256: String,
    /// Taxonomy content hash.
    pub taxonomy_content_hash: String,
    /// Frozen evaluator SHA-256.
    pub frozen_evaluator_sha256: String,
    /// Exact command template.
    pub command_template: Vec<String>,
    /// Empty configuration SHA-256.
    pub configuration_sha256: String,
    /// AI state.
    pub ai_validation: String,
    /// Isolation mechanism.
    pub network_isolation: String,
    /// Namespace lifecycle.
    pub namespace_scope: String,
    /// Sanitized host provenance.
    pub host: HostProvenance,
    /// Pre-execution contract SHA-256.
    pub pre_execution_contract_sha256: String,
    /// Run SHA-256.
    pub run_sha256: String,
    /// Aggregate report SHA-256.
    pub reports_sha256: String,
    /// Ledger SHA-256 before reservation.
    pub ledger_before_sha256: String,
    /// Genesis entry hash.
    pub ledger_genesis_entry_hash: String,
    /// Reservation entry hash.
    pub ledger_started_entry_hash: String,
    /// Schema identities.
    pub schemas: BTreeMap<String, String>,
    /// Frozen Phase 7 evaluator file hashes.
    pub phase7_evaluator_files: BTreeMap<String, String>,
    /// Historical artifact tree hashes.
    pub historical_artifacts: BTreeMap<String, String>,
}

/// Complete deterministic Phase 7 result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase7Result {
    /// Schema identity.
    pub schema_version: String,
    /// Run identity.
    pub run_id: String,
    /// Holdout identity.
    pub holdout_id: String,
    /// Taxonomy version.
    pub taxonomy_version: String,
    /// One decision per case.
    pub cases: Vec<Phase7CaseDecision>,
    /// Privacy-safe finding records.
    pub findings: Vec<Phase7FindingRecord>,
    /// Aggregate strict metrics.
    pub metrics: Phase7Metrics,
    /// Balanced stratum metrics.
    pub breakdowns: Phase7Breakdowns,
    /// Runtime and failure measurement.
    pub measurement: Phase7Measurement,
    /// Stable semantic result fingerprint.
    pub semantic_fingerprint: String,
    /// Complete provenance.
    pub provenance: Phase7Provenance,
}

/// Final artifact index binding all retained outputs to the completed ledger.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase7Artifacts {
    /// Schema identity.
    pub schema_version: String,
    /// Run identity.
    pub run_id: String,
    /// Pre-execution contract path.
    pub pre_execution_contract_path: String,
    /// Pre-execution contract SHA-256.
    pub pre_execution_contract_sha256: String,
    /// Run manifest path.
    pub run_path: String,
    /// Run manifest SHA-256.
    pub run_sha256: String,
    /// Result path.
    pub result_path: String,
    /// Result SHA-256.
    pub result_sha256: String,
    /// Ledger path.
    pub ledger_path: String,
    /// Completed ledger SHA-256.
    pub ledger_sha256: String,
    /// Case journal SHA-256.
    pub case_journal_sha256: String,
    /// Aggregate report SHA-256.
    pub reports_sha256: String,
    /// Retained report count.
    pub report_count: u64,
    /// Validated ledger entry count.
    pub ledger_entries: u64,
}

/// Phase 7 ledger event identity.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase7LedgerEvent {
    /// Irreversible execution reservation.
    ExecutionStarted,
    /// One durably recorded case outcome.
    CaseRecorded,
    /// Successful terminal event.
    ExecutionCompleted,
    /// Infrastructure-failure terminal event.
    ExecutionFailed,
}

/// One Phase 7 append-only ledger entry.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase7LedgerEntry {
    /// Schema identity.
    pub schema_version: String,
    /// Contiguous sequence number.
    pub sequence: u64,
    /// Event.
    pub event: Phase7LedgerEvent,
    /// Holdout identity.
    pub holdout_id: String,
    /// Run identity.
    pub run_id: String,
    /// Manifest SHA-256.
    pub manifest_sha256: String,
    /// Evidence-contract SHA-256.
    pub evidence_contract_sha256: String,
    /// Contract Merkle root.
    pub commitment_root: String,
    /// External binary SHA-256.
    pub binary_sha256: String,
    /// Prior logical entry hash.
    pub previous_entry_hash: String,
    /// UTC timestamp.
    pub timestamp_utc: String,
    /// Case identifier for case events.
    pub case_id: Option<String>,
    /// Case status for case events.
    pub case_status: Option<LiveCaseStatus>,
    /// Canonical case-record SHA-256.
    pub case_record_sha256: Option<String>,
    /// Raw report SHA-256 when retained.
    pub report_sha256: Option<String>,
    /// Result SHA-256 for completion.
    pub result_sha256: Option<String>,
    /// Stable failure code for terminal failure.
    pub failure_code: Option<String>,
    /// Entry hash excluding this field.
    pub entry_hash: String,
}

/// Parsed mixed-generation Phase 5/7 ledger.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Phase7Ledger {
    /// Immutable Phase 5 genesis entry.
    pub genesis: Phase5LedgerEntry,
    /// Phase 7 appended entries.
    pub entries: Vec<Phase7LedgerEntry>,
}

/// Inputs for preparing a scanner-free pre-execution contract.
pub struct Phase7PrepareRequest<'a> {
    /// Current repository root.
    pub repository_root: &'a Path,
    /// Exact read-only Phase 5 Git projection.
    pub frozen_evaluator_root: &'a Path,
    /// External binary, read only for hashing.
    pub binary: &'a Path,
    /// Source RPM, read only for hashing.
    pub source_rpm: &'a Path,
    /// Built release benchmark executable.
    pub benchmark_binary: &'a Path,
    /// Current frozen manifest bytes.
    pub manifest: &'a [u8],
    /// Current evidence contract bytes.
    pub evidence_contract: &'a [u8],
    /// Frozen taxonomy bytes.
    pub taxonomy: &'a [u8],
    /// Genesis ledger bytes.
    pub ledger: &'a [u8],
    /// UTC contract freeze time.
    pub frozen_at_utc: &'a str,
    /// Future run directory, which must not exist.
    pub run_directory: &'a Path,
    /// Future artifact index, which must not exist.
    pub artifacts_path: &'a Path,
    /// Future result path, which must not exist.
    pub result_path: &'a Path,
}

/// Inputs for the sole reserved execution.
pub struct Phase7ExecutionRequest<'a> {
    /// Current repository root.
    pub repository_root: &'a Path,
    /// Exact read-only Phase 5 evaluator projection.
    pub frozen_evaluator_root: &'a Path,
    /// External scanner binary.
    pub binary: &'a Path,
    /// Source RPM.
    pub source_rpm: &'a Path,
    /// Frozen release benchmark executable.
    pub benchmark_binary: &'a Path,
    /// Pre-execution contract bytes.
    pub pre_execution_contract: &'a [u8],
    /// Frozen manifest bytes.
    pub manifest: &'a [u8],
    /// Evidence contract bytes.
    pub evidence_contract: &'a [u8],
    /// Taxonomy bytes.
    pub taxonomy: &'a [u8],
    /// Mutable append-only ledger path.
    pub ledger_path: &'a Path,
    /// New retained run directory.
    pub run_directory: &'a Path,
    /// New result path.
    pub result_path: &'a Path,
    /// New artifact-index path.
    pub artifacts_path: &'a Path,
    /// Portable pre-execution contract path.
    pub pre_execution_contract_path: &'a str,
    /// Portable run manifest path.
    pub run_path: &'a str,
    /// Portable result path.
    pub result_path_relative: &'a str,
    /// Portable ledger path.
    pub ledger_path_relative: &'a str,
    /// Cancellation signal.
    pub cancellation: Arc<AtomicBool>,
}

/// Inputs for scanner-free post-execution verification.
pub struct Phase7VerificationRequest<'a> {
    /// Current repository root.
    pub repository_root: &'a Path,
    /// Exact read-only Phase 5 evaluator projection.
    pub frozen_evaluator_root: &'a Path,
    /// External binary, used only for hashing.
    pub binary: &'a Path,
    /// Source RPM, used only for hashing.
    pub source_rpm: &'a Path,
    /// Frozen benchmark executable.
    pub benchmark_binary: &'a Path,
    /// Pre-execution contract bytes.
    pub pre_execution_contract: &'a [u8],
    /// Manifest bytes.
    pub manifest: &'a [u8],
    /// Evidence contract bytes.
    pub evidence_contract: &'a [u8],
    /// Taxonomy bytes.
    pub taxonomy: &'a [u8],
    /// Completed ledger bytes.
    pub ledger: &'a [u8],
    /// Run bytes.
    pub run: &'a [u8],
    /// Result bytes.
    pub result: &'a [u8],
    /// Artifact-index bytes.
    pub artifacts: &'a [u8],
    /// Retained run directory.
    pub run_directory: &'a Path,
}

/// Phase 7 contract, execution, adapter, or artifact failure.
#[derive(Debug, Error)]
pub enum Phase7Error {
    /// Frozen contract is invalid.
    #[error("invalid Phase 7 contract: {0}")]
    InvalidContract(String),
    /// Filesystem or process runner failed.
    #[error(transparent)]
    Runner(#[from] RunnerError),
    /// Filesystem failure with sanitized context.
    #[error("Phase 7 artifact operation failed for `{path}`: {detail}")]
    Io {
        /// Portable context.
        path: String,
        /// Operating-system detail.
        detail: String,
    },
    /// Deterministic serialization failed.
    #[error("could not serialize deterministic Phase 7 data")]
    Serialization,
}

#[derive(Debug, Deserialize)]
struct RawSecureReport {
    schema_version: String,
    #[serde(default)]
    findings: Vec<RawSecureFinding>,
    #[serde(default)]
    scan: Option<RawScan>,
    #[serde(default)]
    errors: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct RawScan {
    complete: bool,
}

#[derive(Debug, Deserialize)]
struct RawSecureFinding {
    #[serde(default)]
    rule_id: Option<String>,
    #[serde(default)]
    taxonomy: Option<ReportedTaxonomyMetadata>,
    #[serde(default, deserialize_with = "deserialize_cwe")]
    primary_cwe: Option<String>,
    #[serde(default)]
    evidence_path: Vec<RawEvidenceNode>,
    #[serde(default)]
    guards: Vec<serde_json::Value>,
    #[serde(default)]
    verification_state: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawEvidenceNode {
    #[serde(default)]
    edge_id_from_previous: Option<String>,
    kind: String,
    #[serde(default)]
    semantic: Option<RawSemantic>,
    location: RawLocation,
}

#[derive(Debug, Deserialize)]
struct RawSemantic {
    role: String,
    identity: String,
    certainty: String,
}

#[derive(Debug, Deserialize)]
struct RawLocation {
    path: String,
    span: RawSpan,
}

#[derive(Debug, Deserialize)]
struct RawSpan {
    start_line: u32,
    #[serde(default = "one")]
    start_column: u32,
    #[serde(default)]
    end_line: Option<u32>,
    #[serde(default)]
    end_column: Option<u32>,
}

#[derive(Clone, Debug)]
struct AdaptedFinding {
    finding_id: String,
    canonical: CanonicalFindingV2,
    semantic_fingerprint: String,
    adapter_state: Phase7AdapterState,
    reported_taxonomy: Option<ReportedTaxonomyMetadata>,
    primary_cwe: Option<String>,
    report_sha256: String,
}

fn one() -> u32 {
    1
}

fn deserialize_cwe<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(value.and_then(|value| match value {
        serde_json::Value::String(text) => Some(text),
        serde_json::Value::Object(object) => object
            .get("id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        _ => None,
    }))
}

/// Returns canonical pretty JSON with one trailing newline.
///
/// # Errors
///
/// Returns an error when the value cannot be serialized as JSON.
pub fn canonical_phase7_json<T: Serialize>(value: &T) -> Result<Vec<u8>, Phase7Error> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|_| Phase7Error::Serialization)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn argument_template() -> Vec<String> {
    PHASE7_ARGUMENTS.map(str::to_owned).to_vec()
}

fn ratio(numerator: u64, denominator: u64) -> RatioMetric {
    let basis_points = if denominator == 0 {
        None
    } else {
        let scaled = u128::from(numerator)
            .saturating_mul(10_000)
            .saturating_add(u128::from(denominator / 2))
            / u128::from(denominator);
        u32::try_from(scaled).ok()
    };
    RatioMetric {
        numerator,
        denominator,
        basis_points,
    }
}

fn f1(exact: u64, findings: u64, expectations: u64) -> RatioMetric {
    let denominator = findings.saturating_add(expectations);
    ratio(exact.saturating_mul(2), denominator)
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

fn read_file(path: &Path) -> Result<Vec<u8>, Phase7Error> {
    fs::read(path).map_err(|error| Phase7Error::Io {
        path: path.display().to_string(),
        detail: error.to_string(),
    })
}

fn fingerprint_regular_file(path: &Path) -> Result<String, Phase7Error> {
    let metadata = fs::symlink_metadata(path).map_err(|error| Phase7Error::Io {
        path: path.display().to_string(),
        detail: error.to_string(),
    })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(Phase7Error::InvalidContract(format!(
            "`{}` must be a regular non-symlink file",
            path.display()
        )));
    }
    let mut file = fs::File::open(path).map_err(|error| Phase7Error::Io {
        path: path.display().to_string(),
        detail: error.to_string(),
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let read = file.read(&mut buffer).map_err(|error| Phase7Error::Io {
            path: path.display().to_string(),
            detail: error.to_string(),
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex_digest(&hasher.finalize()))
}

fn validate_relative_path(path: &str) -> Result<String, Phase7Error> {
    let normalized = path.replace('\\', "/");
    let candidate = Path::new(&normalized);
    if normalized.is_empty()
        || candidate.is_absolute()
        || normalized.starts_with('/')
        || normalized.as_bytes().get(1) == Some(&b':')
        || candidate.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(Phase7Error::InvalidContract(
            "report contains an unsafe source path".to_owned(),
        ));
    }
    let components = candidate
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => value.to_str(),
            _ => None,
        })
        .collect::<Vec<_>>();
    if components.is_empty() {
        return Err(Phase7Error::InvalidContract(
            "report contains an empty source path".to_owned(),
        ));
    }
    Ok(components.join("/"))
}

fn safe_join(root: &Path, relative: &str) -> Result<PathBuf, Phase7Error> {
    let normalized = validate_relative_path(relative)?;
    Ok(root.join(normalized))
}

fn span_from_raw(location: &RawLocation) -> Result<EvidenceSpanV2, Phase7Error> {
    let file = validate_relative_path(&location.path)?;
    let end_line = location.span.end_line.unwrap_or(location.span.start_line);
    let end_column = location
        .span
        .end_column
        .unwrap_or(location.span.start_column);
    if location.span.start_line == 0
        || location.span.start_column == 0
        || end_line == 0
        || end_column == 0
        || (location.span.start_line, location.span.start_column) > (end_line, end_column)
    {
        return Err(Phase7Error::InvalidContract(
            "report contains an invalid source span".to_owned(),
        ));
    }
    Ok(EvidenceSpanV2 {
        file,
        start_line: location.span.start_line,
        start_column: location.span.start_column,
        end_line,
        end_column,
    })
}

fn canonical_role(value: &str) -> Option<EvidenceRoleV2> {
    match value {
        "source" | "untrusted-source" => Some(EvidenceRoleV2::Source),
        "propagation" => Some(EvidenceRoleV2::Propagation),
        "transformation" => Some(EvidenceRoleV2::Transformation),
        "guard" => Some(EvidenceRoleV2::Guard),
        "sanitizer" => Some(EvidenceRoleV2::Sanitizer),
        "authorization" => Some(EvidenceRoleV2::Authorization),
        "sink" | "sensitive-sink" => Some(EvidenceRoleV2::Sink),
        _ => None,
    }
}

fn source_kind(identity: &str) -> Option<SourceSemanticKind> {
    match identity {
        "source.http-query-value" | "source.http_query_value" => {
            Some(SourceSemanticKind::HttpQueryValue)
        }
        "source.http-body-field" | "source.http_body_field" => {
            Some(SourceSemanticKind::HttpBodyField)
        }
        "source.form-data-value" | "source.form_data_value" => {
            Some(SourceSemanticKind::FormDataValue)
        }
        "source.protected-resource-id" | "source.protected_resource_id" => {
            Some(SourceSemanticKind::ProtectedResourceId)
        }
        _ => None,
    }
}

fn sink_kind(identity: &str) -> Option<SinkSemanticKind> {
    match identity {
        "sink.protected-record-mutation" | "sink.protected_record_mutation" => {
            Some(SinkSemanticKind::ProtectedRecordMutation)
        }
        "sink.os-command-execution" | "sink.os_command_execution" => {
            Some(SinkSemanticKind::OsCommandExecution)
        }
        "sink.dynamic-code-evaluation" | "sink.dynamic_code_evaluation" => {
            Some(SinkSemanticKind::DynamicCodeEvaluation)
        }
        "sink.filesystem-read" | "sink.filesystem_read" => Some(SinkSemanticKind::FilesystemRead),
        "sink.outbound-request" | "sink.outbound_request" => {
            Some(SinkSemanticKind::OutboundRequest)
        }
        "sink.redirect-response" | "sink.redirect_response" => {
            Some(SinkSemanticKind::RedirectResponse)
        }
        "sink.sql-query-execution" | "sink.sql_query_execution" => {
            Some(SinkSemanticKind::SqlQueryExecution)
        }
        _ => None,
    }
}

fn semantic_effect(role: EvidenceRoleV2, identity: &str) -> Option<EvidenceEffectV2> {
    match (role, identity) {
        (EvidenceRoleV2::Source | EvidenceRoleV2::Sink, _)
        | (_, "effect.preserves-influence" | "effect.preserves_influence") => {
            Some(EvidenceEffectV2::PreservesInfluence)
        }
        (_, "effect.separates-control-and-data" | "effect.separates_control_and_data") => {
            Some(EvidenceEffectV2::SeparatesControlAndData)
        }
        (_, "effect.constrains-to-policy" | "effect.constrains_to_policy") => {
            Some(EvidenceEffectV2::ConstrainsToPolicy)
        }
        (_, "effect.rejects-and-terminates" | "effect.rejects_and_terminates") => {
            Some(EvidenceEffectV2::RejectsAndTerminates)
        }
        (_, "effect.authorizes-operation" | "effect.authorizes_operation") => {
            Some(EvidenceEffectV2::AuthorizesOperation)
        }
        _ => None,
    }
}

#[allow(clippy::too_many_lines)]
fn adapt_report(
    case_id: &str,
    report: &[u8],
    report_sha256: &str,
) -> Result<Vec<AdaptedFinding>, Phase7Error> {
    if report.len() > usize::try_from(CASE_OUTPUT_BYTES).unwrap_or(usize::MAX) {
        return Err(Phase7Error::InvalidContract(
            "report exceeds the frozen output limit".to_owned(),
        ));
    }
    let raw: RawSecureReport = serde_json::from_slice(report).map_err(|error| {
        Phase7Error::InvalidContract(format!(
            "secure-json-v1 is malformed at line {}",
            error.line()
        ))
    })?;
    if raw.schema_version != "secure-json-v1" {
        return Err(Phase7Error::InvalidContract(
            "report schema is not secure-json-v1".to_owned(),
        ));
    }
    if raw.scan.as_ref().is_some_and(|scan| !scan.complete) || !raw.errors.is_empty() {
        return Err(Phase7Error::InvalidContract(
            "report declares an incomplete scan or scanner errors".to_owned(),
        ));
    }
    let mut findings = Vec::with_capacity(raw.findings.len());
    for (index, finding) in raw.findings.into_iter().enumerate() {
        let taxonomy = finding.taxonomy.clone().unwrap_or_default();
        let mut path = Vec::with_capacity(finding.evidence_path.len());
        let mut connected_edges = Vec::with_capacity(finding.evidence_path.len().saturating_sub(1));
        let mut effective_barriers = Vec::new();
        let mut uncertain = finding.verification_state.as_deref()
            != Some("verified-deterministic-path")
            || !finding.guards.is_empty();
        let mut unmapped = false;
        let mut unresolved_call = false;
        for (node_index, node) in finding.evidence_path.into_iter().enumerate() {
            if node_index > 0 {
                connected_edges.push(
                    node.edge_id_from_previous
                        .as_deref()
                        .is_some_and(|value| !value.is_empty()),
                );
            }
            let Some(semantic) = node.semantic else {
                uncertain = true;
                unmapped = true;
                path.push(EvidenceNodeV2 {
                    role: EvidenceRoleV2::Propagation,
                    effect: EvidenceEffectV2::PreservesInfluence,
                    source_kind: None,
                    sink_kind: None,
                    span: span_from_raw(&node.location)?,
                    summarizable: false,
                });
                continue;
            };
            let role = canonical_role(&semantic.role).unwrap_or_else(|| {
                uncertain = true;
                unmapped = true;
                EvidenceRoleV2::Propagation
            });
            unresolved_call |= node.kind == "unresolved-call"
                || semantic.identity.contains("unresolved")
                || semantic.certainty == "unresolved";
            if semantic.certainty != "proven" {
                uncertain = true;
            }
            let mapped_source = if role == EvidenceRoleV2::Source {
                source_kind(&semantic.identity)
            } else {
                None
            };
            let mapped_sink = if role == EvidenceRoleV2::Sink {
                sink_kind(&semantic.identity)
            } else {
                None
            };
            if (role == EvidenceRoleV2::Source && mapped_source.is_none())
                || (role == EvidenceRoleV2::Sink && mapped_sink.is_none())
            {
                unmapped = true;
            }
            let effect = semantic_effect(role, &semantic.identity).unwrap_or_else(|| {
                uncertain = true;
                unmapped = true;
                EvidenceEffectV2::PreservesInfluence
            });
            if matches!(
                role,
                EvidenceRoleV2::Guard | EvidenceRoleV2::Sanitizer | EvidenceRoleV2::Authorization
            ) && semantic.certainty == "proven"
            {
                effective_barriers.push(effect);
            }
            path.push(EvidenceNodeV2 {
                role,
                effect,
                source_kind: mapped_source,
                sink_kind: mapped_sink,
                span: span_from_raw(&node.location)?,
                summarizable: false,
            });
        }
        let canonical = CanonicalFindingV2 {
            taxonomy_version: taxonomy.taxonomy_version.clone().unwrap_or_default(),
            category_id: taxonomy.category_id.clone().unwrap_or_default(),
            invariant_id: taxonomy.invariant_id.clone().unwrap_or_default(),
            path,
            connected_edges,
            effective_barriers,
            unresolved_call,
            uncertain,
            rule_id: finding
                .rule_id
                .as_deref()
                .map(|value| fingerprint(value.as_bytes())),
            tool_identity: None,
            prose: None,
        };
        let semantic_fingerprint = evidence_fingerprint_v2(&canonical)
            .map_err(|error| Phase7Error::InvalidContract(error.to_string()))?;
        let finding_id = fingerprint(
            format!("{case_id}\0{report_sha256}\0{index}\0{semantic_fingerprint}").as_bytes(),
        );
        findings.push(AdaptedFinding {
            finding_id,
            canonical,
            semantic_fingerprint,
            adapter_state: if unmapped {
                Phase7AdapterState::UnmappedSemantics
            } else {
                Phase7AdapterState::Canonical
            },
            reported_taxonomy: finding.taxonomy,
            primary_cwe: finding.primary_cwe,
            report_sha256: report_sha256.to_owned(),
        });
    }
    Ok(findings)
}

fn spans_equivalent(expected: &EvidenceSpanV2, actual: &EvidenceSpanV2) -> bool {
    if validate_relative_path(&expected.file).ok() != validate_relative_path(&actual.file).ok() {
        return false;
    }
    if expected == actual {
        return true;
    }
    let expanded = expected.start_line.abs_diff(actual.start_line)
        + expected.end_line.abs_diff(actual.end_line);
    let contains = |outer: &EvidenceSpanV2, inner: &EvidenceSpanV2| {
        (outer.start_line, outer.start_column) <= (inner.start_line, inner.start_column)
            && (outer.end_line, outer.end_column) >= (inner.end_line, inner.end_column)
    };
    (contains(expected, actual) || contains(actual, expected)) && expanded <= 3
}

fn ordered_path_agrees(expected: &[EvidenceNodeV2], actual: &CanonicalFindingV2) -> bool {
    if actual.path.len() < 2
        || actual.connected_edges.len() + 1 != actual.path.len()
        || actual.connected_edges.iter().any(|connected| !connected)
        || !actual.effective_barriers.is_empty()
    {
        return false;
    }
    let mandatory = expected.iter().filter(|node| !node.summarizable);
    let mut offset = 0_usize;
    for expected_node in mandatory {
        let Some(found) = actual.path[offset..].iter().position(|node| {
            node.role == expected_node.role
                && node.effect == expected_node.effect
                && node.source_kind == expected_node.source_kind
                && node.sink_kind == expected_node.sink_kind
        }) else {
            return false;
        };
        offset += found + 1;
    }
    true
}

fn criteria_for(expectation: &EvidenceExpectationV2, finding: &AdaptedFinding) -> Phase7Criteria {
    let actual = &finding.canonical;
    let category = actual.category_id == expectation.category_id;
    let invariant = actual.invariant_id == expectation.invariant_id;
    let taxonomy = actual.taxonomy_version == expectation.taxonomy_version && category && invariant;
    let expected_source = expectation.path.first();
    let actual_source = actual.path.first();
    let source = expected_source
        .zip(actual_source)
        .is_some_and(|(expected, actual)| {
            actual.role == EvidenceRoleV2::Source
                && actual.source_kind == expected.source_kind
                && spans_equivalent(&expected.span, &actual.span)
        });
    let expected_sink = expectation.path.last();
    let actual_sink = actual.path.last();
    let sink = expected_sink
        .zip(actual_sink)
        .is_some_and(|(expected, actual)| {
            actual.role == EvidenceRoleV2::Sink
                && actual.sink_kind == expected.sink_kind
                && spans_equivalent(&expected.span, &actual.span)
        });
    Phase7Criteria {
        taxonomy,
        category,
        invariant,
        cwe: finding.primary_cwe.as_deref() == Some(expectation.primary_cwe.as_str()),
        source,
        sink,
        evidence_path: ordered_path_agrees(&expectation.path, actual),
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

fn framework_name(value: Phase5Framework) -> &'static str {
    match value {
        Phase5Framework::NodeJs => "node_js",
        Phase5Framework::Express => "express",
        Phase5Framework::NextAppRouter => "next_app_router",
        Phase5Framework::ServerActions => "server_actions",
    }
}

fn topology_name(value: Phase5Topology) -> &'static str {
    match value {
        Phase5Topology::Direct => "direct",
        Phase5Topology::HelperMediated => "helper_mediated",
        Phase5Topology::InterFileAliased => "inter_file_aliased",
        Phase5Topology::ControlFlowSensitive => "control_flow_sensitive",
    }
}

fn language_name(value: crate::phase5::Phase5Language) -> &'static str {
    match value {
        crate::phase5::Phase5Language::JavaScript => "javascript",
        crate::phase5::Phase5Language::TypeScript => "typescript",
    }
}

fn flatten_cases(manifest: &Phase5Manifest) -> Vec<(&crate::phase5::Phase5Pair, &Phase5Case)> {
    let mut cases = manifest
        .pairs
        .iter()
        .flat_map(|pair| [(pair, &pair.vulnerable), (pair, &pair.control)])
        .collect::<Vec<_>>();
    cases.sort_by(|left, right| left.1.case_id.cmp(&right.1.case_id));
    cases
}

fn measurement(run: &Phase7Run) -> Phase7Measurement {
    let executions = run
        .cases
        .iter()
        .map(|case| &case.execution)
        .collect::<Vec<_>>();
    let mut status_counts = BTreeMap::new();
    let mut exit_codes = BTreeMap::new();
    let mut peak = None;
    let mut nonzero_exits = 0_u64;
    let mut malformed_reports = 0_u64;
    let mut missing_reports = 0_u64;
    for case in &executions {
        *status_counts
            .entry(status_name(case.status).to_owned())
            .or_insert(0) += 1;
        exit_codes.insert(case.case_id.clone(), case.process_exit_code);
        peak = maximum_option(peak, case.peak_memory_bytes);
        nonzero_exits += u64::from(case.process_exit_code.is_some_and(|code| code != 0));
        malformed_reports += u64::from(
            case.error_code.as_deref() == Some("runner.invalid_output")
                || case.error_code.as_deref() == Some("runner.privacy_unsafe_report"),
        );
        missing_reports += u64::from(case.error_code.as_deref() == Some("runner.missing_report"));
    }
    let total_duration_ms = executions
        .iter()
        .map(|case| case.duration_ms)
        .fold(0_u64, u64::saturating_add);
    let total_output_bytes = executions
        .iter()
        .filter_map(|case| case.output_bytes)
        .fold(0_u64, u64::saturating_add);
    let failures = executions
        .iter()
        .filter(|case| !case.status.is_success())
        .count();
    Phase7Measurement {
        run_id: run.run_id.clone(),
        status: run.status,
        cases: u64::try_from(executions.len()).unwrap_or(u64::MAX),
        completed_cases: u64::try_from(
            executions
                .iter()
                .filter(|case| case.status.is_success())
                .count(),
        )
        .unwrap_or(u64::MAX),
        total_duration_ms,
        runner_duration_ms: run.finished_unix_ms.saturating_sub(run.started_unix_ms),
        peak_rss_bytes: peak,
        total_output_bytes,
        status_counts,
        exit_codes,
        nonzero_exits,
        failures: u64::try_from(failures).unwrap_or(u64::MAX),
        crashes: u64::try_from(
            executions
                .iter()
                .filter(|case| case.status == LiveCaseStatus::Crash)
                .count(),
        )
        .unwrap_or(u64::MAX),
        timeouts: u64::try_from(
            executions
                .iter()
                .filter(|case| case.status == LiveCaseStatus::Timeout)
                .count(),
        )
        .unwrap_or(u64::MAX),
        malformed_reports,
        missing_reports,
    }
}

fn maximum_option(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn group_metrics<'a, I>(
    rows: I,
    decisions: &BTreeMap<&str, &Phase7CaseDecision>,
) -> Phase7GroupMetrics
where
    I: IntoIterator<Item = &'a Phase5Case>,
{
    let mut vulnerable = 0_u64;
    let mut exact = 0_u64;
    let mut partial = 0_u64;
    let mut missed = 0_u64;
    let mut out_of_scope = 0_u64;
    let mut not_attempted = 0_u64;
    let mut controls = 0_u64;
    let mut flagged_controls = 0_u64;
    let mut clean_controls = 0_u64;
    let mut controls_not_attempted = 0_u64;
    let mut distinct_findings = 0_u64;
    let mut duplicate_findings = 0_u64;
    let mut unrelated_findings = 0_u64;
    for case in rows {
        let Some(decision) = decisions.get(case.case_id.as_str()) else {
            continue;
        };
        distinct_findings = distinct_findings.saturating_add(decision.distinct_findings);
        duplicate_findings = duplicate_findings.saturating_add(decision.duplicate_findings);
        unrelated_findings = unrelated_findings.saturating_add(decision.unrelated_findings);
        match decision.outcome {
            Phase7Outcome::ExactDetection => {
                vulnerable += 1;
                exact += 1;
            }
            Phase7Outcome::PartialMatch => {
                vulnerable += 1;
                partial += 1;
            }
            Phase7Outcome::Missed => {
                vulnerable += 1;
                missed += 1;
            }
            Phase7Outcome::OutOfScope => {
                vulnerable += 1;
                out_of_scope += 1;
            }
            Phase7Outcome::NotAttempted if case.kind == Phase5CaseKind::Vulnerable => {
                vulnerable += 1;
                not_attempted += 1;
            }
            Phase7Outcome::NotAttempted => {
                controls += 1;
                controls_not_attempted += 1;
            }
            Phase7Outcome::SafeControlFlagged => {
                controls += 1;
                flagged_controls += 1;
            }
            Phase7Outcome::SafeControlClean => {
                controls += 1;
                clean_controls += 1;
            }
        }
    }
    Phase7GroupMetrics {
        vulnerable,
        exact,
        partial,
        missed,
        out_of_scope,
        not_attempted,
        controls,
        flagged_controls,
        clean_controls,
        controls_not_attempted,
        distinct_findings,
        duplicate_findings,
        unrelated_findings,
        precision: ratio(exact, distinct_findings),
        recall: ratio(exact, vulnerable),
        f1: f1(exact, distinct_findings, vulnerable),
    }
}

#[allow(clippy::too_many_lines)]
fn build_breakdowns(
    manifest: &Phase5Manifest,
    decisions: &[Phase7CaseDecision],
) -> Phase7Breakdowns {
    let by_id = decisions
        .iter()
        .map(|decision| (decision.case_id.as_str(), decision))
        .collect::<BTreeMap<_, _>>();
    let mut taxonomy = BTreeSet::new();
    let mut frameworks = BTreeSet::new();
    let mut languages = BTreeSet::new();
    let mut topologies = BTreeSet::new();
    for pair in &manifest.pairs {
        taxonomy.insert(pair.assignment.category_id.clone());
        frameworks.insert(framework_name(pair.assignment.framework).to_owned());
        languages.insert(language_name(pair.assignment.language).to_owned());
        topologies.insert(topology_name(pair.assignment.topology).to_owned());
    }
    let metrics_for = |predicate: &dyn Fn(&crate::phase5::Phase5Pair) -> bool| {
        group_metrics(
            manifest
                .pairs
                .iter()
                .filter(|pair| predicate(pair))
                .flat_map(|pair| [&pair.vulnerable, &pair.control]),
            &by_id,
        )
    };
    let taxonomy_family = taxonomy
        .iter()
        .map(|value| {
            (
                value.clone(),
                metrics_for(&|pair| pair.assignment.category_id == *value),
            )
        })
        .collect();
    let framework = frameworks
        .iter()
        .map(|value| {
            (
                value.clone(),
                metrics_for(&|pair| framework_name(pair.assignment.framework) == value),
            )
        })
        .collect();
    let language = languages
        .iter()
        .map(|value| {
            (
                value.clone(),
                metrics_for(&|pair| language_name(pair.assignment.language) == value),
            )
        })
        .collect();
    let topology = topologies
        .iter()
        .map(|value| {
            (
                value.clone(),
                metrics_for(&|pair| topology_name(pair.assignment.topology) == value),
            )
        })
        .collect();
    let mut framework_language = BTreeMap::new();
    for framework in &frameworks {
        for language in &languages {
            framework_language.insert(
                format!("{framework}|{language}"),
                metrics_for(&|pair| {
                    framework_name(pair.assignment.framework) == framework
                        && language_name(pair.assignment.language) == language
                }),
            );
        }
    }
    let mut topology_language = BTreeMap::new();
    for topology in &topologies {
        for language in &languages {
            topology_language.insert(
                format!("{topology}|{language}"),
                metrics_for(&|pair| {
                    topology_name(pair.assignment.topology) == topology
                        && language_name(pair.assignment.language) == language
                }),
            );
        }
    }
    let mut framework_topology = BTreeMap::new();
    for framework in &frameworks {
        for topology in &topologies {
            framework_topology.insert(
                format!("{framework}|{topology}"),
                metrics_for(&|pair| {
                    framework_name(pair.assignment.framework) == framework
                        && topology_name(pair.assignment.topology) == topology
                }),
            );
        }
    }
    Phase7Breakdowns {
        taxonomy_family,
        framework,
        language,
        topology,
        framework_language,
        topology_language,
        framework_topology,
    }
}

fn report_aggregate(run: &Phase7Run) -> String {
    let mut rows = run
        .cases
        .iter()
        .filter_map(|case| {
            case.execution
                .report_fingerprint
                .as_ref()
                .map(|hash| format!("{}\0{hash}", case.execution.case_id))
        })
        .collect::<Vec<_>>();
    rows.sort();
    fingerprint(rows.join("\n").as_bytes())
}

fn semantic_result_fingerprint(
    decisions: &[Phase7CaseDecision],
    findings: &[Phase7FindingRecord],
    metrics: &Phase7Metrics,
    breakdowns: &Phase7Breakdowns,
) -> Result<String, Phase7Error> {
    let mut semantic_findings = findings
        .iter()
        .map(|finding| {
            (
                &finding.case_id,
                &finding.semantic_fingerprint,
                finding.adapter_state,
                &finding.reported_taxonomy,
                &finding.primary_cwe,
            )
        })
        .collect::<Vec<_>>();
    semantic_findings.sort();
    let bytes = serde_json::to_vec(&(decisions, semantic_findings, metrics, breakdowns))
        .map_err(|_| Phase7Error::Serialization)?;
    Ok(fingerprint(&bytes))
}

fn metrics_from_decisions(decisions: &[Phase7CaseDecision], findings_count: u64) -> Phase7Metrics {
    let mut counts = Phase7Counts {
        findings: findings_count,
        ..Phase7Counts::default()
    };
    let mut taxonomy = 0_u64;
    let mut category = 0_u64;
    let mut invariant = 0_u64;
    let mut cwe = 0_u64;
    let mut source = 0_u64;
    let mut sink = 0_u64;
    let mut evidence_path = 0_u64;
    for decision in decisions {
        counts.distinct_findings = counts
            .distinct_findings
            .saturating_add(decision.distinct_findings);
        counts.duplicate_findings = counts
            .duplicate_findings
            .saturating_add(decision.duplicate_findings);
        counts.unrelated_findings = counts
            .unrelated_findings
            .saturating_add(decision.unrelated_findings);
        match decision.outcome {
            Phase7Outcome::ExactDetection => {
                counts.vulnerable_expectations += 1;
                counts.exact_detections += 1;
            }
            Phase7Outcome::PartialMatch => {
                counts.vulnerable_expectations += 1;
                counts.partial_matches += 1;
            }
            Phase7Outcome::Missed => {
                counts.vulnerable_expectations += 1;
                counts.misses += 1;
            }
            Phase7Outcome::OutOfScope => {
                counts.vulnerable_expectations += 1;
                counts.out_of_scope += 1;
            }
            Phase7Outcome::NotAttempted if decision.kind == CaseKind::Vulnerable => {
                counts.vulnerable_expectations += 1;
                counts.not_attempted += 1;
            }
            Phase7Outcome::NotAttempted => {
                counts.safe_controls += 1;
                counts.safe_controls_not_attempted += 1;
            }
            Phase7Outcome::SafeControlFlagged => {
                counts.safe_controls += 1;
                counts.safe_controls_flagged += 1;
            }
            Phase7Outcome::SafeControlClean => {
                counts.safe_controls += 1;
                counts.clean_safe_controls += 1;
            }
        }
        if decision.kind == CaseKind::Vulnerable
            && let Some(criteria) = &decision.criteria
        {
            taxonomy += u64::from(criteria.taxonomy);
            category += u64::from(criteria.category);
            invariant += u64::from(criteria.invariant);
            cwe += u64::from(criteria.cwe);
            source += u64::from(criteria.source);
            sink += u64::from(criteria.sink);
            evidence_path += u64::from(criteria.evidence_path);
        }
    }
    counts.strict_false_positive_findings = counts
        .distinct_findings
        .saturating_sub(counts.exact_detections);
    let exact = counts.exact_detections;
    let distinct = counts.distinct_findings;
    let vulnerable = counts.vulnerable_expectations;
    Phase7Metrics {
        counts,
        precision: ratio(exact, distinct),
        recall: ratio(exact, vulnerable),
        f1: f1(exact, distinct, vulnerable),
        taxonomy_agreement: ratio(taxonomy, vulnerable),
        category_agreement: ratio(category, vulnerable),
        invariant_agreement: ratio(invariant, vulnerable),
        cwe_agreement: ratio(cwe, vulnerable),
        source_agreement: ratio(source, vulnerable),
        sink_agreement: ratio(sink, vulnerable),
        evidence_path_agreement: ratio(evidence_path, vulnerable),
    }
}

#[derive(Clone)]
struct CandidateDecision<'a> {
    finding: &'a AdaptedFinding,
    evidence_match: EvidenceMatchV2,
    criteria: Phase7Criteria,
}

fn match_rank(value: EvidenceMatchV2) -> u8 {
    match value {
        EvidenceMatchV2::Exact => 2,
        EvidenceMatchV2::Partial => 1,
        EvidenceMatchV2::NoMatch => 0,
    }
}

fn evaluate_vulnerable_case(
    contract: &EvidenceContractV2,
    case: &Phase5Case,
    status: LiveCaseStatus,
    distinct: &[AdaptedFinding],
    duplicate_count: u64,
) -> Result<Phase7CaseDecision, Phase7Error> {
    let expectation = case.expectation.as_ref().ok_or_else(|| {
        Phase7Error::InvalidContract(format!(
            "vulnerable case `{}` has no expectation",
            case.case_id
        ))
    })?;
    if !status.is_success() {
        let outcome = if status == LiveCaseStatus::UnsupportedSchema {
            Phase7Outcome::OutOfScope
        } else {
            Phase7Outcome::NotAttempted
        };
        return Ok(Phase7CaseDecision {
            case_id: case.case_id.clone(),
            kind: CaseKind::Vulnerable,
            expectation_id: Some(expectation.expectation_id.clone()),
            outcome,
            execution_status: status,
            selected_finding_id: None,
            evidence_match: None,
            criteria: None,
            distinct_findings: 0,
            duplicate_findings: 0,
            unrelated_findings: 0,
        });
    }
    let mut candidates = distinct
        .iter()
        .map(|finding| CandidateDecision {
            finding,
            evidence_match: match_evidence_v2(contract, expectation, &finding.canonical),
            criteria: criteria_for(expectation, finding),
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        match_rank(right.evidence_match)
            .cmp(&match_rank(left.evidence_match))
            .then_with(|| right.criteria.score().cmp(&left.criteria.score()))
            .then_with(|| left.finding.finding_id.cmp(&right.finding.finding_id))
    });
    let unrelated_findings = u64::try_from(
        candidates
            .iter()
            .filter(|candidate| candidate.evidence_match == EvidenceMatchV2::NoMatch)
            .count(),
    )
    .unwrap_or(u64::MAX);
    let selected = candidates.first();
    let outcome = selected.map_or(Phase7Outcome::Missed, |candidate| {
        match candidate.evidence_match {
            EvidenceMatchV2::Exact => Phase7Outcome::ExactDetection,
            EvidenceMatchV2::Partial => Phase7Outcome::PartialMatch,
            EvidenceMatchV2::NoMatch => Phase7Outcome::Missed,
        }
    });
    Ok(Phase7CaseDecision {
        case_id: case.case_id.clone(),
        kind: CaseKind::Vulnerable,
        expectation_id: Some(expectation.expectation_id.clone()),
        outcome,
        execution_status: status,
        selected_finding_id: selected.map(|candidate| candidate.finding.finding_id.clone()),
        evidence_match: selected.map(|candidate| candidate.evidence_match),
        criteria: selected.map(|candidate| candidate.criteria.clone()),
        distinct_findings: u64::try_from(distinct.len()).unwrap_or(u64::MAX),
        duplicate_findings: duplicate_count,
        unrelated_findings,
    })
}

fn evaluate_control_case(
    case: &Phase5Case,
    status: LiveCaseStatus,
    distinct_count: u64,
    duplicate_count: u64,
) -> Phase7CaseDecision {
    let outcome = if !status.is_success() {
        Phase7Outcome::NotAttempted
    } else if distinct_count == 0 {
        Phase7Outcome::SafeControlClean
    } else {
        Phase7Outcome::SafeControlFlagged
    };
    Phase7CaseDecision {
        case_id: case.case_id.clone(),
        kind: CaseKind::SafeControl,
        expectation_id: None,
        outcome,
        execution_status: status,
        selected_finding_id: None,
        evidence_match: None,
        criteria: None,
        distinct_findings: if status.is_success() {
            distinct_count
        } else {
            0
        },
        duplicate_findings: if status.is_success() {
            duplicate_count
        } else {
            0
        },
        unrelated_findings: if status.is_success() {
            distinct_count
        } else {
            0
        },
    }
}

/// Evaluates one retained run without starting a scanner.
///
/// # Errors
///
/// Returns an error when the frozen inputs, retained run, reports, or ledger do not satisfy the
/// Phase 7 contract.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub fn evaluate_phase7(
    manifest: &Phase5Manifest,
    evidence_contract: &EvidenceContractV2,
    taxonomy: &FrozenTaxonomy,
    run: &Phase7Run,
    reports: &BTreeMap<String, Vec<u8>>,
    pre_execution_contract: &Phase7PreExecutionContract,
    pre_execution_bytes: &[u8],
    run_bytes: &[u8],
    ledger: &Phase7Ledger,
) -> Result<Phase7Result, Phase7Error> {
    validate_run_semantics(run, manifest, pre_execution_contract)?;
    if ledger.entries.len() != EXPECTED_CASES + 1
        || ledger.entries[0].event != Phase7LedgerEvent::ExecutionStarted
        || ledger
            .entries
            .iter()
            .skip(1)
            .any(|entry| entry.event != Phase7LedgerEvent::CaseRecorded)
    {
        return Err(Phase7Error::InvalidContract(
            "evaluation requires the reservation entry and no terminal entry".to_owned(),
        ));
    }
    let run_by_id = run
        .cases
        .iter()
        .map(|case| (case.execution.case_id.as_str(), case))
        .collect::<BTreeMap<_, _>>();
    let mut decisions = Vec::with_capacity(EXPECTED_CASES);
    let mut records = Vec::new();
    for (_, case) in flatten_cases(manifest) {
        let case_run = run_by_id.get(case.case_id.as_str()).ok_or_else(|| {
            Phase7Error::InvalidContract(format!("run omitted case `{}`", case.case_id))
        })?;
        let mut adapted = Vec::new();
        if case_run.execution.status.is_success() {
            let report = reports.get(case.case_id.as_str()).ok_or_else(|| {
                Phase7Error::InvalidContract(format!(
                    "successful case `{}` has no retained report",
                    case.case_id
                ))
            })?;
            let report_sha256 = fingerprint(report);
            if case_run.execution.report_fingerprint.as_deref() != Some(report_sha256.as_str()) {
                return Err(Phase7Error::InvalidContract(format!(
                    "report hash differs for `{}`",
                    case.case_id
                )));
            }
            adapted = adapt_report(&case.case_id, report, &report_sha256)?;
        }
        let mut first_by_semantic = BTreeMap::<String, String>::new();
        let mut distinct = Vec::new();
        let mut duplicate_count = 0_u64;
        for finding in &adapted {
            let duplicate_of = first_by_semantic
                .get(&finding.semantic_fingerprint)
                .cloned();
            if duplicate_of.is_some() {
                duplicate_count += 1;
            } else {
                first_by_semantic.insert(
                    finding.semantic_fingerprint.clone(),
                    finding.finding_id.clone(),
                );
                distinct.push(finding.clone());
            }
            records.push(Phase7FindingRecord {
                finding_id: finding.finding_id.clone(),
                case_id: case.case_id.clone(),
                semantic_fingerprint: finding.semantic_fingerprint.clone(),
                duplicate_of,
                adapter_state: finding.adapter_state,
                reported_taxonomy: finding.reported_taxonomy.clone(),
                primary_cwe: finding.primary_cwe.clone(),
                report_sha256: finding.report_sha256.clone(),
            });
        }
        distinct.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
        let decision = match case.kind {
            Phase5CaseKind::Vulnerable => evaluate_vulnerable_case(
                evidence_contract,
                case,
                case_run.execution.status,
                &distinct,
                duplicate_count,
            )?,
            Phase5CaseKind::SafeControl => evaluate_control_case(
                case,
                case_run.execution.status,
                u64::try_from(distinct.len()).unwrap_or(u64::MAX),
                duplicate_count,
            ),
        };
        decisions.push(decision);
    }
    decisions.sort_by(|left, right| left.case_id.cmp(&right.case_id));
    records.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
    let metrics =
        metrics_from_decisions(&decisions, u64::try_from(records.len()).unwrap_or(u64::MAX));
    let breakdowns = build_breakdowns(manifest, &decisions);
    let semantic_fingerprint =
        semantic_result_fingerprint(&decisions, &records, &metrics, &breakdowns)?;
    let mut schemas = BTreeMap::new();
    schemas.insert(
        "evidence_contract".to_owned(),
        evidence_contract.schema_version.clone(),
    );
    schemas.insert("ledger".to_owned(), PHASE7_LEDGER_SCHEMA_V1.to_owned());
    schemas.insert("manifest".to_owned(), manifest.schema_version.clone());
    schemas.insert(
        "pre_execution".to_owned(),
        PHASE7_PRE_EXECUTION_SCHEMA_V1.to_owned(),
    );
    schemas.insert("result".to_owned(), PHASE7_RESULT_SCHEMA_V1.to_owned());
    schemas.insert("run".to_owned(), PHASE7_RUN_SCHEMA_V1.to_owned());
    schemas.insert("taxonomy".to_owned(), taxonomy.schema_version.clone());
    let result = Phase7Result {
        schema_version: PHASE7_RESULT_SCHEMA_V1.to_owned(),
        run_id: PHASE7_RUN_ID.to_owned(),
        holdout_id: manifest.holdout_id.clone(),
        taxonomy_version: taxonomy.taxonomy_version.clone(),
        cases: decisions,
        findings: records,
        metrics,
        breakdowns,
        measurement: measurement(run),
        semantic_fingerprint,
        provenance: Phase7Provenance {
            binary_sha256: PHASE7_BINARY_SHA256.to_owned(),
            source_rpm_sha256: PHASE7_RPM_SHA256.to_owned(),
            manifest_sha256: PHASE7_MANIFEST_SHA256.to_owned(),
            evidence_contract_sha256: PHASE7_EVIDENCE_CONTRACT_SHA256.to_owned(),
            aggregate_corpus_sha256: PHASE7_CORPUS_SHA256.to_owned(),
            contract_merkle_root: PHASE7_MERKLE_ROOT.to_owned(),
            taxonomy_artifact_sha256: TAXONOMY_SHA256.to_owned(),
            taxonomy_content_hash: taxonomy.content_hash.clone(),
            frozen_evaluator_sha256: PHASE7_FROZEN_EVALUATOR_SHA256.to_owned(),
            command_template: argument_template(),
            configuration_sha256: EMPTY_SHA256.to_owned(),
            ai_validation: "disabled".to_owned(),
            network_isolation: pre_execution_contract.environment.isolation.clone(),
            namespace_scope: pre_execution_contract.resources.namespace_scope.clone(),
            host: run.host.clone(),
            pre_execution_contract_sha256: fingerprint(pre_execution_bytes),
            run_sha256: fingerprint(run_bytes),
            reports_sha256: report_aggregate(run),
            ledger_before_sha256: PHASE7_GENESIS_LEDGER_SHA256.to_owned(),
            ledger_genesis_entry_hash: ledger.genesis.entry_hash.clone(),
            ledger_started_entry_hash: ledger.entries[0].entry_hash.clone(),
            schemas,
            phase7_evaluator_files: pre_execution_contract.phase7_evaluator_files.clone(),
            historical_artifacts: pre_execution_contract.historical_artifacts.clone(),
        },
    };
    validate_result_semantics(&result, manifest)?;
    Ok(result)
}

fn validate_result_semantics(
    result: &Phase7Result,
    manifest: &Phase5Manifest,
) -> Result<(), Phase7Error> {
    let counts = &result.metrics.counts;
    if result.schema_version != PHASE7_RESULT_SCHEMA_V1
        || result.run_id != PHASE7_RUN_ID
        || result.holdout_id != manifest.holdout_id
        || result.cases.len() != EXPECTED_CASES
        || counts.vulnerable_expectations != 56
        || counts.safe_controls != 56
        || counts.exact_detections
            + counts.partial_matches
            + counts.misses
            + counts.out_of_scope
            + counts.not_attempted
            != counts.vulnerable_expectations
        || counts.safe_controls_flagged
            + counts.clean_safe_controls
            + counts.safe_controls_not_attempted
            != counts.safe_controls
        || counts.findings != u64::try_from(result.findings.len()).unwrap_or(u64::MAX)
        || counts.distinct_findings + counts.duplicate_findings != counts.findings
    {
        return Err(Phase7Error::InvalidContract(
            "result populations or identities are inconsistent".to_owned(),
        ));
    }
    Ok(())
}

fn collect_regular_files(
    root: &Path,
    relative: &Path,
    output: &mut Vec<PathBuf>,
) -> Result<(), Phase7Error> {
    let directory = root.join(relative);
    let mut entries = fs::read_dir(&directory)
        .map_err(|error| Phase7Error::Io {
            path: relative.display().to_string(),
            detail: error.to_string(),
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| Phase7Error::Io {
            path: relative.display().to_string(),
            detail: error.to_string(),
        })?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let child = relative.join(entry.file_name());
        let metadata = fs::symlink_metadata(&path).map_err(|error| Phase7Error::Io {
            path: child.display().to_string(),
            detail: error.to_string(),
        })?;
        if metadata.file_type().is_symlink() {
            return Err(Phase7Error::InvalidContract(format!(
                "artifact tree contains symlink `{}`",
                child.display()
            )));
        }
        if metadata.is_dir() {
            collect_regular_files(root, &child, output)?;
        } else if metadata.is_file() {
            output.push(child);
        } else {
            return Err(Phase7Error::InvalidContract(format!(
                "artifact tree contains non-regular entry `{}`",
                child.display()
            )));
        }
    }
    Ok(())
}

fn tree_fingerprint(root: &Path, relative: &str) -> Result<String, Phase7Error> {
    let normalized = validate_relative_path(relative)?;
    let mut files = Vec::new();
    collect_regular_files(root, Path::new(&normalized), &mut files)?;
    files.sort();
    let mut hasher = Sha256::new();
    for path in files {
        hasher.update(path.to_string_lossy().replace('\\', "/").as_bytes());
        hasher.update([0]);
        hasher.update(fingerprint_regular_file(&root.join(&path))?.as_bytes());
        hasher.update([b'\n']);
    }
    Ok(hex_digest(&hasher.finalize()))
}

fn phase5_frozen_tree_fingerprint(root: &Path) -> Result<String, Phase7Error> {
    let mut files = Vec::new();
    collect_regular_files(root, Path::new("holdout/phase-5"), &mut files)?;
    files.retain(|path| {
        path != Path::new("holdout/phase-5/execution-ledger.jsonl")
            && !path.starts_with("holdout/phase-5/results")
    });
    files.sort();
    let mut hasher = Sha256::new();
    for path in files {
        hasher.update(path.to_string_lossy().replace('\\', "/").as_bytes());
        hasher.update([0]);
        hasher.update(fingerprint_regular_file(&root.join(&path))?.as_bytes());
        hasher.update([b'\n']);
    }
    Ok(hex_digest(&hasher.finalize()))
}

fn evaluator_fingerprints(
    root: &Path,
    files: &[&str],
) -> Result<BTreeMap<String, String>, Phase7Error> {
    files
        .iter()
        .map(|relative| {
            Ok((
                (*relative).to_owned(),
                fingerprint_regular_file(&safe_join(root, relative)?)?,
            ))
        })
        .collect()
}

fn historical_fingerprints(root: &Path) -> Result<BTreeMap<String, String>, Phase7Error> {
    HISTORICAL_ROOTS
        .into_iter()
        .map(|relative| Ok((relative.to_owned(), tree_fingerprint(root, relative)?)))
        .collect()
}

fn run_git(root: &Path, arguments: &[&str]) -> Result<Vec<u8>, Phase7Error> {
    let output = Command::new("git")
        .args(arguments)
        .current_dir(root)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| Phase7Error::Io {
            path: "git".to_owned(),
            detail: error.to_string(),
        })?;
    if !output.status.success() {
        return Err(Phase7Error::InvalidContract(format!(
            "Git prerequisite `{}` failed",
            arguments.join(" ")
        )));
    }
    Ok(output.stdout)
}

fn git_text(root: &Path, arguments: &[&str]) -> Result<String, Phase7Error> {
    String::from_utf8(run_git(root, arguments)?)
        .map(|value| value.trim().to_owned())
        .map_err(|_| Phase7Error::InvalidContract("Git returned non-UTF-8 output".to_owned()))
}

fn verify_git_contract(root: &Path) -> Result<Phase7GitContract, Phase7Error> {
    let main_commit = git_text(root, &["rev-parse", "main"])?;
    let head_commit = git_text(root, &["rev-parse", "HEAD"])?;
    let current_branch = git_text(root, &["branch", "--show-current"])?;
    if main_commit != PHASE7_GIT_BASE
        || head_commit != PHASE7_GIT_BASE
        || current_branch != PHASE7_BRANCH
    {
        return Err(Phase7Error::InvalidContract(
            "main, branch, or HEAD differs from the Phase 7 starting contract".to_owned(),
        ));
    }
    run_git(root, &["fsck", "--no-dangling"])?;
    let mut signatures = BTreeMap::new();
    let mut dco_signoffs = BTreeMap::new();
    for commit in [PHASE7_GIT_BASE, PHASE5_FREEZE_COMMIT] {
        run_git(root, &["verify-commit", commit])?;
        signatures.insert(commit.to_owned(), "valid".to_owned());
        let message = git_text(root, &["show", "-s", "--format=%B", commit])?;
        if !message
            .lines()
            .any(|line| line.starts_with("Signed-off-by: "))
        {
            return Err(Phase7Error::InvalidContract(format!(
                "commit `{commit}` lacks a DCO sign-off"
            )));
        }
        dco_signoffs.insert(commit.to_owned(), "valid".to_owned());
    }
    Ok(Phase7GitContract {
        main_commit,
        head_commit,
        current_branch,
        object_integrity: "passed".to_owned(),
        signatures,
        dco_signoffs,
    })
}

fn validate_timestamp(value: &str) -> Result<(), Phase7Error> {
    if value.len() != 20
        || value.as_bytes().get(4) != Some(&b'-')
        || value.as_bytes().get(7) != Some(&b'-')
        || value.as_bytes().get(10) != Some(&b'T')
        || value.as_bytes().get(13) != Some(&b':')
        || value.as_bytes().get(16) != Some(&b':')
        || !value.ends_with('Z')
        || value.bytes().enumerate().any(|(index, byte)| {
            !matches!(index, 4 | 7 | 10 | 13 | 16 | 19) && !byte.is_ascii_digit()
        })
    {
        return Err(Phase7Error::InvalidContract(
            "timestamp must be second-precision UTC RFC 3339".to_owned(),
        ));
    }
    Ok(())
}

fn parse_json<T: for<'de> Deserialize<'de>>(bytes: &[u8], label: &str) -> Result<T, Phase7Error> {
    serde_json::from_slice(bytes).map_err(|error| {
        Phase7Error::InvalidContract(format!("{label} JSON is invalid at line {}", error.line()))
    })
}

fn phase5_genesis_hash(entry: &Phase5LedgerEntry) -> Result<String, Phase7Error> {
    let mut projected = entry.clone();
    projected.entry_hash.clear();
    let bytes = serde_json::to_vec(&projected).map_err(|_| Phase7Error::Serialization)?;
    Ok(fingerprint(&bytes))
}

fn phase7_ledger_entry_hash(entry: &Phase7LedgerEntry) -> Result<String, Phase7Error> {
    let mut projected = entry.clone();
    projected.entry_hash.clear();
    let bytes = serde_json::to_vec(&projected).map_err(|_| Phase7Error::Serialization)?;
    Ok(fingerprint(&bytes))
}

/// Parses and validates the mixed Phase 5 genesis and Phase 7 append-only ledger.
///
/// # Errors
///
/// Returns an error when any ledger line is malformed, incorrectly chained, or violates the
/// Phase 7 lifecycle.
pub fn load_phase7_ledger(bytes: &[u8]) -> Result<Phase7Ledger, Phase7Error> {
    let values = serde_json::Deserializer::from_slice(bytes)
        .into_iter::<serde_json::Value>()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            Phase7Error::InvalidContract(format!(
                "append-only ledger JSON is invalid at line {}",
                error.line()
            ))
        })?;
    let Some(first) = values.first() else {
        return Err(Phase7Error::InvalidContract(
            "append-only ledger is empty".to_owned(),
        ));
    };
    let genesis: Phase5LedgerEntry = serde_json::from_value(first.clone()).map_err(|_| {
        Phase7Error::InvalidContract("ledger genesis has the wrong shape".to_owned())
    })?;
    crate::schema::validate_phase5_ledger_entry(&genesis)
        .map_err(|error| Phase7Error::InvalidContract(error.to_string()))?;
    if genesis.sequence != 0
        || genesis.event != "holdout_frozen"
        || genesis.holdout_id != "phase-5-orthogonal-holdout-v2"
        || genesis.manifest_sha256 != PHASE7_MANIFEST_SHA256
        || genesis.evidence_contract_sha256 != PHASE7_EVIDENCE_CONTRACT_SHA256
        || genesis.commitment_root != PHASE7_MERKLE_ROOT
        || genesis.previous_entry_hash != ZERO_HASH
        || genesis.entry_hash != phase5_genesis_hash(&genesis)?
    {
        return Err(Phase7Error::InvalidContract(
            "Phase 5 genesis ledger entry differs from its commitment".to_owned(),
        ));
    }
    let mut previous = genesis.entry_hash.clone();
    let mut entries = Vec::with_capacity(values.len().saturating_sub(1));
    for (offset, value) in values.into_iter().skip(1).enumerate() {
        let entry: Phase7LedgerEntry = serde_json::from_value(value).map_err(|_| {
            Phase7Error::InvalidContract("Phase 7 ledger entry has the wrong shape".to_owned())
        })?;
        crate::schema::validate_phase7_ledger_entry(&entry)
            .map_err(|error| Phase7Error::InvalidContract(error.to_string()))?;
        let sequence = u64::try_from(offset + 1).unwrap_or(u64::MAX);
        if entry.schema_version != PHASE7_LEDGER_SCHEMA_V1
            || entry.sequence != sequence
            || entry.holdout_id != genesis.holdout_id
            || entry.run_id != PHASE7_RUN_ID
            || entry.manifest_sha256 != PHASE7_MANIFEST_SHA256
            || entry.evidence_contract_sha256 != PHASE7_EVIDENCE_CONTRACT_SHA256
            || entry.commitment_root != PHASE7_MERKLE_ROOT
            || entry.binary_sha256 != PHASE7_BINARY_SHA256
            || entry.previous_entry_hash != previous
            || entry.entry_hash != phase7_ledger_entry_hash(&entry)?
        {
            return Err(Phase7Error::InvalidContract(
                "Phase 7 ledger sequence, chain, or commitment differs".to_owned(),
            ));
        }
        validate_timestamp(&entry.timestamp_utc)?;
        match entry.event {
            Phase7LedgerEvent::ExecutionStarted
                if entry.case_id.is_none()
                    && entry.case_status.is_none()
                    && entry.case_record_sha256.is_none()
                    && entry.report_sha256.is_none()
                    && entry.result_sha256.is_none()
                    && entry.failure_code.is_none() => {}
            Phase7LedgerEvent::CaseRecorded
                if entry.case_id.is_some()
                    && entry.case_status.is_some()
                    && entry.case_record_sha256.is_some()
                    && entry.result_sha256.is_none()
                    && entry.failure_code.is_none() => {}
            Phase7LedgerEvent::ExecutionCompleted
                if entry.case_id.is_none()
                    && entry.case_status.is_none()
                    && entry.case_record_sha256.is_none()
                    && entry.report_sha256.is_none()
                    && entry.result_sha256.is_some()
                    && entry.failure_code.is_none() => {}
            Phase7LedgerEvent::ExecutionFailed
                if entry.case_id.is_none()
                    && entry.case_status.is_none()
                    && entry.case_record_sha256.is_none()
                    && entry.report_sha256.is_none()
                    && entry.result_sha256.is_none()
                    && entry.failure_code.is_some() => {}
            _ => {
                return Err(Phase7Error::InvalidContract(
                    "Phase 7 ledger event fields are inconsistent".to_owned(),
                ));
            }
        }
        previous.clone_from(&entry.entry_hash);
        entries.push(entry);
    }
    validate_ledger_lifecycle(&entries)?;
    Ok(Phase7Ledger { genesis, entries })
}

fn validate_ledger_lifecycle(entries: &[Phase7LedgerEntry]) -> Result<(), Phase7Error> {
    if entries.is_empty() {
        return Ok(());
    }
    if entries[0].event != Phase7LedgerEvent::ExecutionStarted {
        return Err(Phase7Error::InvalidContract(
            "Phase 7 ledger does not begin with execution_started".to_owned(),
        ));
    }
    let terminal_positions = entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| {
            matches!(
                entry.event,
                Phase7LedgerEvent::ExecutionCompleted | Phase7LedgerEvent::ExecutionFailed
            )
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    let body_end = terminal_positions.first().copied().unwrap_or(entries.len());
    if terminal_positions.len() > 1
        || terminal_positions
            .first()
            .is_some_and(|index| *index + 1 != entries.len())
        || entries[1..body_end]
            .iter()
            .any(|entry| entry.event != Phase7LedgerEvent::CaseRecorded)
    {
        return Err(Phase7Error::InvalidContract(
            "Phase 7 ledger lifecycle ordering is invalid".to_owned(),
        ));
    }
    let mut cases = BTreeSet::new();
    for entry in entries
        .iter()
        .filter(|entry| entry.event == Phase7LedgerEvent::CaseRecorded)
    {
        if !cases.insert(entry.case_id.as_deref().unwrap_or_default()) {
            return Err(Phase7Error::InvalidContract(
                "Phase 7 ledger records a case more than once".to_owned(),
            ));
        }
    }
    Ok(())
}

fn new_ledger_entry(
    ledger: &Phase7Ledger,
    event: Phase7LedgerEvent,
    case: Option<&Phase7CaseRun>,
    result_sha256: Option<&str>,
    failure_code: Option<&str>,
) -> Result<Phase7LedgerEntry, Phase7Error> {
    let previous_entry_hash = ledger.entries.last().map_or_else(
        || ledger.genesis.entry_hash.clone(),
        |entry| entry.entry_hash.clone(),
    );
    let mut entry = Phase7LedgerEntry {
        schema_version: PHASE7_LEDGER_SCHEMA_V1.to_owned(),
        sequence: u64::try_from(ledger.entries.len() + 1).unwrap_or(u64::MAX),
        event,
        holdout_id: ledger.genesis.holdout_id.clone(),
        run_id: PHASE7_RUN_ID.to_owned(),
        manifest_sha256: PHASE7_MANIFEST_SHA256.to_owned(),
        evidence_contract_sha256: PHASE7_EVIDENCE_CONTRACT_SHA256.to_owned(),
        commitment_root: PHASE7_MERKLE_ROOT.to_owned(),
        binary_sha256: PHASE7_BINARY_SHA256.to_owned(),
        previous_entry_hash,
        timestamp_utc: rfc3339_now(),
        case_id: case.map(|case| case.execution.case_id.clone()),
        case_status: case.map(|case| case.execution.status),
        case_record_sha256: case
            .map(canonical_phase7_json)
            .transpose()?
            .map(|bytes| fingerprint(&bytes)),
        report_sha256: case.and_then(|case| case.execution.report_fingerprint.clone()),
        result_sha256: result_sha256.map(str::to_owned),
        failure_code: failure_code.map(str::to_owned),
        entry_hash: String::new(),
    };
    entry.entry_hash = phase7_ledger_entry_hash(&entry)?;
    Ok(entry)
}

fn ledger_line(entry: &Phase7LedgerEntry) -> Result<Vec<u8>, Phase7Error> {
    let mut bytes = serde_json::to_vec(entry).map_err(|_| Phase7Error::Serialization)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn append_ledger_entry(path: &Path, entry: &Phase7LedgerEntry) -> Result<(), Phase7Error> {
    let bytes = ledger_line(entry)?;
    let mut file = OpenOptions::new()
        .append(true)
        .open(path)
        .map_err(|error| Phase7Error::Io {
            path: path.display().to_string(),
            detail: error.to_string(),
        })?;
    file.write_all(&bytes).map_err(|error| Phase7Error::Io {
        path: path.display().to_string(),
        detail: error.to_string(),
    })?;
    file.sync_all().map_err(|error| Phase7Error::Io {
        path: path.display().to_string(),
        detail: error.to_string(),
    })
}

fn integration_wrapper_drift(
    root: &Path,
    frozen: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, Phase7EvaluatorDrift>, Phase7Error> {
    let mut drift = BTreeMap::new();
    for (relative, frozen_sha256) in frozen {
        let current_sha256 = fingerprint_regular_file(&safe_join(root, relative)?)?;
        if current_sha256 != *frozen_sha256 {
            drift.insert(
                relative.clone(),
                Phase7EvaluatorDrift {
                    frozen_sha256: frozen_sha256.clone(),
                    current_sha256,
                    classification: "integration-wrapper-only-non-scoring".to_owned(),
                },
            );
        }
    }
    let expected = BTreeSet::from([
        "apps/secure-bench-cli/src/main.rs".to_owned(),
        "crates/secure-bench-core/src/lib.rs".to_owned(),
        "crates/secure-bench-core/src/schema.rs".to_owned(),
    ]);
    if drift.keys().cloned().collect::<BTreeSet<_>>() != expected {
        return Err(Phase7Error::InvalidContract(
            "Phase 5 evaluator drift is not limited to the three integration wrappers".to_owned(),
        ));
    }
    Ok(drift)
}

/// Produces the scanner-free Phase 7 pre-execution contract.
///
/// # Errors
///
/// Returns an error when a frozen prerequisite, executable, repository state, environment
/// property, or historical-integrity commitment differs from the Phase 7 contract.
#[allow(clippy::too_many_lines)]
pub fn prepare_phase7(
    request: &Phase7PrepareRequest<'_>,
) -> Result<Phase7PreExecutionContract, Phase7Error> {
    validate_timestamp(request.frozen_at_utc)?;
    if fs::symlink_metadata(request.run_directory).is_ok()
        || fs::symlink_metadata(request.artifacts_path).is_ok()
        || fs::symlink_metadata(request.result_path).is_ok()
    {
        return Err(Phase7Error::InvalidContract(
            "a prior Phase 7 execution artifact already exists".to_owned(),
        ));
    }
    if fingerprint(request.manifest) != PHASE7_MANIFEST_SHA256
        || fingerprint(request.evidence_contract) != PHASE7_EVIDENCE_CONTRACT_SHA256
        || fingerprint(request.taxonomy) != TAXONOMY_SHA256
        || fingerprint(request.ledger) != PHASE7_GENESIS_LEDGER_SHA256
    {
        return Err(Phase7Error::InvalidContract(
            "a frozen Phase 5 artifact differs from the Phase 7 contract".to_owned(),
        ));
    }
    let manifest: Phase5Manifest = parse_json(request.manifest, "Phase 5 manifest")?;
    let evidence_contract: EvidenceContractV2 =
        parse_json(request.evidence_contract, "evidence contract v2")?;
    let taxonomy = load_taxonomy(request.taxonomy)
        .map_err(|error| Phase7Error::InvalidContract(error.to_string()))?;
    crate::schema::validate_phase5_manifest(&manifest)
        .map_err(|error| Phase7Error::InvalidContract(error.to_string()))?;
    crate::schema::validate_evidence_contract_v2(&evidence_contract)
        .map_err(|error| Phase7Error::InvalidContract(error.to_string()))?;
    let ledger = load_phase7_ledger(request.ledger)?;
    if !ledger.entries.is_empty()
        || manifest.pairs.len() != EXPECTED_PAIRS
        || flatten_cases(&manifest).len() != EXPECTED_CASES
        || manifest.commitments.aggregate_corpus_sha256 != PHASE7_CORPUS_SHA256
        || manifest.commitments.contract_merkle_root != PHASE7_MERKLE_ROOT
        || manifest.commitments.evaluator_sha256 != PHASE7_FROZEN_EVALUATOR_SHA256
        || manifest.protocol.evaluation_state != "not_executed"
    {
        return Err(Phase7Error::InvalidContract(
            "the holdout is not frozen, complete, and genesis-only".to_owned(),
        ));
    }
    let projection_validation = validate_phase5(request.frozen_evaluator_root, request.taxonomy)
        .map_err(|error| {
            Phase7Error::InvalidContract(format!("frozen evaluator projection failed: {error}"))
        })?;
    if projection_validation.cases != EXPECTED_CASES as u64
        || projection_validation.pairs != EXPECTED_PAIRS as u64
        || projection_validation.aggregate_corpus_sha256 != PHASE7_CORPUS_SHA256
        || projection_validation.contract_merkle_root != PHASE7_MERKLE_ROOT
        || projection_validation.evaluator_sha256 != PHASE7_FROZEN_EVALUATOR_SHA256
    {
        return Err(Phase7Error::InvalidContract(
            "frozen evaluator projection returned different commitments".to_owned(),
        ));
    }
    let index_bytes = read_file(
        &request
            .frozen_evaluator_root
            .join("holdout/phase-5/commitments.json"),
    )?;
    let index: Phase5CommitmentIndex = parse_json(&index_bytes, "Phase 5 commitment index")?;
    if index.evaluator_sha256 != PHASE7_FROZEN_EVALUATOR_SHA256
        || index.manifest_sha256 != PHASE7_MANIFEST_SHA256
        || index.evidence_contract_sha256 != PHASE7_EVIDENCE_CONTRACT_SHA256
        || index.genesis_ledger_sha256 != PHASE7_GENESIS_LEDGER_SHA256
    {
        return Err(Phase7Error::InvalidContract(
            "frozen evaluator index differs".to_owned(),
        ));
    }
    let current_phase5_tree = phase5_frozen_tree_fingerprint(request.repository_root)?;
    let projection_phase5_tree = phase5_frozen_tree_fingerprint(request.frozen_evaluator_root)?;
    if current_phase5_tree != projection_phase5_tree {
        return Err(Phase7Error::InvalidContract(
            "current Phase 5 frozen tree differs from its Git projection".to_owned(),
        ));
    }
    let binary_sha256 = fingerprint_regular_file(request.binary)?;
    let source_rpm_sha256 = fingerprint_regular_file(request.source_rpm)?;
    if binary_sha256 != PHASE7_BINARY_SHA256 || source_rpm_sha256 != PHASE7_RPM_SHA256 {
        return Err(Phase7Error::InvalidContract(
            "external binary or source RPM differs from the user contract".to_owned(),
        ));
    }
    let benchmark_binary_sha256 = fingerprint_regular_file(request.benchmark_binary)?;
    let bwrap_sha256 = fingerprint_regular_file(Path::new("/usr/bin/bwrap"))?;
    let host = host_provenance();
    let kernel_release = host.kernel_release.ok_or_else(|| {
        Phase7Error::InvalidContract("kernel release provenance is unavailable".to_owned())
    })?;
    let phase7_evaluator_files =
        evaluator_fingerprints(request.repository_root, &PHASE7_EVALUATOR_FILES)?;
    let historical_artifacts = historical_fingerprints(request.repository_root)?;
    let git = verify_git_contract(request.repository_root)?;
    let contract = Phase7PreExecutionContract {
        schema_version: PHASE7_PRE_EXECUTION_SCHEMA_V1.to_owned(),
        frozen_at_utc: request.frozen_at_utc.to_owned(),
        git_base: PHASE7_GIT_BASE.to_owned(),
        branch: PHASE7_BRANCH.to_owned(),
        run_id: PHASE7_RUN_ID.to_owned(),
        git,
        scanner: Phase7ScannerContract {
            declared_version: "Secure Engine 0.1.3 (user-supplied artifact identity)".to_owned(),
            binary_sha256,
            source_rpm_sha256,
            command_template: argument_template(),
            report_schema: "secure-json-v1".to_owned(),
            configuration_sha256: EMPTY_SHA256.to_owned(),
            ai_validation: "disabled-without-provider-credentials-endpoints-or-commands".to_owned(),
            version_probe: "not-executed".to_owned(),
            environment_clear: true,
        },
        holdout: Phase7HoldoutContract {
            holdout_id: manifest.holdout_id,
            manifest_sha256: PHASE7_MANIFEST_SHA256.to_owned(),
            evidence_contract_sha256: PHASE7_EVIDENCE_CONTRACT_SHA256.to_owned(),
            ledger_before_sha256: PHASE7_GENESIS_LEDGER_SHA256.to_owned(),
            aggregate_corpus_sha256: PHASE7_CORPUS_SHA256.to_owned(),
            contract_merkle_root: PHASE7_MERKLE_ROOT.to_owned(),
            taxonomy_artifact_sha256: TAXONOMY_SHA256.to_owned(),
            taxonomy_content_hash: taxonomy.content_hash,
            pairs: EXPECTED_PAIRS as u64,
            cases: EXPECTED_CASES as u64,
            vulnerable_cases: 56,
            safe_controls: 56,
            frozen_tree_sha256: current_phase5_tree,
            prior_execution: "absent".to_owned(),
        },
        frozen_evaluator: Phase7FrozenEvaluatorContract {
            source_commit: PHASE5_FREEZE_COMMIT.to_owned(),
            evaluator_sha256: PHASE7_FROZEN_EVALUATOR_SHA256.to_owned(),
            integration_wrapper_drift: integration_wrapper_drift(
                request.repository_root,
                &index.evaluator_files,
            )?,
            files: index.evaluator_files,
            projection_validation: "passed-112-cases-and-synthetic-contract-vectors".to_owned(),
        },
        resources: Phase7ResourceContract {
            timeout_ms: CASE_TIMEOUT_MS,
            memory_bytes: CASE_MEMORY_BYTES,
            output_bytes: CASE_OUTPUT_BYTES,
            network: "blocked".to_owned(),
            namespace_scope: "fresh-bwrap-unshare-net-per-scanner-process".to_owned(),
        },
        environment: Phase7EnvironmentContract {
            os: std::env::consts::OS.to_owned(),
            architecture: std::env::consts::ARCH.to_owned(),
            kernel_release,
            rust_toolchain: env!("CARGO_PKG_RUST_VERSION").to_owned(),
            bwrap_sha256,
            isolation: "bubblewrap-minimal-read-only-runtime-unshare-net".to_owned(),
            expected_interfaces: vec!["lo".to_owned()],
            probe_target: PROBE_TARGET.to_owned(),
        },
        benchmark_binary_sha256,
        phase7_evaluator_files,
        historical_artifacts,
    };
    validate_pre_execution_semantics(&contract)?;
    crate::schema::validate_phase7_pre_execution(&contract)
        .map_err(|error| Phase7Error::InvalidContract(error.to_string()))?;
    Ok(contract)
}

/// Loads canonical Phase 7 pre-execution contract bytes.
///
/// # Errors
///
/// Returns an error when the document is malformed, non-canonical, or semantically inconsistent.
pub fn load_phase7_pre_execution(bytes: &[u8]) -> Result<Phase7PreExecutionContract, Phase7Error> {
    let contract: Phase7PreExecutionContract = parse_json(bytes, "Phase 7 pre-execution contract")?;
    crate::schema::validate_phase7_pre_execution(&contract)
        .map_err(|error| Phase7Error::InvalidContract(error.to_string()))?;
    if canonical_phase7_json(&contract)? != bytes {
        return Err(Phase7Error::InvalidContract(
            "pre-execution contract is not canonical JSON".to_owned(),
        ));
    }
    validate_pre_execution_semantics(&contract)?;
    Ok(contract)
}

fn validate_pre_execution_semantics(
    contract: &Phase7PreExecutionContract,
) -> Result<(), Phase7Error> {
    if contract.schema_version != PHASE7_PRE_EXECUTION_SCHEMA_V1
        || contract.git_base != PHASE7_GIT_BASE
        || contract.branch != PHASE7_BRANCH
        || contract.run_id != PHASE7_RUN_ID
        || contract.git.main_commit != PHASE7_GIT_BASE
        || contract.git.head_commit != PHASE7_GIT_BASE
        || contract.git.current_branch != PHASE7_BRANCH
        || contract.git.object_integrity != "passed"
        || contract.scanner.binary_sha256 != PHASE7_BINARY_SHA256
        || contract.scanner.source_rpm_sha256 != PHASE7_RPM_SHA256
        || contract.scanner.command_template != argument_template()
        || contract.scanner.report_schema != "secure-json-v1"
        || contract.scanner.configuration_sha256 != EMPTY_SHA256
        || !contract.scanner.ai_validation.starts_with("disabled")
        || contract.scanner.version_probe != "not-executed"
        || !contract.scanner.environment_clear
        || contract.holdout.manifest_sha256 != PHASE7_MANIFEST_SHA256
        || contract.holdout.evidence_contract_sha256 != PHASE7_EVIDENCE_CONTRACT_SHA256
        || contract.holdout.ledger_before_sha256 != PHASE7_GENESIS_LEDGER_SHA256
        || contract.holdout.aggregate_corpus_sha256 != PHASE7_CORPUS_SHA256
        || contract.holdout.contract_merkle_root != PHASE7_MERKLE_ROOT
        || contract.holdout.taxonomy_artifact_sha256 != TAXONOMY_SHA256
        || contract.holdout.pairs != EXPECTED_PAIRS as u64
        || contract.holdout.cases != EXPECTED_CASES as u64
        || contract.holdout.vulnerable_cases != 56
        || contract.holdout.safe_controls != 56
        || contract.holdout.prior_execution != "absent"
        || contract.frozen_evaluator.source_commit != PHASE5_FREEZE_COMMIT
        || contract.frozen_evaluator.evaluator_sha256 != PHASE7_FROZEN_EVALUATOR_SHA256
        || contract.resources.timeout_ms != CASE_TIMEOUT_MS
        || contract.resources.memory_bytes != CASE_MEMORY_BYTES
        || contract.resources.output_bytes != CASE_OUTPUT_BYTES
        || contract.resources.network != "blocked"
        || contract.resources.namespace_scope != "fresh-bwrap-unshare-net-per-scanner-process"
        || contract.environment.expected_interfaces != vec!["lo".to_owned()]
        || contract.environment.probe_target != PROBE_TARGET
        || contract.phase7_evaluator_files.len() != PHASE7_EVALUATOR_FILES.len()
        || contract
            .phase7_evaluator_files
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            != PHASE7_EVALUATOR_FILES.into_iter().collect::<BTreeSet<_>>()
        || contract.historical_artifacts.len() != HISTORICAL_ROOTS.len()
    {
        return Err(Phase7Error::InvalidContract(
            "pre-execution semantics differ from the one-shot Phase 7 policy".to_owned(),
        ));
    }
    validate_timestamp(&contract.frozen_at_utc)
}

fn attest_fresh_network_namespace() -> Result<Phase7IsolationAttestation, Phase7Error> {
    let devices = fs::read_to_string("/proc/net/dev").map_err(|error| Phase7Error::Io {
        path: "/proc/net/dev".to_owned(),
        detail: error.to_string(),
    })?;
    let mut interfaces = devices
        .lines()
        .skip(2)
        .filter_map(|line| line.split_once(':').map(|(name, _)| name.trim().to_owned()))
        .collect::<Vec<_>>();
    interfaces.sort();
    interfaces.dedup();
    if interfaces != vec!["lo".to_owned()] {
        return Err(Phase7Error::InvalidContract(
            "fresh scanner namespace exposes an unexpected interface".to_owned(),
        ));
    }
    let target: SocketAddr = PROBE_TARGET.parse().map_err(|_| {
        Phase7Error::InvalidContract("isolation probe target is invalid".to_owned())
    })?;
    match TcpStream::connect_timeout(&target, Duration::from_millis(250)) {
        Err(error) if error.kind() == std::io::ErrorKind::NetworkUnreachable => {}
        Ok(_) => {
            return Err(Phase7Error::InvalidContract(
                "network isolation failed: outbound connection succeeded".to_owned(),
            ));
        }
        Err(error) => {
            return Err(Phase7Error::InvalidContract(format!(
                "network isolation did not fail closed as unreachable: {error}"
            )));
        }
    }
    Ok(Phase7IsolationAttestation {
        mechanism: "bubblewrap-minimal-read-only-runtime-unshare-net".to_owned(),
        namespace_scope: "fresh-bwrap-unshare-net-per-scanner-process".to_owned(),
        interfaces,
        outbound_connectivity: "blocked".to_owned(),
        probe_target: PROBE_TARGET.to_owned(),
        scanner_invoked_after_probe: true,
    })
}

/// Internal entry point that attests a fresh namespace and then replaces itself with the scanner.
///
/// This is invoked only inside the minimal Bubblewrap filesystem assembled by the Phase 7 runner.
/// It writes the isolation proof before executing the fixed scanner path and fixed argument array.
///
/// # Errors
///
/// Returns an error when isolation cannot be attested, the proof cannot be written, or the scanner
/// process cannot replace this helper.
#[cfg(unix)]
pub fn phase7_isolated_exec() -> Result<(), Phase7Error> {
    use std::os::unix::process::CommandExt;

    let attestation = attest_fresh_network_namespace()?;
    atomic_write(
        Path::new(ISOLATION_PATH),
        &canonical_phase7_json(&attestation)?,
    )?;
    let error = Command::new("/scanner")
        .args([
            "scan",
            ".",
            "--format",
            "secure-json-v1",
            "--output",
            REPORT_PATH,
        ])
        .current_dir("/fixture")
        .env_clear()
        .env("LC_ALL", "C")
        .env("TZ", "UTC")
        .env("NO_COLOR", "1")
        .env("TMPDIR", "/tmp")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .exec();
    Err(Phase7Error::Io {
        path: "/scanner".to_owned(),
        detail: error.to_string(),
    })
}

/// Non-Unix platforms cannot satisfy the Phase 7 namespace contract.
#[cfg(not(unix))]
pub fn phase7_isolated_exec() -> Result<(), Phase7Error> {
    Err(Phase7Error::InvalidContract(
        "Phase 7 requires Unix process replacement and Linux namespaces".to_owned(),
    ))
}

fn contains_private_path(bytes: &[u8]) -> bool {
    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    text.contains("/home/")
        || text.contains("/users/")
        || text.contains("\\users\\")
        || text.contains("c:\\")
}

fn validate_isolation_attestation(
    bytes: &[u8],
    contract: &Phase7PreExecutionContract,
) -> Result<Phase7IsolationAttestation, Phase7Error> {
    let attestation: Phase7IsolationAttestation = parse_json(bytes, "case isolation attestation")?;
    if canonical_phase7_json(&attestation)? != bytes
        || attestation.mechanism != contract.environment.isolation
        || attestation.namespace_scope != contract.resources.namespace_scope
        || attestation.interfaces != contract.environment.expected_interfaces
        || attestation.outbound_connectivity != "blocked"
        || attestation.probe_target != contract.environment.probe_target
        || !attestation.scanner_invoked_after_probe
    {
        return Err(Phase7Error::InvalidContract(
            "per-case isolation attestation differs from the pre-execution contract".to_owned(),
        ));
    }
    Ok(attestation)
}

fn bwrap_arguments(scanner: &Path, benchmark: &Path, fixture: &Path, output: &Path) -> Vec<String> {
    [
        "--unshare-net".to_owned(),
        "--die-with-parent".to_owned(),
        "--new-session".to_owned(),
        "--ro-bind".to_owned(),
        "/usr".to_owned(),
        "/usr".to_owned(),
        "--symlink".to_owned(),
        "usr/lib".to_owned(),
        "/lib".to_owned(),
        "--symlink".to_owned(),
        "usr/lib64".to_owned(),
        "/lib64".to_owned(),
        "--symlink".to_owned(),
        "usr/bin".to_owned(),
        "/bin".to_owned(),
        "--proc".to_owned(),
        "/proc".to_owned(),
        "--dev".to_owned(),
        "/dev".to_owned(),
        "--tmpfs".to_owned(),
        "/tmp".to_owned(),
        "--ro-bind".to_owned(),
        benchmark.display().to_string(),
        "/secure-bench".to_owned(),
        "--ro-bind".to_owned(),
        scanner.display().to_string(),
        "/scanner".to_owned(),
        "--ro-bind".to_owned(),
        fixture.display().to_string(),
        "/fixture".to_owned(),
        "--bind".to_owned(),
        output.display().to_string(),
        "/output".to_owned(),
        "--chdir".to_owned(),
        "/fixture".to_owned(),
        "--setenv".to_owned(),
        "LC_ALL".to_owned(),
        "C".to_owned(),
        "--setenv".to_owned(),
        "TZ".to_owned(),
        "UTC".to_owned(),
        "--setenv".to_owned(),
        "NO_COLOR".to_owned(),
        "1".to_owned(),
        "--setenv".to_owned(),
        "TMPDIR".to_owned(),
        "/tmp".to_owned(),
        "/secure-bench".to_owned(),
        "phase7-isolated-exec".to_owned(),
    ]
    .to_vec()
}

#[allow(clippy::too_many_lines)]
fn run_phase7_case(
    request: &Phase7ExecutionRequest<'_>,
    contract: &Phase7PreExecutionContract,
    case: &Phase5Case,
    scanner: &Path,
    benchmark: &Path,
    reports_directory: &Path,
) -> Result<Phase7CaseRun, Phase7Error> {
    if request.cancellation.load(Ordering::SeqCst) {
        return Err(Phase7Error::InvalidContract(
            "execution was cancelled after one-shot reservation".to_owned(),
        ));
    }
    let workspace = Builder::new()
        .prefix("secure-bench-phase7-")
        .tempdir()
        .map_err(|error| Phase7Error::Io {
            path: "temporary Phase 7 workspace".to_owned(),
            detail: error.to_string(),
        })?;
    let scanner_root = workspace.path().join("fixture");
    let output_root = workspace.path().join("output");
    fs::create_dir(&scanner_root).map_err(|error| Phase7Error::Io {
        path: "temporary scanner fixture".to_owned(),
        detail: error.to_string(),
    })?;
    fs::create_dir(&output_root).map_err(|error| Phase7Error::Io {
        path: "temporary scanner output".to_owned(),
        detail: error.to_string(),
    })?;
    let fixture = safe_join(request.repository_root, &case.fixture_path)?;
    copy_fixture(&fixture, &scanner_root, &case.fixture_path)?;
    let bwrap = Path::new("/usr/bin/bwrap");
    let bwrap_args = bwrap_arguments(scanner, benchmark, &scanner_root, &output_root);
    let scanner_arguments = vec![
        "scan".to_owned(),
        ".".to_owned(),
        "--format".to_owned(),
        "secure-json-v1".to_owned(),
        "--output".to_owned(),
        REPORT_PATH.to_owned(),
    ];
    let started_unix_ms = unix_millis();
    let started = Instant::now();
    let process = execute_process(
        bwrap,
        &bwrap_args,
        workspace.path(),
        Duration::from_millis(contract.resources.timeout_ms),
        contract.resources.memory_bytes,
        &request.cancellation,
    )
    .map_err(|code| {
        Phase7Error::InvalidContract(format!(
            "fresh namespace infrastructure failed before case execution: {code}"
        ))
    })?;
    let finished_unix_ms = unix_millis();
    let duration_ms = millis_u64(started.elapsed());
    let isolation_bytes = read_file(&output_root.join("isolation.json")).map_err(|_| {
        Phase7Error::InvalidContract(
            "fresh namespace did not produce its pre-scanner isolation proof".to_owned(),
        )
    })?;
    let isolation = validate_isolation_attestation(&isolation_bytes, contract)?;
    let report_path = output_root.join("report.json");
    let relative_report = format!("reports/{}.json", case.case_id);
    let mut status = process.status;
    let mut error_code = process.error_code;
    let mut retained_report = None;
    let mut report_fingerprint = None;
    let mut output_bytes = None;
    if let Ok(metadata) = fs::symlink_metadata(&report_path) {
        output_bytes = Some(metadata.len());
        if metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.len() <= contract.resources.output_bytes
        {
            let bytes = read_file(&report_path)?;
            let digest = fingerprint(&bytes);
            atomic_write(
                &reports_directory.join(format!("{}.json", case.case_id)),
                &bytes,
            )?;
            retained_report = Some(relative_report);
            report_fingerprint = Some(digest.clone());
            if contains_private_path(&bytes) {
                status = LiveCaseStatus::InvalidOutput;
                error_code = Some("runner.privacy_unsafe_report".to_owned());
            } else if process.status == LiveCaseStatus::Success {
                let schema = serde_json::from_slice::<serde_json::Value>(&bytes)
                    .ok()
                    .and_then(|value| {
                        value
                            .get("schema_version")
                            .and_then(serde_json::Value::as_str)
                            .map(str::to_owned)
                    });
                if schema
                    .as_deref()
                    .is_some_and(|value| value != "secure-json-v1")
                {
                    status = LiveCaseStatus::UnsupportedSchema;
                    error_code = Some("runner.unsupported_schema".to_owned());
                } else if let Ok(findings) = adapt_report(&case.case_id, &bytes, &digest) {
                    status = if findings.is_empty() {
                        LiveCaseStatus::Success
                    } else {
                        LiveCaseStatus::Findings
                    };
                    error_code = None;
                } else {
                    status = LiveCaseStatus::InvalidOutput;
                    error_code = Some("runner.invalid_output".to_owned());
                }
            }
        } else if process.status == LiveCaseStatus::Success {
            status = LiveCaseStatus::InvalidOutput;
            error_code = Some("runner.oversized_or_unsafe_report".to_owned());
        }
    } else if process.status == LiveCaseStatus::Success {
        status = LiveCaseStatus::InvalidOutput;
        error_code = Some("runner.missing_report".to_owned());
    }
    Ok(Phase7CaseRun {
        execution: LiveCaseRun {
            case_id: case.case_id.clone(),
            fixture_fingerprint: case.fixture_sha256.clone(),
            status,
            arguments: scanner_arguments,
            report_path: retained_report,
            report_fingerprint,
            started_unix_ms,
            finished_unix_ms,
            duration_ms,
            process_exit_code: process.exit_code,
            peak_memory_bytes: process.peak_memory_bytes,
            output_bytes,
            stdout: process.stdout,
            stderr: process.stderr,
            error_code,
        },
        isolation: Some(isolation),
    })
}

fn append_case_journal(path: &Path, case: &Phase7CaseRun) -> Result<(), Phase7Error> {
    let mut bytes = serde_json::to_vec(case).map_err(|_| Phase7Error::Serialization)?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)
        .map_err(|error| Phase7Error::Io {
            path: path.display().to_string(),
            detail: error.to_string(),
        })?;
    file.write_all(&bytes).map_err(|error| Phase7Error::Io {
        path: path.display().to_string(),
        detail: error.to_string(),
    })?;
    file.sync_all().map_err(|error| Phase7Error::Io {
        path: path.display().to_string(),
        detail: error.to_string(),
    })
}

fn load_reports(
    run: &Phase7Run,
    run_directory: &Path,
) -> Result<BTreeMap<String, Vec<u8>>, Phase7Error> {
    let mut reports = BTreeMap::new();
    for case in &run.cases {
        if let Some(relative) = &case.execution.report_path {
            let expected = format!("reports/{}.json", case.execution.case_id);
            if relative != &expected {
                return Err(Phase7Error::InvalidContract(
                    "retained report path differs from the case identity".to_owned(),
                ));
            }
            let bytes = read_file(&safe_join(run_directory, relative)?)?;
            if case.execution.report_fingerprint.as_deref() != Some(fingerprint(&bytes).as_str()) {
                return Err(Phase7Error::InvalidContract(format!(
                    "retained report differs for `{}`",
                    case.execution.case_id
                )));
            }
            reports.insert(case.execution.case_id.clone(), bytes);
        }
    }
    Ok(reports)
}

fn validate_run_semantics(
    run: &Phase7Run,
    manifest: &Phase5Manifest,
    contract: &Phase7PreExecutionContract,
) -> Result<(), Phase7Error> {
    let expected_cases = flatten_cases(manifest);
    let actual_ids = run
        .cases
        .iter()
        .map(|case| case.execution.case_id.as_str())
        .collect::<Vec<_>>();
    let expected_ids = expected_cases
        .iter()
        .map(|(_, case)| case.case_id.as_str())
        .collect::<Vec<_>>();
    let executions = run
        .cases
        .iter()
        .map(|case| case.execution.clone())
        .collect::<Vec<_>>();
    if run.schema_version != PHASE7_RUN_SCHEMA_V1
        || run.run_id != PHASE7_RUN_ID
        || run.holdout_id != manifest.holdout_id
        || run.binary_sha256 != PHASE7_BINARY_SHA256
        || run.source_rpm_sha256 != PHASE7_RPM_SHA256
        || run.command_template != argument_template()
        || run.ai_validation != contract.scanner.ai_validation
        || run.version_probe_executed
        || run.pre_execution_contract_sha256.is_empty()
        || run.cases.len() != EXPECTED_CASES
        || actual_ids != expected_ids
        || run.started_unix_ms > run.finished_unix_ms
        || run.status != aggregate_status(&executions)
    {
        return Err(Phase7Error::InvalidContract(
            "retained run identities, ordering, or aggregate state differ".to_owned(),
        ));
    }
    for ((_, expected), actual) in expected_cases.iter().zip(&run.cases) {
        if actual.execution.fixture_fingerprint != expected.fixture_sha256
            || actual.execution.arguments
                != vec![
                    "scan".to_owned(),
                    ".".to_owned(),
                    "--format".to_owned(),
                    "secure-json-v1".to_owned(),
                    "--output".to_owned(),
                    REPORT_PATH.to_owned(),
                ]
            || actual.isolation.is_none()
        {
            return Err(Phase7Error::InvalidContract(format!(
                "retained case record differs for `{}`",
                expected.case_id
            )));
        }
    }
    Ok(())
}

fn validate_new_artifact_paths(request: &Phase7ExecutionRequest<'_>) -> Result<(), Phase7Error> {
    for path in [
        request.run_directory,
        request.result_path,
        request.artifacts_path,
    ] {
        if fs::symlink_metadata(path).is_ok() {
            return Err(Phase7Error::InvalidContract(format!(
                "create-new artifact `{}` already exists",
                path.display()
            )));
        }
    }
    for relative in [
        request.pre_execution_contract_path,
        request.run_path,
        request.result_path_relative,
        request.ledger_path_relative,
    ] {
        validate_relative_path(relative)?;
    }
    Ok(())
}

fn verify_execution_inputs(
    request: &Phase7ExecutionRequest<'_>,
    contract: &Phase7PreExecutionContract,
    ledger_bytes: &[u8],
) -> Result<
    (
        Phase5Manifest,
        EvidenceContractV2,
        FrozenTaxonomy,
        Phase7Ledger,
    ),
    Phase7Error,
> {
    let recomputed = prepare_phase7(&Phase7PrepareRequest {
        repository_root: request.repository_root,
        frozen_evaluator_root: request.frozen_evaluator_root,
        binary: request.binary,
        source_rpm: request.source_rpm,
        benchmark_binary: request.benchmark_binary,
        manifest: request.manifest,
        evidence_contract: request.evidence_contract,
        taxonomy: request.taxonomy,
        ledger: ledger_bytes,
        frozen_at_utc: &contract.frozen_at_utc,
        run_directory: request.run_directory,
        artifacts_path: request.artifacts_path,
        result_path: request.result_path,
    })?;
    if recomputed != *contract
        || fingerprint(request.pre_execution_contract)
            != fingerprint(&canonical_phase7_json(contract)?)
    {
        return Err(Phase7Error::InvalidContract(
            "pre-execution contract does not reproduce from current inputs".to_owned(),
        ));
    }
    let manifest: Phase5Manifest = parse_json(request.manifest, "Phase 5 manifest")?;
    let evidence_contract: EvidenceContractV2 =
        parse_json(request.evidence_contract, "evidence contract v2")?;
    let taxonomy = load_taxonomy(request.taxonomy)
        .map_err(|error| Phase7Error::InvalidContract(error.to_string()))?;
    let ledger = load_phase7_ledger(ledger_bytes)?;
    Ok((manifest, evidence_contract, taxonomy, ledger))
}

/// Executes the frozen holdout once after durably reserving the Phase 5 ledger.
///
/// # Errors
///
/// Returns an error when preflight reproduction fails, reservation cannot be made durable, an
/// infrastructure invariant fails closed, or final artifact construction cannot complete.
pub fn execute_phase7(
    request: &Phase7ExecutionRequest<'_>,
) -> Result<Phase7Artifacts, Phase7Error> {
    let contract = load_phase7_pre_execution(request.pre_execution_contract)?;
    let ledger_before = read_file(request.ledger_path)?;
    let (manifest, evidence_contract, taxonomy, mut ledger) =
        verify_execution_inputs(request, &contract, &ledger_before)?;
    validate_new_artifact_paths(request)?;
    let scanner = validate_binary(request.binary)?;
    let benchmark = validate_binary(request.benchmark_binary)?;
    if fingerprint_file(&scanner)? != PHASE7_BINARY_SHA256
        || fingerprint_file(&benchmark)? != contract.benchmark_binary_sha256
        || fingerprint_regular_file(Path::new("/usr/bin/bwrap"))?
            != contract.environment.bwrap_sha256
    {
        return Err(Phase7Error::InvalidContract(
            "an executable changed after preflight".to_owned(),
        ));
    }
    let started = new_ledger_entry(
        &ledger,
        Phase7LedgerEvent::ExecutionStarted,
        None,
        None,
        None,
    )?;
    append_ledger_entry(request.ledger_path, &started)?;
    ledger.entries.push(started);
    let readback = load_phase7_ledger(&read_file(request.ledger_path)?)?;
    if readback != ledger {
        return Err(Phase7Error::InvalidContract(
            "execution reservation ledger readback differs".to_owned(),
        ));
    }
    match execute_reserved(
        request,
        &contract,
        &manifest,
        &evidence_contract,
        &taxonomy,
        &mut ledger,
        &scanner,
        &benchmark,
    ) {
        Ok(artifacts) => Ok(artifacts),
        Err(error) => {
            if let Ok(current_bytes) = read_file(request.ledger_path)
                && let Ok(mut current) = load_phase7_ledger(&current_bytes)
                && !current.entries.last().is_some_and(|entry| {
                    matches!(
                        entry.event,
                        Phase7LedgerEvent::ExecutionCompleted | Phase7LedgerEvent::ExecutionFailed
                    )
                })
                && let Ok(failed) = new_ledger_entry(
                    &current,
                    Phase7LedgerEvent::ExecutionFailed,
                    None,
                    None,
                    Some("infrastructure-failure"),
                )
            {
                let _ = append_ledger_entry(request.ledger_path, &failed);
                current.entries.push(failed);
            }
            Err(error)
        }
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn execute_reserved(
    request: &Phase7ExecutionRequest<'_>,
    contract: &Phase7PreExecutionContract,
    manifest: &Phase5Manifest,
    evidence_contract: &EvidenceContractV2,
    taxonomy: &FrozenTaxonomy,
    ledger: &mut Phase7Ledger,
    scanner: &Path,
    benchmark: &Path,
) -> Result<Phase7Artifacts, Phase7Error> {
    fs::create_dir(request.run_directory).map_err(|error| Phase7Error::Io {
        path: request.run_directory.display().to_string(),
        detail: error.to_string(),
    })?;
    let reports_directory = request.run_directory.join("reports");
    fs::create_dir(&reports_directory).map_err(|error| Phase7Error::Io {
        path: reports_directory.display().to_string(),
        detail: error.to_string(),
    })?;
    let journal_path = request.run_directory.join("cases.jsonl");
    let run_started = unix_millis();
    let cases = flatten_cases(manifest);
    if cases.len() != EXPECTED_CASES {
        return Err(Phase7Error::InvalidContract(
            "holdout execution case count drifted".to_owned(),
        ));
    }
    let mut outcomes = Vec::with_capacity(EXPECTED_CASES);
    for (_, case) in cases {
        let outcome = run_phase7_case(
            request,
            contract,
            case,
            scanner,
            benchmark,
            &reports_directory,
        )?;
        append_case_journal(&journal_path, &outcome)?;
        let case_entry = new_ledger_entry(
            ledger,
            Phase7LedgerEvent::CaseRecorded,
            Some(&outcome),
            None,
            None,
        )?;
        append_ledger_entry(request.ledger_path, &case_entry)?;
        ledger.entries.push(case_entry);
        let readback = load_phase7_ledger(&read_file(request.ledger_path)?)?;
        if readback != *ledger {
            return Err(Phase7Error::InvalidContract(
                "per-case ledger readback differs from the appended chain".to_owned(),
            ));
        }
        let cancelled = outcome.execution.status == LiveCaseStatus::Cancelled;
        outcomes.push(outcome);
        if cancelled {
            return Err(Phase7Error::InvalidContract(
                "execution was cancelled after recording the affected case".to_owned(),
            ));
        }
    }
    let run_finished = unix_millis();
    let case_journal_sha256 = fingerprint(&read_file(&journal_path)?);
    let executions = outcomes
        .iter()
        .map(|case| case.execution.clone())
        .collect::<Vec<_>>();
    let run = Phase7Run {
        schema_version: PHASE7_RUN_SCHEMA_V1.to_owned(),
        run_id: PHASE7_RUN_ID.to_owned(),
        holdout_id: manifest.holdout_id.clone(),
        pre_execution_contract_sha256: fingerprint(request.pre_execution_contract),
        binary_sha256: PHASE7_BINARY_SHA256.to_owned(),
        source_rpm_sha256: PHASE7_RPM_SHA256.to_owned(),
        command_template: argument_template(),
        ai_validation: contract.scanner.ai_validation.clone(),
        version_probe_executed: false,
        host: host_provenance(),
        started_unix_ms: run_started,
        finished_unix_ms: run_finished,
        status: aggregate_status(&executions),
        case_journal_sha256: case_journal_sha256.clone(),
        cases: outcomes,
    };
    validate_run_semantics(&run, manifest, contract)?;
    crate::schema::validate_phase7_run(&run)
        .map_err(|error| Phase7Error::InvalidContract(error.to_string()))?;
    let run_bytes = canonical_phase7_json(&run)?;
    atomic_write(&request.run_directory.join("run.json"), &run_bytes)?;
    let reports = load_reports(&run, request.run_directory)?;
    let result = evaluate_phase7(
        manifest,
        evidence_contract,
        taxonomy,
        &run,
        &reports,
        contract,
        request.pre_execution_contract,
        &run_bytes,
        ledger,
    )?;
    crate::schema::validate_phase7_result(&result)
        .map_err(|error| Phase7Error::InvalidContract(error.to_string()))?;
    let result_bytes = canonical_phase7_json(&result)?;
    atomic_write(request.result_path, &result_bytes)?;
    let result_sha256 = fingerprint(&result_bytes);
    let completed = new_ledger_entry(
        ledger,
        Phase7LedgerEvent::ExecutionCompleted,
        None,
        Some(&result_sha256),
        None,
    )?;
    let mut predicted_ledger = read_file(request.ledger_path)?;
    predicted_ledger.extend_from_slice(&ledger_line(&completed)?);
    let reports_sha256 = report_aggregate(&run);
    let artifacts = Phase7Artifacts {
        schema_version: PHASE7_ARTIFACTS_SCHEMA_V1.to_owned(),
        run_id: PHASE7_RUN_ID.to_owned(),
        pre_execution_contract_path: request.pre_execution_contract_path.to_owned(),
        pre_execution_contract_sha256: fingerprint(request.pre_execution_contract),
        run_path: request.run_path.to_owned(),
        run_sha256: fingerprint(&run_bytes),
        result_path: request.result_path_relative.to_owned(),
        result_sha256,
        ledger_path: request.ledger_path_relative.to_owned(),
        ledger_sha256: fingerprint(&predicted_ledger),
        case_journal_sha256,
        reports_sha256,
        report_count: u64::try_from(reports.len()).unwrap_or(u64::MAX),
        ledger_entries: u64::try_from(ledger.entries.len() + 2).unwrap_or(u64::MAX),
    };
    crate::schema::validate_phase7_artifacts(&artifacts)
        .map_err(|error| Phase7Error::InvalidContract(error.to_string()))?;
    atomic_write(request.artifacts_path, &canonical_phase7_json(&artifacts)?)?;
    append_ledger_entry(request.ledger_path, &completed)?;
    ledger.entries.push(completed);
    let final_ledger = read_file(request.ledger_path)?;
    if final_ledger != predicted_ledger || load_phase7_ledger(&final_ledger)? != *ledger {
        return Err(Phase7Error::InvalidContract(
            "completed ledger differs from the predicted durable chain".to_owned(),
        ));
    }
    Ok(artifacts)
}

fn rfc3339_now() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let days = i64::try_from(seconds / 86_400).unwrap_or(i64::MAX);
    let seconds_of_day = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = seconds_of_day / 3_600;
    let minute = seconds_of_day % 3_600 / 60;
    let second = seconds_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn civil_from_days(days_since_epoch: i64) -> (i64, i64, i64) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year, month, day)
}

fn validate_post_execution_inputs(
    request: &Phase7VerificationRequest<'_>,
    contract: &Phase7PreExecutionContract,
) -> Result<(Phase5Manifest, EvidenceContractV2, FrozenTaxonomy), Phase7Error> {
    if fingerprint(request.manifest) != PHASE7_MANIFEST_SHA256
        || fingerprint(request.evidence_contract) != PHASE7_EVIDENCE_CONTRACT_SHA256
        || fingerprint(request.taxonomy) != TAXONOMY_SHA256
        || fingerprint_regular_file(request.binary)? != PHASE7_BINARY_SHA256
        || fingerprint_regular_file(request.source_rpm)? != PHASE7_RPM_SHA256
        || fingerprint_regular_file(request.benchmark_binary)? != contract.benchmark_binary_sha256
        || fingerprint_regular_file(Path::new("/usr/bin/bwrap"))?
            != contract.environment.bwrap_sha256
        || evaluator_fingerprints(request.repository_root, &PHASE7_EVALUATOR_FILES)?
            != contract.phase7_evaluator_files
        || historical_fingerprints(request.repository_root)? != contract.historical_artifacts
        || phase5_frozen_tree_fingerprint(request.repository_root)?
            != contract.holdout.frozen_tree_sha256
        || phase5_frozen_tree_fingerprint(request.frozen_evaluator_root)?
            != contract.holdout.frozen_tree_sha256
    {
        return Err(Phase7Error::InvalidContract(
            "a frozen executable, evaluator, holdout, or historical artifact drifted".to_owned(),
        ));
    }
    let validation = validate_phase5(request.frozen_evaluator_root, request.taxonomy)
        .map_err(|error| Phase7Error::InvalidContract(error.to_string()))?;
    if validation.cases != EXPECTED_CASES as u64
        || validation.aggregate_corpus_sha256 != PHASE7_CORPUS_SHA256
        || validation.contract_merkle_root != PHASE7_MERKLE_ROOT
        || validation.evaluator_sha256 != PHASE7_FROZEN_EVALUATOR_SHA256
    {
        return Err(Phase7Error::InvalidContract(
            "read-only frozen evaluator projection no longer validates".to_owned(),
        ));
    }
    let git = verify_git_contract(request.repository_root)?;
    if git != contract.git {
        return Err(Phase7Error::InvalidContract(
            "Git prerequisite attestation changed after execution".to_owned(),
        ));
    }
    let manifest: Phase5Manifest = parse_json(request.manifest, "Phase 5 manifest")?;
    let evidence_contract: EvidenceContractV2 =
        parse_json(request.evidence_contract, "evidence contract v2")?;
    let taxonomy = load_taxonomy(request.taxonomy)
        .map_err(|error| Phase7Error::InvalidContract(error.to_string()))?;
    Ok((manifest, evidence_contract, taxonomy))
}

fn load_canonical_run(bytes: &[u8]) -> Result<Phase7Run, Phase7Error> {
    let run: Phase7Run = parse_json(bytes, "Phase 7 run")?;
    crate::schema::validate_phase7_run(&run)
        .map_err(|error| Phase7Error::InvalidContract(error.to_string()))?;
    if canonical_phase7_json(&run)? != bytes {
        return Err(Phase7Error::InvalidContract(
            "Phase 7 run is not canonical JSON".to_owned(),
        ));
    }
    Ok(run)
}

fn load_canonical_result(bytes: &[u8]) -> Result<Phase7Result, Phase7Error> {
    let result: Phase7Result = parse_json(bytes, "Phase 7 result")?;
    crate::schema::validate_phase7_result(&result)
        .map_err(|error| Phase7Error::InvalidContract(error.to_string()))?;
    if canonical_phase7_json(&result)? != bytes {
        return Err(Phase7Error::InvalidContract(
            "Phase 7 result is not canonical JSON".to_owned(),
        ));
    }
    Ok(result)
}

fn load_canonical_artifacts(bytes: &[u8]) -> Result<Phase7Artifacts, Phase7Error> {
    let artifacts: Phase7Artifacts = parse_json(bytes, "Phase 7 artifact index")?;
    crate::schema::validate_phase7_artifacts(&artifacts)
        .map_err(|error| Phase7Error::InvalidContract(error.to_string()))?;
    if canonical_phase7_json(&artifacts)? != bytes {
        return Err(Phase7Error::InvalidContract(
            "Phase 7 artifact index is not canonical JSON".to_owned(),
        ));
    }
    Ok(artifacts)
}

fn load_case_journal(bytes: &[u8]) -> Result<Vec<Phase7CaseRun>, Phase7Error> {
    serde_json::Deserializer::from_slice(bytes)
        .into_iter::<Phase7CaseRun>()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            Phase7Error::InvalidContract(format!(
                "case journal JSON is invalid at line {}",
                error.line()
            ))
        })
}

fn validate_run_directory_shape(run: &Phase7Run, run_directory: &Path) -> Result<(), Phase7Error> {
    let mut expected = BTreeSet::from([PathBuf::from("cases.jsonl"), PathBuf::from("run.json")]);
    for case in &run.cases {
        if case.execution.report_path.is_some() {
            expected.insert(PathBuf::from(format!(
                "reports/{}.json",
                case.execution.case_id
            )));
        }
    }
    let mut actual = Vec::new();
    collect_regular_files(run_directory, Path::new("."), &mut actual)?;
    let actual = actual
        .into_iter()
        .filter(|path| path != Path::new("."))
        .map(|path| path.strip_prefix(".").unwrap_or(&path).to_path_buf())
        .collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(Phase7Error::InvalidContract(
            "retained run directory contains missing or unexpected files".to_owned(),
        ));
    }
    Ok(())
}

/// Verifies every Phase 7 artifact and ledger binding without starting a scanner.
///
/// # Errors
///
/// Returns an error when an artifact, report, ledger link, deterministic recomputation, privacy
/// condition, or historical-integrity commitment differs from the completed contract.
#[allow(clippy::too_many_lines)]
pub fn verify_phase7_artifacts(
    request: &Phase7VerificationRequest<'_>,
) -> Result<Phase7Artifacts, Phase7Error> {
    let contract = load_phase7_pre_execution(request.pre_execution_contract)?;
    let (manifest, evidence_contract, taxonomy) =
        validate_post_execution_inputs(request, &contract)?;
    let ledger = load_phase7_ledger(request.ledger)?;
    if ledger.entries.len() != EXPECTED_CASES + 2
        || ledger.entries.first().map(|entry| entry.event)
            != Some(Phase7LedgerEvent::ExecutionStarted)
        || ledger
            .entries
            .iter()
            .skip(1)
            .take(EXPECTED_CASES)
            .any(|entry| entry.event != Phase7LedgerEvent::CaseRecorded)
        || ledger.entries.last().map(|entry| entry.event)
            != Some(Phase7LedgerEvent::ExecutionCompleted)
    {
        return Err(Phase7Error::InvalidContract(
            "completed ledger does not contain one reservation, 112 outcomes, and one completion"
                .to_owned(),
        ));
    }
    let run = load_canonical_run(request.run)?;
    validate_run_semantics(&run, &manifest, &contract)?;
    if run.pre_execution_contract_sha256 != fingerprint(request.pre_execution_contract) {
        return Err(Phase7Error::InvalidContract(
            "run is not bound to the pre-execution contract".to_owned(),
        ));
    }
    let journal_bytes = read_file(&request.run_directory.join("cases.jsonl"))?;
    if fingerprint(&journal_bytes) != run.case_journal_sha256
        || load_case_journal(&journal_bytes)? != run.cases
    {
        return Err(Phase7Error::InvalidContract(
            "case journal differs from the retained run".to_owned(),
        ));
    }
    for (case, entry) in run.cases.iter().zip(ledger.entries.iter().skip(1)) {
        if entry.case_id.as_deref() != Some(case.execution.case_id.as_str())
            || entry.case_status != Some(case.execution.status)
            || entry.case_record_sha256.as_deref()
                != Some(fingerprint(&canonical_phase7_json(case)?).as_str())
            || entry.report_sha256 != case.execution.report_fingerprint
        {
            return Err(Phase7Error::InvalidContract(format!(
                "case ledger binding differs for `{}`",
                case.execution.case_id
            )));
        }
    }
    validate_run_directory_shape(&run, request.run_directory)?;
    let reports = load_reports(&run, request.run_directory)?;
    if reports.values().any(|report| contains_private_path(report)) {
        return Err(Phase7Error::InvalidContract(
            "a retained report contains a private absolute path".to_owned(),
        ));
    }
    let evaluation_ledger = Phase7Ledger {
        genesis: ledger.genesis.clone(),
        entries: ledger
            .entries
            .iter()
            .take(EXPECTED_CASES + 1)
            .cloned()
            .collect(),
    };
    let recomputed = evaluate_phase7(
        &manifest,
        &evidence_contract,
        &taxonomy,
        &run,
        &reports,
        &contract,
        request.pre_execution_contract,
        request.run,
        &evaluation_ledger,
    )?;
    let result = load_canonical_result(request.result)?;
    validate_result_semantics(&result, &manifest)?;
    if recomputed != result || canonical_phase7_json(&recomputed)? != request.result {
        return Err(Phase7Error::InvalidContract(
            "deterministic re-evaluation differs from the retained result".to_owned(),
        ));
    }
    let artifacts = load_canonical_artifacts(request.artifacts)?;
    let completed = ledger.entries.last().ok_or_else(|| {
        Phase7Error::InvalidContract("completed ledger has no terminal entry".to_owned())
    })?;
    if completed.result_sha256.as_deref() != Some(fingerprint(request.result).as_str())
        || artifacts.schema_version != PHASE7_ARTIFACTS_SCHEMA_V1
        || artifacts.run_id != PHASE7_RUN_ID
        || artifacts.pre_execution_contract_sha256 != fingerprint(request.pre_execution_contract)
        || artifacts.run_sha256 != fingerprint(request.run)
        || artifacts.result_sha256 != fingerprint(request.result)
        || artifacts.ledger_sha256 != fingerprint(request.ledger)
        || artifacts.case_journal_sha256 != run.case_journal_sha256
        || artifacts.reports_sha256 != report_aggregate(&run)
        || artifacts.report_count != u64::try_from(reports.len()).unwrap_or(u64::MAX)
        || artifacts.ledger_entries != 115
    {
        return Err(Phase7Error::InvalidContract(
            "artifact index or terminal ledger binding differs".to_owned(),
        ));
    }
    for path in [
        &artifacts.pre_execution_contract_path,
        &artifacts.run_path,
        &artifacts.result_path,
        &artifacts.ledger_path,
    ] {
        validate_relative_path(path)?;
    }
    if [
        request.pre_execution_contract,
        request.run,
        request.result,
        request.artifacts,
        request.ledger,
    ]
    .iter()
    .any(|bytes| contains_private_path(bytes))
    {
        return Err(Phase7Error::InvalidContract(
            "a public Phase 7 JSON artifact contains a private absolute path".to_owned(),
        ));
    }
    Ok(artifacts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expectation() -> EvidenceExpectationV2 {
        EvidenceExpectationV2 {
            expectation_id: "synthetic-expectation".to_owned(),
            taxonomy_version: "1.0.0".to_owned(),
            category_id: "secure-bench.category.synthetic".to_owned(),
            invariant_id: "secure-bench.invariant.synthetic".to_owned(),
            primary_cwe: "CWE-999".to_owned(),
            path: vec![
                EvidenceNodeV2 {
                    role: EvidenceRoleV2::Source,
                    effect: EvidenceEffectV2::PreservesInfluence,
                    source_kind: Some(SourceSemanticKind::HttpQueryValue),
                    sink_kind: None,
                    span: EvidenceSpanV2 {
                        file: "src/entry.ts".to_owned(),
                        start_line: 2,
                        start_column: 5,
                        end_line: 2,
                        end_column: 14,
                    },
                    summarizable: false,
                },
                EvidenceNodeV2 {
                    role: EvidenceRoleV2::Sink,
                    effect: EvidenceEffectV2::PreservesInfluence,
                    source_kind: None,
                    sink_kind: Some(SinkSemanticKind::OutboundRequest),
                    span: EvidenceSpanV2 {
                        file: "src/entry.ts".to_owned(),
                        start_line: 4,
                        start_column: 3,
                        end_line: 4,
                        end_column: 22,
                    },
                    summarizable: false,
                },
            ],
        }
    }

    fn report(source_identity: &str, certainty: &str, copies: usize) -> Vec<u8> {
        let finding = serde_json::json!({
            "rule_id": "neutral-rule",
            "taxonomy": {
                "taxonomy_version": "1.0.0",
                "category_id": "secure-bench.category.synthetic",
                "invariant_id": "secure-bench.invariant.synthetic"
            },
            "primary_cwe": { "id": "CWE-999" },
            "verification_state": "verified-deterministic-path",
            "evidence_path": [
                {
                    "edge_id_from_previous": null,
                    "kind": "source",
                    "semantic": {
                        "role": "untrusted-source",
                        "identity": source_identity,
                        "certainty": certainty
                    },
                    "location": {
                        "path": "src/entry.ts",
                        "span": {
                            "start_line": 2,
                            "start_column": 5,
                            "end_line": 2,
                            "end_column": 14
                        }
                    }
                },
                {
                    "edge_id_from_previous": "edge-1",
                    "kind": "sink",
                    "semantic": {
                        "role": "sensitive-sink",
                        "identity": "sink.outbound-request",
                        "certainty": "proven"
                    },
                    "location": {
                        "path": "src/entry.ts",
                        "span": {
                            "start_line": 4,
                            "start_column": 3,
                            "end_line": 4,
                            "end_column": 22
                        }
                    }
                }
            ]
        });
        let findings = std::iter::repeat_n(finding, copies).collect::<Vec<_>>();
        serde_json::to_vec(&serde_json::json!({
            "schema_version": "secure-json-v1",
            "scan": { "complete": true },
            "errors": [],
            "findings": findings
        }))
        .unwrap_or_default()
    }

    fn contract() -> Result<EvidenceContractV2, Phase7Error> {
        serde_json::from_slice(include_bytes!(
            "../../../holdout/phase-5/evidence-contract-v2.json"
        ))
        .map_err(|_| Phase7Error::Serialization)
    }

    #[test]
    fn strict_adapter_distinguishes_exact_partial_and_unmapped() -> Result<(), Phase7Error> {
        let expected = expectation();
        let exact_bytes = report("source.http-query-value", "proven", 1);
        let exact = adapt_report("synthetic-case", &exact_bytes, &fingerprint(&exact_bytes))?;
        assert_eq!(
            match_evidence_v2(&contract()?, &expected, &exact[0].canonical),
            EvidenceMatchV2::Exact
        );
        assert_eq!(criteria_for(&expected, &exact[0]).score(), 7);

        let partial_bytes = report("source.http-query-value", "possible", 1);
        let partial = adapt_report(
            "synthetic-case",
            &partial_bytes,
            &fingerprint(&partial_bytes),
        )?;
        assert_eq!(
            match_evidence_v2(&contract()?, &expected, &partial[0].canonical),
            EvidenceMatchV2::Partial
        );

        let unmapped_bytes = report("untrusted.request-value", "proven", 1);
        let unmapped = adapt_report(
            "synthetic-case",
            &unmapped_bytes,
            &fingerprint(&unmapped_bytes),
        )?;
        assert_eq!(
            unmapped[0].adapter_state,
            Phase7AdapterState::UnmappedSemantics
        );
        assert_eq!(
            match_evidence_v2(&contract()?, &expected, &unmapped[0].canonical),
            EvidenceMatchV2::NoMatch
        );
        Ok(())
    }

    #[test]
    fn duplicate_fingerprints_never_create_extra_semantic_credit() -> Result<(), Phase7Error> {
        let bytes = report("source.http-query-value", "proven", 2);
        let findings = adapt_report("synthetic-case", &bytes, &fingerprint(&bytes))?;
        assert_eq!(findings.len(), 2);
        assert_eq!(
            findings[0].semantic_fingerprint,
            findings[1].semantic_fingerprint
        );
        assert_ne!(findings[0].finding_id, findings[1].finding_id);
        Ok(())
    }

    #[test]
    fn missing_intermediate_semantics_remain_unmapped_without_repair() -> Result<(), Phase7Error> {
        let mut value: serde_json::Value =
            serde_json::from_slice(&report("source.http-query-value", "proven", 1))
                .map_err(|_| Phase7Error::Serialization)?;
        let finding = value["findings"][0].as_object_mut().ok_or_else(|| {
            Phase7Error::InvalidContract("synthetic finding is absent".to_owned())
        })?;
        let path = finding["evidence_path"]
            .as_array_mut()
            .ok_or_else(|| Phase7Error::InvalidContract("synthetic path is absent".to_owned()))?;
        path.insert(
            1,
            serde_json::json!({
                "edge_id_from_previous": "edge-intermediate",
                "kind": "function",
                "location": {
                    "path": "src/helper.ts",
                    "span": { "start_line": 1, "start_column": 1 }
                }
            }),
        );
        path[2]["edge_id_from_previous"] = serde_json::json!("edge-sink");
        let bytes = serde_json::to_vec(&value).map_err(|_| Phase7Error::Serialization)?;
        let findings = adapt_report("synthetic-case", &bytes, &fingerprint(&bytes))?;
        assert_eq!(
            findings[0].adapter_state,
            Phase7AdapterState::UnmappedSemantics
        );
        assert_eq!(findings[0].canonical.path.len(), 3);
        assert!(findings[0].canonical.uncertain);
        assert_eq!(
            match_evidence_v2(&contract()?, &expectation(), &findings[0].canonical),
            EvidenceMatchV2::Partial
        );
        Ok(())
    }

    #[test]
    fn mixed_generation_ledger_chains_without_rewriting_genesis() -> Result<(), Phase7Error> {
        let genesis = include_bytes!("../../../fixtures/projections/phase5-genesis-ledger.jsonl");
        let mut ledger = load_phase7_ledger(genesis)?;
        assert!(ledger.entries.is_empty());
        let started = new_ledger_entry(
            &ledger,
            Phase7LedgerEvent::ExecutionStarted,
            None,
            None,
            None,
        )?;
        let mut bytes = genesis.to_vec();
        bytes.extend_from_slice(&ledger_line(&started)?);
        ledger.entries.push(started);
        assert_eq!(load_phase7_ledger(&bytes)?, ledger);
        bytes[20] ^= 1;
        assert!(load_phase7_ledger(&bytes).is_err());
        Ok(())
    }

    #[test]
    fn unsafe_report_paths_fail_closed() {
        assert!(validate_relative_path("src/entry.ts").is_ok());
        assert!(validate_relative_path("../answers.json").is_err());
        assert!(validate_relative_path("/home/operator/fixture.ts").is_err());
        assert!(validate_relative_path("C:\\fixture.ts").is_err());
    }

    #[test]
    fn strict_metrics_preserve_every_balanced_and_crossed_stratum() -> Result<(), Phase7Error> {
        let manifest: Phase5Manifest =
            serde_json::from_slice(include_bytes!("../../../holdout/phase-5/manifest.json"))
                .map_err(|_| Phase7Error::Serialization)?;
        let decisions = flatten_cases(&manifest)
            .into_iter()
            .map(|(_, case)| {
                let vulnerable = case.kind == Phase5CaseKind::Vulnerable;
                Phase7CaseDecision {
                    case_id: case.case_id.clone(),
                    kind: if vulnerable {
                        CaseKind::Vulnerable
                    } else {
                        CaseKind::SafeControl
                    },
                    expectation_id: case
                        .expectation
                        .as_ref()
                        .map(|expectation| expectation.expectation_id.clone()),
                    outcome: if vulnerable {
                        Phase7Outcome::ExactDetection
                    } else {
                        Phase7Outcome::SafeControlClean
                    },
                    execution_status: if vulnerable {
                        LiveCaseStatus::Findings
                    } else {
                        LiveCaseStatus::Success
                    },
                    selected_finding_id: vulnerable.then(|| "synthetic-finding".to_owned()),
                    evidence_match: vulnerable.then_some(EvidenceMatchV2::Exact),
                    criteria: vulnerable.then_some(Phase7Criteria {
                        taxonomy: true,
                        category: true,
                        invariant: true,
                        cwe: true,
                        source: true,
                        sink: true,
                        evidence_path: true,
                    }),
                    distinct_findings: u64::from(vulnerable),
                    duplicate_findings: 0,
                    unrelated_findings: 0,
                }
            })
            .collect::<Vec<_>>();
        let metrics = metrics_from_decisions(&decisions, 56);
        assert_eq!(metrics.precision, ratio(56, 56));
        assert_eq!(metrics.recall, ratio(56, 56));
        assert_eq!(metrics.f1, ratio(112, 112));
        let breakdowns = build_breakdowns(&manifest, &decisions);
        assert_eq!(breakdowns.taxonomy_family.len(), 7);
        assert_eq!(breakdowns.framework.len(), 4);
        assert_eq!(breakdowns.language.len(), 2);
        assert_eq!(breakdowns.topology.len(), 4);
        assert_eq!(breakdowns.framework_language.len(), 8);
        assert_eq!(breakdowns.topology_language.len(), 8);
        assert_eq!(breakdowns.framework_topology.len(), 16);
        assert!(
            breakdowns
                .taxonomy_family
                .values()
                .all(|group| group.vulnerable == 8 && group.controls == 8)
        );
        assert!(
            breakdowns
                .framework_language
                .values()
                .all(|group| group.vulnerable == 7 && group.controls == 7)
        );
        assert!(
            breakdowns
                .topology_language
                .values()
                .all(|group| group.vulnerable == 7 && group.controls == 7)
        );
        Ok(())
    }
}
