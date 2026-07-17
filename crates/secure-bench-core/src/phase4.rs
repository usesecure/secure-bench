//! One-shot Phase 4 holdout execution, evaluation, provenance, and artifact contracts.

use crate::adapter::{Adapter, AdapterError, AdapterInput, SecureJsonAdapter, fingerprint};
use crate::holdout::{
    HoldoutFramework, HoldoutLanguage, HoldoutLedgerEntry, HoldoutManifest, HoldoutPair,
    HoldoutVariation, canonical_ledger_jsonl, execution_completed_ledger_entry,
    execution_failed_ledger_entry, execution_started_ledger_entry, load_holdout_manifest,
    validate_holdout_ledger,
};
use crate::model::{
    BenchmarkCase, BenchmarkSuite, CaseKind, Confidence, Eligibility, ExpectedFinding,
    HostProvenance, NetworkPolicy, RatioMetric, ResourceBudget, Severity, TaxonomyCoordinates,
};
use crate::phase2::{
    Phase2CaseDecision, Phase2FindingRecord, Phase2Metrics, Phase2Outcome,
    evaluate_taxonomy_snapshot,
};
use crate::runner::{
    LiveCaseRun, LiveCaseStatus, LiveRun, LiveRunStatus, LiveToolProvenance, RunnerError,
    VersionProbeStatus, aggregate_status, atomic_write, copy_fixture, empty_capture,
    execute_process, fingerprint_file, host_provenance, millis_u64, report_declares_completed_scan,
    unix_millis, validate_binary,
};
use crate::taxonomy::{FrozenTaxonomy, load_taxonomy};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};
use tempfile::Builder;
use thiserror::Error;

/// Phase 4 pre-execution contract schema.
pub const PHASE4_PRE_EXECUTION_SCHEMA_V1: &str = "secure-bench-phase4-pre-execution-v1";
/// Phase 4 retained run schema.
pub const PHASE4_RUN_SCHEMA_V1: &str = "secure-bench-phase4-run-v1";
/// Phase 4 deterministic result schema.
pub const PHASE4_RESULT_SCHEMA_V1: &str = "secure-bench-phase4-result-v1";
/// Phase 4 final artifact index schema.
pub const PHASE4_ARTIFACTS_SCHEMA_V1: &str = "secure-bench-phase4-artifacts-v1";

/// Sole permitted Phase 4 run identity.
pub const PHASE4_RUN_ID: &str = "secure-engine-0-1-2-holdout-once";
/// Exact external binary fingerprint supplied for Phase 4.
pub const PHASE4_BINARY_SHA256: &str =
    "20e941f2f4633f0d1a62bd57d61d6969f5d251568f7abaff5a7a0fc8d5b31055";
/// Exact source RPM fingerprint supplied for Phase 4.
pub const PHASE4_RPM_SHA256: &str =
    "8d6ed234ad87cd422a8c53de08117454423241972caa272a4bbb8bb7282c2276";
/// Exact frozen manifest fingerprint.
pub const PHASE4_MANIFEST_SHA256: &str =
    "a7a2e47fa85c5fcda305e2c193b91216fd9df1c28fd52dd0179b588f83790da2";
/// Exact genesis-only ledger fingerprint.
pub const PHASE4_LEDGER_BEFORE_SHA256: &str =
    "dd8ec1fee4c1f09f06df2c9ffa652563786669d5a670cd2124b644488bbed6ed";
/// Exact frozen aggregate corpus fingerprint.
pub const PHASE4_CORPUS_SHA256: &str =
    "28f4599c9711465a7cbbfe0ebc356e017a3bb6145bc77d57577b3b5d31790844";
/// Exact frozen contract Merkle root.
pub const PHASE4_MERKLE_ROOT: &str =
    "fcfbe4f8d5dc0fc871ce55c1eac3e3d2618bcc76261bfa16bd4b1f98833c96e5";
/// Main commit on which Phase 4 is based.
pub const PHASE4_GIT_BASE: &str = "74474708391b7913fa1ebe29ea8502e87ed11b0d";
/// Required Phase 4 branch.
pub const PHASE4_BRANCH: &str = "codex/phase-4-secure-engine-0-1-2-holdout";
/// Exact report command template.
pub const PHASE4_ARGUMENTS: [&str; 6] = [
    "scan",
    "{fixture}",
    "--format",
    "secure-json-v1",
    "--output",
    "{report}",
];

const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const CASE_TIMEOUT_MS: u64 = 60_000;
const CASE_MEMORY_BYTES: u64 = 1_073_741_824;
const CASE_OUTPUT_BYTES: u64 = 10 * 1024 * 1024;
const EXPECTED_CASES: usize = 56;
const EXPECTED_PAIRS: usize = 28;

/// Complete pre-execution contract frozen before the ledger reservation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase4PreExecutionContract {
    /// Contract schema identity.
    pub schema_version: String,
    /// UTC freeze time.
    pub frozen_at_utc: String,
    /// Exact immutable main commit.
    pub git_base: String,
    /// Dedicated evaluation branch.
    pub branch: String,
    /// Sole permitted run identity.
    pub run_id: String,
    /// External artifact and public command contract.
    pub scanner: Phase4ScannerContract,
    /// Frozen holdout commitments.
    pub holdout: Phase4HoldoutContract,
    /// Fixed per-case resource policy.
    pub resources: Phase4ResourceContract,
    /// Host and network-isolation prerequisites.
    pub environment: Phase4EnvironmentContract,
    /// SHA-256 of the release-mode benchmark executable used for the run.
    pub benchmark_binary_sha256: String,
    /// Source and schema files whose bytes define the frozen runner and evaluator.
    pub frozen_evaluator_files: BTreeMap<String, String>,
}

/// Scanner contract that contains no filesystem path or credential.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase4ScannerContract {
    /// User-declared public artifact identity; no version probe is executed.
    pub declared_version: String,
    /// Binary SHA-256.
    pub binary_sha256: String,
    /// Source RPM SHA-256.
    pub source_rpm_sha256: String,
    /// Exact portable argument template.
    pub command_template: Vec<String>,
    /// Requested public report schema.
    pub report_schema: String,
    /// Empty configuration fingerprint.
    pub configuration_sha256: String,
    /// AI validation state.
    pub ai_validation: String,
    /// Version-probe policy.
    pub version_probe: String,
    /// Environment is cleared before every scanner process.
    pub environment_clear: bool,
}

/// Frozen holdout hashes and counts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase4HoldoutContract {
    /// Holdout identity.
    pub holdout_id: String,
    /// Manifest SHA-256.
    pub manifest_sha256: String,
    /// Genesis-only ledger SHA-256.
    pub ledger_before_sha256: String,
    /// Aggregate scanner-visible corpus SHA-256.
    pub aggregate_corpus_sha256: String,
    /// Contract Merkle root.
    pub contract_merkle_root: String,
    /// Taxonomy artifact SHA-256.
    pub taxonomy_artifact_sha256: String,
    /// Taxonomy content hash.
    pub taxonomy_content_hash: String,
    /// Pair count.
    pub pairs: u64,
    /// Total case count.
    pub cases: u64,
}

/// Frozen resource limits applied independently to every case.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase4ResourceContract {
    /// Wall-clock timeout per scanner process.
    pub timeout_ms: u64,
    /// Maximum sampled direct-process resident memory.
    pub memory_bytes: u64,
    /// Maximum retained report size.
    pub output_bytes: u64,
    /// Network policy inherited from the outer namespace.
    pub network: String,
}

/// Sanitized pre-execution environment and isolation provenance.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase4EnvironmentContract {
    /// Operating-system family.
    pub os: String,
    /// CPU architecture.
    pub architecture: String,
    /// Kernel release.
    pub kernel_release: String,
    /// Workspace Rust minimum/toolchain contract.
    pub rust_toolchain: String,
    /// Isolation executable SHA-256.
    pub bwrap_sha256: String,
    /// Isolation mechanism.
    pub isolation: String,
    /// Required visible interfaces inside the scanner namespace.
    pub expected_interfaces: Vec<String>,
    /// Fixed outbound probe target.
    pub probe_target: String,
}

/// Runtime proof collected inside the scanner network namespace before reservation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase4IsolationAttestation {
    /// Isolation mechanism.
    pub mechanism: String,
    /// Interfaces visible inside the namespace.
    pub interfaces: Vec<String>,
    /// Outbound probe result.
    pub outbound_connectivity: String,
    /// Fixed probe target.
    pub probe_target: String,
}

/// Complete retained run manifest for the sole execution.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase4Run {
    /// Run schema identity.
    pub schema_version: String,
    /// Sole run identity.
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
    /// Explicit absence of a version probe.
    pub version_probe_executed: bool,
    /// Runtime isolation proof.
    pub isolation: Phase4IsolationAttestation,
    /// Sanitized host provenance.
    pub host: HostProvenance,
    /// Start time in Unix milliseconds.
    pub started_unix_ms: u64,
    /// Finish time in Unix milliseconds.
    pub finished_unix_ms: u64,
    /// Aggregate execution state.
    pub status: LiveRunStatus,
    /// SHA-256 of the append-only per-case execution journal.
    pub case_journal_sha256: String,
    /// One immutable outcome for every case.
    pub cases: Vec<LiveCaseRun>,
}

/// Counts and exact ratios for one declared breakdown group.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase4GroupMetrics {
    /// Vulnerable expectations in the group.
    pub vulnerable: u64,
    /// Exact canonical detections.
    pub exact: u64,
    /// Partial matches.
    pub partial: u64,
    /// Misses.
    pub missed: u64,
    /// Unsupported/out-of-scope cases.
    pub out_of_scope: u64,
    /// Operationally not-attempted vulnerable cases.
    pub not_attempted: u64,
    /// Safe controls in the group.
    pub controls: u64,
    /// Flagged safe controls.
    pub flagged_controls: u64,
    /// Clean safe controls.
    pub clean_controls: u64,
    /// Operationally unavailable safe controls.
    pub controls_not_attempted: u64,
    /// Distinct normalized findings.
    pub distinct_findings: u64,
    /// Duplicate normalized findings.
    pub duplicate_findings: u64,
    /// Exact precision within the group.
    pub precision: RatioMetric,
    /// Exact recall within the group.
    pub recall: RatioMetric,
    /// Exact F1 within the group.
    pub f1: RatioMetric,
}

/// Required aggregate result breakdowns.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase4Breakdowns {
    /// Results by frozen taxonomy family.
    pub taxonomy_family: BTreeMap<String, Phase4GroupMetrics>,
    /// Results by framework.
    pub framework: BTreeMap<String, Phase4GroupMetrics>,
    /// Results by source language.
    pub language: BTreeMap<String, Phase4GroupMetrics>,
    /// Results by flow topology.
    pub topology: BTreeMap<String, Phase4GroupMetrics>,
}

/// Process, output, and failure observations for the sole execution.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase4Measurement {
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
    /// Maximum sampled direct-process RSS.
    pub peak_rss_bytes: Option<u64>,
    /// Total observed report bytes.
    pub total_output_bytes: u64,
    /// Explicit status counts.
    pub status_counts: BTreeMap<String, u64>,
    /// Process exit codes keyed by case.
    pub exit_codes: BTreeMap<String, Option<i32>>,
}

/// Complete non-circular provenance embedded in the deterministic result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase4Provenance {
    /// External binary SHA-256.
    pub binary_sha256: String,
    /// Source RPM SHA-256.
    pub source_rpm_sha256: String,
    /// Frozen manifest SHA-256.
    pub manifest_sha256: String,
    /// Frozen corpus aggregate SHA-256.
    pub aggregate_corpus_sha256: String,
    /// Frozen contract Merkle root.
    pub contract_merkle_root: String,
    /// Frozen taxonomy artifact SHA-256.
    pub taxonomy_artifact_sha256: String,
    /// Frozen taxonomy content hash.
    pub taxonomy_content_hash: String,
    /// Exact portable command template.
    pub command_template: Vec<String>,
    /// Empty configuration SHA-256.
    pub configuration_sha256: String,
    /// AI state.
    pub ai_validation: String,
    /// Isolation proof.
    pub isolation: Phase4IsolationAttestation,
    /// Sanitized host provenance.
    pub host: HostProvenance,
    /// Pre-execution contract SHA-256.
    pub pre_execution_contract_sha256: String,
    /// Run manifest SHA-256.
    pub run_sha256: String,
    /// Deterministic aggregate of retained report hashes.
    pub reports_sha256: String,
    /// Ledger SHA-256 before reservation.
    pub ledger_before_sha256: String,
    /// Genesis ledger entry hash.
    pub ledger_genesis_entry_hash: String,
    /// Execution reservation entry hash.
    pub ledger_started_entry_hash: String,
    /// Schema identities participating in the result.
    pub schemas: BTreeMap<String, String>,
}

/// Complete deterministic Phase 4 result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase4Result {
    /// Result schema identity.
    pub schema_version: String,
    /// Run identity.
    pub run_id: String,
    /// Holdout identity.
    pub holdout_id: String,
    /// Taxonomy version.
    pub taxonomy_version: String,
    /// One decision per vulnerable expectation or safe control.
    pub cases: Vec<Phase2CaseDecision>,
    /// Privacy-safe normalized finding records.
    pub findings: Vec<Phase2FindingRecord>,
    /// Overall exact and diagnostic metrics.
    pub metrics: Phase2Metrics,
    /// Required grouped results.
    pub breakdowns: Phase4Breakdowns,
    /// Runtime and operational measurements.
    pub measurement: Phase4Measurement,
    /// Stable semantic fingerprint excluding volatile times and raw report hashes.
    pub semantic_fingerprint: String,
    /// Complete artifact and environment provenance.
    pub provenance: Phase4Provenance,
}

/// Final index binding the result to the completed append-only ledger.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase4Artifacts {
    /// Artifact-index schema identity.
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
    /// Aggregate retained-report SHA-256.
    pub reports_sha256: String,
    /// Retained report count.
    pub report_count: u64,
}

/// Inputs for producing the pre-execution contract without invoking a scanner.
pub struct Phase4PrepareRequest<'a> {
    /// Repository root.
    pub repository_root: &'a Path,
    /// External binary path, read only for hashing.
    pub binary: &'a Path,
    /// Source RPM path, read only for hashing.
    pub source_rpm: &'a Path,
    /// Built release benchmark executable.
    pub benchmark_binary: &'a Path,
    /// Frozen manifest bytes.
    pub manifest: &'a [u8],
    /// Frozen taxonomy bytes.
    pub taxonomy: &'a [u8],
    /// Genesis-only ledger bytes.
    pub ledger: &'a [u8],
    /// UTC contract freeze time.
    pub frozen_at_utc: &'a str,
}

/// Inputs for the sole scanner execution.
pub struct Phase4ExecutionRequest<'a> {
    /// Repository root.
    pub repository_root: &'a Path,
    /// External binary path.
    pub binary: &'a Path,
    /// Source RPM path.
    pub source_rpm: &'a Path,
    /// Release benchmark executable used for preflight hashing.
    pub benchmark_binary: &'a Path,
    /// Frozen pre-execution contract bytes.
    pub pre_execution_contract: &'a [u8],
    /// Frozen manifest bytes.
    pub manifest: &'a [u8],
    /// Frozen taxonomy bytes.
    pub taxonomy: &'a [u8],
    /// Mutable append-only ledger path.
    pub ledger_path: &'a Path,
    /// New retained run directory.
    pub run_directory: &'a Path,
    /// Commitment-bound new result path.
    pub result_path: &'a Path,
    /// New final artifact-index path.
    pub artifacts_path: &'a Path,
    /// Portable repository-relative pre-execution contract path.
    pub pre_execution_contract_path: &'a str,
    /// Portable repository-relative run manifest path.
    pub run_path: &'a str,
    /// Portable repository-relative result path.
    pub result_path_relative: &'a str,
    /// Portable repository-relative ledger path.
    pub ledger_path_relative: &'a str,
    /// Cancellation signal.
    pub cancellation: Arc<AtomicBool>,
}

/// Inputs for post-execution verification that never starts a scanner.
pub struct Phase4VerificationRequest<'a> {
    /// Repository root.
    pub repository_root: &'a Path,
    /// External binary path, used only for hashing.
    pub binary: &'a Path,
    /// Source RPM path, used only for hashing.
    pub source_rpm: &'a Path,
    /// Release benchmark executable used for the run.
    pub benchmark_binary: &'a Path,
    /// Pre-execution contract bytes.
    pub pre_execution_contract: &'a [u8],
    /// Frozen manifest bytes.
    pub manifest: &'a [u8],
    /// Frozen taxonomy bytes.
    pub taxonomy: &'a [u8],
    /// Completed ledger bytes.
    pub ledger: &'a [u8],
    /// Retained run manifest bytes.
    pub run: &'a [u8],
    /// Deterministic result bytes.
    pub result: &'a [u8],
    /// Final artifact-index bytes.
    pub artifacts: &'a [u8],
    /// Retained run directory.
    pub run_directory: &'a Path,
}

/// Phase 4 contract, execution, evaluation, or artifact failure.
#[derive(Debug, Error)]
pub enum Phase4Error {
    /// Frozen contract is invalid.
    #[error("invalid Phase 4 contract: {0}")]
    InvalidContract(String),
    /// Filesystem or runner failure.
    #[error(transparent)]
    Runner(#[from] RunnerError),
    /// Filesystem failure with sanitized context.
    #[error("Phase 4 artifact operation failed for `{path}`: {detail}")]
    Io {
        /// Portable or user-supplied path.
        path: String,
        /// Operating-system detail.
        detail: String,
    },
    /// Deterministic serialization failed.
    #[error("could not serialize deterministic Phase 4 data")]
    Serialization,
}

const FROZEN_EVALUATOR_FILES: [&str; 20] = [
    "Cargo.lock",
    "apps/secure-bench-cli/src/main.rs",
    "crates/secure-bench-core/src/adapter.rs",
    "crates/secure-bench-core/src/holdout.rs",
    "crates/secure-bench-core/src/model.rs",
    "crates/secure-bench-core/src/phase2.rs",
    "crates/secure-bench-core/src/phase4.rs",
    "crates/secure-bench-core/src/runner.rs",
    "crates/secure-bench-core/src/schema.rs",
    "crates/secure-bench-core/src/taxonomy.rs",
    "crates/secure-bench-core/tests/phase2.rs",
    "crates/secure-bench-core/tests/phase3_holdout.rs",
    "crates/secure-bench-core/tests/taxonomy.rs",
    "schemas/holdout-ledger-entry-v1.schema.json",
    "schemas/holdout-v1.schema.json",
    "schemas/phase4-artifacts-v1.schema.json",
    "schemas/phase4-pre-execution-v1.schema.json",
    "schemas/phase4-result-v1.schema.json",
    "schemas/phase4-run-v1.schema.json",
    "schemas/taxonomy-v1.schema.json",
];

/// Produces the canonical pre-execution contract after verifying every non-executing prerequisite.
///
/// This function reads external artifacts only to compute SHA-256 and never starts a process.
///
/// # Errors
///
/// Returns [`Phase4Error`] for any fingerprint, contract, path, schema, or environment mismatch.
pub fn prepare_phase4(
    request: &Phase4PrepareRequest<'_>,
) -> Result<Phase4PreExecutionContract, Phase4Error> {
    let (manifest, validation) =
        load_holdout_manifest(request.manifest, request.repository_root, request.taxonomy)
            .map_err(|error| Phase4Error::InvalidContract(error.to_string()))?;
    let taxonomy = load_taxonomy(request.taxonomy)
        .map_err(|error| Phase4Error::InvalidContract(error.to_string()))?;
    let ledger = validate_holdout_ledger(request.ledger, &manifest)
        .map_err(|error| Phase4Error::InvalidContract(error.to_string()))?;
    if ledger.len() != 1 {
        return Err(Phase4Error::InvalidContract(
            "the pre-execution ledger is not genesis-only".to_owned(),
        ));
    }
    verify_fixed_holdout_hashes(
        request.manifest,
        request.taxonomy,
        request.ledger,
        &validation.aggregate_corpus_sha256,
        &validation.contract_merkle_root,
    )?;
    let binary_sha256 = fingerprint_regular_file(request.binary)?;
    let source_rpm_sha256 = fingerprint_regular_file(request.source_rpm)?;
    let benchmark_binary_sha256 = fingerprint_regular_file(request.benchmark_binary)?;
    if binary_sha256 != PHASE4_BINARY_SHA256 || source_rpm_sha256 != PHASE4_RPM_SHA256 {
        return Err(Phase4Error::InvalidContract(
            "external binary or source RPM fingerprint differs from the user contract".to_owned(),
        ));
    }
    let bwrap_sha256 = fingerprint_regular_file(Path::new("/usr/bin/bwrap"))?;
    let host = host_provenance();
    let kernel_release = host.kernel_release.ok_or_else(|| {
        Phase4Error::InvalidContract("kernel release provenance is unavailable".to_owned())
    })?;
    let contract = Phase4PreExecutionContract {
        schema_version: PHASE4_PRE_EXECUTION_SCHEMA_V1.to_owned(),
        frozen_at_utc: request.frozen_at_utc.to_owned(),
        git_base: PHASE4_GIT_BASE.to_owned(),
        branch: PHASE4_BRANCH.to_owned(),
        run_id: PHASE4_RUN_ID.to_owned(),
        scanner: Phase4ScannerContract {
            declared_version: "Secure Engine 0.1.2 (user-supplied artifact identity)".to_owned(),
            binary_sha256,
            source_rpm_sha256,
            command_template: argument_template(),
            report_schema: "secure-json-v1".to_owned(),
            configuration_sha256: EMPTY_SHA256.to_owned(),
            ai_validation: "disabled".to_owned(),
            version_probe: "not-executed".to_owned(),
            environment_clear: true,
        },
        holdout: Phase4HoldoutContract {
            holdout_id: manifest.holdout_id,
            manifest_sha256: fingerprint(request.manifest),
            ledger_before_sha256: fingerprint(request.ledger),
            aggregate_corpus_sha256: validation.aggregate_corpus_sha256,
            contract_merkle_root: validation.contract_merkle_root,
            taxonomy_artifact_sha256: fingerprint(request.taxonomy),
            taxonomy_content_hash: taxonomy.content_hash,
            pairs: EXPECTED_PAIRS as u64,
            cases: EXPECTED_CASES as u64,
        },
        resources: Phase4ResourceContract {
            timeout_ms: CASE_TIMEOUT_MS,
            memory_bytes: CASE_MEMORY_BYTES,
            output_bytes: CASE_OUTPUT_BYTES,
            network: "disabled".to_owned(),
        },
        environment: Phase4EnvironmentContract {
            os: std::env::consts::OS.to_owned(),
            architecture: std::env::consts::ARCH.to_owned(),
            kernel_release,
            rust_toolchain: env!("CARGO_PKG_RUST_VERSION").to_owned(),
            bwrap_sha256,
            isolation: "bwrap-unshare-net-complete-runner".to_owned(),
            expected_interfaces: vec!["lo".to_owned()],
            probe_target: "1.1.1.1:53".to_owned(),
        },
        benchmark_binary_sha256,
        frozen_evaluator_files: evaluator_fingerprints(request.repository_root)?,
    };
    crate::schema::validate_phase4_pre_execution(&contract)
        .map_err(|error| Phase4Error::InvalidContract(error.to_string()))?;
    validate_pre_execution_semantics(&contract)?;
    Ok(contract)
}

/// Loads canonical pre-execution contract bytes.
///
/// # Errors
///
/// Returns [`Phase4Error`] for malformed, non-canonical, schema-invalid, or semantically invalid
/// input.
pub fn load_phase4_pre_execution(bytes: &[u8]) -> Result<Phase4PreExecutionContract, Phase4Error> {
    let contract: Phase4PreExecutionContract = serde_json::from_slice(bytes).map_err(|error| {
        Phase4Error::InvalidContract(format!(
            "pre-execution JSON is invalid at line {}",
            error.line()
        ))
    })?;
    crate::schema::validate_phase4_pre_execution(&contract)
        .map_err(|error| Phase4Error::InvalidContract(error.to_string()))?;
    if canonical_phase4_json(&contract)? != bytes {
        return Err(Phase4Error::InvalidContract(
            "pre-execution contract is not canonical JSON".to_owned(),
        ));
    }
    validate_pre_execution_semantics(&contract)?;
    Ok(contract)
}

/// Returns canonical pretty JSON with one trailing newline.
///
/// # Errors
///
/// Returns [`Phase4Error::Serialization`] if serialization fails.
pub fn canonical_phase4_json<T: Serialize>(value: &T) -> Result<Vec<u8>, Phase4Error> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|_| Phase4Error::Serialization)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn validate_pre_execution_semantics(
    contract: &Phase4PreExecutionContract,
) -> Result<(), Phase4Error> {
    if contract.schema_version != PHASE4_PRE_EXECUTION_SCHEMA_V1
        || contract.git_base != PHASE4_GIT_BASE
        || contract.branch != PHASE4_BRANCH
        || contract.run_id != PHASE4_RUN_ID
        || contract.scanner.binary_sha256 != PHASE4_BINARY_SHA256
        || contract.scanner.source_rpm_sha256 != PHASE4_RPM_SHA256
        || contract.scanner.command_template != argument_template()
        || contract.scanner.report_schema != "secure-json-v1"
        || contract.scanner.configuration_sha256 != EMPTY_SHA256
        || contract.scanner.ai_validation != "disabled"
        || contract.scanner.version_probe != "not-executed"
        || !contract.scanner.environment_clear
        || contract.holdout.manifest_sha256 != PHASE4_MANIFEST_SHA256
        || contract.holdout.ledger_before_sha256 != PHASE4_LEDGER_BEFORE_SHA256
        || contract.holdout.aggregate_corpus_sha256 != PHASE4_CORPUS_SHA256
        || contract.holdout.contract_merkle_root != PHASE4_MERKLE_ROOT
        || contract.holdout.pairs != EXPECTED_PAIRS as u64
        || contract.holdout.cases != EXPECTED_CASES as u64
        || contract.resources.timeout_ms != CASE_TIMEOUT_MS
        || contract.resources.memory_bytes != CASE_MEMORY_BYTES
        || contract.resources.output_bytes != CASE_OUTPUT_BYTES
        || contract.resources.network != "disabled"
        || contract.environment.isolation != "bwrap-unshare-net-complete-runner"
        || contract.environment.expected_interfaces != vec!["lo".to_owned()]
        || contract.environment.probe_target != "1.1.1.1:53"
        || contract.frozen_evaluator_files.len() != FROZEN_EVALUATOR_FILES.len()
        || contract
            .frozen_evaluator_files
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            != FROZEN_EVALUATOR_FILES.into_iter().collect::<BTreeSet<_>>()
    {
        return Err(Phase4Error::InvalidContract(
            "pre-execution semantics differ from the frozen one-shot policy".to_owned(),
        ));
    }
    Ok(())
}

fn verify_pre_execution_inputs(
    contract: &Phase4PreExecutionContract,
    request: &Phase4ExecutionRequest<'_>,
    ledger: &[u8],
) -> Result<(HoldoutManifest, FrozenTaxonomy, Vec<HoldoutLedgerEntry>), Phase4Error> {
    let (manifest, validation) =
        load_holdout_manifest(request.manifest, request.repository_root, request.taxonomy)
            .map_err(|error| Phase4Error::InvalidContract(error.to_string()))?;
    let taxonomy = load_taxonomy(request.taxonomy)
        .map_err(|error| Phase4Error::InvalidContract(error.to_string()))?;
    let entries = validate_holdout_ledger(ledger, &manifest)
        .map_err(|error| Phase4Error::InvalidContract(error.to_string()))?;
    verify_fixed_holdout_hashes(
        request.manifest,
        request.taxonomy,
        ledger,
        &validation.aggregate_corpus_sha256,
        &validation.contract_merkle_root,
    )?;
    if fingerprint(request.pre_execution_contract) != fingerprint(&canonical_phase4_json(contract)?)
        || fingerprint_regular_file(request.binary)? != contract.scanner.binary_sha256
        || fingerprint_regular_file(request.source_rpm)? != contract.scanner.source_rpm_sha256
        || fingerprint_regular_file(request.benchmark_binary)? != contract.benchmark_binary_sha256
        || evaluator_fingerprints(request.repository_root)? != contract.frozen_evaluator_files
        || fingerprint_regular_file(Path::new("/usr/bin/bwrap"))?
            != contract.environment.bwrap_sha256
        || entries.len() != 1
    {
        return Err(Phase4Error::InvalidContract(
            "a frozen pre-execution input drifted or the one-shot slot is unavailable".to_owned(),
        ));
    }
    Ok((manifest, taxonomy, entries))
}

fn verify_fixed_holdout_hashes(
    manifest: &[u8],
    taxonomy: &[u8],
    ledger: &[u8],
    corpus_sha256: &str,
    merkle_root: &str,
) -> Result<(), Phase4Error> {
    if fingerprint(manifest) != PHASE4_MANIFEST_SHA256
        || fingerprint(ledger) != PHASE4_LEDGER_BEFORE_SHA256
        || corpus_sha256 != PHASE4_CORPUS_SHA256
        || merkle_root != PHASE4_MERKLE_ROOT
        || fingerprint(taxonomy)
            != "059fe22d7707cf8d17f2c1621fdae9819787a1958ba2ef0421eca4e4ec858452"
    {
        return Err(Phase4Error::InvalidContract(
            "a frozen holdout or taxonomy commitment differs".to_owned(),
        ));
    }
    Ok(())
}

fn evaluator_fingerprints(root: &Path) -> Result<BTreeMap<String, String>, Phase4Error> {
    let mut hashes = BTreeMap::new();
    for relative in FROZEN_EVALUATOR_FILES {
        let path = safe_join(root, relative)?;
        hashes.insert(relative.to_owned(), fingerprint_regular_file(&path)?);
    }
    Ok(hashes)
}

fn fingerprint_regular_file(path: &Path) -> Result<String, Phase4Error> {
    let metadata = fs::symlink_metadata(path).map_err(|error| Phase4Error::Io {
        path: path.display().to_string(),
        detail: error.to_string(),
    })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(Phase4Error::InvalidContract(format!(
            "`{}` must be a regular non-symlink file",
            path.display()
        )));
    }
    let mut file = fs::File::open(path).map_err(|error| Phase4Error::Io {
        path: path.display().to_string(),
        detail: error.to_string(),
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let read = file.read(&mut buffer).map_err(|error| Phase4Error::Io {
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

fn argument_template() -> Vec<String> {
    PHASE4_ARGUMENTS.map(str::to_owned).to_vec()
}

/// Executes and evaluates the frozen holdout once after durably reserving the ledger slot.
///
/// The caller must place the complete benchmark process inside the declared network namespace.
/// This function independently proves that only loopback is visible and outbound connectivity is
/// unreachable before it appends the reservation or starts the external binary.
///
/// # Errors
///
/// Returns [`Phase4Error`] for any preflight, isolation, ledger, execution, evaluation, or artifact
/// failure. Once reserved, a fatal failure appends an immutable failed terminal entry when possible.
pub fn execute_phase4(
    request: &Phase4ExecutionRequest<'_>,
) -> Result<Phase4Artifacts, Phase4Error> {
    let contract = load_phase4_pre_execution(request.pre_execution_contract)?;
    let ledger_before = read_file(request.ledger_path)?;
    let (manifest, taxonomy, mut entries) =
        verify_pre_execution_inputs(&contract, request, &ledger_before)?;
    validate_new_artifact_paths(request)?;
    let isolation = attest_network_isolation(&contract.environment)?;
    let binary = validate_binary(request.binary)?;
    if fingerprint_file(&binary)? != PHASE4_BINARY_SHA256 {
        return Err(Phase4Error::InvalidContract(
            "external binary changed after preflight".to_owned(),
        ));
    }

    let started_timestamp = rfc3339_now();
    let started_entry = execution_started_ledger_entry(
        &entries,
        &manifest,
        &started_timestamp,
        PHASE4_RUN_ID,
        PHASE4_BINARY_SHA256,
    )
    .map_err(|error| Phase4Error::InvalidContract(error.to_string()))?;
    append_ledger_entry(request.ledger_path, &started_entry)?;
    entries.push(started_entry.clone());
    let current_ledger = read_file(request.ledger_path)?;
    validate_holdout_ledger(&current_ledger, &manifest)
        .map_err(|error| Phase4Error::InvalidContract(error.to_string()))?;

    match execute_reserved(
        request,
        &contract,
        &manifest,
        &taxonomy,
        &entries,
        &started_entry,
        &binary,
        isolation,
    ) {
        Ok(artifacts) => Ok(artifacts),
        Err(error) => {
            if let Ok(current) = read_file(request.ledger_path)
                && let Ok(current_entries) = validate_holdout_ledger(&current, &manifest)
                && current_entries.len() == 2
            {
                let failure_timestamp = rfc3339_now();
                if let Ok(failed) = execution_failed_ledger_entry(
                    &current_entries,
                    &manifest,
                    &failure_timestamp,
                    PHASE4_RUN_ID,
                    "runner-failure",
                ) {
                    let _ = append_ledger_entry(request.ledger_path, &failed);
                }
            }
            Err(error)
        }
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn execute_reserved(
    request: &Phase4ExecutionRequest<'_>,
    contract: &Phase4PreExecutionContract,
    manifest: &HoldoutManifest,
    taxonomy: &FrozenTaxonomy,
    entries: &[HoldoutLedgerEntry],
    started_entry: &HoldoutLedgerEntry,
    binary: &Path,
    isolation: Phase4IsolationAttestation,
) -> Result<Phase4Artifacts, Phase4Error> {
    fs::create_dir(request.run_directory).map_err(|error| Phase4Error::Io {
        path: request.run_directory.display().to_string(),
        detail: error.to_string(),
    })?;
    let reports_directory = request.run_directory.join("reports");
    fs::create_dir(&reports_directory).map_err(|error| Phase4Error::Io {
        path: reports_directory.display().to_string(),
        detail: error.to_string(),
    })?;
    let journal_path = request.run_directory.join("cases.jsonl");
    let run_started = unix_millis();
    let mut cases = manifest
        .pairs
        .iter()
        .flat_map(|pair| [&pair.vulnerable, &pair.control])
        .collect::<Vec<_>>();
    cases.sort_by(|left, right| left.case_id.cmp(&right.case_id));
    if cases.len() != EXPECTED_CASES {
        return Err(Phase4Error::InvalidContract(
            "holdout execution case count drifted".to_owned(),
        ));
    }
    let mut outcomes = Vec::with_capacity(cases.len());
    for case in cases {
        let outcome = run_phase4_case(
            request,
            case,
            binary,
            &reports_directory,
            contract.resources.timeout_ms,
            contract.resources.memory_bytes,
            contract.resources.output_bytes,
        )?;
        append_case_journal(&journal_path, &outcome)?;
        outcomes.push(outcome);
    }
    let run_finished = unix_millis();
    let case_journal_sha256 = fingerprint(&read_file(&journal_path)?);
    let run = Phase4Run {
        schema_version: PHASE4_RUN_SCHEMA_V1.to_owned(),
        run_id: PHASE4_RUN_ID.to_owned(),
        holdout_id: manifest.holdout_id.clone(),
        pre_execution_contract_sha256: fingerprint(request.pre_execution_contract),
        binary_sha256: PHASE4_BINARY_SHA256.to_owned(),
        source_rpm_sha256: PHASE4_RPM_SHA256.to_owned(),
        command_template: argument_template(),
        ai_validation: "disabled".to_owned(),
        version_probe_executed: false,
        isolation,
        host: host_provenance(),
        started_unix_ms: run_started,
        finished_unix_ms: run_finished,
        status: aggregate_status(&outcomes),
        case_journal_sha256,
        cases: outcomes,
    };
    crate::schema::validate_phase4_run(&run)
        .map_err(|error| Phase4Error::InvalidContract(error.to_string()))?;
    validate_run_semantics(&run, manifest, contract)?;
    let run_bytes = canonical_phase4_json(&run)?;
    let run_file = request.run_directory.join("run.json");
    atomic_write(&run_file, &run_bytes)?;
    let reports = load_phase4_reports(&run, request.run_directory)?;
    let result = evaluate_phase4(
        manifest,
        taxonomy,
        &run,
        &reports,
        request.pre_execution_contract,
        &run_bytes,
        entries,
        started_entry,
    )?;
    let result_bytes = canonical_phase4_json(&result)?;
    crate::schema::validate_phase4_result(&result)
        .map_err(|error| Phase4Error::InvalidContract(error.to_string()))?;
    atomic_write(request.result_path, &result_bytes)?;
    let result_sha256 = fingerprint(&result_bytes);
    let completed = execution_completed_ledger_entry(
        entries,
        manifest,
        &rfc3339_now(),
        PHASE4_RUN_ID,
        &result_sha256,
    )
    .map_err(|error| Phase4Error::InvalidContract(error.to_string()))?;
    append_ledger_entry(request.ledger_path, &completed)?;
    let final_ledger = read_file(request.ledger_path)?;
    let mut final_entries = entries.to_vec();
    final_entries.push(completed);
    let validated = validate_holdout_ledger(&final_ledger, manifest)
        .map_err(|error| Phase4Error::InvalidContract(error.to_string()))?;
    if validated != final_entries {
        return Err(Phase4Error::InvalidContract(
            "completed ledger readback differs from the appended chain".to_owned(),
        ));
    }
    let reports_sha256 = report_aggregate(&run);
    let artifacts = Phase4Artifacts {
        schema_version: PHASE4_ARTIFACTS_SCHEMA_V1.to_owned(),
        run_id: PHASE4_RUN_ID.to_owned(),
        pre_execution_contract_path: request.pre_execution_contract_path.to_owned(),
        pre_execution_contract_sha256: fingerprint(request.pre_execution_contract),
        run_path: request.run_path.to_owned(),
        run_sha256: fingerprint(&run_bytes),
        result_path: request.result_path_relative.to_owned(),
        result_sha256,
        ledger_path: request.ledger_path_relative.to_owned(),
        ledger_sha256: fingerprint(&final_ledger),
        reports_sha256,
        report_count: reports.len().try_into().unwrap_or(u64::MAX),
    };
    crate::schema::validate_phase4_artifacts(&artifacts)
        .map_err(|error| Phase4Error::InvalidContract(error.to_string()))?;
    atomic_write(request.artifacts_path, &canonical_phase4_json(&artifacts)?)?;
    Ok(artifacts)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn run_phase4_case(
    request: &Phase4ExecutionRequest<'_>,
    case: &crate::holdout::HoldoutCase,
    binary: &Path,
    reports_directory: &Path,
    timeout_ms: u64,
    memory_bytes: u64,
    output_limit: u64,
) -> Result<LiveCaseRun, Phase4Error> {
    let arguments = vec![
        "scan".to_owned(),
        ".".to_owned(),
        "--format".to_owned(),
        "secure-json-v1".to_owned(),
        "--output".to_owned(),
        "../.secure-bench-report.json".to_owned(),
    ];
    if request
        .cancellation
        .load(std::sync::atomic::Ordering::SeqCst)
    {
        let now = unix_millis();
        return Ok(LiveCaseRun {
            case_id: case.case_id.clone(),
            fixture_fingerprint: case.fixture_sha256.clone(),
            status: LiveCaseStatus::Cancelled,
            arguments,
            report_path: None,
            report_fingerprint: None,
            started_unix_ms: now,
            finished_unix_ms: now,
            duration_ms: 0,
            process_exit_code: None,
            peak_memory_bytes: None,
            output_bytes: None,
            stdout: empty_capture(),
            stderr: empty_capture(),
            error_code: Some("runner.cancelled".to_owned()),
        });
    }
    let workspace = Builder::new()
        .prefix("secure-bench-holdout-")
        .tempdir()
        .map_err(|error| Phase4Error::Io {
            path: "temporary holdout workspace".to_owned(),
            detail: error.to_string(),
        })?;
    let scanner_root = workspace.path().join("workspace");
    fs::create_dir(&scanner_root).map_err(|error| Phase4Error::Io {
        path: "temporary scanner workspace".to_owned(),
        detail: error.to_string(),
    })?;
    let fixture = safe_join(request.repository_root, &case.fixture_path)?;
    copy_fixture(&fixture, &scanner_root, &case.fixture_path)?;
    let report_path = workspace.path().join(".secure-bench-report.json");
    let started_unix_ms = unix_millis();
    let started = Instant::now();
    let process = execute_process(
        binary,
        &arguments,
        &scanner_root,
        Duration::from_millis(timeout_ms),
        memory_bytes,
        &request.cancellation,
    );
    let finished_unix_ms = unix_millis();
    let duration_ms = millis_u64(started.elapsed());
    let process = match process {
        Ok(process) => process,
        Err(error_code) => {
            return Ok(LiveCaseRun {
                case_id: case.case_id.clone(),
                fixture_fingerprint: case.fixture_sha256.clone(),
                status: LiveCaseStatus::ExecutionFailure,
                arguments,
                report_path: None,
                report_fingerprint: None,
                started_unix_ms,
                finished_unix_ms,
                duration_ms,
                process_exit_code: None,
                peak_memory_bytes: None,
                output_bytes: None,
                stdout: empty_capture(),
                stderr: empty_capture(),
                error_code: Some(error_code),
            });
        }
    };
    let mut status = process.status;
    let mut error_code = process.error_code;
    let mut retained_report = None;
    let mut report_fingerprint = None;
    let mut output_bytes = None;
    if let Ok(metadata) = fs::symlink_metadata(&report_path) {
        output_bytes = Some(metadata.len());
        if metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.len() <= output_limit
        {
            let bytes = fs::read(&report_path).map_err(|error| Phase4Error::Io {
                path: format!("report for {}", case.case_id),
                detail: error.to_string(),
            })?;
            let digest = fingerprint(&bytes);
            let destination = reports_directory.join(format!("{}.json", case.case_id));
            atomic_write(&destination, &bytes)?;
            retained_report = Some(format!("reports/{}.json", case.case_id));
            report_fingerprint = Some(digest.clone());
            if contains_private_path(&bytes) {
                status = LiveCaseStatus::InvalidOutput;
                error_code = Some("runner.privacy_unsafe_report".to_owned());
            } else if process.status.is_success() || report_declares_completed_scan(&bytes) {
                match SecureJsonAdapter.normalize_scoped(AdapterInput {
                    report: &bytes,
                    report_fingerprint: &digest,
                    case_id: Some(&case.case_id),
                    path_prefix: None,
                }) {
                    Ok(findings) => {
                        status = if findings.is_empty() {
                            LiveCaseStatus::Success
                        } else {
                            LiveCaseStatus::Findings
                        };
                        error_code = None;
                    }
                    Err(AdapterError::UnsupportedVersion(_) | AdapterError::UnsupportedFormat) => {
                        status = LiveCaseStatus::UnsupportedSchema;
                        error_code = Some("runner.unsupported_schema".to_owned());
                    }
                    Err(_) => {
                        status = LiveCaseStatus::InvalidOutput;
                        error_code = Some("runner.invalid_output".to_owned());
                    }
                }
            }
        } else if process.status.is_success() {
            status = LiveCaseStatus::InvalidOutput;
            error_code = Some("runner.oversized_or_unsafe_report".to_owned());
        }
    } else if process.status.is_success() {
        status = LiveCaseStatus::InvalidOutput;
        error_code = Some("runner.missing_report".to_owned());
    }
    Ok(LiveCaseRun {
        case_id: case.case_id.clone(),
        fixture_fingerprint: case.fixture_sha256.clone(),
        status,
        arguments,
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
    })
}

fn validate_new_artifact_paths(request: &Phase4ExecutionRequest<'_>) -> Result<(), Phase4Error> {
    for path in [
        request.run_directory,
        request.result_path,
        request.artifacts_path,
    ] {
        if fs::symlink_metadata(path).is_ok() {
            return Err(Phase4Error::InvalidContract(format!(
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

fn attest_network_isolation(
    expected: &Phase4EnvironmentContract,
) -> Result<Phase4IsolationAttestation, Phase4Error> {
    let devices = fs::read_to_string("/proc/net/dev").map_err(|error| Phase4Error::Io {
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
    if interfaces != expected.expected_interfaces {
        return Err(Phase4Error::InvalidContract(
            "network namespace exposes an unexpected interface".to_owned(),
        ));
    }
    let target: SocketAddr = expected.probe_target.parse().map_err(|_| {
        Phase4Error::InvalidContract("isolation probe target is invalid".to_owned())
    })?;
    match TcpStream::connect_timeout(&target, Duration::from_millis(250)) {
        Err(error) if error.kind() == std::io::ErrorKind::NetworkUnreachable => {}
        Ok(_) => {
            return Err(Phase4Error::InvalidContract(
                "network isolation failed: outbound connection succeeded".to_owned(),
            ));
        }
        Err(error) => {
            return Err(Phase4Error::InvalidContract(format!(
                "network isolation did not fail closed with an unreachable network: {error}"
            )));
        }
    }
    Ok(Phase4IsolationAttestation {
        mechanism: expected.isolation.clone(),
        interfaces,
        outbound_connectivity: "blocked".to_owned(),
        probe_target: expected.probe_target.clone(),
    })
}

fn append_ledger_entry(path: &Path, entry: &HoldoutLedgerEntry) -> Result<(), Phase4Error> {
    let bytes = canonical_ledger_jsonl(std::slice::from_ref(entry))
        .map_err(|error| Phase4Error::InvalidContract(error.to_string()))?;
    let mut file = OpenOptions::new()
        .append(true)
        .open(path)
        .map_err(|error| Phase4Error::Io {
            path: path.display().to_string(),
            detail: error.to_string(),
        })?;
    file.write_all(&bytes).map_err(|error| Phase4Error::Io {
        path: path.display().to_string(),
        detail: error.to_string(),
    })?;
    file.sync_all().map_err(|error| Phase4Error::Io {
        path: path.display().to_string(),
        detail: error.to_string(),
    })
}

fn append_case_journal(path: &Path, case: &LiveCaseRun) -> Result<(), Phase4Error> {
    let mut bytes = serde_json::to_vec(case).map_err(|_| Phase4Error::Serialization)?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)
        .map_err(|error| Phase4Error::Io {
            path: path.display().to_string(),
            detail: error.to_string(),
        })?;
    file.write_all(&bytes).map_err(|error| Phase4Error::Io {
        path: path.display().to_string(),
        detail: error.to_string(),
    })?;
    file.sync_all().map_err(|error| Phase4Error::Io {
        path: path.display().to_string(),
        detail: error.to_string(),
    })
}

/// Evaluates retained Phase 4 reports without executing a scanner.
///
/// # Errors
///
/// Returns [`Phase4Error`] for run/report drift, adapter failures in successful cases, or an
/// invalid deterministic projection.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub fn evaluate_phase4(
    manifest: &HoldoutManifest,
    taxonomy: &FrozenTaxonomy,
    run: &Phase4Run,
    reports: &BTreeMap<String, Vec<u8>>,
    pre_execution_contract: &[u8],
    run_bytes: &[u8],
    ledger_entries: &[HoldoutLedgerEntry],
    started_entry: &HoldoutLedgerEntry,
) -> Result<Phase4Result, Phase4Error> {
    validate_run_semantics(
        run,
        manifest,
        &load_phase4_pre_execution(pre_execution_contract)?,
    )?;
    let run_cases = run
        .cases
        .iter()
        .map(|case| (case.case_id.as_str(), case))
        .collect::<BTreeMap<_, _>>();
    let mut findings = Vec::new();
    for pair in &manifest.pairs {
        for case in [&pair.vulnerable, &pair.control] {
            let execution = run_cases.get(case.case_id.as_str()).ok_or_else(|| {
                Phase4Error::InvalidContract(format!("run omitted case `{}`", case.case_id))
            })?;
            if !execution.status.is_success() {
                continue;
            }
            let report_path = execution.report_path.as_ref().ok_or_else(|| {
                Phase4Error::InvalidContract(format!(
                    "successful case `{}` has no retained report",
                    case.case_id
                ))
            })?;
            let report = reports.get(report_path).ok_or_else(|| {
                Phase4Error::InvalidContract(format!("missing retained report `{report_path}`"))
            })?;
            let digest = fingerprint(report);
            if execution.report_fingerprint.as_deref() != Some(digest.as_str()) {
                return Err(Phase4Error::InvalidContract(format!(
                    "report fingerprint drift for case `{}`",
                    case.case_id
                )));
            }
            let mut normalized = SecureJsonAdapter
                .normalize_scoped(AdapterInput {
                    report,
                    report_fingerprint: &digest,
                    case_id: Some(&case.case_id),
                    path_prefix: None,
                })
                .map_err(|error| {
                    Phase4Error::InvalidContract(format!(
                        "successful case `{}` no longer normalizes: {error}",
                        case.case_id
                    ))
                })?;
            findings.append(&mut normalized);
        }
    }
    findings.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
    let suite = holdout_suite(manifest);
    let live_run = evaluation_live_run(run, manifest);
    let (decisions, records, metrics) =
        evaluate_taxonomy_snapshot(&suite, taxonomy, &findings, &live_run)
            .map_err(|error| Phase4Error::InvalidContract(error.to_string()))?;
    let breakdowns = build_breakdowns(manifest, &decisions, &records);
    let measurement = run_measurement(run);
    let semantic_fingerprint =
        semantic_result_fingerprint(&decisions, &records, &metrics, &breakdowns, &measurement)?;
    let genesis = ledger_entries
        .first()
        .ok_or_else(|| Phase4Error::InvalidContract("ledger has no genesis entry".to_owned()))?;
    let result = Phase4Result {
        schema_version: PHASE4_RESULT_SCHEMA_V1.to_owned(),
        run_id: run.run_id.clone(),
        holdout_id: manifest.holdout_id.clone(),
        taxonomy_version: taxonomy.taxonomy_version.clone(),
        cases: decisions,
        findings: records,
        metrics,
        breakdowns,
        measurement,
        semantic_fingerprint,
        provenance: Phase4Provenance {
            binary_sha256: PHASE4_BINARY_SHA256.to_owned(),
            source_rpm_sha256: PHASE4_RPM_SHA256.to_owned(),
            manifest_sha256: PHASE4_MANIFEST_SHA256.to_owned(),
            aggregate_corpus_sha256: PHASE4_CORPUS_SHA256.to_owned(),
            contract_merkle_root: PHASE4_MERKLE_ROOT.to_owned(),
            taxonomy_artifact_sha256: fingerprint(&canonical_taxonomy_bytes(taxonomy)?),
            taxonomy_content_hash: taxonomy.content_hash.clone(),
            command_template: argument_template(),
            configuration_sha256: EMPTY_SHA256.to_owned(),
            ai_validation: "disabled".to_owned(),
            isolation: run.isolation.clone(),
            host: run.host.clone(),
            pre_execution_contract_sha256: fingerprint(pre_execution_contract),
            run_sha256: fingerprint(run_bytes),
            reports_sha256: report_aggregate(run),
            ledger_before_sha256: PHASE4_LEDGER_BEFORE_SHA256.to_owned(),
            ledger_genesis_entry_hash: genesis.entry_hash.clone(),
            ledger_started_entry_hash: started_entry.entry_hash.clone(),
            schemas: BTreeMap::from([
                ("holdout".to_owned(), manifest.schema_version.clone()),
                (
                    "ledger_entry".to_owned(),
                    crate::holdout::HOLDOUT_LEDGER_SCHEMA_V1.to_owned(),
                ),
                (
                    "phase4_pre_execution".to_owned(),
                    PHASE4_PRE_EXECUTION_SCHEMA_V1.to_owned(),
                ),
                (
                    "phase4_result".to_owned(),
                    PHASE4_RESULT_SCHEMA_V1.to_owned(),
                ),
                ("phase4_run".to_owned(), PHASE4_RUN_SCHEMA_V1.to_owned()),
                ("taxonomy".to_owned(), taxonomy.schema_version.clone()),
                ("tool_report".to_owned(), "secure-json-v1".to_owned()),
            ]),
        },
    };
    crate::schema::validate_phase4_result(&result)
        .map_err(|error| Phase4Error::InvalidContract(error.to_string()))?;
    Ok(result)
}

fn validate_run_semantics(
    run: &Phase4Run,
    manifest: &HoldoutManifest,
    contract: &Phase4PreExecutionContract,
) -> Result<(), Phase4Error> {
    if run.schema_version != PHASE4_RUN_SCHEMA_V1
        || run.run_id != PHASE4_RUN_ID
        || run.holdout_id != manifest.holdout_id
        || run.pre_execution_contract_sha256 != fingerprint(&canonical_phase4_json(contract)?)
        || run.binary_sha256 != PHASE4_BINARY_SHA256
        || run.source_rpm_sha256 != PHASE4_RPM_SHA256
        || run.command_template != argument_template()
        || run.ai_validation != "disabled"
        || run.version_probe_executed
        || run.isolation.mechanism != "bwrap-unshare-net-complete-runner"
        || run.isolation.interfaces != vec!["lo".to_owned()]
        || run.isolation.outbound_connectivity != "blocked"
        || run.cases.len() != EXPECTED_CASES
        || !run
            .cases
            .windows(2)
            .all(|window| window[0].case_id < window[1].case_id)
    {
        return Err(Phase4Error::InvalidContract(
            "retained run differs from the frozen execution contract".to_owned(),
        ));
    }
    let expected = manifest
        .pairs
        .iter()
        .flat_map(|pair| [&pair.vulnerable, &pair.control])
        .map(|case| (case.case_id.as_str(), case.fixture_sha256.as_str()))
        .collect::<BTreeMap<_, _>>();
    for case in &run.cases {
        if expected.get(case.case_id.as_str()).copied() != Some(case.fixture_fingerprint.as_str())
            || case.arguments
                != [
                    "scan",
                    ".",
                    "--format",
                    "secure-json-v1",
                    "--output",
                    "../.secure-bench-report.json",
                ]
                .map(str::to_owned)
                .to_vec()
        {
            return Err(Phase4Error::InvalidContract(format!(
                "case `{}` differs from the frozen command or fixture",
                case.case_id
            )));
        }
    }
    Ok(())
}

fn holdout_suite(manifest: &HoldoutManifest) -> BenchmarkSuite {
    let mut cases = Vec::with_capacity(EXPECTED_CASES);
    for pair in &manifest.pairs {
        for case in [&pair.vulnerable, &pair.control] {
            let expected_findings = case.expected.as_ref().map_or_else(Vec::new, |expected| {
                vec![ExpectedFinding {
                    expectation_id: expected.expectation_id.clone(),
                    taxonomy: Some(TaxonomyCoordinates {
                        taxonomy_version: pair.taxonomy.taxonomy_version.clone(),
                        category_id: pair.taxonomy.category_id.clone(),
                        invariant_id: pair.taxonomy.invariant_id.clone(),
                    }),
                    invariant: pair.taxonomy.invariant_id.clone(),
                    category: pair.taxonomy.category_id.clone(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    source: expected.source.clone(),
                    sink: expected.sink.clone(),
                    evidence: expected.evidence.clone(),
                }]
            });
            cases.push(BenchmarkCase {
                case_id: case.case_id.clone(),
                kind: case.kind,
                language: language_name(pair.language).to_owned(),
                framework: Some(framework_name(pair.framework).to_owned()),
                category: pair.taxonomy.category_id.clone(),
                invariant: (case.kind == CaseKind::Vulnerable)
                    .then(|| pair.taxonomy.invariant_id.clone()),
                fixture_path: case.fixture_path.clone(),
                content_fingerprint: Some(case.fixture_sha256.clone()),
                eligibility: Eligibility {
                    required_capabilities: vec!["static-analysis".to_owned()],
                    supported_report_formats: vec!["secure-json-v1".to_owned()],
                    rationale: Some(pair.rationale.clone()),
                },
                resource_budget: ResourceBudget {
                    timeout_ms: CASE_TIMEOUT_MS,
                    memory_bytes: CASE_MEMORY_BYTES,
                    output_bytes: CASE_OUTPUT_BYTES,
                    network: NetworkPolicy::Disabled,
                },
                expected_findings,
                provenance: case.provenance.clone(),
            });
        }
    }
    cases.sort_by(|left, right| left.case_id.cmp(&right.case_id));
    BenchmarkSuite {
        schema_version: crate::model::SUITE_SCHEMA_V2.to_owned(),
        suite_id: manifest.holdout_id.clone(),
        title: manifest.title.clone(),
        description: manifest.description.clone(),
        methodology_version: manifest.methodology_version.clone(),
        corpus_fingerprint: Some(manifest.commitment.aggregate_corpus_sha256.clone()),
        provenance: manifest.provenance.clone(),
        cases,
    }
}

fn evaluation_live_run(run: &Phase4Run, manifest: &HoldoutManifest) -> LiveRun {
    LiveRun {
        schema_version: crate::runner::LIVE_RUN_SCHEMA_V1.to_owned(),
        run_id: run.run_id.clone(),
        suite_id: manifest.holdout_id.clone(),
        corpus_fingerprint: manifest.commitment.aggregate_corpus_sha256.clone(),
        tool: LiveToolProvenance {
            name: "Secure Engine".to_owned(),
            reported_version: "secure 0.1.2 (contract; no probe)".to_owned(),
            binary_fingerprint: run.binary_sha256.clone(),
            report_schema: "secure-json-v1".to_owned(),
            argument_template: argument_template(),
            configuration_fingerprint: EMPTY_SHA256.to_owned(),
            version_probe_status: VersionProbeStatus::ExecutionFailure,
            version_stdout: empty_capture(),
            version_stderr: empty_capture(),
        },
        host: run.host.clone(),
        started_unix_ms: run.started_unix_ms,
        finished_unix_ms: run.finished_unix_ms,
        status: run.status,
        cases: run.cases.clone(),
    }
}

fn build_breakdowns(
    manifest: &HoldoutManifest,
    decisions: &[Phase2CaseDecision],
    records: &[Phase2FindingRecord],
) -> Phase4Breakdowns {
    Phase4Breakdowns {
        taxonomy_family: grouped_metrics(manifest, decisions, records, |pair| {
            pair.taxonomy.category_id.clone()
        }),
        framework: grouped_metrics(manifest, decisions, records, |pair| {
            framework_name(pair.framework).to_owned()
        }),
        language: grouped_metrics(manifest, decisions, records, |pair| {
            language_name(pair.language).to_owned()
        }),
        topology: grouped_metrics(manifest, decisions, records, |pair| {
            topology_name(pair.variation).to_owned()
        }),
    }
}

fn grouped_metrics<F>(
    manifest: &HoldoutManifest,
    decisions: &[Phase2CaseDecision],
    records: &[Phase2FindingRecord],
    group: F,
) -> BTreeMap<String, Phase4GroupMetrics>
where
    F: Fn(&HoldoutPair) -> String,
{
    let pair_by_case = manifest
        .pairs
        .iter()
        .flat_map(|pair| {
            [
                (pair.vulnerable.case_id.as_str(), pair),
                (pair.control.case_id.as_str(), pair),
            ]
        })
        .collect::<BTreeMap<_, _>>();
    let mut grouped = BTreeMap::<String, Vec<&Phase2CaseDecision>>::new();
    for decision in decisions {
        if let Some(pair) = pair_by_case.get(decision.case_id.as_str()) {
            grouped.entry(group(pair)).or_default().push(decision);
        }
    }
    grouped
        .into_iter()
        .map(|(name, decisions)| {
            let case_ids = decisions
                .iter()
                .map(|decision| decision.case_id.as_str())
                .collect::<BTreeSet<_>>();
            let group_records = records
                .iter()
                .filter(|record| case_ids.contains(record.case_id.as_str()))
                .collect::<Vec<_>>();
            (name, group_metric(&decisions, &group_records))
        })
        .collect()
}

fn group_metric(
    decisions: &[&Phase2CaseDecision],
    records: &[&Phase2FindingRecord],
) -> Phase4GroupMetrics {
    let mut metric = Phase4GroupMetrics {
        vulnerable: 0,
        exact: 0,
        partial: 0,
        missed: 0,
        out_of_scope: 0,
        not_attempted: 0,
        controls: 0,
        flagged_controls: 0,
        clean_controls: 0,
        controls_not_attempted: 0,
        distinct_findings: records
            .iter()
            .filter(|record| record.duplicate_of.is_none())
            .count()
            .try_into()
            .unwrap_or(u64::MAX),
        duplicate_findings: records
            .iter()
            .filter(|record| record.duplicate_of.is_some())
            .count()
            .try_into()
            .unwrap_or(u64::MAX),
        precision: ratio(0, 0),
        recall: ratio(0, 0),
        f1: ratio(0, 0),
    };
    for decision in decisions {
        if decision.kind == CaseKind::Vulnerable {
            metric.vulnerable += 1;
            match decision.outcome {
                Phase2Outcome::ExactCanonicalDetection => metric.exact += 1,
                Phase2Outcome::PartialMatch => metric.partial += 1,
                Phase2Outcome::Missed => metric.missed += 1,
                Phase2Outcome::OutOfScope => metric.out_of_scope += 1,
                Phase2Outcome::NotAttempted => metric.not_attempted += 1,
                Phase2Outcome::SafeControlFlagged | Phase2Outcome::SafeControlClean => {}
            }
        } else {
            metric.controls += 1;
            match decision.outcome {
                Phase2Outcome::SafeControlFlagged => metric.flagged_controls += 1,
                Phase2Outcome::SafeControlClean => metric.clean_controls += 1,
                Phase2Outcome::OutOfScope | Phase2Outcome::NotAttempted => {
                    metric.controls_not_attempted += 1;
                }
                Phase2Outcome::ExactCanonicalDetection
                | Phase2Outcome::PartialMatch
                | Phase2Outcome::Missed => {}
            }
        }
    }
    let false_positive_findings = metric.distinct_findings.saturating_sub(metric.exact);
    let false_negatives = metric.vulnerable.saturating_sub(metric.exact);
    metric.precision = ratio(metric.exact, metric.distinct_findings);
    metric.recall = ratio(metric.exact, metric.vulnerable);
    metric.f1 = ratio(
        metric.exact.saturating_mul(2),
        metric
            .exact
            .saturating_mul(2)
            .saturating_add(false_positive_findings)
            .saturating_add(false_negatives),
    );
    metric
}

fn run_measurement(run: &Phase4Run) -> Phase4Measurement {
    let mut status_counts = BTreeMap::new();
    let mut exit_codes = BTreeMap::new();
    let mut completed_cases = 0_u64;
    let mut total_duration_ms = 0_u64;
    let mut peak_rss_bytes = None;
    let mut total_output_bytes = 0_u64;
    for case in &run.cases {
        *status_counts
            .entry(status_name(case.status).to_owned())
            .or_insert(0_u64) += 1;
        completed_cases += u64::from(case.status.is_success());
        total_duration_ms = total_duration_ms.saturating_add(case.duration_ms);
        peak_rss_bytes = maximum_option(peak_rss_bytes, case.peak_memory_bytes);
        total_output_bytes =
            total_output_bytes.saturating_add(case.output_bytes.unwrap_or_default());
        exit_codes.insert(case.case_id.clone(), case.process_exit_code);
    }
    Phase4Measurement {
        run_id: run.run_id.clone(),
        status: run.status,
        cases: run.cases.len().try_into().unwrap_or(u64::MAX),
        completed_cases,
        total_duration_ms,
        runner_duration_ms: run.finished_unix_ms.saturating_sub(run.started_unix_ms),
        peak_rss_bytes,
        total_output_bytes,
        status_counts,
        exit_codes,
    }
}

fn load_phase4_reports(
    run: &Phase4Run,
    run_directory: &Path,
) -> Result<BTreeMap<String, Vec<u8>>, Phase4Error> {
    let expected = run
        .cases
        .iter()
        .filter_map(|case| case.report_path.clone())
        .collect::<BTreeSet<_>>();
    let reports_root = run_directory.join("reports");
    let mut actual = BTreeSet::new();
    for entry in fs::read_dir(&reports_root).map_err(|error| Phase4Error::Io {
        path: reports_root.display().to_string(),
        detail: error.to_string(),
    })? {
        let entry = entry.map_err(|error| Phase4Error::Io {
            path: reports_root.display().to_string(),
            detail: error.to_string(),
        })?;
        let metadata = fs::symlink_metadata(entry.path()).map_err(|error| Phase4Error::Io {
            path: entry.path().display().to_string(),
            detail: error.to_string(),
        })?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(Phase4Error::InvalidContract(
                "run report directory contains a non-regular entry".to_owned(),
            ));
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        actual.insert(format!("reports/{name}"));
    }
    if actual != expected {
        return Err(Phase4Error::InvalidContract(
            "retained report set differs from the run manifest".to_owned(),
        ));
    }
    let mut reports = BTreeMap::new();
    for relative in expected {
        let path = safe_join(run_directory, &relative)?;
        let bytes = read_file(&path)?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > CASE_OUTPUT_BYTES {
            return Err(Phase4Error::InvalidContract(format!(
                "retained report `{relative}` exceeds the frozen limit"
            )));
        }
        reports.insert(relative, bytes);
    }
    Ok(reports)
}

fn report_aggregate(run: &Phase4Run) -> String {
    let mut bytes = Vec::new();
    for case in &run.cases {
        if let Some(digest) = &case.report_fingerprint {
            bytes.extend_from_slice(case.case_id.as_bytes());
            bytes.push(0);
            bytes.extend_from_slice(digest.as_bytes());
            bytes.push(0);
        }
    }
    fingerprint(&bytes)
}

#[derive(Serialize)]
struct StableFinding<'a> {
    finding_id: &'a str,
    case_id: &'a str,
    semantic_fingerprint: &'a str,
    duplicate_of: &'a Option<String>,
    resolved_taxonomy: &'a Option<TaxonomyCoordinates>,
    unmapped_reason: &'a Option<crate::taxonomy::UnmappedReason>,
}

fn semantic_result_fingerprint(
    decisions: &[Phase2CaseDecision],
    records: &[Phase2FindingRecord],
    metrics: &Phase2Metrics,
    breakdowns: &Phase4Breakdowns,
    measurement: &Phase4Measurement,
) -> Result<String, Phase4Error> {
    let findings = records
        .iter()
        .map(|record| StableFinding {
            finding_id: &record.finding_id,
            case_id: &record.case_id,
            semantic_fingerprint: &record.semantic_fingerprint,
            duplicate_of: &record.duplicate_of,
            resolved_taxonomy: &record.resolved_taxonomy,
            unmapped_reason: &record.unmapped_reason,
        })
        .collect::<Vec<_>>();
    let stable_measurement = (
        measurement.status,
        measurement.cases,
        measurement.completed_cases,
        &measurement.status_counts,
        &measurement.exit_codes,
    );
    let bytes = serde_json::to_vec(&(decisions, findings, metrics, breakdowns, stable_measurement))
        .map_err(|_| Phase4Error::Serialization)?;
    Ok(fingerprint(&bytes))
}

fn canonical_taxonomy_bytes(taxonomy: &FrozenTaxonomy) -> Result<Vec<u8>, Phase4Error> {
    crate::taxonomy::canonical_taxonomy_json(taxonomy)
        .map_err(|error| Phase4Error::InvalidContract(error.to_string()))
}

fn contains_private_path(bytes: &[u8]) -> bool {
    let text = String::from_utf8_lossy(bytes);
    text.contains("/home/")
        || text.contains("/Users/")
        || text.contains("danielcastrillon")
        || text.contains("secure-engine/target")
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

fn framework_name(framework: HoldoutFramework) -> &'static str {
    match framework {
        HoldoutFramework::NodeJs => "Node.js",
        HoldoutFramework::Express => "Express",
        HoldoutFramework::NextAppRouter => "Next.js App Router",
        HoldoutFramework::NextServerActions => "Next.js Server Actions",
    }
}

fn language_name(language: HoldoutLanguage) -> &'static str {
    match language {
        HoldoutLanguage::JavaScript => "JavaScript",
        HoldoutLanguage::Jsx => "JSX",
        HoldoutLanguage::TypeScript => "TypeScript",
        HoldoutLanguage::Tsx => "TSX",
    }
}

fn topology_name(variation: HoldoutVariation) -> &'static str {
    match variation {
        HoldoutVariation::Direct => "direct",
        HoldoutVariation::HelperMediated => "helper-mediated",
        HoldoutVariation::InterFileAliased => "inter-file-aliased",
        HoldoutVariation::ControlFlowSensitive => "control-flow-sensitive",
    }
}

fn ratio(numerator: u64, denominator: u64) -> RatioMetric {
    RatioMetric {
        numerator,
        denominator,
        basis_points: if denominator == 0 {
            None
        } else {
            Some(
                u32::try_from(u128::from(numerator) * 10_000 / u128::from(denominator))
                    .unwrap_or(u32::MAX),
            )
        },
    }
}

fn maximum_option(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn read_file(path: &Path) -> Result<Vec<u8>, Phase4Error> {
    fs::read(path).map_err(|error| Phase4Error::Io {
        path: path.display().to_string(),
        detail: error.to_string(),
    })
}

fn validate_relative_path(relative: &str) -> Result<(), Phase4Error> {
    let path = Path::new(relative);
    if relative.is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(Phase4Error::InvalidContract(format!(
            "artifact path `{relative}` is not portable and relative"
        )));
    }
    Ok(())
}

fn safe_join(root: &Path, relative: &str) -> Result<PathBuf, Phase4Error> {
    validate_relative_path(relative)?;
    Ok(root.join(relative))
}

fn rfc3339_now() -> String {
    let seconds = unix_millis() / 1_000;
    let days = i64::try_from(seconds / 86_400).unwrap_or(i64::MAX);
    let seconds_of_day = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
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

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

/// Verifies every retained Phase 4 artifact and deterministically re-evaluates reports without
/// starting a scanner.
///
/// # Errors
///
/// Returns [`Phase4Error`] for any source, schema, artifact, hash, ledger, report, provenance, or
/// deterministic-evaluation mismatch.
pub fn verify_phase4_artifacts(
    request: &Phase4VerificationRequest<'_>,
) -> Result<Phase4Artifacts, Phase4Error> {
    let contract = load_phase4_pre_execution(request.pre_execution_contract)?;
    if fingerprint_regular_file(request.binary)? != PHASE4_BINARY_SHA256
        || fingerprint_regular_file(request.source_rpm)? != PHASE4_RPM_SHA256
        || fingerprint_regular_file(request.benchmark_binary)? != contract.benchmark_binary_sha256
        || evaluator_fingerprints(request.repository_root)? != contract.frozen_evaluator_files
    {
        return Err(Phase4Error::InvalidContract(
            "post-execution artifact or frozen evaluator bytes drifted".to_owned(),
        ));
    }
    let (manifest, validation) =
        load_holdout_manifest(request.manifest, request.repository_root, request.taxonomy)
            .map_err(|error| Phase4Error::InvalidContract(error.to_string()))?;
    let taxonomy = load_taxonomy(request.taxonomy)
        .map_err(|error| Phase4Error::InvalidContract(error.to_string()))?;
    if fingerprint(request.manifest) != PHASE4_MANIFEST_SHA256
        || validation.aggregate_corpus_sha256 != PHASE4_CORPUS_SHA256
        || validation.contract_merkle_root != PHASE4_MERKLE_ROOT
    {
        return Err(Phase4Error::InvalidContract(
            "post-execution holdout commitment drifted".to_owned(),
        ));
    }
    let ledger_entries = validate_holdout_ledger(request.ledger, &manifest)
        .map_err(|error| Phase4Error::InvalidContract(error.to_string()))?;
    let result_sha256 = fingerprint(request.result);
    if ledger_entries.len() != 3
        || ledger_entries[2].event != crate::holdout::HoldoutLedgerEvent::ExecutionCompleted
        || ledger_entries[2].run_id.as_deref() != Some(PHASE4_RUN_ID)
        || ledger_entries[2].result_sha256.as_deref() != Some(result_sha256.as_str())
    {
        return Err(Phase4Error::InvalidContract(
            "completed ledger does not bind the sole result".to_owned(),
        ));
    }
    let run: Phase4Run = parse_canonical_contract(
        request.run,
        "Phase 4 run",
        crate::schema::validate_phase4_run,
    )?;
    validate_run_semantics(&run, &manifest, &contract)?;
    if run.case_journal_sha256
        != fingerprint(&read_file(&request.run_directory.join("cases.jsonl"))?)
    {
        return Err(Phase4Error::InvalidContract(
            "append-only case journal fingerprint differs from the run manifest".to_owned(),
        ));
    }
    let reports = load_phase4_reports(&run, request.run_directory)?;
    let recomputed = evaluate_phase4(
        &manifest,
        &taxonomy,
        &run,
        &reports,
        request.pre_execution_contract,
        request.run,
        &ledger_entries[..2],
        &ledger_entries[1],
    )?;
    let recomputed_bytes = canonical_phase4_json(&recomputed)?;
    if recomputed_bytes != request.result {
        return Err(Phase4Error::InvalidContract(
            "deterministic result re-evaluation differs byte for byte".to_owned(),
        ));
    }
    let result: Phase4Result = parse_canonical_contract(
        request.result,
        "Phase 4 result",
        crate::schema::validate_phase4_result,
    )?;
    if result != recomputed {
        return Err(Phase4Error::InvalidContract(
            "typed result differs from deterministic re-evaluation".to_owned(),
        ));
    }
    let artifacts: Phase4Artifacts = parse_canonical_contract(
        request.artifacts,
        "Phase 4 artifact index",
        crate::schema::validate_phase4_artifacts,
    )?;
    if artifacts.run_id != PHASE4_RUN_ID
        || artifacts.pre_execution_contract_sha256 != fingerprint(request.pre_execution_contract)
        || artifacts.run_sha256 != fingerprint(request.run)
        || artifacts.result_sha256 != fingerprint(request.result)
        || artifacts.ledger_sha256 != fingerprint(request.ledger)
        || artifacts.reports_sha256 != report_aggregate(&run)
        || artifacts.report_count != reports.len().try_into().unwrap_or(u64::MAX)
    {
        return Err(Phase4Error::InvalidContract(
            "final artifact index does not bind every retained artifact".to_owned(),
        ));
    }
    Ok(artifacts)
}

fn parse_canonical_contract<T, F>(bytes: &[u8], label: &str, validate: F) -> Result<T, Phase4Error>
where
    T: for<'de> Deserialize<'de> + Serialize,
    F: Fn(&T) -> Result<(), crate::schema::SchemaError>,
{
    let value: T = serde_json::from_slice(bytes).map_err(|error| {
        Phase4Error::InvalidContract(format!("{label} JSON is invalid at line {}", error.line()))
    })?;
    validate(&value).map_err(|error| Phase4Error::InvalidContract(error.to_string()))?;
    if canonical_phase4_json(&value)? != bytes {
        return Err(Phase4Error::InvalidContract(format!(
            "{label} is not canonical JSON"
        )));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repository_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    fn test_contract(
        manifest: &HoldoutManifest,
        taxonomy: &FrozenTaxonomy,
    ) -> Phase4PreExecutionContract {
        Phase4PreExecutionContract {
            schema_version: PHASE4_PRE_EXECUTION_SCHEMA_V1.to_owned(),
            frozen_at_utc: "2026-07-16T13:00:00Z".to_owned(),
            git_base: PHASE4_GIT_BASE.to_owned(),
            branch: PHASE4_BRANCH.to_owned(),
            run_id: PHASE4_RUN_ID.to_owned(),
            scanner: Phase4ScannerContract {
                declared_version: "Secure Engine 0.1.2 (user-supplied artifact identity)"
                    .to_owned(),
                binary_sha256: PHASE4_BINARY_SHA256.to_owned(),
                source_rpm_sha256: PHASE4_RPM_SHA256.to_owned(),
                command_template: argument_template(),
                report_schema: "secure-json-v1".to_owned(),
                configuration_sha256: EMPTY_SHA256.to_owned(),
                ai_validation: "disabled".to_owned(),
                version_probe: "not-executed".to_owned(),
                environment_clear: true,
            },
            holdout: Phase4HoldoutContract {
                holdout_id: manifest.holdout_id.clone(),
                manifest_sha256: PHASE4_MANIFEST_SHA256.to_owned(),
                ledger_before_sha256: PHASE4_LEDGER_BEFORE_SHA256.to_owned(),
                aggregate_corpus_sha256: PHASE4_CORPUS_SHA256.to_owned(),
                contract_merkle_root: PHASE4_MERKLE_ROOT.to_owned(),
                taxonomy_artifact_sha256: "0".repeat(64),
                taxonomy_content_hash: taxonomy.content_hash.clone(),
                pairs: EXPECTED_PAIRS as u64,
                cases: EXPECTED_CASES as u64,
            },
            resources: Phase4ResourceContract {
                timeout_ms: CASE_TIMEOUT_MS,
                memory_bytes: CASE_MEMORY_BYTES,
                output_bytes: CASE_OUTPUT_BYTES,
                network: "disabled".to_owned(),
            },
            environment: Phase4EnvironmentContract {
                os: "linux".to_owned(),
                architecture: "x86_64".to_owned(),
                kernel_release: "test".to_owned(),
                rust_toolchain: "1.85".to_owned(),
                bwrap_sha256: "0".repeat(64),
                isolation: "bwrap-unshare-net-complete-runner".to_owned(),
                expected_interfaces: vec!["lo".to_owned()],
                probe_target: "1.1.1.1:53".to_owned(),
            },
            benchmark_binary_sha256: "0".repeat(64),
            frozen_evaluator_files: FROZEN_EVALUATOR_FILES
                .into_iter()
                .map(|path| (path.to_owned(), "0".repeat(64)))
                .collect(),
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn mock_only_phase4_evaluation_is_deterministic_and_failure_distinct()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = repository_root();
        let manifest_bytes = fs::read(root.join("holdout/phase-3/manifest.json"))?;
        let taxonomy_bytes = fs::read(root.join("taxonomy/secure-bench-taxonomy-v1.json"))?;
        let ledger_bytes = fs::read(root.join("holdout/phase-3/execution-ledger.jsonl"))?;
        let genesis_ledger_bytes = ledger_bytes
            .split_inclusive(|byte| *byte == b'\n')
            .next()
            .ok_or("Phase 3 genesis ledger entry is missing")?;
        let (manifest, _) = load_holdout_manifest(&manifest_bytes, &root, &taxonomy_bytes)?;
        let taxonomy = load_taxonomy(&taxonomy_bytes)?;
        let contract_bytes = canonical_phase4_json(&test_contract(&manifest, &taxonomy))?;
        load_phase4_pre_execution(&contract_bytes)?;
        let genesis = validate_holdout_ledger(genesis_ledger_bytes, &manifest)?;
        let started = execution_started_ledger_entry(
            &genesis,
            &manifest,
            "2026-07-16T13:01:00Z",
            PHASE4_RUN_ID,
            PHASE4_BINARY_SHA256,
        )?;
        let empty_report = b"{\n  \"schema_version\": \"secure-json-v1\",\n  \"findings\": []\n}\n";
        let report_hash = fingerprint(empty_report);
        let mut cases = manifest
            .pairs
            .iter()
            .flat_map(|pair| [&pair.vulnerable, &pair.control])
            .map(|case| LiveCaseRun {
                case_id: case.case_id.clone(),
                fixture_fingerprint: case.fixture_sha256.clone(),
                status: LiveCaseStatus::Success,
                arguments: [
                    "scan",
                    ".",
                    "--format",
                    "secure-json-v1",
                    "--output",
                    "../.secure-bench-report.json",
                ]
                .map(str::to_owned)
                .to_vec(),
                report_path: Some(format!("reports/{}.json", case.case_id)),
                report_fingerprint: Some(report_hash.clone()),
                started_unix_ms: 1,
                finished_unix_ms: 2,
                duration_ms: 1,
                process_exit_code: Some(0),
                peak_memory_bytes: Some(1),
                output_bytes: Some(u64::try_from(empty_report.len()).unwrap_or(u64::MAX)),
                stdout: empty_capture(),
                stderr: empty_capture(),
                error_code: None,
            })
            .collect::<Vec<_>>();
        cases.sort_by(|left, right| left.case_id.cmp(&right.case_id));
        let reports = cases
            .iter()
            .map(|case| {
                (
                    case.report_path.clone().unwrap_or_default(),
                    empty_report.to_vec(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let run = Phase4Run {
            schema_version: PHASE4_RUN_SCHEMA_V1.to_owned(),
            run_id: PHASE4_RUN_ID.to_owned(),
            holdout_id: manifest.holdout_id.clone(),
            pre_execution_contract_sha256: fingerprint(&contract_bytes),
            binary_sha256: PHASE4_BINARY_SHA256.to_owned(),
            source_rpm_sha256: PHASE4_RPM_SHA256.to_owned(),
            command_template: argument_template(),
            ai_validation: "disabled".to_owned(),
            version_probe_executed: false,
            isolation: Phase4IsolationAttestation {
                mechanism: "bwrap-unshare-net-complete-runner".to_owned(),
                interfaces: vec!["lo".to_owned()],
                outbound_connectivity: "blocked".to_owned(),
                probe_target: "1.1.1.1:53".to_owned(),
            },
            host: HostProvenance {
                os: "linux".to_owned(),
                architecture: "x86_64".to_owned(),
                logical_cpus: None,
                memory_bytes: None,
                kernel_release: Some("test".to_owned()),
            },
            started_unix_ms: 1,
            finished_unix_ms: 2,
            status: LiveRunStatus::Completed,
            case_journal_sha256: "0".repeat(64),
            cases,
        };
        let run_bytes = canonical_phase4_json(&run)?;
        let mut active_ledger = genesis;
        active_ledger.push(started.clone());
        let first = evaluate_phase4(
            &manifest,
            &taxonomy,
            &run,
            &reports,
            &contract_bytes,
            &run_bytes,
            &active_ledger,
            &started,
        )?;
        let second = evaluate_phase4(
            &manifest,
            &taxonomy,
            &run,
            &reports,
            &contract_bytes,
            &run_bytes,
            &active_ledger,
            &started,
        )?;
        assert_eq!(
            canonical_phase4_json(&first)?,
            canonical_phase4_json(&second)?
        );
        assert_eq!(first.metrics.counts.exact_detections, 0);
        assert_eq!(first.metrics.counts.misses, 28);
        assert_eq!(first.metrics.counts.clean_safe_controls, 28);
        assert_eq!(first.metrics.counts.not_attempted, 0);
        Ok(())
    }

    #[test]
    fn portable_paths_and_utc_projection_fail_closed() {
        assert!(validate_relative_path("artifacts/phase-4/result.json").is_ok());
        assert!(validate_relative_path("../result.json").is_err());
        assert!(validate_relative_path("/tmp/result.json").is_err());
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(20_000), (2024, 10, 4));
    }
}
