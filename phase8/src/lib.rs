//! Additive, scanner-free adjudication of the Secure Bench Phase 7 exit-code defect.
//!
//! This crate has no process-launching API. It reads the immutable Phase 7 evidence, applies a
//! prospective tool-neutral process-status policy, and invokes the already-frozen Phase 7
//! evidence-contract-v2 evaluator against retained reports only.

use secure_bench_core::adapter::fingerprint;
use secure_bench_core::phase5::{EvidenceContractV2, Phase5Manifest};
use secure_bench_core::phase7::{
    Phase7Artifacts, Phase7CaseRun, Phase7Ledger, Phase7Result, Phase7Run, canonical_phase7_json,
    evaluate_phase7, load_phase7_ledger, load_phase7_pre_execution,
};
use secure_bench_core::runner::{LiveCaseStatus, LiveRunStatus};
use secure_bench_core::taxonomy::load_taxonomy;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

/// Phase 8 adjudication schema identifier.
pub const PHASE8_RESULT_SCHEMA: &str = "secure-bench-phase8-adjudication-v1";
/// Phase 8 ledger schema identifier.
pub const PHASE8_LEDGER_SCHEMA: &str = "secure-bench-phase8-adjudication-ledger-v1";
/// Phase 8 artifact-index schema identifier.
pub const PHASE8_ARTIFACTS_SCHEMA: &str = "secure-bench-phase8-artifacts-v1";
/// Prospective process-status policy schema identifier.
pub const PROCESS_STATUS_POLICY_SCHEMA: &str = "secure-bench-process-status-policy-v1";
/// Prospective process-status policy semantic version.
pub const PROCESS_STATUS_POLICY_VERSION: &str = "1.0.0";
/// Stable Phase 8 adjudication identity.
pub const PHASE8_ADJUDICATION_ID: &str = "phase-8-exit-code-adjudication";
/// Immutable Phase 7 integration commit.
pub const PHASE7_COMMIT: &str = "421c72cafc8849b7deada92a5788365a5da10d6a";
/// Immutable original Phase 7 result SHA-256.
pub const PHASE7_RESULT_SHA256: &str =
    "5fc423073f11578a2deaf1e21f37e71e72802be17235fd1ad4d7cc0542ea9379";
/// Immutable completed Phase 7 ledger SHA-256.
pub const PHASE7_LEDGER_SHA256: &str =
    "1a11d2d0cb97a800d868e84280fa41ab0b332b367c5c19873faa50603151459e";
/// Immutable Phase 7 report aggregate SHA-256.
pub const PHASE7_REPORT_AGGREGATE_SHA256: &str =
    "f00251036ece1bc6a8370c6c21159d7146d47323534fb4e207675f7c7ecc918d";
/// Immutable raw Phase 7 report-set digest.
pub const PHASE7_RAW_REPORT_SET_DIGEST: &str =
    "cae419c2eb6831919d61b8889088bb2bf376ef5f74e3f929bc672cf65bf3e8da";
/// Immutable Phase 7 case-journal SHA-256.
pub const PHASE7_JOURNAL_SHA256: &str =
    "914ec63dd9ca3c6b4670db030e8a32c65d1f5a2640a8274db1f62704dc5ac513";
/// Immutable Phase 7 run SHA-256.
pub const PHASE7_RUN_SHA256: &str =
    "df0fc817f1aaf54d70dc3faa9e3717201dc31bbcc2ef1540091458cd51a65611";
/// Immutable Phase 7 pre-execution contract SHA-256.
pub const PHASE7_PRE_EXECUTION_SHA256: &str =
    "418d7d592a4748b9457cdd264e01369501b5b1e3c4a09dd276c6555ef3fbd40a";
/// Immutable Phase 7 artifact-index SHA-256.
pub const PHASE7_ARTIFACTS_SHA256: &str =
    "14fbef2e5194970dd424d7ae4b41172b8978ba850a8ca7314ec875dc6f003cbd";

const PHASE7_ROOT: &str = "artifacts/phase-7-secure-engine-0-1-3";
const PHASE7_RUN_PATH: &str = "artifacts/phase-7-secure-engine-0-1-3/run/run.json";
const PHASE7_JOURNAL_PATH: &str = "artifacts/phase-7-secure-engine-0-1-3/run/cases.jsonl";
const PHASE7_REPORTS_PATH: &str = "artifacts/phase-7-secure-engine-0-1-3/run/reports";
const PHASE7_PRE_EXECUTION_PATH: &str =
    "artifacts/phase-7-secure-engine-0-1-3/pre-execution-contract.json";
const PHASE7_ARTIFACTS_PATH: &str = "artifacts/phase-7-secure-engine-0-1-3/artifacts.json";
const PHASE7_RESULT_PATH: &str =
    "holdout/phase-5/results/secure-engine-0-1-3-orthogonal-holdout.json";
const PHASE7_LEDGER_PATH: &str = "holdout/phase-5/execution-ledger.jsonl";
const MANIFEST_PATH: &str = "holdout/phase-5/manifest.json";
const EVIDENCE_CONTRACT_PATH: &str = "holdout/phase-5/evidence-contract-v2.json";
const TAXONOMY_PATH: &str = "taxonomy/secure-bench-taxonomy-v1.json";
const POLICY_PATH: &str = "policies/process-status-v1.json";
const PHASE8_OUTPUT: &str = "artifacts/phase-8-exit-code-adjudication";
const PHASE8_RESULT_PATH: &str = "artifacts/phase-8-exit-code-adjudication/adjudication.json";
const PHASE8_LEDGER_PATH: &str =
    "artifacts/phase-8-exit-code-adjudication/adjudication-ledger.jsonl";
const PHASE8_ARTIFACTS_PATH: &str = "artifacts/phase-8-exit-code-adjudication/artifacts.json";

/// Phase 8 input, validation, or artifact error.
#[derive(Debug, Error)]
pub enum Phase8Error {
    /// Invalid command-line or API request.
    #[error("invalid Phase 8 request: {0}")]
    InvalidRequest(String),
    /// Immutable evidence or a Phase 8 contract differed.
    #[error("invalid Phase 8 contract: {0}")]
    InvalidContract(String),
    /// Filesystem operation failed.
    #[error("Phase 8 filesystem operation failed for `{path}`: {detail}")]
    Io {
        /// Portable path context.
        path: String,
        /// Operating-system detail.
        detail: String,
    },
    /// JSON serialization failed.
    #[error("Phase 8 JSON serialization failed: {0}")]
    Serialization(String),
}

/// Normal process termination evidence available to the policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessTermination {
    /// The process exited normally with the recorded code.
    Exited(i32),
    /// The process was terminated by a signal.
    Signaled,
    /// The wall-clock deadline terminated the process.
    Timeout,
    /// The process could not be started or monitored reliably.
    ExecutionFailure,
}

/// Adapter/report evidence available to the policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReportAssessment {
    /// No report file was produced.
    Missing,
    /// The output was malformed, unsupported, or adapter-invalid.
    Malformed,
    /// The report was incomplete or declared scanner-internal errors.
    InternallyErrored,
    /// The report was complete, internally error-free, and adapter-valid.
    AdapterValid {
        /// Number of raw findings in the authoritative report.
        findings: u64,
    },
}

/// Prospective process-status policy decision.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessStatusDecision {
    /// Exit code zero and an authoritative empty report.
    CleanSuccessfulReport,
    /// Exit code zero and an authoritative report containing findings.
    SuccessfulFindingsReport,
    /// A nonzero normal exit with an authoritative report containing findings.
    PolicyExitWithValidFindingsReport,
    /// Signal, execution failure, or nonzero exit without an authoritative findings report.
    GenuineCrash,
    /// Wall-clock termination.
    Timeout,
    /// Missing output.
    MissingReport,
    /// Malformed, unsupported, privacy-unsafe, or adapter-invalid output.
    MalformedReport,
    /// Incomplete output or output declaring scanner-internal errors.
    InternallyErroredReport,
}

impl ProcessStatusDecision {
    const fn live_status(self) -> LiveCaseStatus {
        match self {
            Self::CleanSuccessfulReport => LiveCaseStatus::Success,
            Self::SuccessfulFindingsReport | Self::PolicyExitWithValidFindingsReport => {
                LiveCaseStatus::Findings
            }
            Self::GenuineCrash => LiveCaseStatus::Crash,
            Self::Timeout => LiveCaseStatus::Timeout,
            Self::MissingReport | Self::MalformedReport | Self::InternallyErroredReport => {
                LiveCaseStatus::InvalidOutput
            }
        }
    }

    const fn error_code(self) -> Option<&'static str> {
        match self {
            Self::CleanSuccessfulReport
            | Self::SuccessfulFindingsReport
            | Self::PolicyExitWithValidFindingsReport => None,
            Self::GenuineCrash => Some("phase8.genuine_crash"),
            Self::Timeout => Some("phase8.timeout"),
            Self::MissingReport => Some("phase8.missing_report"),
            Self::MalformedReport => Some("phase8.malformed_report"),
            Self::InternallyErroredReport => Some("phase8.internally_errored_report"),
        }
    }
}

/// Applies the tool-neutral prospective process-status policy.
#[must_use]
pub const fn adjudicate_status(
    termination: ProcessTermination,
    report: ReportAssessment,
) -> ProcessStatusDecision {
    match termination {
        ProcessTermination::Timeout => ProcessStatusDecision::Timeout,
        ProcessTermination::Signaled | ProcessTermination::ExecutionFailure => {
            ProcessStatusDecision::GenuineCrash
        }
        ProcessTermination::Exited(code) => match report {
            ReportAssessment::Missing => ProcessStatusDecision::MissingReport,
            ReportAssessment::Malformed => ProcessStatusDecision::MalformedReport,
            ReportAssessment::InternallyErrored => ProcessStatusDecision::InternallyErroredReport,
            ReportAssessment::AdapterValid { findings } => {
                if findings == 0 {
                    if code == 0 {
                        ProcessStatusDecision::CleanSuccessfulReport
                    } else {
                        ProcessStatusDecision::GenuineCrash
                    }
                } else if code == 0 {
                    ProcessStatusDecision::SuccessfulFindingsReport
                } else {
                    ProcessStatusDecision::PolicyExitWithValidFindingsReport
                }
            }
        },
    }
}

/// Versioned public process-status policy document.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessStatusPolicy {
    /// Schema identity.
    pub schema_version: String,
    /// Semantic policy version.
    pub policy_version: String,
    /// Tool-neutral scope statement.
    pub scope: String,
    /// Ordered policy precedence.
    pub precedence: Vec<String>,
    /// Required invariants.
    pub invariants: Vec<String>,
    /// Public status definitions.
    pub statuses: BTreeMap<String, String>,
}

/// Exact immutable Phase 7 inputs used by Phase 8.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase8Evidence {
    /// Phase 7 integration commit.
    pub phase7_commit: String,
    /// Original result SHA-256.
    pub original_result_sha256: String,
    /// Completed Phase 7 ledger SHA-256.
    pub completed_ledger_sha256: String,
    /// Original case journal SHA-256.
    pub case_journal_sha256: String,
    /// Original run SHA-256.
    pub run_sha256: String,
    /// Original pre-execution contract SHA-256.
    pub pre_execution_contract_sha256: String,
    /// Original artifact index SHA-256.
    pub artifact_index_sha256: String,
    /// Report aggregate bound by the original artifact index.
    pub report_aggregate_sha256: String,
    /// Independent byte digest over all raw report paths and hashes.
    pub raw_report_set_digest: String,
    /// Retained report count.
    pub report_count: u64,
}

/// Root-cause statement embedded in the adjudication record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase8RootCause {
    /// Source location of the defective gating condition.
    pub source_location: String,
    /// Defective condition.
    pub condition: String,
    /// Consequence in the preregistered result.
    pub effect: String,
    /// Existing public contracts that already defined report authority.
    pub authoritative_contracts: Vec<String>,
}

/// One report-to-outcome derivation with no source code or scanner prose.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase8CaseDerivation {
    /// Frozen case identity.
    pub case_id: String,
    /// Exactly one original retained report.
    pub report_sha256: String,
    /// Recorded normal exit code.
    pub process_exit_code: i32,
    /// Original Phase 7 status.
    pub original_status: LiveCaseStatus,
    /// Corrected prospective policy decision.
    pub policy_status: ProcessStatusDecision,
    /// Status projected into the frozen evaluator.
    pub corrected_status: LiveCaseStatus,
    /// Raw finding count.
    pub raw_findings: u64,
    /// Full frozen Phase 7 adapter validation succeeded.
    pub adapter_valid: bool,
    /// Scanner-internal error count.
    pub scanner_internal_errors: u64,
}

/// Aggregate exit/report correlation proof.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase8Correlation {
    /// Exit-code-zero executions.
    pub exit_code_zero: u64,
    /// Adapter-valid exit-code-zero reports.
    pub exit_code_zero_adapter_valid: u64,
    /// Exit-code-one executions.
    pub exit_code_one: u64,
    /// Adapter-valid exit-code-one reports containing findings.
    pub exit_code_one_adapter_valid_with_findings: u64,
    /// Reports declaring scanner-internal errors.
    pub reports_with_internal_errors: u64,
    /// Corrected policy status counts.
    pub corrected_status_counts: BTreeMap<String, u64>,
}

/// Static proof that Phase 8 has no scanner execution path.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase8ProcessAudit {
    /// Execution mode.
    pub mode: String,
    /// Number of scanner processes launched.
    pub scanner_processes_launched: u64,
    /// Whether a scanner binary was opened or inspected.
    pub scanner_binary_accessed: bool,
    /// Whether network access was requested.
    pub network_access_requested: bool,
    /// Sole evidence source.
    pub evidence_source: String,
}

/// Complete additive retrospective adjudication record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase8AdjudicationResult {
    /// Schema identity.
    pub schema_version: String,
    /// Stable adjudication identity.
    pub adjudication_id: String,
    /// Explicit non-execution interpretation.
    pub interpretation: String,
    /// Prospective status-policy version.
    pub process_status_policy_version: String,
    /// Policy artifact SHA-256.
    pub process_status_policy_sha256: String,
    /// Immutable Phase 7 evidence.
    pub phase7_evidence: Phase8Evidence,
    /// Confirmed root cause.
    pub root_cause: Phase8RootCause,
    /// Exit/report correlation proof.
    pub correlation: Phase8Correlation,
    /// Exactly one derivation per retained report.
    pub cases: Vec<Phase8CaseDerivation>,
    /// Frozen matcher output over the corrected in-memory status projection.
    pub corrected_evaluation: Phase7Result,
    /// Original preregistered Phase 7 result, unchanged.
    pub original_phase7_result: Phase7Result,
    /// Hash of the corrected in-memory run projection.
    pub corrected_run_projection_sha256: String,
    /// No-process audit.
    pub process_audit: Phase8ProcessAudit,
}

/// Phase 8 adjudication-ledger event.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase8LedgerEvent {
    /// Separate adjudication lifecycle began.
    AdjudicationStarted,
    /// One retained report was adjudicated.
    CaseAdjudicated,
    /// The deterministic result was bound terminally.
    AdjudicationCompleted,
}

/// One entry in the separate Phase 8 hash chain.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase8LedgerEntry {
    /// Schema identity.
    pub schema_version: String,
    /// Contiguous sequence.
    pub sequence: u64,
    /// Lifecycle event.
    pub event: Phase8LedgerEvent,
    /// Adjudication identity.
    pub adjudication_id: String,
    /// Immutable original result hash.
    pub phase7_result_sha256: String,
    /// Immutable original ledger hash.
    pub phase7_ledger_sha256: String,
    /// Immutable report aggregate.
    pub phase7_report_aggregate_sha256: String,
    /// Immutable raw report-set digest.
    pub phase7_raw_report_set_digest: String,
    /// Prospective policy hash.
    pub process_status_policy_sha256: String,
    /// Previous entry hash.
    pub previous_entry_hash: String,
    /// Case identity for a case event.
    pub case_id: Option<String>,
    /// Original report hash for a case event.
    pub report_sha256: Option<String>,
    /// Canonical case-derivation hash.
    pub derivation_sha256: Option<String>,
    /// Terminal result hash.
    pub result_sha256: Option<String>,
    /// Hash of this entry excluding this field.
    pub entry_hash: String,
}

#[derive(Serialize)]
struct Phase8LedgerHashMaterial<'a> {
    schema_version: &'a str,
    sequence: u64,
    event: Phase8LedgerEvent,
    adjudication_id: &'a str,
    phase7_result_sha256: &'a str,
    phase7_ledger_sha256: &'a str,
    phase7_report_aggregate_sha256: &'a str,
    phase7_raw_report_set_digest: &'a str,
    process_status_policy_sha256: &'a str,
    previous_entry_hash: &'a str,
    case_id: &'a Option<String>,
    report_sha256: &'a Option<String>,
    derivation_sha256: &'a Option<String>,
    result_sha256: &'a Option<String>,
}

/// Artifact index binding the separate Phase 8 lifecycle.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase8Artifacts {
    /// Schema identity.
    pub schema_version: String,
    /// Adjudication identity.
    pub adjudication_id: String,
    /// Policy path.
    pub process_status_policy_path: String,
    /// Policy SHA-256.
    pub process_status_policy_sha256: String,
    /// Result path.
    pub result_path: String,
    /// Result SHA-256.
    pub result_sha256: String,
    /// Separate ledger path.
    pub ledger_path: String,
    /// Separate ledger SHA-256.
    pub ledger_sha256: String,
    /// Entry count.
    pub ledger_entries: u64,
    /// Immutable Phase 7 result reference.
    pub phase7_result_sha256: String,
    /// Immutable Phase 7 ledger reference.
    pub phase7_ledger_sha256: String,
    /// Immutable report aggregate reference.
    pub phase7_report_aggregate_sha256: String,
    /// Immutable raw report-set digest reference.
    pub phase7_raw_report_set_digest: String,
    /// Retained reports consumed offline.
    pub report_count: u64,
    /// Explicit process audit result.
    pub scanner_processes_launched: u64,
}

/// Canonical rendered Phase 8 artifacts before filesystem publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenderedPhase8 {
    /// Typed result.
    pub result: Phase8AdjudicationResult,
    /// Canonical result bytes.
    pub result_bytes: Vec<u8>,
    /// Typed ledger.
    pub ledger: Vec<Phase8LedgerEntry>,
    /// Canonical JSON Lines ledger bytes.
    pub ledger_bytes: Vec<u8>,
    /// Typed artifact index.
    pub artifacts: Phase8Artifacts,
    /// Canonical artifact-index bytes.
    pub artifacts_bytes: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct ReportEnvelope {
    schema_version: String,
    scan: Option<ReportScan>,
    #[serde(default)]
    errors: Vec<serde_json::Value>,
    #[serde(default)]
    findings: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct ReportScan {
    complete: bool,
}

fn io_error(path: &Path, error: &std::io::Error) -> Phase8Error {
    Phase8Error::Io {
        path: path.to_string_lossy().to_string(),
        detail: error.to_string(),
    }
}

fn read(root: &Path, relative: &str) -> Result<Vec<u8>, Phase8Error> {
    let path = safe_join(root, relative)?;
    fs::read(&path).map_err(|error| io_error(&path, &error))
}

fn safe_join(root: &Path, relative: &str) -> Result<PathBuf, Phase8Error> {
    let path = Path::new(relative);
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(Phase8Error::InvalidContract(format!(
            "unsafe relative path `{relative}`"
        )));
    }
    Ok(root.join(path))
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, Phase8Error> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| Phase8Error::Serialization(error.to_string()))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn compact_json<T: Serialize>(value: &T) -> Result<Vec<u8>, Phase8Error> {
    serde_json::to_vec(value).map_err(|error| Phase8Error::Serialization(error.to_string()))
}

fn verify_hash(label: &str, bytes: &[u8], expected: &str) -> Result<(), Phase8Error> {
    let actual = fingerprint(bytes);
    if actual != expected {
        return Err(Phase8Error::InvalidContract(format!(
            "{label} SHA-256 differs: expected {expected}, observed {actual}"
        )));
    }
    Ok(())
}

fn collect_regular_files(
    root: &Path,
    relative: &Path,
    output: &mut Vec<PathBuf>,
) -> Result<(), Phase8Error> {
    let directory = root.join(relative);
    let metadata =
        fs::symlink_metadata(&directory).map_err(|error| io_error(&directory, &error))?;
    if metadata.file_type().is_symlink() {
        return Err(Phase8Error::InvalidContract(format!(
            "symlink is forbidden in evidence tree `{}`",
            relative.display()
        )));
    }
    if metadata.is_file() {
        output.push(relative.to_path_buf());
        return Ok(());
    }
    if !metadata.is_dir() {
        return Err(Phase8Error::InvalidContract(format!(
            "non-regular evidence entry `{}`",
            relative.display()
        )));
    }
    let mut entries = fs::read_dir(&directory)
        .map_err(|error| io_error(&directory, &error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| io_error(&directory, &error))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        collect_regular_files(root, &relative.join(entry.file_name()), output)?;
    }
    Ok(())
}

fn file_hash(root: &Path, relative: &Path) -> Result<String, Phase8Error> {
    let path = root.join(relative);
    let metadata = fs::symlink_metadata(&path).map_err(|error| io_error(&path, &error))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(Phase8Error::InvalidContract(format!(
            "evidence file is not a regular file `{}`",
            relative.display()
        )));
    }
    fs::read(&path)
        .map(|bytes| fingerprint(&bytes))
        .map_err(|error| io_error(&path, &error))
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn tree_fingerprint(root: &Path, relative: &str) -> Result<String, Phase8Error> {
    let mut files = Vec::new();
    collect_regular_files(root, Path::new(relative), &mut files)?;
    files.sort();
    let mut hasher = Sha256::new();
    for path in files {
        hasher.update(path.to_string_lossy().replace('\\', "/").as_bytes());
        hasher.update([0]);
        hasher.update(file_hash(root, &path)?.as_bytes());
        hasher.update([b'\n']);
    }
    Ok(hex_digest(&hasher.finalize()))
}

fn phase5_frozen_tree_fingerprint(root: &Path) -> Result<String, Phase8Error> {
    let mut files = Vec::new();
    collect_regular_files(root, Path::new("holdout/phase-5"), &mut files)?;
    files.retain(|path| {
        path != Path::new(PHASE7_LEDGER_PATH) && !path.starts_with("holdout/phase-5/results")
    });
    files.sort();
    let mut hasher = Sha256::new();
    for path in files {
        hasher.update(path.to_string_lossy().replace('\\', "/").as_bytes());
        hasher.update([0]);
        hasher.update(file_hash(root, &path)?.as_bytes());
        hasher.update([b'\n']);
    }
    Ok(hex_digest(&hasher.finalize()))
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

fn raw_report_set_digest(root: &Path) -> Result<String, Phase8Error> {
    let mut files = Vec::new();
    collect_regular_files(root, Path::new(PHASE7_REPORTS_PATH), &mut files)?;
    files.sort();
    let mut hasher = Sha256::new();
    for path in files {
        let hash = file_hash(root, &path)?;
        hasher.update(hash.as_bytes());
        hasher.update(b"  ");
        hasher.update(path.to_string_lossy().replace('\\', "/").as_bytes());
        hasher.update([b'\n']);
    }
    Ok(hex_digest(&hasher.finalize()))
}

const fn policy_status_name(status: ProcessStatusDecision) -> &'static str {
    match status {
        ProcessStatusDecision::CleanSuccessfulReport => "clean_successful_report",
        ProcessStatusDecision::SuccessfulFindingsReport => "successful_findings_report",
        ProcessStatusDecision::PolicyExitWithValidFindingsReport => {
            "policy_exit_with_valid_findings_report"
        }
        ProcessStatusDecision::GenuineCrash => "genuine_crash",
        ProcessStatusDecision::Timeout => "timeout",
        ProcessStatusDecision::MissingReport => "missing_report",
        ProcessStatusDecision::MalformedReport => "malformed_report",
        ProcessStatusDecision::InternallyErroredReport => "internally_errored_report",
    }
}

fn validate_policy(policy: &ProcessStatusPolicy) -> Result<(), Phase8Error> {
    let required = [
        "clean_successful_report",
        "genuine_crash",
        "internally_errored_report",
        "malformed_report",
        "missing_report",
        "policy_exit_with_valid_findings_report",
        "successful_findings_report",
        "timeout",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();
    if policy.schema_version != PROCESS_STATUS_POLICY_SCHEMA
        || policy.policy_version != PROCESS_STATUS_POLICY_VERSION
        || policy.precedence.len() != 4
        || policy.invariants.len() < 4
        || policy.statuses.keys().cloned().collect::<BTreeSet<_>>() != required
    {
        return Err(Phase8Error::InvalidContract(
            "prospective process-status policy is incomplete or changed".to_owned(),
        ));
    }
    Ok(())
}

fn preliminary_report_assessment(bytes: &[u8]) -> ReportAssessment {
    let Ok(report) = serde_json::from_slice::<ReportEnvelope>(bytes) else {
        return ReportAssessment::Malformed;
    };
    if report.schema_version != "secure-json-v1" {
        return ReportAssessment::Malformed;
    }
    if !report.scan.is_some_and(|scan| scan.complete) || !report.errors.is_empty() {
        return ReportAssessment::InternallyErrored;
    }
    ReportAssessment::AdapterValid {
        findings: u64::try_from(report.findings.len()).unwrap_or(u64::MAX),
    }
}

fn termination(case: &Phase7CaseRun) -> Result<ProcessTermination, Phase8Error> {
    match case.execution.status {
        LiveCaseStatus::Timeout => Ok(ProcessTermination::Timeout),
        LiveCaseStatus::ExecutionFailure | LiveCaseStatus::Cancelled => {
            Ok(ProcessTermination::ExecutionFailure)
        }
        _ => case
            .execution
            .process_exit_code
            .map(ProcessTermination::Exited)
            .ok_or_else(|| {
                Phase8Error::InvalidContract(format!(
                    "recorded case `{}` lacks normal-exit evidence",
                    case.execution.case_id
                ))
            }),
    }
}

struct LoadedEvidence {
    manifest: Phase5Manifest,
    evidence_contract: EvidenceContractV2,
    taxonomy: secure_bench_core::taxonomy::FrozenTaxonomy,
    pre_execution: secure_bench_core::phase7::Phase7PreExecutionContract,
    pre_execution_bytes: Vec<u8>,
    run: Phase7Run,
    original_result: Phase7Result,
    ledger: Phase7Ledger,
    reports: BTreeMap<String, Vec<u8>>,
    policy: ProcessStatusPolicy,
    policy_bytes: Vec<u8>,
}

#[allow(clippy::too_many_lines)]
fn load_evidence(root: &Path) -> Result<LoadedEvidence, Phase8Error> {
    let result_bytes = read(root, PHASE7_RESULT_PATH)?;
    let ledger_bytes = read(root, PHASE7_LEDGER_PATH)?;
    let journal_bytes = read(root, PHASE7_JOURNAL_PATH)?;
    let run_bytes = read(root, PHASE7_RUN_PATH)?;
    let pre_execution_bytes = read(root, PHASE7_PRE_EXECUTION_PATH)?;
    let artifacts_bytes = read(root, PHASE7_ARTIFACTS_PATH)?;
    verify_hash(
        "original Phase 7 result",
        &result_bytes,
        PHASE7_RESULT_SHA256,
    )?;
    verify_hash(
        "completed Phase 7 ledger",
        &ledger_bytes,
        PHASE7_LEDGER_SHA256,
    )?;
    verify_hash(
        "Phase 7 case journal",
        &journal_bytes,
        PHASE7_JOURNAL_SHA256,
    )?;
    verify_hash("Phase 7 run", &run_bytes, PHASE7_RUN_SHA256)?;
    verify_hash(
        "Phase 7 pre-execution contract",
        &pre_execution_bytes,
        PHASE7_PRE_EXECUTION_SHA256,
    )?;
    verify_hash(
        "Phase 7 artifact index",
        &artifacts_bytes,
        PHASE7_ARTIFACTS_SHA256,
    )?;

    let run: Phase7Run = serde_json::from_slice(&run_bytes)
        .map_err(|error| Phase8Error::InvalidContract(error.to_string()))?;
    let original_result: Phase7Result = serde_json::from_slice(&result_bytes)
        .map_err(|error| Phase8Error::InvalidContract(error.to_string()))?;
    let artifacts: Phase7Artifacts = serde_json::from_slice(&artifacts_bytes)
        .map_err(|error| Phase8Error::InvalidContract(error.to_string()))?;
    if artifacts.result_sha256 != PHASE7_RESULT_SHA256
        || artifacts.ledger_sha256 != PHASE7_LEDGER_SHA256
        || artifacts.case_journal_sha256 != PHASE7_JOURNAL_SHA256
        || artifacts.run_sha256 != PHASE7_RUN_SHA256
        || artifacts.pre_execution_contract_sha256 != PHASE7_PRE_EXECUTION_SHA256
        || artifacts.reports_sha256 != PHASE7_REPORT_AGGREGATE_SHA256
        || artifacts.report_count != 112
        || report_aggregate(&run) != PHASE7_REPORT_AGGREGATE_SHA256
        || raw_report_set_digest(root)? != PHASE7_RAW_REPORT_SET_DIGEST
    {
        return Err(Phase8Error::InvalidContract(
            "Phase 7 artifact bindings or report digests differ".to_owned(),
        ));
    }

    let pre_execution = load_phase7_pre_execution(&pre_execution_bytes)
        .map_err(|error| Phase8Error::InvalidContract(error.to_string()))?;
    for (path, expected) in &pre_execution.phase7_evaluator_files {
        let actual = file_hash(root, Path::new(path))?;
        if &actual != expected {
            return Err(Phase8Error::InvalidContract(format!(
                "frozen Phase 7 evaluator file `{path}` differs"
            )));
        }
    }
    for (path, expected) in &pre_execution.historical_artifacts {
        let actual = tree_fingerprint(root, path)?;
        if &actual != expected {
            return Err(Phase8Error::InvalidContract(format!(
                "historical artifact tree `{path}` differs"
            )));
        }
    }
    if phase5_frozen_tree_fingerprint(root)? != pre_execution.holdout.frozen_tree_sha256 {
        return Err(Phase8Error::InvalidContract(
            "frozen Phase 5 holdout tree differs".to_owned(),
        ));
    }

    let manifest: Phase5Manifest = serde_json::from_slice(&read(root, MANIFEST_PATH)?)
        .map_err(|error| Phase8Error::InvalidContract(error.to_string()))?;
    let evidence_contract: EvidenceContractV2 =
        serde_json::from_slice(&read(root, EVIDENCE_CONTRACT_PATH)?)
            .map_err(|error| Phase8Error::InvalidContract(error.to_string()))?;
    let taxonomy = load_taxonomy(&read(root, TAXONOMY_PATH)?)
        .map_err(|error| Phase8Error::InvalidContract(error.to_string()))?;
    let ledger = load_phase7_ledger(&ledger_bytes)
        .map_err(|error| Phase8Error::InvalidContract(error.to_string()))?;
    if ledger.entries.len() != 114 {
        return Err(Phase8Error::InvalidContract(
            "completed Phase 7 ledger lifecycle differs".to_owned(),
        ));
    }

    let mut reports = BTreeMap::new();
    for case in &run.cases {
        let relative = case.execution.report_path.as_deref().ok_or_else(|| {
            Phase8Error::InvalidContract(format!(
                "Phase 7 case `{}` lacks its retained report",
                case.execution.case_id
            ))
        })?;
        let expected = format!("reports/{}.json", case.execution.case_id);
        if relative != expected {
            return Err(Phase8Error::InvalidContract(
                "retained report path does not match case identity".to_owned(),
            ));
        }
        let bytes = read(root, &format!("{PHASE7_ROOT}/run/{relative}"))?;
        let hash = fingerprint(&bytes);
        if case.execution.report_fingerprint.as_deref() != Some(hash.as_str()) {
            return Err(Phase8Error::InvalidContract(format!(
                "retained report hash differs for `{}`",
                case.execution.case_id
            )));
        }
        reports.insert(case.execution.case_id.clone(), bytes);
    }
    if reports.len() != 112 {
        return Err(Phase8Error::InvalidContract(
            "Phase 8 requires exactly 112 original reports".to_owned(),
        ));
    }

    let policy_bytes = read(root, POLICY_PATH)?;
    let policy: ProcessStatusPolicy = serde_json::from_slice(&policy_bytes)
        .map_err(|error| Phase8Error::InvalidContract(error.to_string()))?;
    validate_policy(&policy)?;
    Ok(LoadedEvidence {
        manifest,
        evidence_contract,
        taxonomy,
        pre_execution,
        pre_execution_bytes,
        run,
        original_result,
        ledger,
        reports,
        policy,
        policy_bytes,
    })
}

fn corrected_projection(
    evidence: &LoadedEvidence,
) -> Result<(Phase7Run, Vec<Phase8CaseDerivation>, Phase8Correlation), Phase8Error> {
    let mut corrected = evidence.run.clone();
    let mut derivations = Vec::with_capacity(corrected.cases.len());
    let mut exit_zero = 0_u64;
    let mut exit_one = 0_u64;
    let mut exit_zero_valid = 0_u64;
    let mut exit_one_valid_findings = 0_u64;
    let mut internal_error_reports = 0_u64;
    let mut status_counts = BTreeMap::<String, u64>::new();
    for case in &mut corrected.cases {
        let report = evidence
            .reports
            .get(&case.execution.case_id)
            .ok_or_else(|| Phase8Error::InvalidContract("report map is incomplete".to_owned()))?;
        let envelope: ReportEnvelope = serde_json::from_slice(report)
            .map_err(|_| Phase8Error::InvalidContract("retained report is malformed".to_owned()))?;
        let raw_findings = u64::try_from(envelope.findings.len()).unwrap_or(u64::MAX);
        let internal_errors = u64::try_from(envelope.errors.len()).unwrap_or(u64::MAX);
        let assessment = preliminary_report_assessment(report);
        let process = termination(case)?;
        let policy_status = adjudicate_status(process, assessment);
        let exit_code = case.execution.process_exit_code.ok_or_else(|| {
            Phase8Error::InvalidContract("Phase 7 case lacks its recorded exit code".to_owned())
        })?;
        match exit_code {
            0 => {
                exit_zero += 1;
                if matches!(assessment, ReportAssessment::AdapterValid { .. }) {
                    exit_zero_valid += 1;
                }
            }
            1 => {
                exit_one += 1;
                if matches!(assessment, ReportAssessment::AdapterValid { findings } if findings > 0)
                {
                    exit_one_valid_findings += 1;
                }
            }
            _ => {
                return Err(Phase8Error::InvalidContract(
                    "Phase 7 contains an unpreregistered exit-code population".to_owned(),
                ));
            }
        }
        internal_error_reports += u64::from(internal_errors > 0);
        let original_status = case.execution.status;
        let corrected_status = policy_status.live_status();
        case.execution.status = corrected_status;
        case.execution.error_code = policy_status.error_code().map(str::to_owned);
        *status_counts
            .entry(policy_status_name(policy_status).to_owned())
            .or_default() += 1;
        derivations.push(Phase8CaseDerivation {
            case_id: case.execution.case_id.clone(),
            report_sha256: case
                .execution
                .report_fingerprint
                .clone()
                .ok_or_else(|| Phase8Error::InvalidContract("report hash missing".to_owned()))?,
            process_exit_code: exit_code,
            original_status,
            policy_status,
            corrected_status,
            raw_findings,
            adapter_valid: true,
            scanner_internal_errors: internal_errors,
        });
    }
    corrected.status = LiveRunStatus::Completed;
    let derivation_bytes = canonical_json(&derivations)?;
    corrected.case_journal_sha256 = fingerprint(&derivation_bytes);
    derivations.sort_by(|left, right| left.case_id.cmp(&right.case_id));
    if exit_zero != 79
        || exit_one != 33
        || exit_zero_valid != 79
        || exit_one_valid_findings != 33
        || internal_error_reports != 0
    {
        return Err(Phase8Error::InvalidContract(
            "exit/report correlation differs from the immutable Phase 7 evidence".to_owned(),
        ));
    }
    Ok((
        corrected,
        derivations,
        Phase8Correlation {
            exit_code_zero: exit_zero,
            exit_code_zero_adapter_valid: exit_zero_valid,
            exit_code_one: exit_one,
            exit_code_one_adapter_valid_with_findings: exit_one_valid_findings,
            reports_with_internal_errors: internal_error_reports,
            corrected_status_counts: status_counts,
        },
    ))
}

fn ledger_entry(
    sequence: u64,
    event: Phase8LedgerEvent,
    policy_hash: &str,
    previous_entry_hash: &str,
    case: Option<&Phase8CaseDerivation>,
    result_sha256: Option<String>,
) -> Result<Phase8LedgerEntry, Phase8Error> {
    let case_id = case.map(|value| value.case_id.clone());
    let report_sha256 = case.map(|value| value.report_sha256.clone());
    let derivation_sha256 = case
        .map(canonical_json)
        .transpose()?
        .map(|bytes| fingerprint(&bytes));
    let material = Phase8LedgerHashMaterial {
        schema_version: PHASE8_LEDGER_SCHEMA,
        sequence,
        event,
        adjudication_id: PHASE8_ADJUDICATION_ID,
        phase7_result_sha256: PHASE7_RESULT_SHA256,
        phase7_ledger_sha256: PHASE7_LEDGER_SHA256,
        phase7_report_aggregate_sha256: PHASE7_REPORT_AGGREGATE_SHA256,
        phase7_raw_report_set_digest: PHASE7_RAW_REPORT_SET_DIGEST,
        process_status_policy_sha256: policy_hash,
        previous_entry_hash,
        case_id: &case_id,
        report_sha256: &report_sha256,
        derivation_sha256: &derivation_sha256,
        result_sha256: &result_sha256,
    };
    let entry_hash = fingerprint(&compact_json(&material)?);
    Ok(Phase8LedgerEntry {
        schema_version: PHASE8_LEDGER_SCHEMA.to_owned(),
        sequence,
        event,
        adjudication_id: PHASE8_ADJUDICATION_ID.to_owned(),
        phase7_result_sha256: PHASE7_RESULT_SHA256.to_owned(),
        phase7_ledger_sha256: PHASE7_LEDGER_SHA256.to_owned(),
        phase7_report_aggregate_sha256: PHASE7_REPORT_AGGREGATE_SHA256.to_owned(),
        phase7_raw_report_set_digest: PHASE7_RAW_REPORT_SET_DIGEST.to_owned(),
        process_status_policy_sha256: policy_hash.to_owned(),
        previous_entry_hash: previous_entry_hash.to_owned(),
        case_id,
        report_sha256,
        derivation_sha256,
        result_sha256,
        entry_hash,
    })
}

fn build_ledger(
    policy_hash: &str,
    derivations: &[Phase8CaseDerivation],
    result_hash: &str,
) -> Result<Vec<Phase8LedgerEntry>, Phase8Error> {
    let mut entries = Vec::with_capacity(114);
    entries.push(ledger_entry(
        0,
        Phase8LedgerEvent::AdjudicationStarted,
        policy_hash,
        &"0".repeat(64),
        None,
        None,
    )?);
    for (index, derivation) in derivations.iter().enumerate() {
        let previous = entries
            .last()
            .map(|entry| entry.entry_hash.clone())
            .ok_or_else(|| Phase8Error::InvalidContract("ledger genesis missing".to_owned()))?;
        entries.push(ledger_entry(
            u64::try_from(index + 1).unwrap_or(u64::MAX),
            Phase8LedgerEvent::CaseAdjudicated,
            policy_hash,
            &previous,
            Some(derivation),
            None,
        )?);
    }
    let previous = entries
        .last()
        .map(|entry| entry.entry_hash.clone())
        .ok_or_else(|| Phase8Error::InvalidContract("ledger cases missing".to_owned()))?;
    entries.push(ledger_entry(
        113,
        Phase8LedgerEvent::AdjudicationCompleted,
        policy_hash,
        &previous,
        None,
        Some(result_hash.to_owned()),
    )?);
    Ok(entries)
}

fn ledger_bytes(entries: &[Phase8LedgerEntry]) -> Result<Vec<u8>, Phase8Error> {
    let mut bytes = Vec::new();
    for entry in entries {
        bytes.extend(compact_json(entry)?);
        bytes.push(b'\n');
    }
    Ok(bytes)
}

fn validate_ledger(entries: &[Phase8LedgerEntry], result_hash: &str) -> Result<(), Phase8Error> {
    if entries.len() != 114
        || entries.first().map(|entry| entry.event) != Some(Phase8LedgerEvent::AdjudicationStarted)
        || entries.last().map(|entry| entry.event) != Some(Phase8LedgerEvent::AdjudicationCompleted)
        || entries
            .iter()
            .skip(1)
            .take(112)
            .any(|entry| entry.event != Phase8LedgerEvent::CaseAdjudicated)
    {
        return Err(Phase8Error::InvalidContract(
            "Phase 8 adjudication ledger lifecycle differs".to_owned(),
        ));
    }
    for (index, entry) in entries.iter().enumerate() {
        if entry.sequence != u64::try_from(index).unwrap_or(u64::MAX) {
            return Err(Phase8Error::InvalidContract(
                "Phase 8 ledger sequence is not contiguous".to_owned(),
            ));
        }
        let expected_previous = if index == 0 {
            "0".repeat(64)
        } else {
            entries[index - 1].entry_hash.clone()
        };
        if entry.previous_entry_hash != expected_previous {
            return Err(Phase8Error::InvalidContract(
                "Phase 8 ledger chain is broken".to_owned(),
            ));
        }
        let rebuilt = ledger_entry(
            entry.sequence,
            entry.event,
            &entry.process_status_policy_sha256,
            &entry.previous_entry_hash,
            None,
            entry.result_sha256.clone(),
        )?;
        let expected_hash = if entry.event == Phase8LedgerEvent::CaseAdjudicated {
            let material = Phase8LedgerHashMaterial {
                schema_version: &entry.schema_version,
                sequence: entry.sequence,
                event: entry.event,
                adjudication_id: &entry.adjudication_id,
                phase7_result_sha256: &entry.phase7_result_sha256,
                phase7_ledger_sha256: &entry.phase7_ledger_sha256,
                phase7_report_aggregate_sha256: &entry.phase7_report_aggregate_sha256,
                phase7_raw_report_set_digest: &entry.phase7_raw_report_set_digest,
                process_status_policy_sha256: &entry.process_status_policy_sha256,
                previous_entry_hash: &entry.previous_entry_hash,
                case_id: &entry.case_id,
                report_sha256: &entry.report_sha256,
                derivation_sha256: &entry.derivation_sha256,
                result_sha256: &entry.result_sha256,
            };
            fingerprint(&compact_json(&material)?)
        } else {
            rebuilt.entry_hash
        };
        if entry.entry_hash != expected_hash {
            return Err(Phase8Error::InvalidContract(
                "Phase 8 ledger entry hash differs".to_owned(),
            ));
        }
    }
    if entries
        .last()
        .and_then(|entry| entry.result_sha256.as_deref())
        != Some(result_hash)
    {
        return Err(Phase8Error::InvalidContract(
            "Phase 8 terminal ledger entry does not bind the result".to_owned(),
        ));
    }
    Ok(())
}

fn validate_schema(root: &Path, relative: &str, instance: &[u8]) -> Result<(), Phase8Error> {
    let schema_value: serde_json::Value = serde_json::from_slice(&read(root, relative)?)
        .map_err(|error| Phase8Error::InvalidContract(error.to_string()))?;
    let instance_value: serde_json::Value = serde_json::from_slice(instance)
        .map_err(|error| Phase8Error::InvalidContract(error.to_string()))?;
    let validator = jsonschema::validator_for(&schema_value)
        .map_err(|error| Phase8Error::InvalidContract(error.to_string()))?;
    if !validator.is_valid(&instance_value) {
        return Err(Phase8Error::InvalidContract(format!(
            "instance does not satisfy `{relative}`"
        )));
    }
    Ok(())
}

/// Recomputes the complete Phase 8 adjudication in memory without starting any process.
///
/// # Errors
///
/// Returns an error when immutable evidence, schemas, policy, matching, or ledger construction
/// differs from the Phase 8 contract.
#[allow(clippy::too_many_lines)]
pub fn adjudicate_repository(root: &Path) -> Result<RenderedPhase8, Phase8Error> {
    let evidence = load_evidence(root)?;
    let (corrected_run, derivations, correlation) = corrected_projection(&evidence)?;
    let corrected_run_bytes = canonical_phase7_json(&corrected_run)
        .map_err(|error| Phase8Error::InvalidContract(error.to_string()))?;
    let evaluation_ledger = Phase7Ledger {
        genesis: evidence.ledger.genesis.clone(),
        entries: evidence.ledger.entries.iter().take(113).cloned().collect(),
    };
    let corrected_evaluation = evaluate_phase7(
        &evidence.manifest,
        &evidence.evidence_contract,
        &evidence.taxonomy,
        &corrected_run,
        &evidence.reports,
        &evidence.pre_execution,
        &evidence.pre_execution_bytes,
        &corrected_run_bytes,
        &evaluation_ledger,
    )
    .map_err(|error| Phase8Error::InvalidContract(error.to_string()))?;
    if corrected_evaluation.cases.len() != 112
        || corrected_evaluation.measurement.completed_cases != 112
        || corrected_evaluation.measurement.failures != 0
        || derivations.iter().any(|case| !case.adapter_valid)
    {
        return Err(Phase8Error::InvalidContract(
            "frozen adapter did not validate every retained report".to_owned(),
        ));
    }
    let policy_hash = fingerprint(&evidence.policy_bytes);
    let result = Phase8AdjudicationResult {
        schema_version: PHASE8_RESULT_SCHEMA.to_owned(),
        adjudication_id: PHASE8_ADJUDICATION_ID.to_owned(),
        interpretation: "retrospective protocol correction over immutable retained reports; not another scanner execution and not a replacement for Phase 7".to_owned(),
        process_status_policy_version: evidence.policy.policy_version,
        process_status_policy_sha256: policy_hash.clone(),
        phase7_evidence: Phase8Evidence {
            phase7_commit: PHASE7_COMMIT.to_owned(),
            original_result_sha256: PHASE7_RESULT_SHA256.to_owned(),
            completed_ledger_sha256: PHASE7_LEDGER_SHA256.to_owned(),
            case_journal_sha256: PHASE7_JOURNAL_SHA256.to_owned(),
            run_sha256: PHASE7_RUN_SHA256.to_owned(),
            pre_execution_contract_sha256: PHASE7_PRE_EXECUTION_SHA256.to_owned(),
            artifact_index_sha256: PHASE7_ARTIFACTS_SHA256.to_owned(),
            report_aggregate_sha256: PHASE7_REPORT_AGGREGATE_SHA256.to_owned(),
            raw_report_set_digest: PHASE7_RAW_REPORT_SET_DIGEST.to_owned(),
            report_count: 112,
        },
        root_cause: Phase8RootCause {
            source_location: "crates/secure-bench-core/src/phase7.rs:3229-3254".to_owned(),
            condition: "Phase 7 invoked authoritative report adjudication only when the preliminary process status was success".to_owned(),
            effect: "all 33 normal exit-code-1 findings reports retained runner.crash and were excluded from the frozen matcher".to_owned(),
            authoritative_contracts: vec![
                "docs/contracts.md#phase-1-live-runs".to_owned(),
                "docs/phase-1-runner.md#provenance-and-artifacts".to_owned(),
            ],
        },
        correlation,
        cases: derivations,
        corrected_evaluation,
        original_phase7_result: evidence.original_result,
        corrected_run_projection_sha256: fingerprint(&corrected_run_bytes),
        process_audit: Phase8ProcessAudit {
            mode: "offline-retained-artifact-adjudication".to_owned(),
            scanner_processes_launched: 0,
            scanner_binary_accessed: false,
            network_access_requested: false,
            evidence_source: "112 immutable Phase 7 reports and recorded execution metadata".to_owned(),
        },
    };
    let result_bytes = canonical_json(&result)?;
    let result_hash = fingerprint(&result_bytes);
    let ledger = build_ledger(&policy_hash, &result.cases, &result_hash)?;
    validate_ledger(&ledger, &result_hash)?;
    let ledger_bytes = ledger_bytes(&ledger)?;
    let artifacts = Phase8Artifacts {
        schema_version: PHASE8_ARTIFACTS_SCHEMA.to_owned(),
        adjudication_id: PHASE8_ADJUDICATION_ID.to_owned(),
        process_status_policy_path: POLICY_PATH.to_owned(),
        process_status_policy_sha256: policy_hash,
        result_path: PHASE8_RESULT_PATH.to_owned(),
        result_sha256: result_hash,
        ledger_path: PHASE8_LEDGER_PATH.to_owned(),
        ledger_sha256: fingerprint(&ledger_bytes),
        ledger_entries: u64::try_from(ledger.len()).unwrap_or(u64::MAX),
        phase7_result_sha256: PHASE7_RESULT_SHA256.to_owned(),
        phase7_ledger_sha256: PHASE7_LEDGER_SHA256.to_owned(),
        phase7_report_aggregate_sha256: PHASE7_REPORT_AGGREGATE_SHA256.to_owned(),
        phase7_raw_report_set_digest: PHASE7_RAW_REPORT_SET_DIGEST.to_owned(),
        report_count: 112,
        scanner_processes_launched: 0,
    };
    let artifacts_bytes = canonical_json(&artifacts)?;
    validate_schema(
        root,
        "schemas/phase8-adjudication-v1.schema.json",
        &result_bytes,
    )?;
    validate_schema(
        root,
        "schemas/phase8-artifacts-v1.schema.json",
        &artifacts_bytes,
    )?;
    validate_schema(
        root,
        "schemas/process-status-policy-v1.schema.json",
        &evidence.policy_bytes,
    )?;
    for entry in &ledger {
        validate_schema(
            root,
            "schemas/phase8-adjudication-ledger-v1.schema.json",
            &compact_json(entry)?,
        )?;
    }
    Ok(RenderedPhase8 {
        result,
        result_bytes,
        ledger,
        ledger_bytes,
        artifacts,
        artifacts_bytes,
    })
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), Phase8Error> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| io_error(path, &error))?;
    file.write_all(bytes)
        .map_err(|error| io_error(path, &error))?;
    file.sync_all().map_err(|error| io_error(path, &error))
}

/// Publishes the deterministic Phase 8 artifacts with create-new semantics.
///
/// # Errors
///
/// Returns an error when adjudication fails or an artifact path already exists or cannot be
/// written safely.
pub fn generate_artifacts(root: &Path) -> Result<Phase8Artifacts, Phase8Error> {
    let rendered = adjudicate_repository(root)?;
    let output = safe_join(root, PHASE8_OUTPUT)?;
    fs::create_dir(&output).map_err(|error| io_error(&output, &error))?;
    write_new(&output.join("adjudication.json"), &rendered.result_bytes)?;
    write_new(
        &output.join("adjudication-ledger.jsonl"),
        &rendered.ledger_bytes,
    )?;
    write_new(&output.join("artifacts.json"), &rendered.artifacts_bytes)?;
    Ok(rendered.artifacts)
}

/// Recomputes and verifies committed Phase 8 artifacts without starting any process.
///
/// # Errors
///
/// Returns an error when immutable inputs differ or committed Phase 8 bytes do not equal the
/// deterministic offline recomputation.
pub fn verify_artifacts(root: &Path) -> Result<Phase8Artifacts, Phase8Error> {
    let rendered = adjudicate_repository(root)?;
    let result = read(root, PHASE8_RESULT_PATH)?;
    let ledger = read(root, PHASE8_LEDGER_PATH)?;
    let artifacts = read(root, PHASE8_ARTIFACTS_PATH)?;
    if result != rendered.result_bytes
        || ledger != rendered.ledger_bytes
        || artifacts != rendered.artifacts_bytes
    {
        return Err(Phase8Error::InvalidContract(
            "committed Phase 8 artifacts differ from deterministic offline adjudication".to_owned(),
        ));
    }
    Ok(rendered.artifacts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid(findings: u64) -> ReportAssessment {
        ReportAssessment::AdapterValid { findings }
    }

    #[test]
    fn prospective_policy_distinguishes_all_required_states() {
        assert_eq!(
            adjudicate_status(ProcessTermination::Exited(0), valid(0)),
            ProcessStatusDecision::CleanSuccessfulReport
        );
        assert_eq!(
            adjudicate_status(ProcessTermination::Exited(0), valid(1)),
            ProcessStatusDecision::SuccessfulFindingsReport
        );
        assert_eq!(
            adjudicate_status(ProcessTermination::Exited(1), valid(1)),
            ProcessStatusDecision::PolicyExitWithValidFindingsReport
        );
        assert_eq!(
            adjudicate_status(ProcessTermination::Exited(73), valid(2)),
            ProcessStatusDecision::PolicyExitWithValidFindingsReport
        );
        assert_eq!(
            adjudicate_status(ProcessTermination::Exited(1), valid(0)),
            ProcessStatusDecision::GenuineCrash
        );
        assert_eq!(
            adjudicate_status(ProcessTermination::Exited(0), ReportAssessment::Missing),
            ProcessStatusDecision::MissingReport
        );
        assert_eq!(
            adjudicate_status(ProcessTermination::Exited(0), ReportAssessment::Malformed),
            ProcessStatusDecision::MalformedReport
        );
        assert_eq!(
            adjudicate_status(
                ProcessTermination::Exited(0),
                ReportAssessment::InternallyErrored
            ),
            ProcessStatusDecision::InternallyErroredReport
        );
        assert_eq!(
            adjudicate_status(ProcessTermination::Timeout, valid(1)),
            ProcessStatusDecision::Timeout
        );
        assert_eq!(
            adjudicate_status(ProcessTermination::Signaled, valid(1)),
            ProcessStatusDecision::GenuineCrash
        );
        assert_eq!(
            adjudicate_status(ProcessTermination::ExecutionFailure, valid(1)),
            ProcessStatusDecision::GenuineCrash
        );
    }

    #[test]
    fn report_shape_observation_is_fail_closed() {
        assert_eq!(
            preliminary_report_assessment(b"not-json"),
            ReportAssessment::Malformed
        );
        assert_eq!(
            preliminary_report_assessment(
                br#"{"schema_version":"other","scan":{"complete":true},"errors":[],"findings":[]}"#
            ),
            ReportAssessment::Malformed
        );
        assert_eq!(
            preliminary_report_assessment(
                br#"{"schema_version":"secure-json-v1","scan":{"complete":false},"errors":[],"findings":[]}"#
            ),
            ReportAssessment::InternallyErrored
        );
        assert_eq!(
            preliminary_report_assessment(
                br#"{"schema_version":"secure-json-v1","scan":{"complete":true},"errors":[{}],"findings":[]}"#
            ),
            ReportAssessment::InternallyErrored
        );
        assert_eq!(
            preliminary_report_assessment(
                br#"{"schema_version":"secure-json-v1","scan":{"complete":true},"errors":[],"findings":[{}]}"#
            ),
            ReportAssessment::AdapterValid { findings: 1 }
        );
    }

    #[test]
    fn offline_adjudication_is_deterministic_and_complete() -> Result<(), Phase8Error> {
        let root = Path::new("..");
        let first = adjudicate_repository(root)?;
        let second = adjudicate_repository(root)?;
        assert_eq!(first, second);
        assert_eq!(first.result.cases.len(), 112);
        assert_eq!(first.result.correlation.exit_code_zero_adapter_valid, 79);
        assert_eq!(
            first
                .result
                .correlation
                .exit_code_one_adapter_valid_with_findings,
            33
        );
        assert_eq!(
            first
                .result
                .corrected_evaluation
                .measurement
                .completed_cases,
            112
        );
        assert_eq!(first.result.corrected_evaluation.measurement.failures, 0);
        assert_eq!(first.ledger.len(), 114);
        Ok(())
    }

    #[test]
    fn frozen_adapter_rejects_syntactically_valid_invalid_findings() -> Result<(), Phase8Error> {
        let root = Path::new("..");
        let mut evidence = load_evidence(root)?;
        let case_id = evidence
            .run
            .cases
            .iter()
            .find(|case| case.execution.process_exit_code == Some(0))
            .map(|case| case.execution.case_id.clone())
            .ok_or_else(|| Phase8Error::InvalidContract("exit-zero case missing".to_owned()))?;
        let invalid = br#"{"schema_version":"secure-json-v1","scan":{"complete":true},"errors":[],"findings":[{"evidence_path":[{}]}]}"#.to_vec();
        let invalid_hash = fingerprint(&invalid);
        evidence.reports.insert(case_id.clone(), invalid);
        let case = evidence
            .run
            .cases
            .iter_mut()
            .find(|case| case.execution.case_id == case_id)
            .ok_or_else(|| Phase8Error::InvalidContract("case projection missing".to_owned()))?;
        case.execution.report_fingerprint = Some(invalid_hash);
        let (corrected_run, _, _) = corrected_projection(&evidence)?;
        let corrected_run_bytes = canonical_phase7_json(&corrected_run)
            .map_err(|error| Phase8Error::InvalidContract(error.to_string()))?;
        let evaluation_ledger = Phase7Ledger {
            genesis: evidence.ledger.genesis.clone(),
            entries: evidence.ledger.entries.iter().take(113).cloned().collect(),
        };
        assert!(
            evaluate_phase7(
                &evidence.manifest,
                &evidence.evidence_contract,
                &evidence.taxonomy,
                &corrected_run,
                &evidence.reports,
                &evidence.pre_execution,
                &evidence.pre_execution_bytes,
                &corrected_run_bytes,
                &evaluation_ledger,
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn separate_adjudication_ledger_fails_closed_on_tampering() -> Result<(), Phase8Error> {
        let root = Path::new("..");
        let rendered = adjudicate_repository(root)?;
        let mut tampered = rendered.ledger.clone();
        let entry = tampered
            .get_mut(8)
            .ok_or_else(|| Phase8Error::InvalidContract("test ledger entry missing".to_owned()))?;
        entry.previous_entry_hash = "f".repeat(64);
        assert!(validate_ledger(&tampered, &rendered.artifacts.result_sha256).is_err());
        Ok(())
    }

    #[test]
    fn phase8_source_has_no_process_launch_or_scanner_path() {
        let production_source = include_str!("lib.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap_or_default();
        assert!(!production_source.contains(&["Command", "::new"].concat()));
        assert!(!production_source.contains(&["std::process", "::Command"].concat()));
        assert!(!production_source.contains(&["execute_", "process("].concat()));
        assert!(!production_source.contains(&["/usr/bin/", "secure"].concat()));
        assert!(!production_source.contains(&["phase7", " execute"].concat()));
    }

    #[test]
    fn committed_artifacts_match_when_present() -> Result<(), Phase8Error> {
        let root = Path::new("..");
        if root.join(PHASE8_ARTIFACTS_PATH).exists() {
            let verified = verify_artifacts(root)?;
            assert_eq!(verified.ledger_entries, 114);
            assert_eq!(verified.scanner_processes_launched, 0);
        }
        Ok(())
    }
}
