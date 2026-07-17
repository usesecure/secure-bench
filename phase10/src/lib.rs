//! One-shot Phase 10 execution and scanner-free deterministic verification.
//!
//! The runner treats Secure Engine only as an external process. The `prepare` and `verify`
//! operations hash the supplied artifact but cannot launch it. Only `execute` reserves the
//! append-only evidence lifecycle and starts one fresh network-isolated process per frozen case.

use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use secure_bench_core::adapter::fingerprint;
use secure_bench_core::model::{CaseKind, HostProvenance, RatioMetric, ReportedTaxonomyMetadata};
use secure_bench_core::phase5::{
    CanonicalFindingV2, EvidenceContractV2, EvidenceEffectV2, EvidenceExpectationV2,
    EvidenceMatchV2, EvidenceNodeV2, EvidenceRoleV2, EvidenceSpanV2, Phase5Framework,
    Phase5Language, Phase5Topology, SinkSemanticKind, SourceSemanticKind, evidence_fingerprint_v2,
    match_evidence_v2,
};
use secure_bench_core::phase7::{Phase7AdapterState, Phase7FindingRecord, Phase7Outcome};
use secure_bench_core::runner::{LiveCaseRun, LiveCaseStatus, LiveRunStatus, StreamCapture};
use secure_bench_core::taxonomy::{FrozenTaxonomy, load_taxonomy};
use secure_bench_phase8::{
    PROCESS_STATUS_POLICY_VERSION, ProcessStatusDecision, ProcessTermination, ReportAssessment,
    adjudicate_status,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tempfile::Builder;
use thiserror::Error;

/// Phase 10 pre-execution contract schema.
pub const PRE_EXECUTION_SCHEMA: &str = "secure-bench-phase10-pre-execution-v1";
/// Phase 10 retained-run schema.
pub const RUN_SCHEMA: &str = "secure-bench-phase10-run-v1";
/// Phase 10 deterministic-result schema.
pub const RESULT_SCHEMA: &str = "secure-bench-phase10-result-v1";
/// Phase 10 artifact-index schema.
pub const ARTIFACTS_SCHEMA: &str = "secure-bench-phase10-artifacts-v1";
/// Phase 10 ledger-entry schema.
pub const LEDGER_SCHEMA: &str = "secure-bench-phase10-ledger-entry-v1";
/// Phase 10 isolation-attestation schema.
pub const ISOLATION_SCHEMA: &str = "secure-bench-phase10-isolation-v1";
/// Phase 10 process-audit schema.
pub const PROCESS_AUDIT_SCHEMA: &str = "secure-bench-phase10-process-audit-v1";

/// Required immutable Git base.
pub const GIT_BASE: &str = "8c35a7fec6b26da0057370f9d67391791bfe889c";
/// Required dedicated branch.
pub const BRANCH: &str = "codex/phase-10-secure-engine-0-1-4-evaluation";
/// Stable one-shot run identity.
pub const RUN_ID: &str = "secure-engine-0-1-4-phase9-holdout-once";
/// Exact scanner SHA-256.
pub const BINARY_SHA256: &str = "fe15135e878a768d452eaae2c014da4bd1e61f6ca0dca45d7ada54fd69a6c075";
/// Exact source RPM SHA-256.
pub const RPM_SHA256: &str = "c470f8bab478c937d6924f4d1bf7f6328da564cc392624622b4cc234130c0aef";
/// Exact Phase 9 manifest SHA-256.
pub const MANIFEST_SHA256: &str =
    "136f92a3bbe324d8f0e3c49438b93aa4ef6eb09731998784feed0b6f75553a9f";
/// Exact Phase 9 genesis-ledger SHA-256.
pub const GENESIS_LEDGER_SHA256: &str =
    "edd48b4b70115db7c43d93d987003b62b025b5943c17d96b3dfd0262dbc69841";
/// Exact Phase 9 commitment-index SHA-256.
pub const COMMITMENTS_SHA256: &str =
    "31c83b443c889e8f3dbc0ddea358f27d4ec990dae11a4138373ea9a6fb6e13b0";
/// Exact scanner-visible aggregate corpus SHA-256.
pub const CORPUS_SHA256: &str = "30f51f643da6d27c8c94758289ee77c937104d372b97f0de90d4d40ced56dbe2";
/// Exact case-contract Merkle root.
pub const MERKLE_ROOT: &str = "7c41259cb2bc36cdab2582ac9867df6a95c1fd59686315118f70c07fe5eedf6a";
/// Exact Evidence Contract v2 SHA-256.
pub const EVIDENCE_CONTRACT_SHA256: &str =
    "142c7f31c6c584cc808410130fa7db8451427e87504e72e64868c9cbc6564c42";
/// Exact taxonomy artifact SHA-256.
pub const TAXONOMY_SHA256: &str =
    "059fe22d7707cf8d17f2c1621fdae9819787a1958ba2ef0421eca4e4ec858452";

const EXPECTED_CASES: usize = 224;
const EXPECTED_PAIRS: usize = 112;
const TIMEOUT_MS: u64 = 60_000;
const MEMORY_BYTES: u64 = 1_073_741_824;
const OUTPUT_BYTES: u64 = 10 * 1024 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const REPORT_PATH: &str = "/output/report.json";
const ISOLATION_PATH: &str = "/output/isolation.json";
const PROBE_TARGET: &str = "1.1.1.1:53";
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const OUTPUT_ROOT: &str = "phase10/output/secure-engine-0-1-4-phase9-holdout";
const PRE_EXECUTION_PATH: &str =
    "phase10/output/secure-engine-0-1-4-phase9-holdout/pre-execution-contract.json";
const LEDGER_PATH: &str =
    "phase10/output/secure-engine-0-1-4-phase9-holdout/completed-ledger.jsonl";
const RUN_DIRECTORY: &str = "phase10/output/secure-engine-0-1-4-phase9-holdout/run";
const RUN_PATH: &str = "phase10/output/secure-engine-0-1-4-phase9-holdout/run/run.json";
const RESULT_PATH: &str = "phase10/output/secure-engine-0-1-4-phase9-holdout/result.json";
const ARTIFACTS_PATH: &str = "phase10/output/secure-engine-0-1-4-phase9-holdout/artifacts.json";
const PROCESS_AUDIT_PATH: &str =
    "phase10/output/secure-engine-0-1-4-phase9-holdout/process-audit.json";
const MANIFEST_PATH: &str = "holdout/phase-9/manifest.json";
const GENESIS_PATH: &str = "holdout/phase-9/execution-ledger.jsonl";
const COMMITMENTS_PATH: &str = "holdout/phase-9/commitments.json";
const EVIDENCE_PATH: &str = "holdout/phase-5/evidence-contract-v2.json";
const TAXONOMY_PATH: &str = "taxonomy/secure-bench-taxonomy-v1.json";
const POLICY_PATH: &str = "policies/process-status-v1.json";

const COMMAND_TEMPLATE: [&str; 6] = [
    "scan",
    "{fixture}",
    "--format",
    "secure-json-v1",
    "--output",
    "{report}",
];

const EVALUATOR_FILES: [&str; 20] = [
    "phase10/Cargo.lock",
    "phase10/Cargo.toml",
    "phase10/src/lib.rs",
    "phase10/src/main.rs",
    "phase10/schemas/phase10-pre-execution-v1.schema.json",
    "phase10/schemas/phase10-run-v1.schema.json",
    "phase10/schemas/phase10-result-v1.schema.json",
    "phase10/schemas/phase10-artifacts-v1.schema.json",
    "phase10/schemas/phase10-ledger-entry-v1.schema.json",
    "phase10/schemas/phase10-isolation-v1.schema.json",
    "phase10/schemas/phase10-process-audit-v1.schema.json",
    "crates/secure-bench-core/src/lib.rs",
    "crates/secure-bench-core/src/model.rs",
    "crates/secure-bench-core/src/phase5.rs",
    "crates/secure-bench-core/src/taxonomy.rs",
    "phase8/src/lib.rs",
    "policies/process-status-v1.json",
    "schemas/evidence-contract-v2.schema.json",
    "holdout/phase-5/evidence-contract-v2.json",
    "taxonomy/secure-bench-taxonomy-v1.json",
];

/// Phase 10 input, process, contract, or artifact error.
#[derive(Debug, Error)]
pub enum Phase10Error {
    /// Invalid invocation.
    #[error("invalid Phase 10 request: {0}")]
    InvalidRequest(String),
    /// Frozen contract or retained evidence differs.
    #[error("invalid Phase 10 contract: {0}")]
    InvalidContract(String),
    /// Filesystem operation failed.
    #[error("Phase 10 filesystem operation failed for `{path}`: {detail}")]
    Io {
        /// Portable path context.
        path: String,
        /// Operating-system detail.
        detail: String,
    },
    /// JSON serialization failed.
    #[error("Phase 10 serialization failed: {0}")]
    Serialization(String),
}

fn io_error(path: &Path, error: &std::io::Error) -> Phase10Error {
    Phase10Error::Io {
        path: path.display().to_string(),
        detail: error.to_string(),
    }
}

fn read(path: &Path) -> Result<Vec<u8>, Phase10Error> {
    fs::read(path).map_err(|error| io_error(path, &error))
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, Phase10Error> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| Phase10Error::Serialization(error.to_string()))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn compact_json<T: Serialize>(value: &T) -> Result<Vec<u8>, Phase10Error> {
    serde_json::to_vec(value).map_err(|error| Phase10Error::Serialization(error.to_string()))
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), Phase10Error> {
    let parent = path.parent().ok_or_else(|| {
        Phase10Error::InvalidRequest("artifact path has no parent directory".to_owned())
    })?;
    fs::create_dir_all(parent).map_err(|error| io_error(parent, &error))?;
    let mut temporary = path.to_path_buf();
    temporary.set_extension(format!("tmp-{}", std::process::id()));
    if fs::symlink_metadata(&temporary).is_ok() {
        return Err(Phase10Error::InvalidContract(format!(
            "temporary artifact `{}` already exists",
            temporary.display()
        )));
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| io_error(&temporary, &error))?;
    file.write_all(bytes)
        .map_err(|error| io_error(&temporary, &error))?;
    file.sync_all()
        .map_err(|error| io_error(&temporary, &error))?;
    fs::rename(&temporary, path).map_err(|error| io_error(path, &error))
}

fn create_new(path: &Path, bytes: &[u8]) -> Result<(), Phase10Error> {
    let parent = path.parent().ok_or_else(|| {
        Phase10Error::InvalidRequest("artifact path has no parent directory".to_owned())
    })?;
    fs::create_dir_all(parent).map_err(|error| io_error(parent, &error))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| io_error(path, &error))?;
    file.write_all(bytes)
        .map_err(|error| io_error(path, &error))?;
    file.sync_all().map_err(|error| io_error(path, &error))
}

fn hash_file(path: &Path) -> Result<String, Phase10Error> {
    let metadata = fs::symlink_metadata(path).map_err(|error| io_error(path, &error))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(Phase10Error::InvalidContract(format!(
            "`{}` must be a regular non-symlink file",
            path.display()
        )));
    }
    Ok(fingerprint(&read(path)?))
}

fn safe_relative(value: &str) -> Result<String, Phase10Error> {
    let normalized = value.replace('\\', "/");
    let path = Path::new(&normalized);
    if normalized.is_empty()
        || path.is_absolute()
        || normalized.starts_with('/')
        || normalized.as_bytes().get(1) == Some(&b':')
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(Phase10Error::InvalidContract(
            "an artifact contains an unsafe path".to_owned(),
        ));
    }
    let parts = path
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => value.to_str(),
            _ => None,
        })
        .collect::<Vec<_>>();
    if parts.is_empty() {
        return Err(Phase10Error::InvalidContract(
            "an artifact contains an empty path".to_owned(),
        ));
    }
    Ok(parts.join("/"))
}

fn join(root: &Path, relative: &str) -> Result<PathBuf, Phase10Error> {
    Ok(root.join(safe_relative(relative)?))
}

fn contains_private_data(bytes: &[u8]) -> bool {
    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    text.contains("/home/")
        || text.contains("/users/")
        || text.contains("\\users\\")
        || text.contains("c:\\")
        || text.contains("authorization: bearer")
        || text.contains("api_key")
        || text.contains("api-key")
        || text.contains("secure_ai_")
}

fn command_template() -> Vec<String> {
    COMMAND_TEMPLATE.map(str::to_owned).to_vec()
}

#[derive(Clone, Debug, Deserialize)]
struct ManifestProjection {
    schema_version: String,
    holdout_id: String,
    taxonomy: ManifestTaxonomy,
    evidence_contract: ManifestEvidence,
    historical_integrity: BTreeMap<String, String>,
    commitments: ManifestCommitments,
    pairs: Vec<ManifestPair>,
}

#[derive(Clone, Debug, Deserialize)]
struct ManifestTaxonomy {
    sha256: String,
    content_hash: String,
}

#[derive(Clone, Debug, Deserialize)]
struct ManifestEvidence {
    schema_version: String,
    contract_version: String,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
struct ManifestCommitments {
    aggregate_corpus_sha256: String,
    contract_merkle_root: String,
    schedule_sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
struct ManifestPair {
    pair_id: String,
    assignment: ManifestAssignment,
    invariant_id: String,
    primary_cwe: String,
    source_kind: SourceSemanticKind,
    sink_kind: SinkSemanticKind,
    first: ManifestCase,
    second: ManifestCase,
}

#[derive(Clone, Debug, Deserialize)]
struct ManifestAssignment {
    ordinal: u32,
    framework: Phase5Framework,
    language: Phase5Language,
    topology: Phase5Topology,
    category_id: String,
    family_id: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum ManifestCaseKind {
    Vulnerable,
    SafeControl,
}

#[derive(Clone, Debug, Deserialize)]
struct ManifestCase {
    case_id: String,
    fixture_path: String,
    fixture_sha256: String,
    contract_sha256: String,
    kind: ManifestCaseKind,
    expectation: Option<ManifestExpectation>,
}

#[derive(Clone, Debug, Deserialize)]
struct ManifestExpectation {
    expectation_id: String,
    taxonomy_version: String,
    category_id: String,
    invariant_id: String,
    primary_cwe: String,
    path: Vec<ManifestPathNode>,
}

#[derive(Clone, Debug, Deserialize)]
struct ManifestPathNode {
    role: String,
    effect: EvidenceEffectV2,
    source_kind: Option<SourceSemanticKind>,
    sink_kind: Option<SinkSemanticKind>,
    span: EvidenceSpanV2,
    summarizable: bool,
}

impl ManifestExpectation {
    fn canonical(&self) -> Result<EvidenceExpectationV2, Phase10Error> {
        let path = self
            .path
            .iter()
            .map(|node| {
                let role = match node.role.as_str() {
                    "source" => EvidenceRoleV2::Source,
                    "intermediate" => EvidenceRoleV2::Propagation,
                    "sink" => EvidenceRoleV2::Sink,
                    _ => {
                        return Err(Phase10Error::InvalidContract(
                            "manifest contains an unknown evidence role".to_owned(),
                        ));
                    }
                };
                Ok(EvidenceNodeV2 {
                    role,
                    effect: node.effect,
                    source_kind: node.source_kind,
                    sink_kind: node.sink_kind,
                    span: node.span.clone(),
                    summarizable: node.summarizable,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(EvidenceExpectationV2 {
            expectation_id: self.expectation_id.clone(),
            taxonomy_version: self.taxonomy_version.clone(),
            category_id: self.category_id.clone(),
            invariant_id: self.invariant_id.clone(),
            primary_cwe: self.primary_cwe.clone(),
            path,
        })
    }
}

fn parse_manifest(bytes: &[u8]) -> Result<ManifestProjection, Phase10Error> {
    let manifest: ManifestProjection = serde_json::from_slice(bytes).map_err(|error| {
        Phase10Error::InvalidContract(format!("Phase 9 manifest is invalid: {error}"))
    })?;
    let cases = manifest.pairs.len().saturating_mul(2);
    if manifest.schema_version != "secure-bench-orthogonal-holdout-v3"
        || manifest.holdout_id != "phase-9-orthogonal-holdout-v3"
        || manifest.pairs.len() != EXPECTED_PAIRS
        || cases != EXPECTED_CASES
        || manifest.taxonomy.sha256 != TAXONOMY_SHA256
        || manifest.taxonomy.content_hash.len() != 64
        || manifest.evidence_contract.schema_version != "secure-bench-evidence-contract-v2"
        || manifest.evidence_contract.contract_version != "2.0.0"
        || manifest.evidence_contract.sha256 != EVIDENCE_CONTRACT_SHA256
        || manifest.commitments.aggregate_corpus_sha256 != CORPUS_SHA256
        || manifest.commitments.contract_merkle_root != MERKLE_ROOT
    {
        return Err(Phase10Error::InvalidContract(
            "Phase 9 manifest identity or commitments differ".to_owned(),
        ));
    }
    let mut ids = BTreeSet::new();
    for pair in &manifest.pairs {
        if pair.assignment.ordinal == 0
            || pair.assignment.category_id.is_empty()
            || pair.assignment.family_id.is_empty()
            || pair.pair_id.is_empty()
            || pair.invariant_id.is_empty()
            || pair.primary_cwe.is_empty()
            || !ids.insert(pair.first.case_id.clone())
            || !ids.insert(pair.second.case_id.clone())
        {
            return Err(Phase10Error::InvalidContract(
                "Phase 9 manifest contains invalid or duplicate identities".to_owned(),
            ));
        }
        for case in [&pair.first, &pair.second] {
            safe_relative(&case.fixture_path)?;
            if case.fixture_sha256.len() != 64 || case.contract_sha256.len() != 64 {
                return Err(Phase10Error::InvalidContract(
                    "Phase 9 case commitment is malformed".to_owned(),
                ));
            }
            match (case.kind, case.expectation.as_ref()) {
                (ManifestCaseKind::Vulnerable, Some(expectation)) => {
                    let canonical = expectation.canonical()?;
                    let expected_source = if pair.assignment.framework
                        == Phase5Framework::ServerActions
                        && pair.source_kind == SourceSemanticKind::HttpBodyField
                    {
                        SourceSemanticKind::FormDataValue
                    } else {
                        pair.source_kind
                    };
                    if canonical.path.first().and_then(|node| node.source_kind)
                        != Some(expected_source)
                        || canonical.path.last().and_then(|node| node.sink_kind)
                            != Some(pair.sink_kind)
                    {
                        return Err(Phase10Error::InvalidContract(
                            "Phase 9 endpoint commitment differs".to_owned(),
                        ));
                    }
                }
                (ManifestCaseKind::SafeControl, None) => {}
                _ => {
                    return Err(Phase10Error::InvalidContract(
                        "Phase 9 case label and expectation differ".to_owned(),
                    ));
                }
            }
        }
    }
    Ok(manifest)
}

fn flatten_cases(manifest: &ManifestProjection) -> Vec<(&ManifestPair, &ManifestCase)> {
    let mut cases = manifest
        .pairs
        .iter()
        .flat_map(|pair| [(pair, &pair.first), (pair, &pair.second)])
        .collect::<Vec<_>>();
    cases.sort_by(|left, right| left.1.case_id.cmp(&right.1.case_id));
    cases
}

/// Git prerequisite evidence frozen before execution.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitContract {
    /// Immutable main reference.
    pub main_commit: String,
    /// Immutable branch head.
    pub head_commit: String,
    /// Dedicated branch name.
    pub branch: String,
    /// Commit signature verification.
    pub signature: String,
    /// DCO verification.
    pub dco: String,
    /// Git object verification.
    pub object_integrity: String,
    /// Starting-tree cleanliness observed before creating the Phase 10 branch.
    pub starting_tree_clean: bool,
    /// Pre-execution changes are restricted to the prospective Phase 10 bundle.
    pub prospective_changes_phase10_only: bool,
    /// SHA-256 of the exact pre-execution porcelain status.
    pub prospective_status_sha256: String,
}

/// External black-box artifact contract.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScannerContract {
    /// Declared artifact identity.
    pub declared_version: String,
    /// Scanner binary SHA-256.
    pub binary_sha256: String,
    /// Source RPM SHA-256.
    pub source_rpm_sha256: String,
    /// Exact public command template.
    pub command_template: Vec<String>,
    /// Requested report schema.
    pub report_schema: String,
    /// Empty configuration SHA-256.
    pub configuration_sha256: String,
    /// AI status.
    pub ai_validation: String,
    /// Version probe policy.
    pub version_probe: String,
    /// Environment policy.
    pub environment_clear: bool,
    /// External black-box treatment.
    pub integration_boundary: String,
}

/// Frozen Phase 9 input contract.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HoldoutContract {
    /// Holdout identity.
    pub holdout_id: String,
    /// Manifest SHA-256.
    pub manifest_sha256: String,
    /// Commitment-index SHA-256.
    pub commitments_sha256: String,
    /// Immutable genesis-ledger SHA-256.
    pub genesis_ledger_sha256: String,
    /// Evidence Contract v2 SHA-256.
    pub evidence_contract_sha256: String,
    /// Taxonomy artifact SHA-256.
    pub taxonomy_sha256: String,
    /// Taxonomy content hash.
    pub taxonomy_content_hash: String,
    /// Scanner-visible aggregate corpus SHA-256.
    pub aggregate_corpus_sha256: String,
    /// Contract Merkle root.
    pub contract_merkle_root: String,
    /// Schedule SHA-256.
    pub schedule_sha256: String,
    /// Frozen pair count.
    pub pairs: u64,
    /// Frozen case count.
    pub cases: u64,
    /// Vulnerable-case count.
    pub vulnerable_cases: u64,
    /// Safe-control count.
    pub safe_controls: u64,
    /// Phase 9 validation result.
    pub phase9_validation: String,
    /// Prior execution state.
    pub prior_execution: String,
}

/// Frozen evaluator and schema binding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluatorContract {
    /// Evidence contract schema identity.
    pub evidence_contract_schema: String,
    /// Evidence contract semantic version.
    pub evidence_contract_version: String,
    /// Process-status policy version.
    pub process_status_policy_version: String,
    /// Process-status policy SHA-256.
    pub process_status_policy_sha256: String,
    /// Exact evaluator file hashes.
    pub files: BTreeMap<String, String>,
    /// Aggregate evaluator fingerprint.
    pub aggregate_sha256: String,
    /// Phase 10 schema hashes.
    pub schemas: BTreeMap<String, String>,
    /// Frozen matcher statement.
    pub matcher: String,
}

/// Fixed per-case resource and isolation contract.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceContract {
    /// Wall-clock timeout.
    pub timeout_ms: u64,
    /// Peak sampled RSS limit.
    pub memory_bytes: u64,
    /// Raw report limit.
    pub report_bytes: u64,
    /// Network policy.
    pub network: String,
    /// Namespace lifecycle.
    pub namespace_scope: String,
    /// Case process policy.
    pub process_scope: String,
}

/// Host and Bubblewrap provenance.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentContract {
    /// Operating system.
    pub os: String,
    /// Architecture.
    pub architecture: String,
    /// Kernel release.
    pub kernel_release: String,
    /// Rust version used to build the runner.
    pub rust_version: String,
    /// Bubblewrap SHA-256.
    pub bwrap_sha256: String,
    /// Isolation mechanism.
    pub isolation: String,
    /// Expected isolated interface set.
    pub expected_interfaces: Vec<String>,
    /// Outbound probe target.
    pub probe_target: String,
}

/// Complete pre-execution contract frozen before the first reservation entry.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreExecutionContract {
    /// Schema identity.
    pub schema_version: String,
    /// Freeze time.
    pub frozen_at_utc: String,
    /// Stable run identity.
    pub run_id: String,
    /// Git prerequisites.
    pub git: GitContract,
    /// External scanner contract.
    pub scanner: ScannerContract,
    /// Frozen holdout contract.
    pub holdout: HoldoutContract,
    /// Evaluator binding.
    pub evaluator: EvaluatorContract,
    /// Resource policy.
    pub resources: ResourceContract,
    /// Host/isolation policy.
    pub environment: EnvironmentContract,
    /// Release Phase 10 executable SHA-256.
    pub benchmark_binary_sha256: String,
    /// Exact historical Phase 9 commitments.
    pub historical_integrity: BTreeMap<String, String>,
    /// Output lifecycle.
    pub evidence_lifecycle: String,
    /// Public interpretation boundary.
    pub interpretation: String,
}

/// Per-process termination evidence.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "exit_code")]
pub enum TerminationRecord {
    /// Normal process exit.
    Exited(i32),
    /// Signal termination.
    Signaled,
    /// Runner timeout.
    Timeout,
    /// Process could not be executed or monitored.
    ExecutionFailure,
}

impl TerminationRecord {
    fn policy(self) -> ProcessTermination {
        match self {
            Self::Exited(code) => ProcessTermination::Exited(code),
            Self::Signaled => ProcessTermination::Signaled,
            Self::Timeout => ProcessTermination::Timeout,
            Self::ExecutionFailure => ProcessTermination::ExecutionFailure,
        }
    }
}

/// Per-case network isolation attestation written before scanner replacement.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IsolationAttestation {
    /// Schema identity.
    pub schema_version: String,
    /// Frozen case identity.
    pub case_id: String,
    /// Isolation mechanism.
    pub mechanism: String,
    /// Namespace lifecycle.
    pub namespace_scope: String,
    /// Interfaces visible inside the namespace.
    pub interfaces: Vec<String>,
    /// Outbound probe result.
    pub outbound_connectivity: String,
    /// Probe target.
    pub probe_target: String,
    /// Scanner replacement occurs only after the proof is durable.
    pub scanner_invoked_after_probe: bool,
    /// AI environment was absent.
    pub ai_environment: String,
}

/// One retained case record with raw-artifact bindings.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseRun {
    /// Public execution record.
    pub execution: LiveCaseRun,
    /// Raw termination evidence.
    pub termination: TerminationRecord,
    /// Prospective Phase 8 policy decision.
    pub process_status: ProcessStatusDecision,
    /// Report assessment used by the policy.
    pub report_assessment: String,
    /// Retained stdout path.
    pub stdout_path: String,
    /// Retained stdout SHA-256.
    pub stdout_sha256: String,
    /// Retained stderr path.
    pub stderr_path: String,
    /// Retained stderr SHA-256.
    pub stderr_sha256: String,
    /// Retained isolation path, when the namespace attested.
    pub isolation_path: Option<String>,
    /// Retained isolation SHA-256.
    pub isolation_sha256: Option<String>,
    /// Parsed isolation attestation.
    pub isolation: Option<IsolationAttestation>,
    /// Exactly one scanner-process launch attempt was made.
    pub scanner_launch_attempts: u64,
}

/// Complete retained one-shot run.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase10Run {
    /// Schema identity.
    pub schema_version: String,
    /// Stable run identity.
    pub run_id: String,
    /// Holdout identity.
    pub holdout_id: String,
    /// Pre-execution contract SHA-256.
    pub pre_execution_contract_sha256: String,
    /// Scanner binary SHA-256.
    pub binary_sha256: String,
    /// Source RPM SHA-256.
    pub source_rpm_sha256: String,
    /// Exact command template.
    pub command_template: Vec<String>,
    /// Process-status policy version.
    pub process_status_policy_version: String,
    /// AI status.
    pub ai_validation: String,
    /// Scanner version probe was forbidden.
    pub version_probe_executed: bool,
    /// Sanitized host provenance.
    pub host: HostProvenance,
    /// Start time.
    pub started_unix_ms: u64,
    /// Finish time.
    pub finished_unix_ms: u64,
    /// Aggregate status.
    pub status: LiveRunStatus,
    /// Case journal SHA-256.
    pub case_journal_sha256: String,
    /// Scanner launch attempts.
    pub scanner_launch_attempts: u64,
    /// Scanner launches preceded by valid isolation proof.
    pub scanner_processes_attested: u64,
    /// One immutable record per case.
    pub cases: Vec<CaseRun>,
}

/// Atomic evidence agreement for the selected candidate.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::struct_excessive_bools)]
#[serde(deny_unknown_fields)]
pub struct Criteria {
    /// Taxonomy version, category, and invariant jointly agree.
    pub taxonomy: bool,
    /// Category agrees.
    pub category: bool,
    /// Invariant agrees.
    pub invariant: bool,
    /// Primary CWE agrees.
    pub cwe: bool,
    /// Source semantics and span agree.
    pub source: bool,
    /// Sink semantics and span agree.
    pub sink: bool,
    /// Ordered connected path agrees.
    pub evidence_path: bool,
    /// Effective-barrier semantics agree.
    pub barrier: bool,
    /// Sanitizer semantics agree.
    pub sanitizer: bool,
    /// Guard semantics agree.
    pub guard: bool,
    /// Dominance semantics agree.
    pub dominance: bool,
}

impl Criteria {
    fn score(&self) -> u8 {
        [
            self.taxonomy,
            self.category,
            self.invariant,
            self.cwe,
            self.source,
            self.sink,
            self.evidence_path,
            self.barrier,
            self.sanitizer,
            self.guard,
            self.dominance,
        ]
        .into_iter()
        .map(u8::from)
        .sum()
    }
}

/// One frozen case decision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseDecision {
    /// Case identity.
    pub case_id: String,
    /// Frozen label.
    pub kind: CaseKind,
    /// Vulnerable expectation identity.
    pub expectation_id: Option<String>,
    /// Strict result.
    pub outcome: Phase7Outcome,
    /// Process/report status.
    pub execution_status: LiveCaseStatus,
    /// Selected finding identity.
    pub selected_finding_id: Option<String>,
    /// Frozen evidence-contract match.
    pub evidence_match: Option<EvidenceMatchV2>,
    /// Atomic agreement.
    pub criteria: Option<Criteria>,
    /// Distinct findings.
    pub distinct_findings: u64,
    /// Semantic duplicates.
    pub duplicate_findings: u64,
    /// Findings unrelated to the expected contract.
    pub unrelated_findings: u64,
}

/// Raw aggregate counts.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Counts {
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
    /// Flagged controls.
    pub safe_controls_flagged: u64,
    /// Clean controls.
    pub clean_safe_controls: u64,
    /// Operationally unavailable controls.
    pub safe_controls_not_attempted: u64,
    /// All findings in completed reports.
    pub findings: u64,
    /// Distinct semantic findings.
    pub distinct_findings: u64,
    /// Duplicate findings.
    pub duplicate_findings: u64,
    /// Unrelated findings.
    pub unrelated_findings: u64,
    /// Strict false-positive findings.
    pub strict_false_positive_findings: u64,
}

/// Strict metrics and evidence agreement.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Metrics {
    /// Supporting counts.
    pub counts: Counts,
    /// Exact finding-level precision.
    pub precision: RatioMetric,
    /// Exact expectation-level recall.
    pub recall: RatioMetric,
    /// Exact F1.
    pub f1: RatioMetric,
    /// Taxonomy agreement.
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
    /// Ordered path agreement.
    pub evidence_path_agreement: RatioMetric,
    /// Effective barrier agreement.
    pub barrier_agreement: RatioMetric,
    /// Sanitizer agreement.
    pub sanitizer_agreement: RatioMetric,
    /// Guard agreement.
    pub guard_agreement: RatioMetric,
    /// Dominance agreement.
    pub dominance_agreement: RatioMetric,
}

/// Metrics for one frozen stratum.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroupMetrics {
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
    /// Operationally unavailable vulnerable cases.
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
    /// Duplicates.
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

/// Complete frozen-factor and pairwise-intersection breakdowns.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Breakdowns {
    /// Seven taxonomy families.
    pub taxonomy_family: BTreeMap<String, GroupMetrics>,
    /// Four frameworks.
    pub framework: BTreeMap<String, GroupMetrics>,
    /// Two languages.
    pub language: BTreeMap<String, GroupMetrics>,
    /// Four topologies.
    pub topology: BTreeMap<String, GroupMetrics>,
    /// Taxonomy by framework.
    pub taxonomy_framework: BTreeMap<String, GroupMetrics>,
    /// Taxonomy by language.
    pub taxonomy_language: BTreeMap<String, GroupMetrics>,
    /// Taxonomy by topology.
    pub taxonomy_topology: BTreeMap<String, GroupMetrics>,
    /// Framework by language.
    pub framework_language: BTreeMap<String, GroupMetrics>,
    /// Framework by topology.
    pub framework_topology: BTreeMap<String, GroupMetrics>,
    /// Language by topology.
    pub language_topology: BTreeMap<String, GroupMetrics>,
}

/// Runtime, resource, output, and failure measurements.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Measurement {
    /// Run identity.
    pub run_id: String,
    /// Aggregate run status.
    pub status: LiveRunStatus,
    /// Total cases.
    pub cases: u64,
    /// Adapter-valid completed cases.
    pub completed_cases: u64,
    /// Sum of per-case wall time.
    pub total_duration_ms: u64,
    /// End-to-end runner wall time.
    pub runner_duration_ms: u64,
    /// Maximum sampled RSS.
    pub peak_rss_bytes: Option<u64>,
    /// Total retained report bytes.
    pub report_bytes: u64,
    /// Total retained stdout bytes.
    pub stdout_bytes: u64,
    /// Total retained stderr bytes.
    pub stderr_bytes: u64,
    /// Status counts.
    pub status_counts: BTreeMap<String, u64>,
    /// Process-policy decision counts.
    pub process_status_counts: BTreeMap<String, u64>,
    /// Exit codes by case.
    pub exit_codes: BTreeMap<String, Option<i32>>,
    /// Nonzero normal exits.
    pub nonzero_exits: u64,
    /// All non-completed cases.
    pub failures: u64,
    /// Genuine crashes.
    pub crashes: u64,
    /// Timeouts.
    pub timeouts: u64,
    /// Malformed reports.
    pub malformed_reports: u64,
    /// Missing reports.
    pub missing_reports: u64,
    /// Internally errored reports.
    pub internally_errored_reports: u64,
    /// Unsupported schemas.
    pub unsupported_reports: u64,
    /// Execution infrastructure failures.
    pub execution_failures: u64,
    /// Completed policy exits with findings.
    pub valid_findings_policy_exits: u64,
}

/// No-rerun and isolation process audit.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessAudit {
    /// Schema identity.
    pub schema_version: String,
    /// Run identity.
    pub run_id: String,
    /// Frozen case count.
    pub frozen_cases: u64,
    /// Unique case records.
    pub unique_case_records: u64,
    /// Total scanner launch attempts.
    pub scanner_launch_attempts: u64,
    /// Maximum attempts for any case.
    pub maximum_attempts_per_case: u64,
    /// Isolation-attested scanner replacements.
    pub isolation_attested_scanner_processes: u64,
    /// Version probes executed.
    pub version_probes: u64,
    /// AI commands executed.
    pub ai_commands: u64,
    /// Processes permitted network access.
    pub network_permitted_processes: u64,
    /// Exact command template.
    pub command_template: Vec<String>,
    /// Process-status policy.
    pub process_status_policy_version: String,
    /// Audit conclusion.
    pub conclusion: String,
}

/// Complete deterministic result provenance.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    /// Scanner binary SHA-256.
    pub binary_sha256: String,
    /// Source RPM SHA-256.
    pub source_rpm_sha256: String,
    /// Manifest SHA-256.
    pub manifest_sha256: String,
    /// Commitment-index SHA-256.
    pub commitments_sha256: String,
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
    /// Exact command template.
    pub command_template: Vec<String>,
    /// Empty configuration SHA-256.
    pub configuration_sha256: String,
    /// AI status.
    pub ai_validation: String,
    /// Network isolation mechanism.
    pub network_isolation: String,
    /// Namespace lifecycle.
    pub namespace_scope: String,
    /// Process-status policy version.
    pub process_status_policy_version: String,
    /// Process-status policy SHA-256.
    pub process_status_policy_sha256: String,
    /// Sanitized host provenance.
    pub host: HostProvenance,
    /// Pre-execution contract SHA-256.
    pub pre_execution_contract_sha256: String,
    /// Run SHA-256.
    pub run_sha256: String,
    /// Report-set aggregate SHA-256.
    pub reports_sha256: String,
    /// Stdout/stderr aggregate SHA-256.
    pub streams_sha256: String,
    /// Isolation-attestation aggregate SHA-256.
    pub isolation_attestations_sha256: String,
    /// Immutable Phase 9 genesis-ledger SHA-256.
    pub ledger_genesis_sha256: String,
    /// Ledger prefix through all case records.
    pub evaluation_ledger_sha256: String,
    /// Process-audit SHA-256.
    pub process_audit_sha256: String,
    /// Frozen evaluator aggregate SHA-256.
    pub evaluator_sha256: String,
    /// Exact evaluator file hashes.
    pub evaluator_files: BTreeMap<String, String>,
    /// Historical Phase 9 integrity bindings.
    pub historical_integrity: BTreeMap<String, String>,
    /// Schema identities.
    pub schemas: BTreeMap<String, String>,
}

/// Complete immutable Phase 10 result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase10Result {
    /// Schema identity.
    pub schema_version: String,
    /// Run identity.
    pub run_id: String,
    /// Holdout identity.
    pub holdout_id: String,
    /// Explicit interpretation.
    pub interpretation: String,
    /// One decision per case.
    pub cases: Vec<CaseDecision>,
    /// Privacy-safe finding records.
    pub findings: Vec<Phase7FindingRecord>,
    /// Aggregate metrics.
    pub metrics: Metrics,
    /// Frozen factor and pairwise metrics.
    pub breakdowns: Breakdowns,
    /// Runtime and operational measurements.
    pub measurement: Measurement,
    /// Deterministic semantic result fingerprint.
    pub semantic_fingerprint: String,
    /// Complete provenance.
    pub provenance: Provenance,
    /// Explicit limitations.
    pub limitations: Vec<String>,
}

/// Phase 10 append-only ledger event.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LedgerEvent {
    /// Irreversible one-shot reservation.
    ExecutionStarted,
    /// One case outcome was durably recorded.
    CaseRecorded,
    /// Result was durably sealed.
    ExecutionCompleted,
    /// Runner infrastructure could not seal a result.
    ExecutionFailed,
}

/// One Phase 10 entry appended after the exact Phase 9 genesis bytes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerEntry {
    /// Schema identity.
    pub schema_version: String,
    /// Contiguous sequence after the Phase 9 genesis at zero.
    pub sequence: u64,
    /// Event.
    pub event: LedgerEvent,
    /// Holdout identity.
    pub holdout_id: String,
    /// Run identity.
    pub run_id: String,
    /// Manifest SHA-256.
    pub manifest_sha256: String,
    /// Evidence contract SHA-256.
    pub evidence_contract_sha256: String,
    /// Taxonomy SHA-256.
    pub taxonomy_sha256: String,
    /// Corpus SHA-256.
    pub aggregate_corpus_sha256: String,
    /// Merkle root.
    pub commitment_root: String,
    /// Scanner binary SHA-256.
    pub binary_sha256: String,
    /// Previous logical entry hash.
    pub previous_entry_hash: String,
    /// Event timestamp.
    pub timestamp_utc: String,
    /// Case identity for case events.
    pub case_id: Option<String>,
    /// Case execution status.
    pub case_status: Option<LiveCaseStatus>,
    /// Process policy decision.
    pub process_status: Option<ProcessStatusDecision>,
    /// Canonical case-record SHA-256.
    pub case_record_sha256: Option<String>,
    /// Retained report SHA-256.
    pub report_sha256: Option<String>,
    /// Isolation attestation SHA-256.
    pub isolation_sha256: Option<String>,
    /// Result SHA-256 for completion.
    pub result_sha256: Option<String>,
    /// Stable terminal failure code.
    pub failure_code: Option<String>,
    /// Hash of this entry excluding this field.
    pub entry_hash: String,
}

/// Parsed completed ledger retaining the original genesis bytes.
#[derive(Clone, Debug)]
struct CompletedLedger {
    genesis_entry_hash: String,
    entries: Vec<LedgerEntry>,
}

/// Final artifact index binding every evidence surface.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactIndex {
    /// Schema identity.
    pub schema_version: String,
    /// Run identity.
    pub run_id: String,
    /// Pre-execution contract path.
    pub pre_execution_contract_path: String,
    /// Pre-execution contract SHA-256.
    pub pre_execution_contract_sha256: String,
    /// Run path.
    pub run_path: String,
    /// Run SHA-256.
    pub run_sha256: String,
    /// Result path.
    pub result_path: String,
    /// Result SHA-256.
    pub result_sha256: String,
    /// Completed ledger path.
    pub completed_ledger_path: String,
    /// Completed ledger SHA-256.
    pub completed_ledger_sha256: String,
    /// Immutable genesis ledger SHA-256.
    pub genesis_ledger_sha256: String,
    /// Case journal SHA-256.
    pub case_journal_sha256: String,
    /// Raw report-set aggregate.
    pub reports_sha256: String,
    /// Raw stdout/stderr aggregate.
    pub streams_sha256: String,
    /// Isolation-attestation aggregate.
    pub isolation_attestations_sha256: String,
    /// Process-audit path.
    pub process_audit_path: String,
    /// Process-audit SHA-256.
    pub process_audit_sha256: String,
    /// Case records.
    pub case_records: u64,
    /// Retained reports.
    pub report_count: u64,
    /// Retained stdout records.
    pub stdout_records: u64,
    /// Retained stderr records.
    pub stderr_records: u64,
    /// Isolation attestations.
    pub isolation_attestations: u64,
    /// Total ledger entries including the original genesis.
    pub ledger_entries: u64,
}

fn parse_json<T: for<'de> Deserialize<'de>>(bytes: &[u8], label: &str) -> Result<T, Phase10Error> {
    serde_json::from_slice(bytes).map_err(|error| {
        Phase10Error::InvalidContract(format!(
            "{label} JSON is invalid at line {}: {error}",
            error.line()
        ))
    })
}

fn validate_schema(root: &Path, relative: &str, bytes: &[u8]) -> Result<(), Phase10Error> {
    let schema: serde_json::Value = parse_json(&read(&join(root, relative)?)?, "JSON Schema")?;
    let instance: serde_json::Value = parse_json(bytes, "schema instance")?;
    let validator = jsonschema::validator_for(&schema)
        .map_err(|error| Phase10Error::InvalidContract(error.to_string()))?;
    if let Err(error) = validator.validate(&instance) {
        return Err(Phase10Error::InvalidContract(format!(
            "schema `{relative}` rejected an artifact: {error}"
        )));
    }
    Ok(())
}

fn schema_paths() -> [(&'static str, &'static str); 7] {
    [
        (
            "pre_execution",
            "phase10/schemas/phase10-pre-execution-v1.schema.json",
        ),
        ("run", "phase10/schemas/phase10-run-v1.schema.json"),
        ("result", "phase10/schemas/phase10-result-v1.schema.json"),
        (
            "artifacts",
            "phase10/schemas/phase10-artifacts-v1.schema.json",
        ),
        (
            "ledger",
            "phase10/schemas/phase10-ledger-entry-v1.schema.json",
        ),
        (
            "isolation",
            "phase10/schemas/phase10-isolation-v1.schema.json",
        ),
        (
            "process_audit",
            "phase10/schemas/phase10-process-audit-v1.schema.json",
        ),
    ]
}

fn schema_hashes(root: &Path) -> Result<BTreeMap<String, String>, Phase10Error> {
    schema_paths()
        .into_iter()
        .map(|(name, path)| Ok((name.to_owned(), hash_file(&join(root, path)?)?)))
        .collect()
}

fn evaluator_files(root: &Path) -> Result<BTreeMap<String, String>, Phase10Error> {
    EVALUATOR_FILES
        .into_iter()
        .map(|relative| Ok((relative.to_owned(), hash_file(&join(root, relative)?)?)))
        .collect()
}

fn aggregate_hashes(values: &BTreeMap<String, String>) -> String {
    let mut hasher = Sha256::new();
    for (path, hash) in values {
        hasher.update(path.as_bytes());
        hasher.update([0]);
        hasher.update(hash.as_bytes());
        hasher.update([b'\n']);
    }
    hex_digest(&hasher.finalize())
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

fn git_output(root: &Path, arguments: &[&str]) -> Result<Vec<u8>, Phase10Error> {
    let output = Command::new("git")
        .args(arguments)
        .current_dir(root)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| io_error(Path::new("git"), &error))?;
    if !output.status.success() {
        return Err(Phase10Error::InvalidContract(format!(
            "Git prerequisite `{}` failed",
            arguments.join(" ")
        )));
    }
    Ok(output.stdout)
}

fn git_text(root: &Path, arguments: &[&str]) -> Result<String, Phase10Error> {
    String::from_utf8(git_output(root, arguments)?)
        .map(|value| value.trim().to_owned())
        .map_err(|_| Phase10Error::InvalidContract("Git returned non-UTF-8 output".to_owned()))
}

fn prospective_status_is_phase10_only(status: &str) -> bool {
    status.lines().all(|line| {
        let path = line.get(3..).unwrap_or_default();
        let path = path.rsplit(" -> ").next().unwrap_or(path);
        path == "phase10" || path.starts_with("phase10/")
    })
}

fn git_contract(
    root: &Path,
    require_phase10_only_status: bool,
) -> Result<GitContract, Phase10Error> {
    let main_commit = git_text(root, &["rev-parse", "main"])?;
    let head_commit = git_text(root, &["rev-parse", "HEAD"])?;
    let branch = git_text(root, &["branch", "--show-current"])?;
    if main_commit != GIT_BASE || head_commit != GIT_BASE || branch != BRANCH {
        return Err(Phase10Error::InvalidContract(
            "main, HEAD, or branch differs from the Phase 10 starting contract".to_owned(),
        ));
    }
    let signer = root.join(".git/allowed_signers");
    let signer = signer.to_str().ok_or_else(|| {
        Phase10Error::InvalidContract("allowed-signers path is not UTF-8".to_owned())
    })?;
    git_output(
        root,
        &[
            "-c",
            &format!("gpg.ssh.allowedSignersFile={signer}"),
            "verify-commit",
            GIT_BASE,
        ],
    )?;
    let message = git_text(root, &["show", "-s", "--format=%B", GIT_BASE])?;
    if !message.lines().any(|line| {
        line == "Signed-off-by: Daniel Castrillon <danielcadev@users.noreply.github.com>"
    }) {
        return Err(Phase10Error::InvalidContract(
            "Phase 9 freeze commit lacks the exact DCO sign-off".to_owned(),
        ));
    }
    git_output(root, &["fsck", "--no-dangling"])?;
    let status = git_text(root, &["status", "--porcelain=v1", "--untracked-files=all"])?;
    let prospective_changes_phase10_only = prospective_status_is_phase10_only(&status);
    if require_phase10_only_status && !prospective_changes_phase10_only {
        return Err(Phase10Error::InvalidContract(
            "pre-execution changes are not restricted to Phase 10".to_owned(),
        ));
    }
    Ok(GitContract {
        main_commit,
        head_commit,
        branch,
        signature: "valid-ed25519".to_owned(),
        dco: "valid-exact-author-signoff".to_owned(),
        object_integrity: "passed".to_owned(),
        starting_tree_clean: true,
        prospective_changes_phase10_only,
        prospective_status_sha256: fingerprint(status.as_bytes()),
    })
}

fn host_provenance() -> HostProvenance {
    let memory_bytes = fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|content| {
            let kib = content
                .lines()
                .find(|line| line.starts_with("MemTotal:"))?
                .split_whitespace()
                .nth(1)?
                .parse::<u64>()
                .ok()?;
            kib.checked_mul(1024)
        });
    HostProvenance {
        os: std::env::consts::OS.to_owned(),
        architecture: std::env::consts::ARCH.to_owned(),
        logical_cpus: thread::available_parallelism()
            .ok()
            .and_then(|value| u32::try_from(value.get()).ok()),
        memory_bytes,
        kernel_release: fs::read_to_string("/proc/sys/kernel/osrelease")
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty() && value.len() <= 128),
    }
}

fn verify_fixed_inputs(
    root: &Path,
    scanner: &Path,
    rpm: &Path,
) -> Result<(ManifestProjection, EvidenceContractV2, FrozenTaxonomy), Phase10Error> {
    let expected = [
        (MANIFEST_PATH, MANIFEST_SHA256),
        (GENESIS_PATH, GENESIS_LEDGER_SHA256),
        (COMMITMENTS_PATH, COMMITMENTS_SHA256),
        (EVIDENCE_PATH, EVIDENCE_CONTRACT_SHA256),
        (TAXONOMY_PATH, TAXONOMY_SHA256),
    ];
    for (relative, expected_hash) in expected {
        let actual = hash_file(&join(root, relative)?)?;
        if actual != expected_hash {
            return Err(Phase10Error::InvalidContract(format!(
                "`{relative}` SHA-256 differs: expected {expected_hash}, observed {actual}"
            )));
        }
    }
    if hash_file(scanner)? != BINARY_SHA256 || hash_file(rpm)? != RPM_SHA256 {
        return Err(Phase10Error::InvalidContract(
            "external scanner binary or source RPM hash differs".to_owned(),
        ));
    }
    let validation = secure_bench_phase9::validate_holdout(root)
        .map_err(|error| Phase10Error::InvalidContract(error.to_string()))?;
    if validation.pairs != EXPECTED_PAIRS as u64
        || validation.cases != EXPECTED_CASES as u64
        || validation.aggregate_corpus_sha256 != CORPUS_SHA256
        || validation.contract_merkle_root != MERKLE_ROOT
    {
        return Err(Phase10Error::InvalidContract(
            "Phase 9 deterministic validation returned different commitments".to_owned(),
        ));
    }
    let _ = secure_bench_phase8::verify_artifacts(root)
        .map_err(|error| Phase10Error::InvalidContract(error.to_string()))?;
    let manifest_bytes = read(&join(root, MANIFEST_PATH)?)?;
    let manifest = parse_manifest(&manifest_bytes)?;
    let evidence: EvidenceContractV2 =
        parse_json(&read(&join(root, EVIDENCE_PATH)?)?, "evidence contract")?;
    if evidence.schema_version != "secure-bench-evidence-contract-v2"
        || evidence.contract_version != "2.0.0"
    {
        return Err(Phase10Error::InvalidContract(
            "Evidence Contract v2 identity differs".to_owned(),
        ));
    }
    let taxonomy = load_taxonomy(&read(&join(root, TAXONOMY_PATH)?)?)
        .map_err(|error| Phase10Error::InvalidContract(error.to_string()))?;
    Ok((manifest, evidence, taxonomy))
}

fn validate_pre_execution(contract: &PreExecutionContract) -> Result<(), Phase10Error> {
    if contract.schema_version != PRE_EXECUTION_SCHEMA
        || contract.run_id != RUN_ID
        || contract.git.main_commit != GIT_BASE
        || contract.git.head_commit != GIT_BASE
        || contract.git.branch != BRANCH
        || contract.scanner.binary_sha256 != BINARY_SHA256
        || contract.scanner.source_rpm_sha256 != RPM_SHA256
        || contract.scanner.command_template != command_template()
        || contract.scanner.report_schema != "secure-json-v1"
        || contract.scanner.configuration_sha256 != EMPTY_SHA256
        || !contract.scanner.ai_validation.starts_with("disabled")
        || contract.scanner.version_probe != "not-executed"
        || !contract.scanner.environment_clear
        || contract.holdout.manifest_sha256 != MANIFEST_SHA256
        || contract.holdout.commitments_sha256 != COMMITMENTS_SHA256
        || contract.holdout.genesis_ledger_sha256 != GENESIS_LEDGER_SHA256
        || contract.holdout.evidence_contract_sha256 != EVIDENCE_CONTRACT_SHA256
        || contract.holdout.taxonomy_sha256 != TAXONOMY_SHA256
        || contract.holdout.aggregate_corpus_sha256 != CORPUS_SHA256
        || contract.holdout.contract_merkle_root != MERKLE_ROOT
        || contract.holdout.pairs != EXPECTED_PAIRS as u64
        || contract.holdout.cases != EXPECTED_CASES as u64
        || contract.holdout.vulnerable_cases != 112
        || contract.holdout.safe_controls != 112
        || contract.holdout.prior_execution != "absent"
        || contract.evaluator.evidence_contract_version != "2.0.0"
        || contract.evaluator.process_status_policy_version != PROCESS_STATUS_POLICY_VERSION
        || contract.resources.timeout_ms != TIMEOUT_MS
        || contract.resources.memory_bytes != MEMORY_BYTES
        || contract.resources.report_bytes != OUTPUT_BYTES
        || contract.resources.network != "blocked"
        || contract.environment.expected_interfaces != ["lo"]
        || contract.environment.probe_target != PROBE_TARGET
    {
        return Err(Phase10Error::InvalidContract(
            "pre-execution contract semantics differ".to_owned(),
        ));
    }
    Ok(())
}

fn load_pre_execution(root: &Path) -> Result<(PreExecutionContract, Vec<u8>), Phase10Error> {
    let bytes = read(&join(root, PRE_EXECUTION_PATH)?)?;
    let contract: PreExecutionContract = parse_json(&bytes, "pre-execution contract")?;
    if canonical_json(&contract)? != bytes {
        return Err(Phase10Error::InvalidContract(
            "pre-execution contract is not canonical JSON".to_owned(),
        ));
    }
    validate_schema(
        root,
        "phase10/schemas/phase10-pre-execution-v1.schema.json",
        &bytes,
    )?;
    validate_pre_execution(&contract)?;
    Ok((contract, bytes))
}

/// Freezes and writes the pre-execution contract without launching the scanner.
///
/// # Errors
///
/// Returns an error if any frozen hash, historical artifact, Git prerequisite, schema, process
/// policy, or isolation prerequisite differs.
#[allow(clippy::too_many_lines)]
pub fn prepare_repository(
    root: &Path,
    scanner: &Path,
    rpm: &Path,
) -> Result<PreExecutionContract, Phase10Error> {
    let output_root = join(root, OUTPUT_ROOT)?;
    if fs::symlink_metadata(&output_root).is_ok() {
        return Err(Phase10Error::InvalidContract(
            "Phase 10 evidence bundle already exists".to_owned(),
        ));
    }
    let (manifest, _, taxonomy) = verify_fixed_inputs(root, scanner, rpm)?;
    let current_exe = std::env::current_exe()
        .map_err(|error| io_error(Path::new("current executable"), &error))?;
    let benchmark_binary_sha256 = hash_file(&current_exe)?;
    let bwrap = Path::new("/usr/bin/bwrap");
    let bwrap_sha256 = hash_file(bwrap)?;
    let evaluator_files = evaluator_files(root)?;
    let evaluator_sha256 = aggregate_hashes(&evaluator_files);
    let schemas = schema_hashes(root)?;
    let process_policy_sha256 = hash_file(&join(root, POLICY_PATH)?)?;
    let git = git_contract(root, true)?;
    let host = host_provenance();
    let kernel_release = host.kernel_release.clone().ok_or_else(|| {
        Phase10Error::InvalidContract("kernel release provenance is unavailable".to_owned())
    })?;
    let contract = PreExecutionContract {
        schema_version: PRE_EXECUTION_SCHEMA.to_owned(),
        frozen_at_utc: rfc3339_now(),
        run_id: RUN_ID.to_owned(),
        git,
        scanner: ScannerContract {
            declared_version: "Secure Engine 0.1.4 (user-supplied artifact identity)".to_owned(),
            binary_sha256: BINARY_SHA256.to_owned(),
            source_rpm_sha256: RPM_SHA256.to_owned(),
            command_template: command_template(),
            report_schema: "secure-json-v1".to_owned(),
            configuration_sha256: EMPTY_SHA256.to_owned(),
            ai_validation:
                "disabled-without-providers-credentials-endpoints-environment-or-commands"
                    .to_owned(),
            version_probe: "not-executed".to_owned(),
            environment_clear: true,
            integration_boundary: "external-black-box-process-only".to_owned(),
        },
        holdout: HoldoutContract {
            holdout_id: manifest.holdout_id.clone(),
            manifest_sha256: MANIFEST_SHA256.to_owned(),
            commitments_sha256: COMMITMENTS_SHA256.to_owned(),
            genesis_ledger_sha256: GENESIS_LEDGER_SHA256.to_owned(),
            evidence_contract_sha256: EVIDENCE_CONTRACT_SHA256.to_owned(),
            taxonomy_sha256: TAXONOMY_SHA256.to_owned(),
            taxonomy_content_hash: taxonomy.content_hash.clone(),
            aggregate_corpus_sha256: CORPUS_SHA256.to_owned(),
            contract_merkle_root: MERKLE_ROOT.to_owned(),
            schedule_sha256: manifest.commitments.schedule_sha256.clone(),
            pairs: EXPECTED_PAIRS as u64,
            cases: EXPECTED_CASES as u64,
            vulnerable_cases: 112,
            safe_controls: 112,
            phase9_validation: "passed-deterministic-224-case-validation".to_owned(),
            prior_execution: "absent".to_owned(),
        },
        evaluator: EvaluatorContract {
            evidence_contract_schema: manifest.evidence_contract.schema_version.clone(),
            evidence_contract_version: manifest.evidence_contract.contract_version.clone(),
            process_status_policy_version: PROCESS_STATUS_POLICY_VERSION.to_owned(),
            process_status_policy_sha256: process_policy_sha256,
            files: evaluator_files,
            aggregate_sha256: evaluator_sha256,
            schemas,
            matcher: "frozen-evidence-contract-v2-without-post-execution-modification".to_owned(),
        },
        resources: ResourceContract {
            timeout_ms: TIMEOUT_MS,
            memory_bytes: MEMORY_BYTES,
            report_bytes: OUTPUT_BYTES,
            network: "blocked".to_owned(),
            namespace_scope: "fresh-bwrap-unshare-net-per-case".to_owned(),
            process_scope: "one-fresh-scanner-process-per-frozen-case".to_owned(),
        },
        environment: EnvironmentContract {
            os: std::env::consts::OS.to_owned(),
            architecture: std::env::consts::ARCH.to_owned(),
            kernel_release,
            rust_version: "1.96".to_owned(),
            bwrap_sha256,
            isolation: "bubblewrap-minimal-read-only-runtime-unshare-net".to_owned(),
            expected_interfaces: vec!["lo".to_owned()],
            probe_target: PROBE_TARGET.to_owned(),
        },
        benchmark_binary_sha256,
        historical_integrity: manifest.historical_integrity.clone(),
        evidence_lifecycle:
            "completed-ledger-is-an-exact-byte-prefix-extension-of-the-immutable-phase9-genesis"
                .to_owned(),
        interpretation:
            "one-shot-synthetic-holdout-evaluation-not-a-ranking-superiority-production-readiness-or-complete-coverage-claim"
                .to_owned(),
    };
    validate_pre_execution(&contract)?;
    let bytes = canonical_json(&contract)?;
    validate_schema(
        root,
        "phase10/schemas/phase10-pre-execution-v1.schema.json",
        &bytes,
    )?;
    fs::create_dir_all(&output_root).map_err(|error| io_error(&output_root, &error))?;
    create_new(&join(root, PRE_EXECUTION_PATH)?, &bytes)?;
    let genesis = read(&join(root, GENESIS_PATH)?)?;
    create_new(&join(root, LEDGER_PATH)?, &genesis)?;
    Ok(contract)
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

#[derive(Clone, Debug)]
enum AssessmentKind {
    Missing,
    Malformed,
    Unsupported,
    InternallyErrored,
    Valid(Vec<AdaptedFinding>),
}

impl AssessmentKind {
    fn policy(&self) -> ReportAssessment {
        match self {
            Self::Missing => ReportAssessment::Missing,
            Self::Malformed | Self::Unsupported => ReportAssessment::Malformed,
            Self::InternallyErrored => ReportAssessment::InternallyErrored,
            Self::Valid(findings) => ReportAssessment::AdapterValid {
                findings: u64::try_from(findings.len()).unwrap_or(u64::MAX),
            },
        }
    }

    fn name(&self) -> String {
        match self {
            Self::Missing => "missing".to_owned(),
            Self::Malformed => "malformed".to_owned(),
            Self::Unsupported => "unsupported_schema".to_owned(),
            Self::InternallyErrored => "internally_errored".to_owned(),
            Self::Valid(findings) if findings.is_empty() => "adapter_valid_empty".to_owned(),
            Self::Valid(findings) => format!("adapter_valid_findings_{}", findings.len()),
        }
    }
}

const fn one() -> u32 {
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

fn span_from_raw(location: &RawLocation) -> Result<EvidenceSpanV2, Phase10Error> {
    let file = safe_relative(&location.path)?;
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
        return Err(Phase10Error::InvalidContract(
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
) -> Result<Vec<AdaptedFinding>, Phase10Error> {
    if report.len() > usize::try_from(OUTPUT_BYTES).unwrap_or(usize::MAX) {
        return Err(Phase10Error::InvalidContract(
            "report exceeds the frozen output limit".to_owned(),
        ));
    }
    let raw: RawSecureReport = serde_json::from_slice(report).map_err(|error| {
        Phase10Error::InvalidContract(format!(
            "secure-json-v1 is malformed at line {}",
            error.line()
        ))
    })?;
    if raw.schema_version != "secure-json-v1" {
        return Err(Phase10Error::InvalidContract(
            "report schema is not secure-json-v1".to_owned(),
        ));
    }
    if raw.scan.as_ref().is_none_or(|scan| !scan.complete) || !raw.errors.is_empty() {
        return Err(Phase10Error::InvalidContract(
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
            .map_err(|error| Phase10Error::InvalidContract(error.to_string()))?;
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

fn assess_report(case_id: &str, report: Option<&[u8]>) -> AssessmentKind {
    let Some(report) = report else {
        return AssessmentKind::Missing;
    };
    if report.len() > usize::try_from(OUTPUT_BYTES).unwrap_or(usize::MAX)
        || contains_private_data(report)
    {
        return AssessmentKind::Malformed;
    }
    let Ok(raw) = serde_json::from_slice::<RawSecureReport>(report) else {
        return AssessmentKind::Malformed;
    };
    if raw.schema_version != "secure-json-v1" {
        return AssessmentKind::Unsupported;
    }
    if raw.scan.as_ref().is_none_or(|scan| !scan.complete) || !raw.errors.is_empty() {
        return AssessmentKind::InternallyErrored;
    }
    let digest = fingerprint(report);
    match adapt_report(case_id, report, &digest) {
        Ok(findings) => AssessmentKind::Valid(findings),
        Err(_) => AssessmentKind::Malformed,
    }
}

fn spans_equivalent(expected: &EvidenceSpanV2, actual: &EvidenceSpanV2) -> bool {
    if safe_relative(&expected.file).ok() != safe_relative(&actual.file).ok() {
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

fn criteria_for(expectation: &EvidenceExpectationV2, finding: &AdaptedFinding) -> Criteria {
    let actual = &finding.canonical;
    let category = actual.category_id == expectation.category_id;
    let invariant = actual.invariant_id == expectation.invariant_id;
    let taxonomy = actual.taxonomy_version == expectation.taxonomy_version && category && invariant;
    let source = expectation
        .path
        .first()
        .zip(actual.path.first())
        .is_some_and(|(expected, observed)| {
            observed.role == EvidenceRoleV2::Source
                && observed.source_kind == expected.source_kind
                && spans_equivalent(&expected.span, &observed.span)
        });
    let sink =
        expectation
            .path
            .last()
            .zip(actual.path.last())
            .is_some_and(|(expected, observed)| {
                observed.role == EvidenceRoleV2::Sink
                    && observed.sink_kind == expected.sink_kind
                    && spans_equivalent(&expected.span, &observed.span)
            });
    let barrier = actual.effective_barriers.is_empty();
    let sanitizer = !actual
        .effective_barriers
        .contains(&EvidenceEffectV2::SeparatesControlAndData);
    let guard = !actual
        .effective_barriers
        .contains(&EvidenceEffectV2::RejectsAndTerminates);
    let dominance = barrier
        && actual.connected_edges.len() + 1 == actual.path.len()
        && actual.connected_edges.iter().all(|connected| *connected);
    Criteria {
        taxonomy,
        category,
        invariant,
        cwe: finding.primary_cwe.as_deref() == Some(expectation.primary_cwe.as_str()),
        source,
        sink,
        evidence_path: ordered_path_agrees(&expectation.path, actual),
        barrier,
        sanitizer,
        guard,
        dominance,
    }
}

struct CapturedStream {
    bytes: Vec<u8>,
    metadata: StreamCapture,
}

struct ProcessOutcome {
    termination: TerminationRecord,
    exit_code: Option<i32>,
    peak_memory_bytes: Option<u64>,
    stdout: CapturedStream,
    stderr: CapturedStream,
    error_code: Option<String>,
}

fn empty_stream() -> CapturedStream {
    CapturedStream {
        bytes: Vec::new(),
        metadata: StreamCapture {
            fingerprint: EMPTY_SHA256.to_owned(),
            bytes: 0,
            truncated: false,
        },
    }
}

fn capture_stream<R: Read>(mut reader: R) -> Result<CapturedStream, ()> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let count = reader.read(&mut buffer).map_err(|_| ())?;
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    Ok(CapturedStream {
        metadata: StreamCapture {
            fingerprint: fingerprint(&bytes),
            bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            truncated: false,
        },
        bytes,
    })
}

fn configure_process_group(command: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
}

fn terminate_process_group(child: &mut Child) {
    if let Ok(pid) = i32::try_from(child.id()) {
        let _ = killpg(Pid::from_raw(pid), Signal::SIGKILL);
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn sample_peak_memory(pid: u32) -> Option<u64> {
    let content = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let line = content.lines().find(|line| line.starts_with("VmHWM:"))?;
    let kib = line.split_whitespace().nth(1)?.parse::<u64>().ok()?;
    kib.checked_mul(1024)
}

fn maximum_option(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

#[allow(clippy::too_many_lines)]
fn execute_process(binary: &Path, arguments: &[String], directory: &Path) -> ProcessOutcome {
    let mut command = Command::new(binary);
    command
        .args(arguments)
        .current_dir(directory)
        .env_clear()
        .env("LC_ALL", "C")
        .env("TZ", "UTC")
        .env("NO_COLOR", "1")
        .env("TMPDIR", directory)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure_process_group(&mut command);
    let Ok(mut child) = command.spawn() else {
        return ProcessOutcome {
            termination: TerminationRecord::ExecutionFailure,
            exit_code: None,
            peak_memory_bytes: None,
            stdout: empty_stream(),
            stderr: empty_stream(),
            error_code: Some("runner.spawn_failed".to_owned()),
        };
    };
    let Some(stdout) = child.stdout.take() else {
        terminate_process_group(&mut child);
        return ProcessOutcome {
            termination: TerminationRecord::ExecutionFailure,
            exit_code: None,
            peak_memory_bytes: None,
            stdout: empty_stream(),
            stderr: empty_stream(),
            error_code: Some("runner.stdout_capture_failed".to_owned()),
        };
    };
    let Some(stderr) = child.stderr.take() else {
        terminate_process_group(&mut child);
        return ProcessOutcome {
            termination: TerminationRecord::ExecutionFailure,
            exit_code: None,
            peak_memory_bytes: None,
            stdout: empty_stream(),
            stderr: empty_stream(),
            error_code: Some("runner.stderr_capture_failed".to_owned()),
        };
    };
    let stdout_thread = thread::spawn(move || capture_stream(stdout));
    let stderr_thread = thread::spawn(move || capture_stream(stderr));
    let started = Instant::now();
    let mut peak_memory = None;
    let (termination, exit_code, error_code) = loop {
        peak_memory = maximum_option(peak_memory, sample_peak_memory(child.id()));
        if peak_memory.is_some_and(|bytes| bytes > MEMORY_BYTES) {
            terminate_process_group(&mut child);
            break (
                TerminationRecord::ExecutionFailure,
                None,
                Some("runner.memory_limit".to_owned()),
            );
        }
        if started.elapsed() >= Duration::from_millis(TIMEOUT_MS) {
            terminate_process_group(&mut child);
            break (
                TerminationRecord::Timeout,
                None,
                Some("runner.timeout".to_owned()),
            );
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                let code = status.code();
                break if let Some(code) = code {
                    (TerminationRecord::Exited(code), Some(code), None)
                } else {
                    (
                        TerminationRecord::Signaled,
                        None,
                        Some("runner.signal".to_owned()),
                    )
                };
            }
            Ok(None) => thread::sleep(POLL_INTERVAL),
            Err(_) => {
                terminate_process_group(&mut child);
                break (
                    TerminationRecord::ExecutionFailure,
                    None,
                    Some("runner.wait_failed".to_owned()),
                );
            }
        }
    };
    let stdout = stdout_thread
        .join()
        .ok()
        .and_then(Result::ok)
        .unwrap_or_else(empty_stream);
    let stderr = stderr_thread
        .join()
        .ok()
        .and_then(Result::ok)
        .unwrap_or_else(empty_stream);
    ProcessOutcome {
        termination,
        exit_code,
        peak_memory_bytes: peak_memory,
        stdout,
        stderr,
        error_code,
    }
}

fn copy_fixture(source: &Path, destination: &Path) -> Result<(), Phase10Error> {
    let mut pending = vec![(source.to_path_buf(), destination.to_path_buf())];
    while let Some((source_directory, destination_directory)) = pending.pop() {
        fs::create_dir_all(&destination_directory)
            .map_err(|error| io_error(&destination_directory, &error))?;
        let mut entries = fs::read_dir(&source_directory)
            .map_err(|error| io_error(&source_directory, &error))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| io_error(&source_directory, &error))?;
        entries.sort_by_key(fs::DirEntry::file_name);
        for entry in entries {
            let source_path = entry.path();
            let destination_path = destination_directory.join(entry.file_name());
            let metadata = fs::symlink_metadata(&source_path)
                .map_err(|error| io_error(&source_path, &error))?;
            if metadata.file_type().is_symlink() {
                return Err(Phase10Error::InvalidContract(
                    "scanner fixture contains a symlink".to_owned(),
                ));
            }
            if metadata.is_dir() {
                pending.push((source_path, destination_path));
            } else if metadata.is_file() {
                fs::copy(&source_path, &destination_path)
                    .map_err(|error| io_error(&destination_path, &error))?;
            } else {
                return Err(Phase10Error::InvalidContract(
                    "scanner fixture contains a non-regular entry".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

fn isolated_interfaces() -> Result<Vec<String>, Phase10Error> {
    let content = fs::read_to_string("/proc/net/dev")
        .map_err(|error| io_error(Path::new("/proc/net/dev"), &error))?;
    let mut interfaces = content
        .lines()
        .skip(2)
        .filter_map(|line| line.split(':').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    interfaces.sort();
    interfaces.dedup();
    Ok(interfaces)
}

fn attest_isolation(case_id: &str) -> Result<IsolationAttestation, Phase10Error> {
    let interfaces = isolated_interfaces()?;
    if interfaces != ["lo"] {
        return Err(Phase10Error::InvalidContract(
            "network namespace exposes an unexpected interface".to_owned(),
        ));
    }
    let address: SocketAddr = PROBE_TARGET.parse().map_err(|_| {
        Phase10Error::InvalidContract("outbound probe target is invalid".to_owned())
    })?;
    if TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_ok() {
        return Err(Phase10Error::InvalidContract(
            "network namespace permitted outbound connectivity".to_owned(),
        ));
    }
    Ok(IsolationAttestation {
        schema_version: ISOLATION_SCHEMA.to_owned(),
        case_id: case_id.to_owned(),
        mechanism: "bubblewrap-minimal-read-only-runtime-unshare-net".to_owned(),
        namespace_scope: "fresh-bwrap-unshare-net-per-case".to_owned(),
        interfaces,
        outbound_connectivity: "blocked".to_owned(),
        probe_target: PROBE_TARGET.to_owned(),
        scanner_invoked_after_probe: true,
        ai_environment: "absent-after-env-clear".to_owned(),
    })
}

/// Attests the fresh network namespace, then replaces the helper with the fixed scanner command.
///
/// # Errors
///
/// Returns an error if the isolated namespace, proof write, or process replacement fails.
#[cfg(unix)]
pub fn isolated_exec(case_id: &str) -> Result<(), Phase10Error> {
    use std::os::unix::process::CommandExt;

    if !case_id.starts_with("case-v3-")
        || !case_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(Phase10Error::InvalidRequest(
            "isolated case identity is invalid".to_owned(),
        ));
    }
    let attestation = attest_isolation(case_id)?;
    atomic_write(Path::new(ISOLATION_PATH), &canonical_json(&attestation)?)?;
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
    Err(Phase10Error::Io {
        path: "/scanner".to_owned(),
        detail: error.to_string(),
    })
}

/// Non-Unix hosts cannot satisfy the required namespace contract.
#[cfg(not(unix))]
pub fn isolated_exec(_case_id: &str) -> Result<(), Phase10Error> {
    Err(Phase10Error::InvalidContract(
        "Phase 10 requires Unix process replacement".to_owned(),
    ))
}

fn bwrap_arguments(
    scanner: &Path,
    benchmark: &Path,
    fixture: &Path,
    output: &Path,
    case_id: &str,
) -> Vec<String> {
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
        "/secure-bench-phase10".to_owned(),
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
        "/secure-bench-phase10".to_owned(),
        "isolated-exec".to_owned(),
        case_id.to_owned(),
    ]
    .to_vec()
}

fn status_from_decision(decision: ProcessStatusDecision) -> LiveCaseStatus {
    match decision {
        ProcessStatusDecision::CleanSuccessfulReport => LiveCaseStatus::Success,
        ProcessStatusDecision::SuccessfulFindingsReport
        | ProcessStatusDecision::PolicyExitWithValidFindingsReport => LiveCaseStatus::Findings,
        ProcessStatusDecision::GenuineCrash => LiveCaseStatus::Crash,
        ProcessStatusDecision::Timeout => LiveCaseStatus::Timeout,
        ProcessStatusDecision::MissingReport
        | ProcessStatusDecision::MalformedReport
        | ProcessStatusDecision::InternallyErroredReport => LiveCaseStatus::InvalidOutput,
    }
}

fn decision_error(decision: ProcessStatusDecision) -> Option<String> {
    match decision {
        ProcessStatusDecision::CleanSuccessfulReport
        | ProcessStatusDecision::SuccessfulFindingsReport
        | ProcessStatusDecision::PolicyExitWithValidFindingsReport => None,
        ProcessStatusDecision::GenuineCrash => Some("phase10.genuine_crash".to_owned()),
        ProcessStatusDecision::Timeout => Some("phase10.timeout".to_owned()),
        ProcessStatusDecision::MissingReport => Some("phase10.missing_report".to_owned()),
        ProcessStatusDecision::MalformedReport => Some("phase10.malformed_report".to_owned()),
        ProcessStatusDecision::InternallyErroredReport => {
            Some("phase10.internally_errored_report".to_owned())
        }
    }
}

fn validate_isolation(
    root: &Path,
    contract: &PreExecutionContract,
    case_id: &str,
    bytes: &[u8],
) -> Result<IsolationAttestation, Phase10Error> {
    let attestation: IsolationAttestation = parse_json(bytes, "isolation attestation")?;
    if canonical_json(&attestation)? != bytes
        || attestation.schema_version != ISOLATION_SCHEMA
        || attestation.case_id != case_id
        || attestation.mechanism != contract.environment.isolation
        || attestation.namespace_scope != contract.resources.namespace_scope
        || attestation.interfaces != contract.environment.expected_interfaces
        || attestation.outbound_connectivity != "blocked"
        || attestation.probe_target != contract.environment.probe_target
        || !attestation.scanner_invoked_after_probe
        || attestation.ai_environment != "absent-after-env-clear"
    {
        return Err(Phase10Error::InvalidContract(
            "per-case isolation proof differs from the frozen contract".to_owned(),
        ));
    }
    validate_schema(
        root,
        "phase10/schemas/phase10-isolation-v1.schema.json",
        bytes,
    )?;
    Ok(attestation)
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn raw_path(kind: &str, case_id: &str, extension: &str) -> String {
    format!("{kind}/{case_id}.{extension}")
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn run_case(
    root: &Path,
    contract: &PreExecutionContract,
    case: &ManifestCase,
    scanner: &Path,
    benchmark: &Path,
    run_directory: &Path,
) -> Result<CaseRun, Phase10Error> {
    let workspace = Builder::new()
        .prefix("secure-bench-phase10-")
        .tempdir()
        .map_err(|error| io_error(Path::new("temporary Phase 10 workspace"), &error))?;
    let fixture_root = workspace.path().join("fixture");
    let output_root = workspace.path().join("output");
    fs::create_dir(&fixture_root).map_err(|error| io_error(&fixture_root, &error))?;
    fs::create_dir(&output_root).map_err(|error| io_error(&output_root, &error))?;
    copy_fixture(&join(root, &case.fixture_path)?, &fixture_root)?;
    let bwrap_arguments = bwrap_arguments(
        scanner,
        benchmark,
        &fixture_root,
        &output_root,
        &case.case_id,
    );
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
        Path::new("/usr/bin/bwrap"),
        &bwrap_arguments,
        workspace.path(),
    );
    let finished_unix_ms = unix_millis();
    let duration_ms = millis(started.elapsed());

    let stdout_relative = raw_path("stdout", &case.case_id, "bin");
    let stderr_relative = raw_path("stderr", &case.case_id, "bin");
    create_new(&run_directory.join(&stdout_relative), &process.stdout.bytes)?;
    create_new(&run_directory.join(&stderr_relative), &process.stderr.bytes)?;

    let report_source = output_root.join("report.json");
    let mut report_bytes = None;
    let mut report_path = None;
    let mut report_fingerprint = None;
    let mut output_bytes = None;
    if let Ok(metadata) = fs::symlink_metadata(&report_source) {
        output_bytes = Some(metadata.len());
        if metadata.is_file() && !metadata.file_type().is_symlink() {
            let bytes = read(&report_source)?;
            let relative = raw_path("reports", &case.case_id, "json");
            create_new(&run_directory.join(&relative), &bytes)?;
            report_fingerprint = Some(fingerprint(&bytes));
            report_path = Some(relative);
            report_bytes = Some(bytes);
        }
    }
    let assessment = assess_report(&case.case_id, report_bytes.as_deref());

    let isolation_source = output_root.join("isolation.json");
    let mut isolation_path = None;
    let mut isolation_sha256 = None;
    let mut isolation = None;
    if let Ok(metadata) = fs::symlink_metadata(&isolation_source)
        && metadata.is_file()
        && !metadata.file_type().is_symlink()
    {
        let bytes = read(&isolation_source)?;
        let relative = raw_path("isolation", &case.case_id, "json");
        create_new(&run_directory.join(&relative), &bytes)?;
        let digest = fingerprint(&bytes);
        if let Ok(attestation) = validate_isolation(root, contract, &case.case_id, &bytes) {
            isolation = Some(attestation);
        }
        isolation_path = Some(relative);
        isolation_sha256 = Some(digest);
    }

    let policy_termination = if isolation.is_some() {
        process.termination
    } else {
        TerminationRecord::ExecutionFailure
    };
    let process_status = adjudicate_status(policy_termination.policy(), assessment.policy());
    let mut status = status_from_decision(process_status);
    let mut error_code = decision_error(process_status).or(process.error_code);
    if matches!(assessment, AssessmentKind::Unsupported)
        && matches!(policy_termination, TerminationRecord::Exited(_))
    {
        status = LiveCaseStatus::UnsupportedSchema;
        error_code = Some("phase10.unsupported_schema".to_owned());
    }
    if isolation.is_none() {
        status = LiveCaseStatus::ExecutionFailure;
        error_code = Some("phase10.isolation_not_attested".to_owned());
    }
    Ok(CaseRun {
        execution: LiveCaseRun {
            case_id: case.case_id.clone(),
            fixture_fingerprint: case.fixture_sha256.clone(),
            status,
            arguments: scanner_arguments,
            report_path,
            report_fingerprint,
            started_unix_ms,
            finished_unix_ms,
            duration_ms,
            process_exit_code: process.exit_code,
            peak_memory_bytes: process.peak_memory_bytes,
            output_bytes,
            stdout: process.stdout.metadata,
            stderr: process.stderr.metadata,
            error_code,
        },
        termination: process.termination,
        process_status,
        report_assessment: assessment.name(),
        stdout_path: stdout_relative,
        stdout_sha256: fingerprint(&process.stdout.bytes),
        stderr_path: stderr_relative,
        stderr_sha256: fingerprint(&process.stderr.bytes),
        isolation_path,
        isolation_sha256,
        isolation,
        scanner_launch_attempts: 1,
    })
}

fn synthetic_case_failure(
    case: &ManifestCase,
    run_directory: &Path,
) -> Result<CaseRun, Phase10Error> {
    let stdout_relative = raw_path("stdout", &case.case_id, "bin");
    let stderr_relative = raw_path("stderr", &case.case_id, "bin");
    create_new(&run_directory.join(&stdout_relative), &[])?;
    create_new(&run_directory.join(&stderr_relative), &[])?;
    let now = unix_millis();
    Ok(CaseRun {
        execution: LiveCaseRun {
            case_id: case.case_id.clone(),
            fixture_fingerprint: case.fixture_sha256.clone(),
            status: LiveCaseStatus::ExecutionFailure,
            arguments: vec![
                "scan".to_owned(),
                ".".to_owned(),
                "--format".to_owned(),
                "secure-json-v1".to_owned(),
                "--output".to_owned(),
                REPORT_PATH.to_owned(),
            ],
            report_path: None,
            report_fingerprint: None,
            started_unix_ms: now,
            finished_unix_ms: now,
            duration_ms: 0,
            process_exit_code: None,
            peak_memory_bytes: None,
            output_bytes: None,
            stdout: StreamCapture {
                fingerprint: EMPTY_SHA256.to_owned(),
                bytes: 0,
                truncated: false,
            },
            stderr: StreamCapture {
                fingerprint: EMPTY_SHA256.to_owned(),
                bytes: 0,
                truncated: false,
            },
            error_code: Some("phase10.case_infrastructure_failure".to_owned()),
        },
        termination: TerminationRecord::ExecutionFailure,
        process_status: ProcessStatusDecision::GenuineCrash,
        report_assessment: "missing".to_owned(),
        stdout_path: stdout_relative,
        stdout_sha256: EMPTY_SHA256.to_owned(),
        stderr_path: stderr_relative,
        stderr_sha256: EMPTY_SHA256.to_owned(),
        isolation_path: None,
        isolation_sha256: None,
        isolation: None,
        scanner_launch_attempts: 1,
    })
}

fn ledger_entry_hash(entry: &LedgerEntry) -> Result<String, Phase10Error> {
    let mut projected = entry.clone();
    projected.entry_hash.clear();
    Ok(fingerprint(&compact_json(&projected)?))
}

fn ledger_line(entry: &LedgerEntry) -> Result<Vec<u8>, Phase10Error> {
    let mut bytes = compact_json(entry)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn append_bytes(path: &Path, bytes: &[u8]) -> Result<(), Phase10Error> {
    let mut file = OpenOptions::new()
        .append(true)
        .open(path)
        .map_err(|error| io_error(path, &error))?;
    file.write_all(bytes)
        .map_err(|error| io_error(path, &error))?;
    file.sync_all().map_err(|error| io_error(path, &error))
}

fn append_ledger(path: &Path, entry: &LedgerEntry) -> Result<(), Phase10Error> {
    append_bytes(path, &ledger_line(entry)?)
}

fn load_completed_ledger(root: &Path, bytes: &[u8]) -> Result<CompletedLedger, Phase10Error> {
    let genesis = read(&join(root, GENESIS_PATH)?)?;
    if fingerprint(&genesis) != GENESIS_LEDGER_SHA256 || !bytes.starts_with(&genesis) {
        return Err(Phase10Error::InvalidContract(
            "completed ledger does not preserve the exact Phase 9 genesis byte prefix".to_owned(),
        ));
    }
    let genesis_value: serde_json::Value = parse_json(&genesis, "Phase 9 genesis ledger")?;
    let genesis_entry_hash = genesis_value
        .get("entry_hash")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            Phase10Error::InvalidContract("Phase 9 genesis entry hash is absent".to_owned())
        })?
        .to_owned();
    let suffix = &bytes[genesis.len()..];
    let entries = serde_json::Deserializer::from_slice(suffix)
        .into_iter::<LedgerEntry>()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            Phase10Error::InvalidContract(format!(
                "completed ledger suffix is malformed at line {}",
                error.line()
            ))
        })?;
    let mut previous = genesis_entry_hash.clone();
    for (index, entry) in entries.iter().enumerate() {
        let expected_sequence = u64::try_from(index + 1).unwrap_or(u64::MAX);
        if entry.schema_version != LEDGER_SCHEMA
            || entry.sequence != expected_sequence
            || entry.previous_entry_hash != previous
            || entry.entry_hash != ledger_entry_hash(entry)?
            || entry.run_id != RUN_ID
            || entry.holdout_id != "phase-9-orthogonal-holdout-v3"
            || entry.manifest_sha256 != MANIFEST_SHA256
            || entry.evidence_contract_sha256 != EVIDENCE_CONTRACT_SHA256
            || entry.taxonomy_sha256 != TAXONOMY_SHA256
            || entry.aggregate_corpus_sha256 != CORPUS_SHA256
            || entry.commitment_root != MERKLE_ROOT
            || entry.binary_sha256 != BINARY_SHA256
        {
            return Err(Phase10Error::InvalidContract(format!(
                "completed ledger entry {} breaks the frozen chain",
                entry.sequence
            )));
        }
        validate_schema(
            root,
            "phase10/schemas/phase10-ledger-entry-v1.schema.json",
            &compact_json(entry)?,
        )?;
        previous.clone_from(&entry.entry_hash);
    }
    Ok(CompletedLedger {
        genesis_entry_hash,
        entries,
    })
}

fn new_ledger_entry(
    ledger: &CompletedLedger,
    event: LedgerEvent,
    case: Option<&CaseRun>,
    result_sha256: Option<&str>,
    failure_code: Option<&str>,
) -> Result<LedgerEntry, Phase10Error> {
    let previous_entry_hash = ledger.entries.last().map_or_else(
        || ledger.genesis_entry_hash.clone(),
        |entry| entry.entry_hash.clone(),
    );
    let mut entry = LedgerEntry {
        schema_version: LEDGER_SCHEMA.to_owned(),
        sequence: u64::try_from(ledger.entries.len() + 1).unwrap_or(u64::MAX),
        event,
        holdout_id: "phase-9-orthogonal-holdout-v3".to_owned(),
        run_id: RUN_ID.to_owned(),
        manifest_sha256: MANIFEST_SHA256.to_owned(),
        evidence_contract_sha256: EVIDENCE_CONTRACT_SHA256.to_owned(),
        taxonomy_sha256: TAXONOMY_SHA256.to_owned(),
        aggregate_corpus_sha256: CORPUS_SHA256.to_owned(),
        commitment_root: MERKLE_ROOT.to_owned(),
        binary_sha256: BINARY_SHA256.to_owned(),
        previous_entry_hash,
        timestamp_utc: rfc3339_now(),
        case_id: case.map(|value| value.execution.case_id.clone()),
        case_status: case.map(|value| value.execution.status),
        process_status: case.map(|value| value.process_status),
        case_record_sha256: case
            .map(canonical_json)
            .transpose()?
            .map(|bytes| fingerprint(&bytes)),
        report_sha256: case.and_then(|value| value.execution.report_fingerprint.clone()),
        isolation_sha256: case.and_then(|value| value.isolation_sha256.clone()),
        result_sha256: result_sha256.map(str::to_owned),
        failure_code: failure_code.map(str::to_owned),
        entry_hash: String::new(),
    };
    entry.entry_hash = ledger_entry_hash(&entry)?;
    Ok(entry)
}

fn append_journal(path: &Path, case: &CaseRun) -> Result<(), Phase10Error> {
    let mut bytes = compact_json(case)?;
    bytes.push(b'\n');
    append_bytes(path, &bytes)
}

fn aggregate_status(cases: &[CaseRun]) -> LiveRunStatus {
    let completed = cases
        .iter()
        .filter(|case| case.execution.status.is_success())
        .count();
    if completed == cases.len() {
        LiveRunStatus::Completed
    } else if completed == 0 {
        LiveRunStatus::Failed
    } else {
        LiveRunStatus::PartialFailure
    }
}

fn aggregate_named_hashes<'a, I>(rows: I) -> String
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    let mut rows = rows
        .into_iter()
        .map(|(name, hash)| format!("{name}\0{hash}"))
        .collect::<Vec<_>>();
    rows.sort();
    fingerprint(rows.join("\n").as_bytes())
}

fn reports_aggregate(run: &Phase10Run) -> String {
    aggregate_named_hashes(run.cases.iter().filter_map(|case| {
        case.execution
            .report_fingerprint
            .as_deref()
            .map(|hash| (case.execution.case_id.as_str(), hash))
    }))
}

fn streams_aggregate(run: &Phase10Run) -> String {
    aggregate_named_hashes(run.cases.iter().flat_map(|case| {
        [
            (case.stdout_path.as_str(), case.stdout_sha256.as_str()),
            (case.stderr_path.as_str(), case.stderr_sha256.as_str()),
        ]
    }))
}

fn isolation_aggregate(run: &Phase10Run) -> String {
    aggregate_named_hashes(run.cases.iter().filter_map(|case| {
        case.isolation_path
            .as_deref()
            .zip(case.isolation_sha256.as_deref())
    }))
}

fn process_audit(run: &Phase10Run) -> ProcessAudit {
    let unique = run
        .cases
        .iter()
        .map(|case| case.execution.case_id.as_str())
        .collect::<BTreeSet<_>>()
        .len();
    ProcessAudit {
        schema_version: PROCESS_AUDIT_SCHEMA.to_owned(),
        run_id: RUN_ID.to_owned(),
        frozen_cases: EXPECTED_CASES as u64,
        unique_case_records: u64::try_from(unique).unwrap_or(u64::MAX),
        scanner_launch_attempts: run
            .cases
            .iter()
            .map(|case| case.scanner_launch_attempts)
            .sum(),
        maximum_attempts_per_case: run
            .cases
            .iter()
            .map(|case| case.scanner_launch_attempts)
            .max()
            .unwrap_or(0),
        isolation_attested_scanner_processes: run.scanner_processes_attested,
        version_probes: u64::from(run.version_probe_executed),
        ai_commands: 0,
        network_permitted_processes: 0,
        command_template: command_template(),
        process_status_policy_version: PROCESS_STATUS_POLICY_VERSION.to_owned(),
        conclusion: "one-record-and-at-most-one-launch-attempt-per-frozen-case-with-no-reruns"
            .to_owned(),
    }
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
    ratio(
        exact.saturating_mul(2),
        findings.saturating_add(expectations),
    )
}

fn match_rank(value: EvidenceMatchV2) -> u8 {
    match value {
        EvidenceMatchV2::Exact => 2,
        EvidenceMatchV2::Partial => 1,
        EvidenceMatchV2::NoMatch => 0,
    }
}

struct CandidateDecision<'a> {
    finding: &'a AdaptedFinding,
    evidence_match: EvidenceMatchV2,
    criteria: Criteria,
}

fn evaluate_vulnerable(
    contract: &EvidenceContractV2,
    case: &ManifestCase,
    status: LiveCaseStatus,
    distinct: &[AdaptedFinding],
    duplicate_findings: u64,
) -> Result<CaseDecision, Phase10Error> {
    let expectation = case
        .expectation
        .as_ref()
        .ok_or_else(|| {
            Phase10Error::InvalidContract("vulnerable case lacks expectation".to_owned())
        })?
        .canonical()?;
    if !status.is_success() {
        return Ok(CaseDecision {
            case_id: case.case_id.clone(),
            kind: CaseKind::Vulnerable,
            expectation_id: Some(expectation.expectation_id),
            outcome: if status == LiveCaseStatus::UnsupportedSchema {
                Phase7Outcome::OutOfScope
            } else {
                Phase7Outcome::NotAttempted
            },
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
            evidence_match: match_evidence_v2(contract, &expectation, &finding.canonical),
            criteria: criteria_for(&expectation, finding),
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
    Ok(CaseDecision {
        case_id: case.case_id.clone(),
        kind: CaseKind::Vulnerable,
        expectation_id: Some(expectation.expectation_id),
        outcome,
        execution_status: status,
        selected_finding_id: selected.map(|candidate| candidate.finding.finding_id.clone()),
        evidence_match: selected.map(|candidate| candidate.evidence_match),
        criteria: selected.map(|candidate| candidate.criteria.clone()),
        distinct_findings: u64::try_from(distinct.len()).unwrap_or(u64::MAX),
        duplicate_findings,
        unrelated_findings,
    })
}

fn evaluate_control(
    case: &ManifestCase,
    status: LiveCaseStatus,
    distinct_findings: u64,
    duplicate_findings: u64,
) -> CaseDecision {
    let outcome = if !status.is_success() {
        Phase7Outcome::NotAttempted
    } else if distinct_findings == 0 {
        Phase7Outcome::SafeControlClean
    } else {
        Phase7Outcome::SafeControlFlagged
    };
    CaseDecision {
        case_id: case.case_id.clone(),
        kind: CaseKind::SafeControl,
        expectation_id: None,
        outcome,
        execution_status: status,
        selected_finding_id: None,
        evidence_match: None,
        criteria: None,
        distinct_findings: if status.is_success() {
            distinct_findings
        } else {
            0
        },
        duplicate_findings: if status.is_success() {
            duplicate_findings
        } else {
            0
        },
        unrelated_findings: if status.is_success() {
            distinct_findings
        } else {
            0
        },
    }
}

fn metrics_from(decisions: &[CaseDecision], finding_count: u64) -> Metrics {
    let mut counts = Counts {
        findings: finding_count,
        ..Counts::default()
    };
    let mut agreement = [0_u64; 11];
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
            for (slot, value) in agreement.iter_mut().zip([
                criteria.taxonomy,
                criteria.category,
                criteria.invariant,
                criteria.cwe,
                criteria.source,
                criteria.sink,
                criteria.evidence_path,
                criteria.barrier,
                criteria.sanitizer,
                criteria.guard,
                criteria.dominance,
            ]) {
                *slot += u64::from(value);
            }
        }
    }
    counts.strict_false_positive_findings = counts
        .distinct_findings
        .saturating_sub(counts.exact_detections);
    let exact = counts.exact_detections;
    let findings = counts.distinct_findings;
    let vulnerable = counts.vulnerable_expectations;
    Metrics {
        counts,
        precision: ratio(exact, findings),
        recall: ratio(exact, vulnerable),
        f1: f1(exact, findings, vulnerable),
        taxonomy_agreement: ratio(agreement[0], vulnerable),
        category_agreement: ratio(agreement[1], vulnerable),
        invariant_agreement: ratio(agreement[2], vulnerable),
        cwe_agreement: ratio(agreement[3], vulnerable),
        source_agreement: ratio(agreement[4], vulnerable),
        sink_agreement: ratio(agreement[5], vulnerable),
        evidence_path_agreement: ratio(agreement[6], vulnerable),
        barrier_agreement: ratio(agreement[7], vulnerable),
        sanitizer_agreement: ratio(agreement[8], vulnerable),
        guard_agreement: ratio(agreement[9], vulnerable),
        dominance_agreement: ratio(agreement[10], vulnerable),
    }
}

fn group_metrics<'a, I>(rows: I, decisions: &BTreeMap<&str, &CaseDecision>) -> GroupMetrics
where
    I: IntoIterator<Item = &'a ManifestCase>,
{
    let mut value = GroupMetrics {
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
        distinct_findings: 0,
        duplicate_findings: 0,
        unrelated_findings: 0,
        precision: ratio(0, 0),
        recall: ratio(0, 0),
        f1: ratio(0, 0),
    };
    for case in rows {
        let Some(decision) = decisions.get(case.case_id.as_str()) else {
            continue;
        };
        value.distinct_findings = value
            .distinct_findings
            .saturating_add(decision.distinct_findings);
        value.duplicate_findings = value
            .duplicate_findings
            .saturating_add(decision.duplicate_findings);
        value.unrelated_findings = value
            .unrelated_findings
            .saturating_add(decision.unrelated_findings);
        match decision.outcome {
            Phase7Outcome::ExactDetection => {
                value.vulnerable += 1;
                value.exact += 1;
            }
            Phase7Outcome::PartialMatch => {
                value.vulnerable += 1;
                value.partial += 1;
            }
            Phase7Outcome::Missed => {
                value.vulnerable += 1;
                value.missed += 1;
            }
            Phase7Outcome::OutOfScope => {
                value.vulnerable += 1;
                value.out_of_scope += 1;
            }
            Phase7Outcome::NotAttempted if case.kind == ManifestCaseKind::Vulnerable => {
                value.vulnerable += 1;
                value.not_attempted += 1;
            }
            Phase7Outcome::NotAttempted => {
                value.controls += 1;
                value.controls_not_attempted += 1;
            }
            Phase7Outcome::SafeControlFlagged => {
                value.controls += 1;
                value.flagged_controls += 1;
            }
            Phase7Outcome::SafeControlClean => {
                value.controls += 1;
                value.clean_controls += 1;
            }
        }
    }
    value.precision = ratio(value.exact, value.distinct_findings);
    value.recall = ratio(value.exact, value.vulnerable);
    value.f1 = f1(value.exact, value.distinct_findings, value.vulnerable);
    value
}

fn framework_name(value: Phase5Framework) -> &'static str {
    match value {
        Phase5Framework::NodeJs => "node_js",
        Phase5Framework::Express => "express",
        Phase5Framework::NextAppRouter => "next_app_router",
        Phase5Framework::ServerActions => "server_actions",
    }
}

fn language_name(value: Phase5Language) -> &'static str {
    match value {
        Phase5Language::JavaScript => "java_script",
        Phase5Language::TypeScript => "type_script",
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

#[allow(clippy::too_many_lines)]
fn build_breakdowns(manifest: &ManifestProjection, decisions: &[CaseDecision]) -> Breakdowns {
    let by_id = decisions
        .iter()
        .map(|decision| (decision.case_id.as_str(), decision))
        .collect::<BTreeMap<_, _>>();
    let taxonomy = manifest
        .pairs
        .iter()
        .map(|pair| pair.assignment.family_id.clone())
        .collect::<BTreeSet<_>>();
    let frameworks = manifest
        .pairs
        .iter()
        .map(|pair| framework_name(pair.assignment.framework).to_owned())
        .collect::<BTreeSet<_>>();
    let languages = manifest
        .pairs
        .iter()
        .map(|pair| language_name(pair.assignment.language).to_owned())
        .collect::<BTreeSet<_>>();
    let topologies = manifest
        .pairs
        .iter()
        .map(|pair| topology_name(pair.assignment.topology).to_owned())
        .collect::<BTreeSet<_>>();
    let metrics_for = |predicate: &dyn Fn(&ManifestPair) -> bool| {
        group_metrics(
            manifest
                .pairs
                .iter()
                .filter(|pair| predicate(pair))
                .flat_map(|pair| [&pair.first, &pair.second]),
            &by_id,
        )
    };
    let taxonomy_family = taxonomy
        .iter()
        .map(|value| {
            (
                value.clone(),
                metrics_for(&|pair| pair.assignment.family_id == *value),
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
    let mut taxonomy_framework = BTreeMap::new();
    let mut taxonomy_language = BTreeMap::new();
    let mut taxonomy_topology = BTreeMap::new();
    let mut framework_language = BTreeMap::new();
    let mut framework_topology = BTreeMap::new();
    let mut language_topology = BTreeMap::new();
    for family in &taxonomy {
        for framework in &frameworks {
            taxonomy_framework.insert(
                format!("{family}|{framework}"),
                metrics_for(&|pair| {
                    pair.assignment.family_id == *family
                        && framework_name(pair.assignment.framework) == framework
                }),
            );
        }
        for language in &languages {
            taxonomy_language.insert(
                format!("{family}|{language}"),
                metrics_for(&|pair| {
                    pair.assignment.family_id == *family
                        && language_name(pair.assignment.language) == language
                }),
            );
        }
        for topology in &topologies {
            taxonomy_topology.insert(
                format!("{family}|{topology}"),
                metrics_for(&|pair| {
                    pair.assignment.family_id == *family
                        && topology_name(pair.assignment.topology) == topology
                }),
            );
        }
    }
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
    for language in &languages {
        for topology in &topologies {
            language_topology.insert(
                format!("{language}|{topology}"),
                metrics_for(&|pair| {
                    language_name(pair.assignment.language) == language
                        && topology_name(pair.assignment.topology) == topology
                }),
            );
        }
    }
    Breakdowns {
        taxonomy_family,
        framework,
        language,
        topology,
        taxonomy_framework,
        taxonomy_language,
        taxonomy_topology,
        framework_language,
        framework_topology,
        language_topology,
    }
}

fn live_status_name(status: LiveCaseStatus) -> &'static str {
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

fn process_status_name(status: ProcessStatusDecision) -> &'static str {
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

#[allow(clippy::too_many_lines)]
fn measurement(run: &Phase10Run) -> Measurement {
    let mut status_counts = BTreeMap::new();
    let mut process_status_counts = BTreeMap::new();
    let mut exit_codes = BTreeMap::new();
    let mut peak_rss_bytes = None;
    for case in &run.cases {
        *status_counts
            .entry(live_status_name(case.execution.status).to_owned())
            .or_insert(0) += 1;
        *process_status_counts
            .entry(process_status_name(case.process_status).to_owned())
            .or_insert(0) += 1;
        exit_codes.insert(
            case.execution.case_id.clone(),
            case.execution.process_exit_code,
        );
        peak_rss_bytes = maximum_option(peak_rss_bytes, case.execution.peak_memory_bytes);
    }
    let completed_cases = run
        .cases
        .iter()
        .filter(|case| case.execution.status.is_success())
        .count();
    let failures = run.cases.len().saturating_sub(completed_cases);
    Measurement {
        run_id: run.run_id.clone(),
        status: run.status,
        cases: u64::try_from(run.cases.len()).unwrap_or(u64::MAX),
        completed_cases: u64::try_from(completed_cases).unwrap_or(u64::MAX),
        total_duration_ms: run
            .cases
            .iter()
            .map(|case| case.execution.duration_ms)
            .sum(),
        runner_duration_ms: run.finished_unix_ms.saturating_sub(run.started_unix_ms),
        peak_rss_bytes,
        report_bytes: run
            .cases
            .iter()
            .filter_map(|case| case.execution.output_bytes)
            .sum(),
        stdout_bytes: run
            .cases
            .iter()
            .map(|case| case.execution.stdout.bytes)
            .sum(),
        stderr_bytes: run
            .cases
            .iter()
            .map(|case| case.execution.stderr.bytes)
            .sum(),
        status_counts,
        process_status_counts,
        exit_codes,
        nonzero_exits: u64::try_from(
            run.cases
                .iter()
                .filter(|case| {
                    case.execution
                        .process_exit_code
                        .is_some_and(|code| code != 0)
                })
                .count(),
        )
        .unwrap_or(u64::MAX),
        failures: u64::try_from(failures).unwrap_or(u64::MAX),
        crashes: u64::try_from(
            run.cases
                .iter()
                .filter(|case| case.process_status == ProcessStatusDecision::GenuineCrash)
                .count(),
        )
        .unwrap_or(u64::MAX),
        timeouts: u64::try_from(
            run.cases
                .iter()
                .filter(|case| case.process_status == ProcessStatusDecision::Timeout)
                .count(),
        )
        .unwrap_or(u64::MAX),
        malformed_reports: u64::try_from(
            run.cases
                .iter()
                .filter(|case| case.process_status == ProcessStatusDecision::MalformedReport)
                .count(),
        )
        .unwrap_or(u64::MAX),
        missing_reports: u64::try_from(
            run.cases
                .iter()
                .filter(|case| case.process_status == ProcessStatusDecision::MissingReport)
                .count(),
        )
        .unwrap_or(u64::MAX),
        internally_errored_reports: u64::try_from(
            run.cases
                .iter()
                .filter(|case| {
                    case.process_status == ProcessStatusDecision::InternallyErroredReport
                })
                .count(),
        )
        .unwrap_or(u64::MAX),
        unsupported_reports: u64::try_from(
            run.cases
                .iter()
                .filter(|case| case.execution.status == LiveCaseStatus::UnsupportedSchema)
                .count(),
        )
        .unwrap_or(u64::MAX),
        execution_failures: u64::try_from(
            run.cases
                .iter()
                .filter(|case| case.execution.status == LiveCaseStatus::ExecutionFailure)
                .count(),
        )
        .unwrap_or(u64::MAX),
        valid_findings_policy_exits: u64::try_from(
            run.cases
                .iter()
                .filter(|case| {
                    case.process_status == ProcessStatusDecision::PolicyExitWithValidFindingsReport
                })
                .count(),
        )
        .unwrap_or(u64::MAX),
    }
}

fn load_reports(
    run: &Phase10Run,
    run_directory: &Path,
) -> Result<BTreeMap<String, Vec<u8>>, Phase10Error> {
    let mut reports = BTreeMap::new();
    for case in &run.cases {
        if let Some(relative) = &case.execution.report_path {
            let expected = raw_path("reports", &case.execution.case_id, "json");
            if relative != &expected {
                return Err(Phase10Error::InvalidContract(
                    "retained report path differs from its case identity".to_owned(),
                ));
            }
            let bytes = read(&run_directory.join(safe_relative(relative)?))?;
            if case.execution.report_fingerprint.as_deref() != Some(fingerprint(&bytes).as_str()) {
                return Err(Phase10Error::InvalidContract(format!(
                    "retained report differs for `{}`",
                    case.execution.case_id
                )));
            }
            reports.insert(case.execution.case_id.clone(), bytes);
        }
    }
    Ok(reports)
}

fn semantic_fingerprint(
    decisions: &[CaseDecision],
    findings: &[Phase7FindingRecord],
    metrics: &Metrics,
    breakdowns: &Breakdowns,
) -> Result<String, Phase10Error> {
    let mut semantic_findings = findings
        .iter()
        .map(|finding| {
            (
                &finding.case_id,
                &finding.semantic_fingerprint,
                &finding.duplicate_of,
                finding.adapter_state,
                &finding.reported_taxonomy,
                &finding.primary_cwe,
            )
        })
        .collect::<Vec<_>>();
    semantic_findings.sort();
    Ok(fingerprint(&compact_json(&(
        decisions,
        semantic_findings,
        metrics,
        breakdowns,
    ))?))
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn evaluate(
    manifest: &ManifestProjection,
    evidence_contract: &EvidenceContractV2,
    taxonomy: &FrozenTaxonomy,
    run: &Phase10Run,
    reports: &BTreeMap<String, Vec<u8>>,
    contract: &PreExecutionContract,
    pre_execution_bytes: &[u8],
    run_bytes: &[u8],
    evaluation_ledger_bytes: &[u8],
    process_audit_bytes: &[u8],
) -> Result<Phase10Result, Phase10Error> {
    let by_id = run
        .cases
        .iter()
        .map(|case| (case.execution.case_id.as_str(), case))
        .collect::<BTreeMap<_, _>>();
    let mut decisions = Vec::with_capacity(EXPECTED_CASES);
    let mut records = Vec::new();
    for (_, case) in flatten_cases(manifest) {
        let case_run = by_id.get(case.case_id.as_str()).ok_or_else(|| {
            Phase10Error::InvalidContract(format!("run omitted `{}`", case.case_id))
        })?;
        let mut adapted = Vec::new();
        if case_run.execution.status.is_success() {
            let report = reports.get(&case.case_id).ok_or_else(|| {
                Phase10Error::InvalidContract(format!(
                    "completed case `{}` has no retained report",
                    case.case_id
                ))
            })?;
            let report_sha256 = fingerprint(report);
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
        decisions.push(match case.kind {
            ManifestCaseKind::Vulnerable => evaluate_vulnerable(
                evidence_contract,
                case,
                case_run.execution.status,
                &distinct,
                duplicate_count,
            )?,
            ManifestCaseKind::SafeControl => evaluate_control(
                case,
                case_run.execution.status,
                u64::try_from(distinct.len()).unwrap_or(u64::MAX),
                duplicate_count,
            ),
        });
    }
    decisions.sort_by(|left, right| left.case_id.cmp(&right.case_id));
    records.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
    let metrics = metrics_from(&decisions, u64::try_from(records.len()).unwrap_or(u64::MAX));
    let breakdowns = build_breakdowns(manifest, &decisions);
    let semantic_fingerprint = semantic_fingerprint(&decisions, &records, &metrics, &breakdowns)?;
    let mut schemas = BTreeMap::new();
    schemas.insert("manifest".to_owned(), manifest.schema_version.clone());
    schemas.insert(
        "evidence_contract".to_owned(),
        evidence_contract.schema_version.clone(),
    );
    schemas.insert("taxonomy".to_owned(), taxonomy.schema_version.clone());
    schemas.insert("pre_execution".to_owned(), PRE_EXECUTION_SCHEMA.to_owned());
    schemas.insert("run".to_owned(), RUN_SCHEMA.to_owned());
    schemas.insert("result".to_owned(), RESULT_SCHEMA.to_owned());
    schemas.insert("ledger".to_owned(), LEDGER_SCHEMA.to_owned());
    schemas.insert("isolation".to_owned(), ISOLATION_SCHEMA.to_owned());
    let result = Phase10Result {
        schema_version: RESULT_SCHEMA.to_owned(),
        run_id: RUN_ID.to_owned(),
        holdout_id: manifest.holdout_id.clone(),
        interpretation:
            "one-shot-retained-report-evaluation-under-frozen-evidence-contract-v2".to_owned(),
        cases: decisions,
        findings: records,
        metrics,
        breakdowns,
        measurement: measurement(run),
        semantic_fingerprint,
        provenance: Provenance {
            binary_sha256: BINARY_SHA256.to_owned(),
            source_rpm_sha256: RPM_SHA256.to_owned(),
            manifest_sha256: MANIFEST_SHA256.to_owned(),
            commitments_sha256: COMMITMENTS_SHA256.to_owned(),
            evidence_contract_sha256: EVIDENCE_CONTRACT_SHA256.to_owned(),
            aggregate_corpus_sha256: CORPUS_SHA256.to_owned(),
            contract_merkle_root: MERKLE_ROOT.to_owned(),
            taxonomy_artifact_sha256: TAXONOMY_SHA256.to_owned(),
            taxonomy_content_hash: taxonomy.content_hash.clone(),
            command_template: command_template(),
            configuration_sha256: EMPTY_SHA256.to_owned(),
            ai_validation: contract.scanner.ai_validation.clone(),
            network_isolation: contract.environment.isolation.clone(),
            namespace_scope: contract.resources.namespace_scope.clone(),
            process_status_policy_version: PROCESS_STATUS_POLICY_VERSION.to_owned(),
            process_status_policy_sha256: contract
                .evaluator
                .process_status_policy_sha256
                .clone(),
            host: run.host.clone(),
            pre_execution_contract_sha256: fingerprint(pre_execution_bytes),
            run_sha256: fingerprint(run_bytes),
            reports_sha256: reports_aggregate(run),
            streams_sha256: streams_aggregate(run),
            isolation_attestations_sha256: isolation_aggregate(run),
            ledger_genesis_sha256: GENESIS_LEDGER_SHA256.to_owned(),
            evaluation_ledger_sha256: fingerprint(evaluation_ledger_bytes),
            process_audit_sha256: fingerprint(process_audit_bytes),
            evaluator_sha256: contract.evaluator.aggregate_sha256.clone(),
            evaluator_files: contract.evaluator.files.clone(),
            historical_integrity: contract.historical_integrity.clone(),
            schemas,
        },
        limitations: vec![
            "This synthetic holdout does not establish production prevalence or exploitability."
                .to_owned(),
            "This result is not a scanner ranking, superiority claim, production-readiness claim, or complete-coverage claim."
                .to_owned(),
            "Phase 10 is not directly score-comparable with evaluations that used a different corpus."
                .to_owned(),
            "Partial evidence receives no exact-detection credit under the frozen contract."
                .to_owned(),
            "Runtime and peak RSS are local measurements from this recorded environment."
                .to_owned(),
        ],
    };
    validate_result_semantics(&result)?;
    Ok(result)
}

fn validate_result_semantics(result: &Phase10Result) -> Result<(), Phase10Error> {
    let counts = &result.metrics.counts;
    if result.schema_version != RESULT_SCHEMA
        || result.run_id != RUN_ID
        || result.cases.len() != EXPECTED_CASES
        || counts.vulnerable_expectations != 112
        || counts.safe_controls != 112
        || counts.exact_detections
            + counts.partial_matches
            + counts.misses
            + counts.out_of_scope
            + counts.not_attempted
            != 112
        || counts.safe_controls_flagged
            + counts.clean_safe_controls
            + counts.safe_controls_not_attempted
            != 112
        || counts.findings != u64::try_from(result.findings.len()).unwrap_or(u64::MAX)
        || counts.distinct_findings + counts.duplicate_findings != counts.findings
        || result.breakdowns.taxonomy_family.len() != 7
        || result.breakdowns.framework.len() != 4
        || result.breakdowns.language.len() != 2
        || result.breakdowns.topology.len() != 4
        || result.breakdowns.taxonomy_framework.len() != 28
        || result.breakdowns.taxonomy_language.len() != 14
        || result.breakdowns.taxonomy_topology.len() != 28
        || result.breakdowns.framework_language.len() != 8
        || result.breakdowns.framework_topology.len() != 16
        || result.breakdowns.language_topology.len() != 8
    {
        return Err(Phase10Error::InvalidContract(
            "result populations, denominators, or strata differ".to_owned(),
        ));
    }
    Ok(())
}

fn validate_execution_inputs(
    root: &Path,
    scanner: &Path,
    rpm: &Path,
    contract: &PreExecutionContract,
) -> Result<
    (
        ManifestProjection,
        EvidenceContractV2,
        FrozenTaxonomy,
        PathBuf,
    ),
    Phase10Error,
> {
    let (manifest, evidence, taxonomy) = verify_fixed_inputs(root, scanner, rpm)?;
    if evaluator_files(root)? != contract.evaluator.files
        || aggregate_hashes(&contract.evaluator.files) != contract.evaluator.aggregate_sha256
        || schema_hashes(root)? != contract.evaluator.schemas
        || hash_file(&join(root, POLICY_PATH)?)? != contract.evaluator.process_status_policy_sha256
        || hash_file(Path::new("/usr/bin/bwrap"))? != contract.environment.bwrap_sha256
    {
        return Err(Phase10Error::InvalidContract(
            "evaluator, schema, process policy, or isolation executable drifted".to_owned(),
        ));
    }
    let benchmark = std::env::current_exe()
        .map_err(|error| io_error(Path::new("current executable"), &error))?;
    if hash_file(&benchmark)? != contract.benchmark_binary_sha256 {
        return Err(Phase10Error::InvalidContract(
            "Phase 10 release executable drifted after preflight".to_owned(),
        ));
    }
    Ok((manifest, evidence, taxonomy, benchmark))
}

fn validate_run(run: &Phase10Run, manifest: &ManifestProjection) -> Result<(), Phase10Error> {
    let expected = flatten_cases(manifest);
    let expected_ids = expected
        .iter()
        .map(|(_, case)| case.case_id.as_str())
        .collect::<Vec<_>>();
    let actual_ids = run
        .cases
        .iter()
        .map(|case| case.execution.case_id.as_str())
        .collect::<Vec<_>>();
    if run.schema_version != RUN_SCHEMA
        || run.run_id != RUN_ID
        || run.holdout_id != manifest.holdout_id
        || run.binary_sha256 != BINARY_SHA256
        || run.source_rpm_sha256 != RPM_SHA256
        || run.command_template != command_template()
        || run.process_status_policy_version != PROCESS_STATUS_POLICY_VERSION
        || !run.ai_validation.starts_with("disabled")
        || run.version_probe_executed
        || run.cases.len() != EXPECTED_CASES
        || expected_ids != actual_ids
        || run.scanner_launch_attempts != EXPECTED_CASES as u64
        || run.started_unix_ms > run.finished_unix_ms
        || run.status != aggregate_status(&run.cases)
    {
        return Err(Phase10Error::InvalidContract(
            "run identities, ordering, launch count, or aggregate status differ".to_owned(),
        ));
    }
    for ((_, expected_case), observed) in expected.iter().zip(&run.cases) {
        if observed.execution.fixture_fingerprint != expected_case.fixture_sha256
            || observed.execution.arguments
                != vec![
                    "scan".to_owned(),
                    ".".to_owned(),
                    "--format".to_owned(),
                    "secure-json-v1".to_owned(),
                    "--output".to_owned(),
                    REPORT_PATH.to_owned(),
                ]
            || observed.scanner_launch_attempts != 1
        {
            return Err(Phase10Error::InvalidContract(format!(
                "run record differs for `{}`",
                expected_case.case_id
            )));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn execute_reserved(
    root: &Path,
    scanner: &Path,
    rpm: &Path,
    contract: &PreExecutionContract,
    pre_execution_bytes: &[u8],
    manifest: &ManifestProjection,
    evidence: &EvidenceContractV2,
    taxonomy: &FrozenTaxonomy,
    benchmark: &Path,
    ledger: &mut CompletedLedger,
) -> Result<ArtifactIndex, Phase10Error> {
    let run_directory = join(root, RUN_DIRECTORY)?;
    fs::create_dir(&run_directory).map_err(|error| io_error(&run_directory, &error))?;
    for child in ["reports", "stdout", "stderr", "isolation"] {
        let path = run_directory.join(child);
        fs::create_dir(&path).map_err(|error| io_error(&path, &error))?;
    }
    let journal_path = run_directory.join("cases.jsonl");
    create_new(&journal_path, &[])?;
    let run_started = unix_millis();
    let cases = flatten_cases(manifest);
    if cases.len() != EXPECTED_CASES {
        return Err(Phase10Error::InvalidContract(
            "holdout execution case count drifted".to_owned(),
        ));
    }
    let mut outcomes = Vec::with_capacity(EXPECTED_CASES);
    for (_, case) in cases {
        let outcome = match run_case(root, contract, case, scanner, benchmark, &run_directory) {
            Ok(outcome) => outcome,
            Err(_) => synthetic_case_failure(case, &run_directory)?,
        };
        append_journal(&journal_path, &outcome)?;
        let entry = new_ledger_entry(
            ledger,
            LedgerEvent::CaseRecorded,
            Some(&outcome),
            None,
            None,
        )?;
        append_ledger(&join(root, LEDGER_PATH)?, &entry)?;
        ledger.entries.push(entry);
        let readback = load_completed_ledger(root, &read(&join(root, LEDGER_PATH)?)?)?;
        if readback.entries != ledger.entries {
            return Err(Phase10Error::InvalidContract(
                "per-case ledger readback differs".to_owned(),
            ));
        }
        outcomes.push(outcome);
    }
    let run_finished = unix_millis();
    let run = Phase10Run {
        schema_version: RUN_SCHEMA.to_owned(),
        run_id: RUN_ID.to_owned(),
        holdout_id: manifest.holdout_id.clone(),
        pre_execution_contract_sha256: fingerprint(pre_execution_bytes),
        binary_sha256: BINARY_SHA256.to_owned(),
        source_rpm_sha256: RPM_SHA256.to_owned(),
        command_template: command_template(),
        process_status_policy_version: PROCESS_STATUS_POLICY_VERSION.to_owned(),
        ai_validation: contract.scanner.ai_validation.clone(),
        version_probe_executed: false,
        host: host_provenance(),
        started_unix_ms: run_started,
        finished_unix_ms: run_finished,
        status: aggregate_status(&outcomes),
        case_journal_sha256: hash_file(&journal_path)?,
        scanner_launch_attempts: outcomes
            .iter()
            .map(|case| case.scanner_launch_attempts)
            .sum(),
        scanner_processes_attested: u64::try_from(
            outcomes
                .iter()
                .filter(|case| case.isolation.is_some())
                .count(),
        )
        .unwrap_or(u64::MAX),
        cases: outcomes,
    };
    validate_run(&run, manifest)?;
    let run_bytes = canonical_json(&run)?;
    validate_schema(
        root,
        "phase10/schemas/phase10-run-v1.schema.json",
        &run_bytes,
    )?;
    create_new(&join(root, RUN_PATH)?, &run_bytes)?;

    let audit = process_audit(&run);
    let audit_bytes = canonical_json(&audit)?;
    validate_schema(
        root,
        "phase10/schemas/phase10-process-audit-v1.schema.json",
        &audit_bytes,
    )?;
    create_new(&join(root, PROCESS_AUDIT_PATH)?, &audit_bytes)?;

    let reports = load_reports(&run, &run_directory)?;
    let evaluation_ledger_bytes = read(&join(root, LEDGER_PATH)?)?;
    let result = evaluate(
        manifest,
        evidence,
        taxonomy,
        &run,
        &reports,
        contract,
        pre_execution_bytes,
        &run_bytes,
        &evaluation_ledger_bytes,
        &audit_bytes,
    )?;
    let result_bytes = canonical_json(&result)?;
    validate_schema(
        root,
        "phase10/schemas/phase10-result-v1.schema.json",
        &result_bytes,
    )?;
    create_new(&join(root, RESULT_PATH)?, &result_bytes)?;
    let result_sha256 = fingerprint(&result_bytes);
    let completed = new_ledger_entry(
        ledger,
        LedgerEvent::ExecutionCompleted,
        None,
        Some(&result_sha256),
        None,
    )?;
    let mut predicted_ledger = evaluation_ledger_bytes;
    predicted_ledger.extend_from_slice(&ledger_line(&completed)?);
    let artifacts = ArtifactIndex {
        schema_version: ARTIFACTS_SCHEMA.to_owned(),
        run_id: RUN_ID.to_owned(),
        pre_execution_contract_path: PRE_EXECUTION_PATH.to_owned(),
        pre_execution_contract_sha256: fingerprint(pre_execution_bytes),
        run_path: RUN_PATH.to_owned(),
        run_sha256: fingerprint(&run_bytes),
        result_path: RESULT_PATH.to_owned(),
        result_sha256,
        completed_ledger_path: LEDGER_PATH.to_owned(),
        completed_ledger_sha256: fingerprint(&predicted_ledger),
        genesis_ledger_sha256: GENESIS_LEDGER_SHA256.to_owned(),
        case_journal_sha256: run.case_journal_sha256.clone(),
        reports_sha256: reports_aggregate(&run),
        streams_sha256: streams_aggregate(&run),
        isolation_attestations_sha256: isolation_aggregate(&run),
        process_audit_path: PROCESS_AUDIT_PATH.to_owned(),
        process_audit_sha256: fingerprint(&audit_bytes),
        case_records: EXPECTED_CASES as u64,
        report_count: u64::try_from(reports.len()).unwrap_or(u64::MAX),
        stdout_records: EXPECTED_CASES as u64,
        stderr_records: EXPECTED_CASES as u64,
        isolation_attestations: run.scanner_processes_attested,
        ledger_entries: u64::try_from(ledger.entries.len() + 2).unwrap_or(u64::MAX),
    };
    let artifact_bytes = canonical_json(&artifacts)?;
    validate_schema(
        root,
        "phase10/schemas/phase10-artifacts-v1.schema.json",
        &artifact_bytes,
    )?;
    create_new(&join(root, ARTIFACTS_PATH)?, &artifact_bytes)?;
    append_ledger(&join(root, LEDGER_PATH)?, &completed)?;
    ledger.entries.push(completed);
    let final_bytes = read(&join(root, LEDGER_PATH)?)?;
    if final_bytes != predicted_ledger
        || load_completed_ledger(root, &final_bytes)?.entries != ledger.entries
    {
        return Err(Phase10Error::InvalidContract(
            "completed ledger differs from the predicted durable chain".to_owned(),
        ));
    }
    let _ = rpm;
    Ok(artifacts)
}

/// Executes the 224-case holdout once after durably reserving the evidence lifecycle.
///
/// # Errors
///
/// Returns an error when preflight reproduction, durable reservation, evidence retention, or
/// terminal sealing fails. A second invocation is rejected after the first reservation.
#[allow(clippy::too_many_lines)]
pub fn execute_repository(
    root: &Path,
    scanner: &Path,
    rpm: &Path,
) -> Result<ArtifactIndex, Phase10Error> {
    let (contract, pre_execution_bytes) = load_pre_execution(root)?;
    let (manifest, evidence, taxonomy, benchmark) =
        validate_execution_inputs(root, scanner, rpm, &contract)?;
    for relative in [
        RUN_DIRECTORY,
        RESULT_PATH,
        ARTIFACTS_PATH,
        PROCESS_AUDIT_PATH,
    ] {
        if fs::symlink_metadata(join(root, relative)?).is_ok() {
            return Err(Phase10Error::InvalidContract(format!(
                "create-new execution artifact `{relative}` already exists"
            )));
        }
    }
    let ledger_path = join(root, LEDGER_PATH)?;
    let ledger_bytes = read(&ledger_path)?;
    let mut ledger = load_completed_ledger(root, &ledger_bytes)?;
    if !ledger.entries.is_empty() || fingerprint(&ledger_bytes) != GENESIS_LEDGER_SHA256 {
        return Err(Phase10Error::InvalidContract(
            "one-shot ledger is no longer genesis-only".to_owned(),
        ));
    }
    let started = new_ledger_entry(&ledger, LedgerEvent::ExecutionStarted, None, None, None)?;
    append_ledger(&ledger_path, &started)?;
    ledger.entries.push(started);
    if load_completed_ledger(root, &read(&ledger_path)?)?.entries != ledger.entries {
        return Err(Phase10Error::InvalidContract(
            "one-shot reservation readback differs".to_owned(),
        ));
    }
    match execute_reserved(
        root,
        scanner,
        rpm,
        &contract,
        &pre_execution_bytes,
        &manifest,
        &evidence,
        &taxonomy,
        &benchmark,
        &mut ledger,
    ) {
        Ok(artifacts) => Ok(artifacts),
        Err(error) => {
            if let Ok(bytes) = read(&ledger_path)
                && let Ok(mut current) = load_completed_ledger(root, &bytes)
                && !current.entries.last().is_some_and(|entry| {
                    matches!(
                        entry.event,
                        LedgerEvent::ExecutionCompleted | LedgerEvent::ExecutionFailed
                    )
                })
                && let Ok(failed) = new_ledger_entry(
                    &current,
                    LedgerEvent::ExecutionFailed,
                    None,
                    None,
                    Some("phase10.infrastructure_failure"),
                )
            {
                let _ = append_ledger(&ledger_path, &failed);
                current.entries.push(failed);
            }
            Err(error)
        }
    }
}

fn load_canonical<T>(
    root: &Path,
    relative: &str,
    schema: &str,
    label: &str,
) -> Result<(T, Vec<u8>), Phase10Error>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let bytes = read(&join(root, relative)?)?;
    let value: T = parse_json(&bytes, label)?;
    if canonical_json(&value)? != bytes {
        return Err(Phase10Error::InvalidContract(format!(
            "{label} is not canonical JSON"
        )));
    }
    validate_schema(root, schema, &bytes)?;
    Ok((value, bytes))
}

fn load_journal(bytes: &[u8]) -> Result<Vec<CaseRun>, Phase10Error> {
    serde_json::Deserializer::from_slice(bytes)
        .into_iter::<CaseRun>()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            Phase10Error::InvalidContract(format!(
                "case journal is malformed at line {}",
                error.line()
            ))
        })
}

fn collect_regular_files(
    root: &Path,
    relative: &Path,
    output: &mut Vec<PathBuf>,
) -> Result<(), Phase10Error> {
    let path = root.join(relative);
    let metadata = fs::symlink_metadata(&path).map_err(|error| io_error(&path, &error))?;
    if metadata.file_type().is_symlink() {
        return Err(Phase10Error::InvalidContract(format!(
            "evidence tree contains symlink `{}`",
            relative.display()
        )));
    }
    if metadata.is_file() {
        output.push(relative.to_path_buf());
        return Ok(());
    }
    if !metadata.is_dir() {
        return Err(Phase10Error::InvalidContract(format!(
            "evidence tree contains non-regular entry `{}`",
            relative.display()
        )));
    }
    let mut entries = fs::read_dir(&path)
        .map_err(|error| io_error(&path, &error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| io_error(&path, &error))?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        collect_regular_files(root, &relative.join(entry.file_name()), output)?;
    }
    Ok(())
}

fn validate_output_shape(root: &Path, run: &Phase10Run) -> Result<(), Phase10Error> {
    let output_root = join(root, OUTPUT_ROOT)?;
    let mut files = Vec::new();
    collect_regular_files(&output_root, Path::new("."), &mut files)?;
    let actual = files
        .into_iter()
        .map(|path| {
            path.strip_prefix(".")
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect::<BTreeSet<_>>();
    let mut expected = BTreeSet::from([
        "pre-execution-contract.json".to_owned(),
        "completed-ledger.jsonl".to_owned(),
        "result.json".to_owned(),
        "artifacts.json".to_owned(),
        "process-audit.json".to_owned(),
        "run/cases.jsonl".to_owned(),
        "run/run.json".to_owned(),
    ]);
    for case in &run.cases {
        expected.insert(format!("run/{}", case.stdout_path));
        expected.insert(format!("run/{}", case.stderr_path));
        if let Some(path) = &case.execution.report_path {
            expected.insert(format!("run/{path}"));
        }
        if let Some(path) = &case.isolation_path {
            expected.insert(format!("run/{path}"));
        }
    }
    if actual != expected {
        return Err(Phase10Error::InvalidContract(
            "Phase 10 output tree contains a missing or unexpected file".to_owned(),
        ));
    }
    Ok(())
}

fn expected_case_status(
    case: &CaseRun,
    assessment: &AssessmentKind,
    isolation_valid: bool,
) -> (ProcessStatusDecision, LiveCaseStatus) {
    let termination = if isolation_valid {
        case.termination.policy()
    } else {
        ProcessTermination::ExecutionFailure
    };
    let decision = adjudicate_status(termination, assessment.policy());
    let status = if !isolation_valid {
        LiveCaseStatus::ExecutionFailure
    } else if matches!(assessment, AssessmentKind::Unsupported)
        && matches!(case.termination, TerminationRecord::Exited(_))
    {
        LiveCaseStatus::UnsupportedSchema
    } else {
        status_from_decision(decision)
    };
    (decision, status)
}

#[allow(clippy::too_many_lines)]
fn validate_retained_cases(
    root: &Path,
    run: &Phase10Run,
    run_directory: &Path,
) -> Result<BTreeMap<String, Vec<u8>>, Phase10Error> {
    let reports = load_reports(run, run_directory)?;
    for case in &run.cases {
        let stdout = read(&run_directory.join(safe_relative(&case.stdout_path)?))?;
        let stderr = read(&run_directory.join(safe_relative(&case.stderr_path)?))?;
        if fingerprint(&stdout) != case.stdout_sha256
            || fingerprint(&stdout) != case.execution.stdout.fingerprint
            || u64::try_from(stdout.len()).unwrap_or(u64::MAX) != case.execution.stdout.bytes
            || case.execution.stdout.truncated
            || fingerprint(&stderr) != case.stderr_sha256
            || fingerprint(&stderr) != case.execution.stderr.fingerprint
            || u64::try_from(stderr.len()).unwrap_or(u64::MAX) != case.execution.stderr.bytes
            || case.execution.stderr.truncated
        {
            return Err(Phase10Error::InvalidContract(format!(
                "retained process streams differ for `{}`",
                case.execution.case_id
            )));
        }
        if contains_private_data(&stdout) || contains_private_data(&stderr) {
            return Err(Phase10Error::InvalidContract(format!(
                "retained process stream leaks private data for `{}`",
                case.execution.case_id
            )));
        }
        let report = reports.get(&case.execution.case_id).map(Vec::as_slice);
        if report.is_some_and(contains_private_data) {
            return Err(Phase10Error::InvalidContract(format!(
                "retained report leaks private data for `{}`",
                case.execution.case_id
            )));
        }
        let assessment = assess_report(&case.execution.case_id, report);
        if assessment.name() != case.report_assessment {
            return Err(Phase10Error::InvalidContract(format!(
                "report assessment differs for `{}`",
                case.execution.case_id
            )));
        }
        let isolation_valid = match (
            &case.isolation_path,
            &case.isolation_sha256,
            &case.isolation,
        ) {
            (Some(path), Some(expected_hash), expected) => {
                let bytes = read(&run_directory.join(safe_relative(path)?))?;
                if fingerprint(&bytes) != *expected_hash {
                    return Err(Phase10Error::InvalidContract(format!(
                        "isolation bytes differ for `{}`",
                        case.execution.case_id
                    )));
                }
                let parsed = validate_isolation(
                    root,
                    &load_pre_execution(root)?.0,
                    &case.execution.case_id,
                    &bytes,
                );
                match (expected, parsed) {
                    (Some(expected), Ok(parsed)) if *expected == parsed => true,
                    (None, Err(_)) => false,
                    _ => {
                        return Err(Phase10Error::InvalidContract(format!(
                            "isolation interpretation differs for `{}`",
                            case.execution.case_id
                        )));
                    }
                }
            }
            (None, None, None) => false,
            _ => {
                return Err(Phase10Error::InvalidContract(format!(
                    "isolation binding is incomplete for `{}`",
                    case.execution.case_id
                )));
            }
        };
        let (decision, status) = expected_case_status(case, &assessment, isolation_valid);
        if decision != case.process_status || status != case.execution.status {
            return Err(Phase10Error::InvalidContract(format!(
                "process-status policy differs for `{}`",
                case.execution.case_id
            )));
        }
        if matches!(assessment, AssessmentKind::Valid(_))
            && matches!(case.termination, TerminationRecord::Exited(1))
            && case.process_status != ProcessStatusDecision::PolicyExitWithValidFindingsReport
        {
            return Err(Phase10Error::InvalidContract(
                "exit code 1 with an authoritative findings report was not completed".to_owned(),
            ));
        }
    }
    Ok(reports)
}

/// Verifies the complete retained Phase 10 bundle without launching a scanner process.
///
/// # Errors
///
/// Returns an error for any input drift, raw-artifact mismatch, policy disagreement, ledger
/// break, privacy issue, non-deterministic evaluation, schema error, or process-audit defect.
#[allow(clippy::too_many_lines)]
pub fn verify_repository(
    root: &Path,
    scanner: &Path,
    rpm: &Path,
) -> Result<ArtifactIndex, Phase10Error> {
    let (contract, pre_execution_bytes) = load_pre_execution(root)?;
    let (manifest, evidence, taxonomy, _) =
        validate_execution_inputs(root, scanner, rpm, &contract)?;
    let git = git_contract(root, false)?;
    if git.main_commit != contract.git.main_commit
        || git.head_commit != contract.git.head_commit
        || git.branch != contract.git.branch
        || git.signature != contract.git.signature
        || git.dco != contract.git.dco
    {
        return Err(Phase10Error::InvalidContract(
            "Git prerequisites changed after execution".to_owned(),
        ));
    }
    let ledger_bytes = read(&join(root, LEDGER_PATH)?)?;
    let ledger = load_completed_ledger(root, &ledger_bytes)?;
    if ledger.entries.len() != EXPECTED_CASES + 2
        || ledger.entries.first().map(|entry| entry.event) != Some(LedgerEvent::ExecutionStarted)
        || ledger
            .entries
            .iter()
            .skip(1)
            .take(EXPECTED_CASES)
            .any(|entry| entry.event != LedgerEvent::CaseRecorded)
        || ledger.entries.last().map(|entry| entry.event) != Some(LedgerEvent::ExecutionCompleted)
    {
        return Err(Phase10Error::InvalidContract(
            "completed ledger does not contain one reservation, 224 cases, and one completion"
                .to_owned(),
        ));
    }
    let (run, run_bytes): (Phase10Run, Vec<u8>) = load_canonical(
        root,
        RUN_PATH,
        "phase10/schemas/phase10-run-v1.schema.json",
        "Phase 10 run",
    )?;
    validate_run(&run, &manifest)?;
    if run.pre_execution_contract_sha256 != fingerprint(&pre_execution_bytes) {
        return Err(Phase10Error::InvalidContract(
            "run is not bound to the pre-execution contract".to_owned(),
        ));
    }
    let run_directory = join(root, RUN_DIRECTORY)?;
    let journal_bytes = read(&run_directory.join("cases.jsonl"))?;
    if fingerprint(&journal_bytes) != run.case_journal_sha256
        || load_journal(&journal_bytes)? != run.cases
    {
        return Err(Phase10Error::InvalidContract(
            "case journal differs from the retained run".to_owned(),
        ));
    }
    for (case, entry) in run.cases.iter().zip(ledger.entries.iter().skip(1)) {
        if entry.case_id.as_deref() != Some(case.execution.case_id.as_str())
            || entry.case_status != Some(case.execution.status)
            || entry.process_status != Some(case.process_status)
            || entry.case_record_sha256.as_deref()
                != Some(fingerprint(&canonical_json(case)?).as_str())
            || entry.report_sha256 != case.execution.report_fingerprint
            || entry.isolation_sha256 != case.isolation_sha256
        {
            return Err(Phase10Error::InvalidContract(format!(
                "ledger binding differs for `{}`",
                case.execution.case_id
            )));
        }
    }
    validate_output_shape(root, &run)?;
    let reports = validate_retained_cases(root, &run, &run_directory)?;
    let (audit, audit_bytes): (ProcessAudit, Vec<u8>) = load_canonical(
        root,
        PROCESS_AUDIT_PATH,
        "phase10/schemas/phase10-process-audit-v1.schema.json",
        "Phase 10 process audit",
    )?;
    if audit != process_audit(&run)
        || audit.frozen_cases != EXPECTED_CASES as u64
        || audit.unique_case_records != EXPECTED_CASES as u64
        || audit.scanner_launch_attempts != EXPECTED_CASES as u64
        || audit.maximum_attempts_per_case != 1
        || audit.version_probes != 0
        || audit.ai_commands != 0
        || audit.network_permitted_processes != 0
    {
        return Err(Phase10Error::InvalidContract(
            "process audit does not prove at-most-once isolated execution".to_owned(),
        ));
    }
    let terminal = ledger.entries.last().ok_or_else(|| {
        Phase10Error::InvalidContract("completed ledger has no terminal entry".to_owned())
    })?;
    let terminal_line = ledger_line(terminal)?;
    let prefix_length = ledger_bytes
        .len()
        .checked_sub(terminal_line.len())
        .ok_or_else(|| {
            Phase10Error::InvalidContract("completed ledger length is invalid".to_owned())
        })?;
    let evaluation_ledger_bytes = &ledger_bytes[..prefix_length];
    let first = evaluate(
        &manifest,
        &evidence,
        &taxonomy,
        &run,
        &reports,
        &contract,
        &pre_execution_bytes,
        &run_bytes,
        evaluation_ledger_bytes,
        &audit_bytes,
    )?;
    let second = evaluate(
        &manifest,
        &evidence,
        &taxonomy,
        &run,
        &reports,
        &contract,
        &pre_execution_bytes,
        &run_bytes,
        evaluation_ledger_bytes,
        &audit_bytes,
    )?;
    if first != second || canonical_json(&first)? != canonical_json(&second)? {
        return Err(Phase10Error::InvalidContract(
            "repeated offline evaluation is not deterministic".to_owned(),
        ));
    }
    let (result, result_bytes): (Phase10Result, Vec<u8>) = load_canonical(
        root,
        RESULT_PATH,
        "phase10/schemas/phase10-result-v1.schema.json",
        "Phase 10 result",
    )?;
    validate_result_semantics(&result)?;
    if result != first || result_bytes != canonical_json(&first)? {
        return Err(Phase10Error::InvalidContract(
            "retained result differs from deterministic offline evaluation".to_owned(),
        ));
    }
    let (artifacts, artifact_bytes): (ArtifactIndex, Vec<u8>) = load_canonical(
        root,
        ARTIFACTS_PATH,
        "phase10/schemas/phase10-artifacts-v1.schema.json",
        "Phase 10 artifact index",
    )?;
    if terminal.result_sha256.as_deref() != Some(fingerprint(&result_bytes).as_str())
        || artifacts.schema_version != ARTIFACTS_SCHEMA
        || artifacts.run_id != RUN_ID
        || artifacts.pre_execution_contract_sha256 != fingerprint(&pre_execution_bytes)
        || artifacts.run_sha256 != fingerprint(&run_bytes)
        || artifacts.result_sha256 != fingerprint(&result_bytes)
        || artifacts.completed_ledger_sha256 != fingerprint(&ledger_bytes)
        || artifacts.genesis_ledger_sha256 != GENESIS_LEDGER_SHA256
        || artifacts.case_journal_sha256 != run.case_journal_sha256
        || artifacts.reports_sha256 != reports_aggregate(&run)
        || artifacts.streams_sha256 != streams_aggregate(&run)
        || artifacts.isolation_attestations_sha256 != isolation_aggregate(&run)
        || artifacts.process_audit_sha256 != fingerprint(&audit_bytes)
        || artifacts.case_records != EXPECTED_CASES as u64
        || artifacts.report_count != u64::try_from(reports.len()).unwrap_or(u64::MAX)
        || artifacts.stdout_records != EXPECTED_CASES as u64
        || artifacts.stderr_records != EXPECTED_CASES as u64
        || artifacts.isolation_attestations != run.scanner_processes_attested
        || artifacts.ledger_entries != u64::try_from(EXPECTED_CASES + 3).unwrap_or(u64::MAX)
    {
        return Err(Phase10Error::InvalidContract(
            "artifact index or terminal binding differs".to_owned(),
        ));
    }
    for bytes in [
        pre_execution_bytes.as_slice(),
        run_bytes.as_slice(),
        result_bytes.as_slice(),
        artifact_bytes.as_slice(),
        audit_bytes.as_slice(),
        ledger_bytes.as_slice(),
    ] {
        if contains_private_data(bytes) {
            return Err(Phase10Error::InvalidContract(
                "public Phase 10 artifact contains private data".to_owned(),
            ));
        }
    }
    Ok(artifacts)
}

/// Returns a concise aggregate summary from the immutable result without starting a process.
///
/// # Errors
///
/// Returns an error if the result is absent or malformed.
pub fn summarize_repository(root: &Path) -> Result<String, Phase10Error> {
    let (result, _): (Phase10Result, Vec<u8>) = load_canonical(
        root,
        RESULT_PATH,
        "phase10/schemas/phase10-result-v1.schema.json",
        "Phase 10 result",
    )?;
    let counts = &result.metrics.counts;
    Ok(format!(
        "exact={}/{} partial={} missed={} out_of_scope={} not_attempted={} controls_flagged={}/{} controls_clean={} findings={} duplicates={} unrelated={} precision={}/{} recall={}/{} f1={}/{} failures={} semantic_fingerprint={}",
        counts.exact_detections,
        counts.vulnerable_expectations,
        counts.partial_matches,
        counts.misses,
        counts.out_of_scope,
        counts.not_attempted,
        counts.safe_controls_flagged,
        counts.safe_controls,
        counts.clean_safe_controls,
        counts.findings,
        counts.duplicate_findings,
        counts.unrelated_findings,
        result.metrics.precision.numerator,
        result.metrics.precision.denominator,
        result.metrics.recall.numerator,
        result.metrics.recall.denominator,
        result.metrics.f1.numerator,
        result.metrics.f1.denominator,
        result.measurement.failures,
        result.semantic_fingerprint
    ))
}

fn rfc3339_now() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn report(exit_findings: usize, complete: bool, errors: bool) -> Vec<u8> {
        let finding = serde_json::json!({
            "rule_id": "neutral-rule",
            "taxonomy": {
                "taxonomy_version": "1.0.0",
                "category_id": "secure-bench.category.outbound-request-boundary",
                "invariant_id": "secure-bench.invariant.outbound-request-requires-final-destination-policy"
            },
            "primary_cwe": { "id": "CWE-918" },
            "verification_state": "verified-deterministic-path",
            "evidence_path": [
                {
                    "edge_id_from_previous": null,
                    "kind": "source",
                    "semantic": {
                        "role": "untrusted-source",
                        "identity": "source.http-query-value",
                        "certainty": "proven"
                    },
                    "location": {
                        "path": "src/entry.ts",
                        "span": { "start_line": 2, "start_column": 2, "end_line": 2, "end_column": 12 }
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
                        "span": { "start_line": 4, "start_column": 2, "end_line": 4, "end_column": 16 }
                    }
                }
            ]
        });
        let findings = std::iter::repeat_n(finding, exit_findings).collect::<Vec<_>>();
        serde_json::to_vec(&serde_json::json!({
            "schema_version": "secure-json-v1",
            "scan": { "complete": complete },
            "errors": if errors { vec![serde_json::json!({"code": "internal"})] } else { vec![] },
            "findings": findings
        }))
        .unwrap_or_default()
    }

    #[test]
    fn phase8_policy_is_applied_before_exit_code_failure_classification() {
        let valid_findings = assess_report("case-v3-0001", Some(&report(1, true, false)));
        assert_eq!(
            adjudicate_status(ProcessTermination::Exited(1), valid_findings.policy()),
            ProcessStatusDecision::PolicyExitWithValidFindingsReport
        );
        assert_eq!(
            status_from_decision(ProcessStatusDecision::PolicyExitWithValidFindingsReport),
            LiveCaseStatus::Findings
        );
        let clean = assess_report("case-v3-0001", Some(&report(0, true, false)));
        assert_eq!(
            adjudicate_status(ProcessTermination::Exited(0), clean.policy()),
            ProcessStatusDecision::CleanSuccessfulReport
        );
    }

    #[test]
    fn process_policy_covers_failures_without_clean_credit() {
        let malformed = assess_report("case-v3-0001", Some(b"{"));
        let internal = assess_report("case-v3-0001", Some(&report(1, false, true)));
        assert_eq!(
            adjudicate_status(ProcessTermination::Exited(2), malformed.policy()),
            ProcessStatusDecision::MalformedReport
        );
        assert_eq!(
            adjudicate_status(ProcessTermination::Exited(0), internal.policy()),
            ProcessStatusDecision::InternallyErroredReport
        );
        assert_eq!(
            adjudicate_status(ProcessTermination::Exited(2), ReportAssessment::Missing),
            ProcessStatusDecision::MissingReport
        );
        assert_eq!(
            adjudicate_status(ProcessTermination::Timeout, ReportAssessment::Missing),
            ProcessStatusDecision::Timeout
        );
        assert_eq!(
            adjudicate_status(ProcessTermination::Signaled, ReportAssessment::Missing),
            ProcessStatusDecision::GenuineCrash
        );
        assert_eq!(
            adjudicate_status(
                ProcessTermination::ExecutionFailure,
                ReportAssessment::Missing
            ),
            ProcessStatusDecision::GenuineCrash
        );
    }

    #[test]
    fn adapter_retains_duplicates_and_canonical_semantics() -> Result<(), Phase10Error> {
        let bytes = report(2, true, false);
        let findings = adapt_report("case-v3-0001", &bytes, &fingerprint(&bytes))?;
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].adapter_state, Phase7AdapterState::Canonical);
        assert_eq!(
            findings[0].semantic_fingerprint,
            findings[1].semantic_fingerprint
        );
        assert_ne!(findings[0].finding_id, findings[1].finding_id);
        Ok(())
    }

    #[test]
    fn phase9_projection_has_every_frozen_case_and_intersection() -> Result<(), Phase10Error> {
        let manifest = parse_manifest(include_bytes!("../../holdout/phase-9/manifest.json"))?;
        assert_eq!(manifest.pairs.len(), 112);
        assert_eq!(flatten_cases(&manifest).len(), 224);
        assert_eq!(
            manifest
                .pairs
                .iter()
                .map(|pair| pair.assignment.family_id.as_str())
                .collect::<BTreeSet<_>>()
                .len(),
            7
        );
        for pair in &manifest.pairs {
            for case in [&pair.first, &pair.second] {
                if let Some(expectation) = &case.expectation {
                    let canonical = expectation.canonical()?;
                    assert_eq!(canonical.primary_cwe, pair.primary_cwe);
                    assert_eq!(canonical.invariant_id, pair.invariant_id);
                    assert_eq!(
                        canonical.path.last().and_then(|node| node.sink_kind),
                        Some(pair.sink_kind)
                    );
                }
            }
        }
        Ok(())
    }

    #[test]
    fn verify_dispatch_has_no_implicit_execution() {
        let main = include_str!("main.rs");
        let verify_arm = main
            .split("\"verify\" =>")
            .nth(1)
            .and_then(|value| value.split("\"summary\" =>").next())
            .unwrap_or_default();
        assert!(verify_arm.contains("verify_repository"));
        assert!(!verify_arm.contains("execute_repository"));
        assert!(!verify_arm.contains("isolated_exec"));
    }

    #[test]
    fn private_and_parent_paths_are_rejected() {
        assert!(safe_relative("src/entry.ts").is_ok());
        assert!(safe_relative("../answers.json").is_err());
        assert!(safe_relative("/home/private/report.json").is_err());
        assert!(contains_private_data(b"/home/private/report.json"));
    }
}
