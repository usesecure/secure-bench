//! Secure Bench Phase 24 Semgrep-only post-open normalized recovery.

#![allow(
    clippy::cast_precision_loss,
    clippy::doc_markdown,
    clippy::format_collect,
    clippy::format_push_string,
    clippy::items_after_statements,
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unreadable_literal
)]

use secure_bench_phase21::sandbox::{
    SEMGREP_SOURCE, Scanner, fixed_environment, scanner_command, scanner_sandbox,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use thiserror::Error;

const PHASE23: &str = "85e9ad1e9c87dbd238c2f5529ce9421dce920092";
const PHASE22: &str = "b8ef30bfcd9761644001b63ed9b9f717ebd09d93";
const PHASE23_ROOT_TREE: &str = "db4b34885b689447874c8c53a7cf376764b05a94";
const PHASE20_TREE: &str = "05cd69281777263a4f9286069767d870014cab52";
const PHASE22_TREE: &str = "048b3c30e0864ca6e61e2af40de11016050a1ca3";
const PHASE23_TREE: &str = "c0d7a4b3e39617718a6e3b23c1b723c45de9a313";
const CORPUS_TREE: &str = "ddfe1134b007aa52a6c5e351d535c9ed4c0cd76a";
const MANIFEST: &str = "phase19/holdout/manifest.json";
const MANIFEST_SHA256: &str = "c035f9de14e2a1cb7c65562f9a643f0eefafc682d23c90e520770c7183068cb6";
const CORPUS_SHA256: &str = "d059653d836647296bef93a43d9e9f046899ad4fa0a87d561b4463ce0db2781c";
const MERKLE_ROOT: &str = "2bcc11f20b0f9d06eeb10f05130b752fa8125421ebf37d6050cd3119aef4452e";
const RULESET: &str = "phase19/rules/capability-normalized-v1.yml";
const RULESET_SHA256: &str = "06af4cf6d10da30ad585d57b781cf6aef734add03b90ea36c78e920c4c10a07c";
const ADAPTER: &str = "phase20/config/semgrep-normalized-adapter-v1.json";
const ADAPTER_SHA256: &str = "53317a4e71b14548d618fd79430b74b8fc906edebbf7180cbea418df98b1afc3";
const SCORING: &str = "phase20/config/scoring-methodology-v1.json";
const SCORING_SHA256: &str = "0e0a767e8b1df51ca8018d27956e1d0f4ba943d520888923221bbf67f9a7b2a6";
const PHASE22_PLAN: &str = "phase22/config/execution-plan-v1.json";
const PHASE22_PLAN_SHA256: &str =
    "4b3c91e72431854c7e4a240003ce2f0fe8fc988f8de102f593b223991ed9c6c4";
const PHASE22_RESULTS: &str = "phase22/output/results.json";
const PHASE22_RESULTS_SHA256: &str =
    "150bcf3c41e5d1602f90da902d892d8bc32b5e1fd13bcdc11a3774c15bcb1892";
const PHASE23_CONTRACT: &str = "phase23/config/corrected-environment-contract-v1.json";
const PHASE23_CONTRACT_SHA256: &str =
    "df737de168c1c78855ee589cbe105f9123601be3571a765dfcc21cddbf4cbe5a";
const PHASE23_SUMS_SHA256: &str =
    "676661e77ead8d851ae7ac633e4588b89ed7d5b0ab088e2e718c2f059c1a3f2e";
const PLAN: &str = "phase24/config/execution-plan-v1.json";
const CONTRACT: &str = "phase24/config/execution-contract-v1.json";
const PREFLIGHT: &str = "phase24/preflight";
const OUTPUT: &str = "phase24/output";
const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const TIMEOUT: Duration = Duration::from_mins(2);
const MAX_OUTPUT: u64 = 10 * 1024 * 1024;
const SEMGREP_ENTRYPOINT_SHA256: &str =
    "0280e5c6cca8d8e4cb2c41858b06697b957daf23d718cac411999c4c515507e1";
const SEMGREP_WHEEL_SHA256: &str =
    "09a7e8eeff5e2549161124957184f3566f484370aa6127e425897cef725eb99b";
const SEMGREP_CLOSURE_SHA256: &str =
    "5371b438dc6e3c5529794b21c668057164f52fa1375e0e91ee6c8f241fb74181";
const SEMGREP_LOCK_SHA256: &str =
    "50bc99977b0205235301b2508c5cc84dbc4a421f593f18d75e19fa19d7969e39";
const ALLOWED_RULES: [&str; 7] = [
    "secure-bench.phase19.SE1001.resource-authorization",
    "secure-bench.phase19.SE1002.command-injection",
    "secure-bench.phase19.SE1003.dynamic-code",
    "secure-bench.phase19.SE1004.path-traversal",
    "secure-bench.phase19.SE1005.outbound-request",
    "secure-bench.phase19.SE1006.open-redirect",
    "secure-bench.phase19.SE1007.sql-injection",
];

/// Phase 24 fail-closed error.
#[derive(Debug, Error)]
pub enum Phase24Error {
    /// Frozen contract or input drift.
    #[error("Phase 24 contract failure: {0}")]
    Contract(String),
    /// Preflight failure before corpus opening.
    #[error("Phase 24 preflight failure: {0}")]
    Preflight(String),
    /// Post-open execution failure.
    #[error("Phase 24 execution failure: {0}")]
    Execution(String),
    /// Scanner-free verification failure.
    #[error("Phase 24 verification failure: {0}")]
    Verification(String),
    /// Filesystem operation failed.
    #[error("Phase 24 filesystem failure: {0}")]
    Io(#[from] std::io::Error),
    /// JSON operation failed.
    #[error("Phase 24 JSON failure: {0}")]
    Json(#[from] serde_json::Error),
}

/// One opaque Semgrep/case key frozen before opening cases.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanAttempt {
    /// Contiguous sequence from 1 through 112.
    pub sequence: u64,
    /// Frozen scanner identity.
    pub scanner: String,
    /// Frozen lane identity.
    pub lane: String,
    /// Opaque Phase 19 case ID.
    pub case_id: String,
}

/// Canonical Phase 24 execution plan.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionPlan {
    /// Schema identity.
    pub schema_version: String,
    /// Study identity.
    pub study: String,
    /// Exclusive run identity.
    pub run_id: String,
    /// Planned attempts.
    pub total_attempts: u64,
    /// Frozen retries.
    pub retries: u64,
    /// Explicit excluded process counts.
    pub excluded_attempts: BTreeMap<String, u64>,
    /// Ordered unique keys.
    pub attempts: Vec<PlanAttempt>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CaseSpec {
    case_id: String,
    pair_id: String,
    classification: String,
    family: String,
    framework: String,
    source_format: String,
    topology: String,
    adversarial_variant: Option<String>,
    fixture_path: String,
}

/// Explicit execution state; failures are never numeric results.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptState {
    /// Adapter-valid completed report.
    Completed,
    /// Spawn, process, signal, or adapter failure.
    Failed,
    /// External watchdog timeout.
    Timeout,
    /// Invalid JSON report.
    Malformed,
    /// Evidence was not emitted.
    Unavailable,
}

/// One immutable Phase 24 attempt observation.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    /// Plan sequence.
    pub sequence: u64,
    /// Exclusive attempt ID.
    pub attempt_id: String,
    /// Scanner identity.
    pub scanner: String,
    /// Lane identity.
    pub lane: String,
    /// Opaque case ID.
    pub case_id: String,
    /// Explicit state.
    pub state: AttemptState,
    /// Process-policy decision.
    pub process_decision: String,
    /// Normal exit code.
    pub exit_code: Option<i32>,
    /// Terminating signal.
    pub signal: Option<i32>,
    /// Watchdog state.
    pub timed_out: bool,
    /// Wall duration.
    pub duration_ms: u64,
    /// Exact command vector.
    pub command: Vec<String>,
    /// Command hash.
    pub command_sha256: String,
    /// Fixed environment.
    pub environment: Vec<String>,
    /// Environment hash.
    pub environment_sha256: String,
    /// Standard output path.
    pub stdout_path: String,
    /// Standard output hash.
    pub stdout_sha256: String,
    /// Standard error path.
    pub stderr_path: String,
    /// Standard error hash.
    pub stderr_sha256: String,
    /// Raw JSON path.
    pub raw_output_path: Option<String>,
    /// Raw JSON hash.
    pub raw_output_sha256: Option<String>,
    /// GNU time evidence path.
    pub resource_path: String,
    /// GNU time evidence hash.
    pub resource_sha256: String,
    /// Effective environment/limit evidence path.
    pub effective_environment_path: Option<String>,
    /// Effective environment/limit evidence hash.
    pub effective_environment_sha256: Option<String>,
    /// Adapter-valid finding count.
    pub finding_count: Option<u64>,
    /// Explicit failure, never imputed.
    pub failure: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LedgerEntry {
    schema_version: String,
    sequence: u64,
    event: String,
    payload_sha256: String,
    previous_entry_hash: String,
    entry_hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Ratio {
    numerator: u64,
    denominator: u64,
    decimal: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Metrics {
    tp: u64,
    fp: u64,
    tn: u64,
    fn_count: u64,
    precision: Option<Ratio>,
    recall: Option<Ratio>,
    specificity: Option<Ratio>,
    f1: Option<Ratio>,
    balanced_accuracy: Option<Ratio>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CaseDecision {
    case_id: String,
    pair_id: String,
    expected: String,
    finding_count: u64,
    predicted_positive: bool,
    outcome: String,
    family: String,
    framework: String,
    source_format: String,
    topology: String,
    adversarial_variant: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PairDecision {
    pair_id: String,
    vulnerable_case_id: String,
    control_case_id: String,
    vulnerable_flagged: bool,
    control_flagged: bool,
    pair_exact: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Operations {
    attempts: u64,
    completed: u64,
    failed: u64,
    timeouts: u64,
    malformed: u64,
    unavailable: u64,
    total_duration_ms: u64,
    min_duration_ms: Option<u64>,
    median_duration_ms: Option<u64>,
    p95_duration_ms: Option<u64>,
    max_duration_ms: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LaneResult {
    phase: u64,
    scanner: String,
    lane: String,
    environment: String,
    state: String,
    operations: Operations,
    metrics: Option<Metrics>,
    cases: Vec<CaseDecision>,
    pairs: Vec<PairDecision>,
    by_family: BTreeMap<String, Metrics>,
    by_framework: BTreeMap<String, Metrics>,
    by_source_format: BTreeMap<String, Metrics>,
    by_topology: BTreeMap<String, Metrics>,
    by_adversarial_variant: BTreeMap<String, Metrics>,
    by_classification: BTreeMap<String, Metrics>,
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn sha_file(path: &Path) -> Result<String, Phase24Error> {
    Ok(sha256(&fs::read(path)?))
}

fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, Phase24Error> {
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), Phase24Error> {
    let parent = path
        .parent()
        .ok_or_else(|| Phase24Error::Contract("output path has no parent".to_owned()))?;
    fs::create_dir_all(parent)?;
    let temporary = path.with_extension("phase24-tmp");
    if temporary.exists() {
        fs::remove_file(&temporary)?;
    }
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(temporary, path)?;
    Ok(())
}

fn create_irreversible(path: &Path, bytes: &[u8]) -> Result<(), Phase24Error> {
    let parent = path
        .parent()
        .ok_or_else(|| Phase24Error::Contract("marker path has no parent".to_owned()))?;
    fs::create_dir_all(parent)?;
    let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn git(root: &Path, arguments: &[&str]) -> Result<String, Phase24Error> {
    let output = Command::new("git")
        .args(arguments)
        .current_dir(root)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()?;
    if !output.status.success() {
        return Err(Phase24Error::Preflight(format!(
            "git {} failed: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn collect_files(path: &Path, output: &mut Vec<PathBuf>) -> Result<(), Phase24Error> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(Phase24Error::Contract(format!(
            "symlink is forbidden: {}",
            path.display()
        )));
    }
    if metadata.is_file() {
        output.push(path.to_path_buf());
        return Ok(());
    }
    if path.file_name().and_then(|name| name.to_str()) == Some("target") {
        return Ok(());
    }
    let mut entries = fs::read_dir(path)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        collect_files(&entry.path(), output)?;
    }
    Ok(())
}

fn implementation_digest(root: &Path) -> Result<String, Phase24Error> {
    let phase = root.join("phase24");
    let mut files = Vec::new();
    collect_files(&phase, &mut files)?;
    files.retain(|file| {
        file.strip_prefix(&phase).is_ok_and(|relative| {
            !matches!(
                relative
                    .components()
                    .next()
                    .and_then(|component| component.as_os_str().to_str()),
                Some("config" | "preflight" | "output" | "target")
            )
        })
    });
    files.sort();
    let mut projection = Vec::new();
    for file in files {
        let relative = file
            .strip_prefix(root)
            .map_err(|_| Phase24Error::Contract("implementation escaped root".to_owned()))?;
        projection.extend_from_slice(relative.to_string_lossy().as_bytes());
        projection.push(0);
        projection.extend_from_slice(sha_file(&file)?.as_bytes());
        projection.push(b'\n');
    }
    Ok(sha256(&projection))
}

fn now_ms() -> Result<u128, Phase24Error> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .map_err(|_| Phase24Error::Execution("system clock predates Unix epoch".to_owned()))
}

fn safe_relative(value: &str) -> Result<&Path, Phase24Error> {
    let path = Path::new(value);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(Phase24Error::Contract(format!(
            "unsafe relative path: {value}"
        )));
    }
    Ok(path)
}

fn validate_plan(plan: &ExecutionPlan) -> Result<(), Phase24Error> {
    if plan.schema_version != "secure-bench-phase24-execution-plan-v1"
        || plan.study != "semgrep post-open normalized recovery"
        || plan.run_id != "phase24-semgrep-normalized-recovery-v1"
        || plan.total_attempts != 112
        || plan.retries != 0
        || plan.attempts.len() != 112
        || plan.excluded_attempts.get("secure-engine") != Some(&0)
        || plan.excluded_attempts.get("opengrep") != Some(&0)
        || plan.excluded_attempts.get("native") != Some(&0)
    {
        return Err(Phase24Error::Contract(
            "Phase 24 plan header drift".to_owned(),
        ));
    }
    let mut ids = BTreeSet::new();
    for (index, attempt) in plan.attempts.iter().enumerate() {
        let numeric_case = attempt
            .case_id
            .strip_prefix("case-p19-")
            .is_some_and(|suffix| {
                suffix.len() == 4 && suffix.bytes().all(|byte| byte.is_ascii_digit())
            });
        if attempt.sequence != u64::try_from(index + 1).unwrap_or(u64::MAX)
            || attempt.scanner != "semgrep-ce"
            || attempt.lane != "capability-normalized"
            || !numeric_case
            || !ids.insert(attempt.case_id.as_str())
        {
            return Err(Phase24Error::Contract(format!(
                "invalid or repeated plan key at sequence {}",
                attempt.sequence
            )));
        }
    }
    if ids.len() != 112 {
        return Err(Phase24Error::Contract(
            "Phase 24 plan does not contain 112 unique cases".to_owned(),
        ));
    }
    Ok(())
}

fn load_plan(root: &Path) -> Result<ExecutionPlan, Phase24Error> {
    let plan: ExecutionPlan = serde_json::from_slice(&fs::read(root.join(PLAN))?)?;
    validate_plan(&plan)?;
    Ok(plan)
}

fn opaque_case_ids(root: &Path) -> Result<Vec<String>, Phase24Error> {
    if sha_file(&root.join(PHASE22_PLAN))? != PHASE22_PLAN_SHA256 {
        return Err(Phase24Error::Contract(
            "immutable Phase 22 execution plan drift".to_owned(),
        ));
    }
    let historical: Value = serde_json::from_slice(&fs::read(root.join(PHASE22_PLAN))?)?;
    let attempts = historical
        .get("attempts")
        .and_then(Value::as_array)
        .ok_or_else(|| Phase24Error::Contract("Phase 22 plan has no attempts".to_owned()))?;
    let mut ids = attempts
        .iter()
        .filter(|attempt| attempt.get("scanner").and_then(Value::as_str) == Some("semgrep-ce"))
        .map(|attempt| {
            attempt
                .get("case_id")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| Phase24Error::Contract("historical attempt omitted ID".to_owned()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    ids.sort();
    ids.dedup();
    if ids.len() != 112 {
        return Err(Phase24Error::Contract(format!(
            "historical plan exposed {} Semgrep IDs, expected 112",
            ids.len()
        )));
    }
    Ok(ids)
}

fn contract_value(
    root: &Path,
    plan_sha256: &str,
    implementation_sha256: &str,
) -> Result<Value, Phase24Error> {
    Ok(json!({
        "schema_version": "secure-bench-phase24-execution-contract-v1",
        "study": "semgrep post-open normalized recovery",
        "run_id": "phase24-semgrep-normalized-recovery-v1",
        "methodological_classification": {
            "blind_holdout": false,
            "one_shot_restored": false,
            "phase22_failure_replacement": false,
            "overall_three_scanner_ranking": false,
            "cross_lane_metric_merging": false,
        },
        "base": {
            "phase23_commit": PHASE23,
            "phase23_parent": PHASE22,
            "phase23_root_tree": PHASE23_ROOT_TREE,
            "phase20_subtree": PHASE20_TREE,
            "phase22_subtree": PHASE22_TREE,
            "phase23_subtree": PHASE23_TREE,
            "phase23_corrected_contract_sha256": PHASE23_CONTRACT_SHA256,
            "phase23_sha256s_sha256": PHASE23_SUMS_SHA256,
        },
        "frozen_inputs": {
            "manifest_sha256": MANIFEST_SHA256,
            "aggregate_corpus_sha256": CORPUS_SHA256,
            "corpus_git_tree": CORPUS_TREE,
            "contract_merkle_root": MERKLE_ROOT,
            "ruleset_path": RULESET,
            "ruleset_sha256": RULESET_SHA256,
            "semgrep_adapter_path": ADAPTER,
            "semgrep_adapter_sha256": ADAPTER_SHA256,
            "scoring_methodology_path": SCORING,
            "scoring_methodology_sha256": SCORING_SHA256,
            "phase22_plan_sha256": PHASE22_PLAN_SHA256,
            "phase22_results_sha256": PHASE22_RESULTS_SHA256,
            "corpus_open_during_prepare": false,
            "corpus_open_during_preflight": false,
        },
        "plan": {
            "path": PLAN,
            "sha256": plan_sha256,
            "attempts": 112,
            "semgrep_attempts": 112,
            "opengrep_attempts": 0,
            "secure_engine_attempts": 0,
            "native_attempts": 0,
            "retries": 0,
            "order": "semgrep-ce-lexical-opaque-case-id",
        },
        "scanner": {
            "id": "semgrep-ce",
            "version": "1.170.0",
            "engine": "OSS",
            "lane": "capability-normalized",
            "entrypoint_sha256": "0280e5c6cca8d8e4cb2c41858b06697b957daf23d718cac411999c4c515507e1",
            "wheel_sha256": "09a7e8eeff5e2549161124957184f3566f484370aa6127e425897cef725eb99b",
            "wheel_closure_sha256": "5371b438dc6e3c5529794b21c668057164f52fa1375e0e91ee6c8f241fb74181",
        },
        "sandbox": {
            "profile": "phase23-stack-bounded-v1",
            "network": false,
            "new_pid_namespace": true,
            "fresh_proc": true,
            "read_only_root": true,
            "devices": ["/dev/null"],
            "masked_paths": ["/home", "/root", "/run/user", "/var/tmp"],
            "environment": fixed_environment(),
            "address_space_bytes": 4294967296_u64,
            "process_limit": 64,
            "stack_soft_bytes": 8388608_u64,
            "stack_hard_bytes": 8388608_u64,
            "timeout_ms": 120000,
            "max_raw_output_bytes": MAX_OUTPUT,
            "permissions_widened": false,
        },
        "process_policy": {
            "zero_exit_valid_zero_or_findings": "completed",
            "one_exit_valid_findings": "completed",
            "timeout": "timeout-no-retry",
            "signal": "failed-no-retry",
            "crash": "failed-no-retry",
            "empty_output": "unavailable-no-retry",
            "malformed_json": "malformed-no-retry",
            "adapter_error": "failed-no-retry",
            "missing_values_imputed": false,
        },
        "comparison": {
            "left": {"phase":22,"scanner":"opengrep","lane":"capability-normalized"},
            "right": {"phase":24,"scanner":"semgrep-ce","lane":"capability-normalized"},
            "complete_only_after_112_valid_attempts_and_independent_verification": true,
            "secure_engine_native_excluded": true,
        },
        "implementation_sha256": implementation_sha256,
        "methodology_sha256": sha_file(&root.join("phase24/METHODOLOGY.md"))?,
    }))
}

fn verify_signature(root: &Path, commit: &str) -> Result<Value, Phase24Error> {
    let output = Command::new("git")
        .args(["verify-commit", commit])
        .current_dir(root)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()?;
    if !output.status.success()
        || !String::from_utf8_lossy(&output.stderr).contains("Good \"git\" signature")
    {
        return Err(Phase24Error::Preflight(format!(
            "commit {commit} signature is not trusted"
        )));
    }
    let message = git(root, &["log", "-1", "--format=%B", commit])?;
    let dco = message
        .lines()
        .filter(|line| line.starts_with("Signed-off-by: "))
        .count();
    if dco != 1 {
        return Err(Phase24Error::Preflight(format!(
            "commit {commit} has {dco} DCO trailers"
        )));
    }
    Ok(json!({
        "commit": commit,
        "parent": git(root, &["rev-parse", &format!("{commit}^")])?,
        "tree": git(root, &["rev-parse", &format!("{commit}^{{tree}}")])?,
        "signature": "good-ed25519",
        "dco_trailers": 1,
    }))
}

fn verify_checksum_file(root: &Path, sums: &Path) -> Result<u64, Phase24Error> {
    let base = sums
        .parent()
        .ok_or_else(|| Phase24Error::Preflight("checksum file has no parent".to_owned()))?;
    let mut count = 0_u64;
    for line in fs::read_to_string(sums)?.lines() {
        let (expected, relative) = line.split_once("  ").ok_or_else(|| {
            Phase24Error::Preflight(format!("malformed checksum line in {}", sums.display()))
        })?;
        let relative = safe_relative(relative)?;
        if sha_file(&base.join(relative))? != expected {
            return Err(Phase24Error::Preflight(format!(
                "checksum mismatch for {}",
                relative.display()
            )));
        }
        count += 1;
    }
    let _ = root;
    Ok(count)
}

fn no_scanner_processes() -> Result<bool, Phase24Error> {
    let output = Command::new("ps")
        .args(["-eo", "comm="])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()?;
    let forbidden = ["semgrep", "semgrep-core", "opengrep", "secure-engine"];
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .all(|name| !forbidden.contains(&name)))
}

fn validate_semgrep_tools(root: &Path) -> Result<Value, Phase24Error> {
    let cache = Path::new(SEMGREP_SOURCE);
    let entrypoint = cache.join("venv/bin/semgrep");
    let installed_path = cache.join("installed-distributions.json");
    let requirements_path = cache.join("requirements.lock");
    let lock_path = root.join("phase18/provenance/semgrep-python314-linux-x86_64-lock.json");
    for (path, expected) in [
        (
            Path::new("/usr/bin/bwrap"),
            "139bf12775025adf5c8523d119c5ad2950281335573708fd839c60181a3886dc",
        ),
        (
            Path::new("/usr/bin/python3.14"),
            "7af874aca05879e1823cd820913b42fb8d8b994738a05ec39ce4256d85b03861",
        ),
        (entrypoint.as_path(), SEMGREP_ENTRYPOINT_SHA256),
        (
            installed_path.as_path(),
            "703922233fb0e415b50e4b88ba9622dc6ea3d207a5f4fcb64b6b980da35056df",
        ),
        (
            requirements_path.as_path(),
            "bae00f126f98e84b32b92269d42f6567abab789307383094009030d7f13caf50",
        ),
        (lock_path.as_path(), SEMGREP_LOCK_SHA256),
    ] {
        if !path.is_file() {
            return Err(Phase24Error::Preflight(format!(
                "frozen Semgrep prerequisite absent: {}",
                path.display()
            )));
        }
        let actual = sha_file(path)?;
        if actual != expected {
            return Err(Phase24Error::Preflight(format!(
                "frozen Semgrep prerequisite drift at {}: {actual}",
                path.display()
            )));
        }
    }
    let lock: Value = serde_json::from_slice(&fs::read(&lock_path)?)?;
    let packages = lock
        .get("packages")
        .and_then(Value::as_array)
        .ok_or_else(|| Phase24Error::Preflight("Semgrep lock has no packages".to_owned()))?;
    if packages.len() != 66
        || lock.get("closure_sha256").and_then(Value::as_str) != Some(SEMGREP_CLOSURE_SHA256)
    {
        return Err(Phase24Error::Preflight(
            "Semgrep dependency closure drift".to_owned(),
        ));
    }
    let installed: BTreeMap<String, String> = serde_json::from_slice(&fs::read(&installed_path)?)?;
    if installed.len() != 66 {
        return Err(Phase24Error::Preflight(format!(
            "Semgrep installed distribution count is {}, expected 66",
            installed.len()
        )));
    }
    for package in packages {
        let field = |name: &str| {
            package
                .get(name)
                .and_then(Value::as_str)
                .ok_or_else(|| Phase24Error::Preflight(format!("Semgrep lock omits {name}")))
        };
        let name = field("name")?;
        let version = field("version")?;
        let filename = field("filename")?;
        let expected = field("sha256")?;
        let wheel = cache.join("wheelhouse").join(filename);
        if !wheel.is_file()
            || sha_file(&wheel)? != expected
            || installed
                .get(&name.to_ascii_lowercase().replace('_', "-"))
                .map(String::as_str)
                != Some(version)
        {
            return Err(Phase24Error::Preflight(format!(
                "Semgrep wheel closure drift: {name} {version}"
            )));
        }
    }
    Ok(json!({
        "semgrep_cache": SEMGREP_SOURCE,
        "semgrep_entrypoint_sha256": SEMGREP_ENTRYPOINT_SHA256,
        "semgrep_wheel_sha256": SEMGREP_WHEEL_SHA256,
        "semgrep_wheel_closure_sha256": SEMGREP_CLOSURE_SHA256,
        "dependency_lock_sha256": SEMGREP_LOCK_SHA256,
        "installed_distributions": 66,
        "wheels_verified": 66,
        "scanner_processes_started": 0,
    }))
}

fn verify_frozen_preopen(root: &Path) -> Result<Value, Phase24Error> {
    if git(root, &["rev-parse", "HEAD"])? != PHASE23
        || git(root, &["rev-parse", "main"])? != PHASE23
        || git(root, &["rev-parse", &format!("{PHASE23}^")])? != PHASE22
        || git(root, &["rev-parse", &format!("{PHASE23}:phase20")])? != PHASE20_TREE
        || git(root, &["rev-parse", &format!("{PHASE23}:phase22")])? != PHASE22_TREE
        || git(root, &["rev-parse", &format!("{PHASE23}:phase23")])? != PHASE23_TREE
        || git(
            root,
            &[
                "rev-parse",
                "b3e983891e4ae3e12cd727f6bdb460962f876a30:phase19/holdout/cases",
            ],
        )? != CORPUS_TREE
    {
        return Err(Phase24Error::Preflight(
            "authoritative commit or frozen subtree drift".to_owned(),
        ));
    }
    let sensitive = git(
        root,
        &[
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--",
            "phase19",
            "phase20",
            "phase22",
            "phase23",
        ],
    )?;
    if !sensitive.is_empty() {
        return Err(Phase24Error::Preflight(format!(
            "historical worktree drift: {sensitive}"
        )));
    }
    for (path, expected) in [
        (RULESET, RULESET_SHA256),
        (ADAPTER, ADAPTER_SHA256),
        (SCORING, SCORING_SHA256),
        (PHASE22_PLAN, PHASE22_PLAN_SHA256),
        (PHASE22_RESULTS, PHASE22_RESULTS_SHA256),
        (PHASE23_CONTRACT, PHASE23_CONTRACT_SHA256),
        ("phase23/SHA256SUMS", PHASE23_SUMS_SHA256),
    ] {
        if sha_file(&root.join(path))? != expected {
            return Err(Phase24Error::Preflight(format!(
                "frozen input drift: {path}"
            )));
        }
    }
    let phase23_checksums = verify_checksum_file(root, &root.join("phase23/SHA256SUMS"))?;
    let tool_evidence = validate_semgrep_tools(root)?;
    if !no_scanner_processes()? {
        return Err(Phase24Error::Preflight(
            "forbidden scanner process exists during preflight".to_owned(),
        ));
    }
    Ok(json!({
        "phase23_commit": verify_signature(root, PHASE23)?,
        "phase20_subtree": PHASE20_TREE,
        "phase22_subtree": PHASE22_TREE,
        "phase23_subtree": PHASE23_TREE,
        "corpus_tree": CORPUS_TREE,
        "phase23_checksum_entries_verified": phase23_checksums,
        "tool_evidence": tool_evidence,
        "scanner_processes_started": 0,
        "corpus_opened": false,
    }))
}

/// Freeze the canonical opaque 112-attempt plan without opening cases.
pub fn prepare(root: &Path) -> Result<Value, Phase24Error> {
    if root.join("phase24/config").exists()
        || root.join(PREFLIGHT).exists()
        || root.join(OUTPUT).exists()
    {
        return Err(Phase24Error::Contract(
            "Phase 24 lifecycle artifacts already exist".to_owned(),
        ));
    }
    if git(root, &["rev-parse", "HEAD"])? != PHASE23
        || git(root, &["rev-parse", "main"])? != PHASE23
    {
        return Err(Phase24Error::Contract(
            "prepare requires exact Phase 23 HEAD/main".to_owned(),
        ));
    }
    let ids = opaque_case_ids(root)?;
    let attempts = ids
        .into_iter()
        .enumerate()
        .map(|(index, case_id)| PlanAttempt {
            sequence: u64::try_from(index + 1).unwrap_or(u64::MAX),
            scanner: "semgrep-ce".to_owned(),
            lane: "capability-normalized".to_owned(),
            case_id,
        })
        .collect::<Vec<_>>();
    let plan = ExecutionPlan {
        schema_version: "secure-bench-phase24-execution-plan-v1".to_owned(),
        study: "semgrep post-open normalized recovery".to_owned(),
        run_id: "phase24-semgrep-normalized-recovery-v1".to_owned(),
        total_attempts: 112,
        retries: 0,
        excluded_attempts: BTreeMap::from([
            ("native".to_owned(), 0),
            ("opengrep".to_owned(), 0),
            ("secure-engine".to_owned(), 0),
        ]),
        attempts,
    };
    validate_plan(&plan)?;
    fs::create_dir_all(root.join("phase24/config"))?;
    let plan_bytes = canonical(&plan)?;
    write_atomic(&root.join(PLAN), &plan_bytes)?;
    let plan_hash = sha256(&plan_bytes);
    let contract = contract_value(root, &plan_hash, &implementation_digest(root)?)?;
    write_atomic(&root.join(CONTRACT), &canonical(&contract)?)?;
    Ok(json!({
        "state": "frozen-before-corpus-opening",
        "plan_sha256": plan_hash,
        "contract_sha256": sha_file(&root.join(CONTRACT))?,
        "attempts": 112,
        "retries": 0,
        "semgrep_attempts": 112,
        "opengrep_attempts": 0,
        "secure_engine_attempts": 0,
        "native_attempts": 0,
        "corpus_opened": false,
    }))
}

fn validate_contract(root: &Path) -> Result<ExecutionPlan, Phase24Error> {
    let plan = load_plan(root)?;
    let actual: Value = serde_json::from_slice(&fs::read(root.join(CONTRACT))?)?;
    let expected = contract_value(
        root,
        &sha_file(&root.join(PLAN))?,
        &implementation_digest(root)?,
    )?;
    if actual != expected {
        return Err(Phase24Error::Contract(
            "execution contract does not match implementation or frozen inputs".to_owned(),
        ));
    }
    Ok(plan)
}

fn write_sums(output: &Path) -> Result<(), Phase24Error> {
    let mut files = Vec::new();
    collect_files(output, &mut files)?;
    files.retain(|path| path.file_name().and_then(|name| name.to_str()) != Some("SHA256SUMS"));
    files.sort();
    let mut sums = String::new();
    for file in files {
        let relative = file
            .strip_prefix(output)
            .map_err(|_| Phase24Error::Contract("hash path escaped output".to_owned()))?;
        sums.push_str(&format!("{}  {}\n", sha_file(&file)?, relative.display()));
    }
    write_atomic(&output.join("SHA256SUMS"), sums.as_bytes())
}

/// Verify all preconditions and seal preflight without opening cases.
pub fn preflight(root: &Path) -> Result<Value, Phase24Error> {
    if root.join(PREFLIGHT).exists() || root.join(OUTPUT).exists() {
        return Err(Phase24Error::Preflight(
            "preflight or output already exists".to_owned(),
        ));
    }
    let plan = validate_contract(root)?;
    let verified = verify_frozen_preopen(root)?;
    let report = json!({
        "schema_version": "secure-bench-phase24-preflight-v1",
        "state": "ready-before-corpus-opening",
        "verified_at_unix_ms": now_ms()?,
        "plan_sha256": sha_file(&root.join(PLAN))?,
        "contract_sha256": sha_file(&root.join(CONTRACT))?,
        "implementation_sha256": implementation_digest(root)?,
        "planned_attempts": plan.total_attempts,
        "retries": 0,
        "semgrep_attempts": 112,
        "opengrep_attempts": 0,
        "secure_engine_attempts": 0,
        "native_attempts": 0,
        "network": false,
        "ai": false,
        "telemetry": false,
        "credentials": false,
        "corpus_opened": false,
        "verified": verified,
    });
    let output = root.join(PREFLIGHT);
    fs::create_dir_all(&output)?;
    write_atomic(&output.join("preflight.json"), &canonical(&report)?)?;
    write_sums(&output)?;
    Ok(report)
}

fn verify_saved_preflight(root: &Path) -> Result<ExecutionPlan, Phase24Error> {
    let plan = validate_contract(root)?;
    let preflight = root.join(PREFLIGHT);
    let report: Value = serde_json::from_slice(&fs::read(preflight.join("preflight.json"))?)?;
    if report.get("state").and_then(Value::as_str) != Some("ready-before-corpus-opening")
        || report.get("planned_attempts").and_then(Value::as_u64) != Some(112)
        || report.get("retries").and_then(Value::as_u64) != Some(0)
        || report.get("corpus_opened").and_then(Value::as_bool) != Some(false)
        || report.get("implementation_sha256").and_then(Value::as_str)
            != Some(implementation_digest(root)?.as_str())
        || report.get("plan_sha256").and_then(Value::as_str)
            != Some(sha_file(&root.join(PLAN))?.as_str())
        || report.get("contract_sha256").and_then(Value::as_str)
            != Some(sha_file(&root.join(CONTRACT))?.as_str())
        || sha_file(&preflight.join("preflight.json"))?
            != fs::read_to_string(preflight.join("SHA256SUMS"))?
                .split_once("  ")
                .map(|(hash, _)| hash)
                .unwrap_or_default()
    {
        return Err(Phase24Error::Preflight(
            "saved preflight is invalid or drifted".to_owned(),
        ));
    }
    if verify_checksum_file(root, &preflight.join("SHA256SUMS"))? != 1 {
        return Err(Phase24Error::Preflight(
            "saved preflight checksum scope drift".to_owned(),
        ));
    }
    verify_frozen_preopen(root)?;
    Ok(plan)
}

fn text(value: &Value, field: &str) -> Result<String, Phase24Error> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| Phase24Error::Execution(format!("manifest object omits {field}")))
}

fn load_cases_post_open(root: &Path) -> Result<BTreeMap<String, CaseSpec>, Phase24Error> {
    let bytes = fs::read(root.join(MANIFEST))?;
    if sha256(&bytes) != MANIFEST_SHA256 {
        return Err(Phase24Error::Execution(
            "Phase 19 manifest hash drift after corpus opening".to_owned(),
        ));
    }
    let manifest: Value = serde_json::from_slice(&bytes)?;
    if manifest
        .get("aggregate_corpus_sha256")
        .and_then(Value::as_str)
        != Some(CORPUS_SHA256)
        || manifest.get("contract_merkle_root").and_then(Value::as_str) != Some(MERKLE_ROOT)
    {
        return Err(Phase24Error::Execution(
            "Phase 19 corpus commitments drift after opening".to_owned(),
        ));
    }
    let pairs = manifest
        .get("pairs")
        .and_then(Value::as_array)
        .ok_or_else(|| Phase24Error::Execution("manifest has no pairs".to_owned()))?;
    let mut cases = BTreeMap::new();
    let mut corpus_projection = BTreeMap::<String, String>::new();
    for pair in pairs {
        let pair_id = text(pair, "pair_id")?;
        let assignment = pair
            .get("assignment")
            .ok_or_else(|| Phase24Error::Execution("pair has no assignment".to_owned()))?;
        for side in ["first", "second"] {
            let value = pair
                .get(side)
                .ok_or_else(|| Phase24Error::Execution(format!("pair {pair_id} has no {side}")))?;
            let case = CaseSpec {
                case_id: text(value, "case_id")?,
                pair_id: pair_id.clone(),
                classification: text(value, "classification")?,
                family: text(assignment, "family")?,
                framework: text(assignment, "framework")?,
                source_format: text(assignment, "source_format")?,
                topology: text(assignment, "topology")?,
                adversarial_variant: assignment
                    .get("adversarial_variant")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                fixture_path: text(value, "fixture_path")?,
            };
            let expected_fixture = format!("phase19/holdout/cases/{}", case.case_id);
            if case.fixture_path != expected_fixture {
                return Err(Phase24Error::Execution(format!(
                    "fixture identity drift for {}",
                    case.case_id
                )));
            }
            let fixture = root.join(safe_relative(&case.fixture_path)?);
            let files = value
                .get("files")
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    Phase24Error::Execution(format!(
                        "case {} has no file commitments",
                        case.case_id
                    ))
                })?;
            let mut declared = BTreeSet::new();
            for file in files {
                let name = text(file, "path")?;
                let relative = portable_relative(&name).map_err(Phase24Error::Execution)?;
                let path = fixture.join(&relative);
                let metadata = fs::symlink_metadata(&path)?;
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    return Err(Phase24Error::Execution(format!(
                        "case file is absent or unsafe: {}/{}",
                        case.case_id, relative
                    )));
                }
                let body = fs::read(&path)?;
                let expected_hash = text(file, "sha256")?;
                let expected_bytes =
                    file.get("bytes").and_then(Value::as_u64).ok_or_else(|| {
                        Phase24Error::Execution(format!(
                            "case file omits byte count: {}/{}",
                            case.case_id, relative
                        ))
                    })?;
                if sha256(&body) != expected_hash
                    || u64::try_from(body.len()).unwrap_or(u64::MAX) != expected_bytes
                    || !declared.insert(relative.clone())
                {
                    return Err(Phase24Error::Execution(format!(
                        "case file commitment drift: {}/{}",
                        case.case_id, relative
                    )));
                }
                corpus_projection
                    .insert(format!("{}/{}", case.fixture_path, relative), expected_hash);
            }
            let mut actual_files = Vec::new();
            collect_files(&fixture, &mut actual_files)?;
            let actual = actual_files
                .iter()
                .map(|path| {
                    path.strip_prefix(&fixture)
                        .map(|relative| relative.to_string_lossy().into_owned())
                        .map_err(|_| {
                            Phase24Error::Execution("case file escaped fixture".to_owned())
                        })
                })
                .collect::<Result<BTreeSet<_>, _>>()?;
            if actual != declared {
                return Err(Phase24Error::Execution(format!(
                    "case file set drift for {}",
                    case.case_id
                )));
            }
            if cases.insert(case.case_id.clone(), case).is_some() {
                return Err(Phase24Error::Execution(
                    "manifest repeats case ID".to_owned(),
                ));
            }
        }
    }
    if cases.len() != 112 {
        return Err(Phase24Error::Execution(format!(
            "manifest has {} cases, expected 112",
            cases.len()
        )));
    }
    let mut aggregate = Vec::new();
    for (path, hash) in corpus_projection {
        aggregate.extend_from_slice(path.as_bytes());
        aggregate.push(0);
        aggregate.extend_from_slice(hash.as_bytes());
        aggregate.push(b'\n');
    }
    if sha256(&aggregate) != CORPUS_SHA256 {
        return Err(Phase24Error::Execution(
            "recomputed aggregate corpus hash drift".to_owned(),
        ));
    }
    Ok(cases)
}

fn portable_relative(value: &str) -> Result<String, String> {
    let value = value.strip_prefix("./").unwrap_or(value);
    if value.is_empty()
        || value.starts_with('/')
        || value.contains('\\')
        || value
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
    {
        return Err(format!("unsafe scanner path `{value}`"));
    }
    Ok(value.to_owned())
}

fn source_bytes(fixture: &Path, value: &str) -> Result<(String, Vec<u8>), String> {
    let relative = portable_relative(value)?;
    let root = fixture.canonicalize().map_err(|error| error.to_string())?;
    let mut cursor = root.clone();
    for component in Path::new(&relative).components() {
        let std::path::Component::Normal(part) = component else {
            return Err(format!("unsafe scanner path `{relative}`"));
        };
        cursor.push(part);
        let metadata = fs::symlink_metadata(&cursor).map_err(|error| error.to_string())?;
        if metadata.file_type().is_symlink() {
            return Err(format!("scanner path traverses symlink `{relative}`"));
        }
    }
    let canonical = cursor.canonicalize().map_err(|error| error.to_string())?;
    if !canonical.starts_with(&root) || !canonical.is_file() {
        return Err(format!("scanner path escaped fixture `{relative}`"));
    }
    fs::read(canonical)
        .map(|bytes| (relative, bytes))
        .map_err(|error| error.to_string())
}

fn position(result: &Value, side: &str, field: &str) -> Result<u64, String> {
    result
        .pointer(&format!("/{side}/{field}"))
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("result has no {side}.{field}"))
}

fn coordinate_offset(file: &[u8], line: u64, column: u64) -> Option<u64> {
    let target_line = usize::try_from(line).ok()?;
    let target_column = usize::try_from(column).ok()?;
    let mut current_line = 1_usize;
    let mut line_start = 0_usize;
    for (index, byte) in file.iter().enumerate() {
        if current_line == target_line {
            let line_end = file[line_start..]
                .iter()
                .position(|candidate| *candidate == b'\n')
                .map_or(file.len(), |relative| line_start + relative);
            let offset = line_start.checked_add(target_column.checked_sub(1)?)?;
            return (offset <= line_end)
                .then(|| u64::try_from(offset).ok())
                .flatten();
        }
        if *byte == b'\n' {
            current_line += 1;
            line_start = index + 1;
        }
    }
    if current_line == target_line {
        let offset = line_start.checked_add(target_column.checked_sub(1)?)?;
        return (offset <= file.len())
            .then(|| u64::try_from(offset).ok())
            .flatten();
    }
    None
}

fn validate_result(fixture: &Path, result: &Value) -> Result<String, String> {
    let path = result
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| "result has no path".to_owned())?;
    let (relative, file) = source_bytes(fixture, path)?;
    let start_line = position(result, "start", "line")?;
    let start_col = position(result, "start", "col")?;
    let end_line = position(result, "end", "line")?;
    let end_col = position(result, "end", "col")?;
    if start_line == 0
        || start_col == 0
        || end_line == 0
        || end_col == 0
        || (start_line, start_col) >= (end_line, end_col)
    {
        return Err(format!("invalid scanner span for {relative}"));
    }
    let expected_start = coordinate_offset(&file, start_line, start_col)
        .ok_or_else(|| format!("invalid scanner start for {relative}"))?;
    let expected_end = coordinate_offset(&file, end_line, end_col)
        .ok_or_else(|| format!("invalid scanner end for {relative}"))?;
    let start_offset = result.pointer("/start/offset").and_then(Value::as_u64);
    let end_offset = result.pointer("/end/offset").and_then(Value::as_u64);
    match (start_offset, end_offset) {
        (Some(start), Some(end))
            if start < end
                && end <= u64::try_from(file.len()).unwrap_or(u64::MAX)
                && start == expected_start
                && end == expected_end => {}
        _ => return Err(format!("invalid Semgrep offsets for {relative}")),
    }
    Ok(relative)
}

fn adapt_raw(root: &Path, fixture: &Path, raw: &[u8]) -> Result<u64, String> {
    if sha_file(&root.join(ADAPTER)).map_err(|error| error.to_string())? != ADAPTER_SHA256 {
        return Err("frozen adapter manifest drift".to_owned());
    }
    if u64::try_from(raw.len()).unwrap_or(u64::MAX) > MAX_OUTPUT {
        return Err("raw output exceeded 10485760 bytes".to_owned());
    }
    let value: Value = serde_json::from_slice(raw).map_err(|error| error.to_string())?;
    if value.get("version").and_then(Value::as_str) != Some("1.170.0")
        || value.get("engine_requested").and_then(Value::as_str) != Some("OSS")
        || value
            .get("errors")
            .and_then(Value::as_array)
            .is_none_or(|errors| !errors.is_empty())
        || value
            .get("skipped_rules")
            .and_then(Value::as_array)
            .is_none_or(|rules| !rules.is_empty())
    {
        return Err("scanner identity, errors, or skipped rules are invalid".to_owned());
    }
    let paths = value
        .pointer("/paths/scanned")
        .and_then(Value::as_array)
        .ok_or_else(|| "Semgrep report has no paths.scanned".to_owned())?;
    let mut scanned = BTreeSet::new();
    for path in paths {
        let path = path
            .as_str()
            .ok_or_else(|| "Semgrep scanned path is not text".to_owned())?;
        if !scanned.insert(source_bytes(fixture, path)?.0) {
            return Err("Semgrep repeats a scanned path".to_owned());
        }
    }
    let allowed = ALLOWED_RULES.into_iter().collect::<BTreeSet<_>>();
    let results = value
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(|| "raw report has no results array".to_owned())?;
    for finding in results {
        let rule = finding
            .get("check_id")
            .and_then(Value::as_str)
            .ok_or_else(|| "finding has no check_id".to_owned())?;
        if !allowed.contains(rule)
            || finding
                .pointer("/extra/engine_kind")
                .and_then(Value::as_str)
                != Some("OSS")
        {
            return Err("Semgrep finding provenance is invalid".to_owned());
        }
        let relative = validate_result(fixture, finding)?;
        if !scanned.contains(&relative) {
            return Err("Semgrep finding path was not scanned".to_owned());
        }
    }
    Ok(u64::try_from(results.len()).unwrap_or(u64::MAX))
}

struct ProcessEvidence {
    launch_error: Option<String>,
    exit_code: Option<i32>,
    signal: Option<i32>,
    duration_ms: u64,
    timed_out: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    raw: Option<Vec<u8>>,
    resource: Vec<u8>,
    effective: Option<Vec<u8>>,
}

fn resource_signal(resource: &[u8]) -> Option<i32> {
    String::from_utf8_lossy(resource).lines().find_map(|line| {
        line.strip_prefix("Command terminated by signal ")
            .and_then(|value| value.trim().parse().ok())
    })
}

fn run_process(arguments: &[String], output: &Path) -> Result<ProcessEvidence, Phase24Error> {
    fs::create_dir_all(output)?;
    let stdout = File::create(output.join("stdout.bin"))?;
    let stderr = File::create(output.join("stderr.bin"))?;
    let started = Instant::now();
    let spawn = Command::new("/usr/bin/bwrap")
        .args(arguments)
        .env_clear()
        .env("LANG", "C.UTF-8")
        .env("LC_ALL", "C.UTF-8")
        .env("PATH", "/usr/bin:/bin")
        .env("TZ", "UTC")
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn();
    let mut child = match spawn {
        Ok(child) => child,
        Err(error) => {
            let message = format!("bubblewrap launch failed: {error}\n");
            OpenOptions::new()
                .append(true)
                .open(output.join("stderr.bin"))?
                .write_all(message.as_bytes())?;
            File::create(output.join("resource.txt"))?.sync_all()?;
            return Ok(ProcessEvidence {
                launch_error: Some(error.to_string()),
                exit_code: None,
                signal: None,
                duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                timed_out: false,
                stdout: fs::read(output.join("stdout.bin"))?,
                stderr: fs::read(output.join("stderr.bin"))?,
                raw: None,
                resource: Vec::new(),
                effective: None,
            });
        }
    };
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() >= TIMEOUT {
            child.kill()?;
            timed_out = true;
            break child.wait()?;
        }
        thread::sleep(Duration::from_millis(10));
    };
    let raw = output.join("raw.json");
    let resource = output.join("resource.txt");
    let effective = output.join("effective-environment.json");
    let resource_bytes = if resource.exists() {
        fs::read(&resource)?
    } else {
        File::create(&resource)?.sync_all()?;
        Vec::new()
    };
    Ok(ProcessEvidence {
        launch_error: None,
        exit_code: status.code(),
        signal: status.signal(),
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        timed_out,
        stdout: fs::read(output.join("stdout.bin"))?,
        stderr: fs::read(output.join("stderr.bin"))?,
        raw: raw.exists().then(|| fs::read(raw)).transpose()?,
        resource: resource_bytes,
        effective: effective
            .exists()
            .then(|| fs::read(effective))
            .transpose()?,
    })
}

fn attempt_directory(attempt: &PlanAttempt) -> String {
    format!(
        "phase24/output/attempts/{:03}-phase24-semgrep-ce-{}",
        attempt.sequence, attempt.case_id
    )
}

fn attempt_arguments(root: &Path, fixture: &Path, output: &Path) -> Vec<String> {
    let mut arguments =
        scanner_sandbox(Scanner::Semgrep, true, fixture, &root.join(RULESET), output);
    arguments.extend([
        "--ro-bind".to_owned(),
        root.join("phase24/reproducer/runtime_wrapper.py")
            .to_string_lossy()
            .into_owned(),
        "/tmp/runtime-wrapper.py".to_owned(),
        "--".to_owned(),
        "/usr/bin/time".to_owned(),
        "--verbose".to_owned(),
        "--output=/tmp/run/resource.txt".to_owned(),
        "--".to_owned(),
        "/usr/bin/prlimit".to_owned(),
        "--as=4294967296".to_owned(),
        "--nproc=64".to_owned(),
        "--stack=8388608".to_owned(),
        "--".to_owned(),
        "/usr/bin/python3.14".to_owned(),
        "/tmp/runtime-wrapper.py".to_owned(),
    ]);
    arguments.extend(scanner_command(Scanner::Semgrep));
    arguments
}

fn validate_effective_environment(bytes: Option<&[u8]>) -> Result<(), String> {
    let bytes = bytes.ok_or_else(|| "effective environment evidence is absent".to_owned())?;
    let value: Value = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    for (field, expected) in [
        ("address_space", 4_294_967_296_u64),
        ("processes", 64_u64),
        ("stack", 8_388_608_u64),
    ] {
        let limits = value
            .get(field)
            .and_then(Value::as_array)
            .ok_or_else(|| format!("effective {field} limit is absent"))?;
        if limits.len() != 2 || limits.iter().any(|limit| limit.as_u64() != Some(expected)) {
            return Err(format!("effective {field} limit drift"));
        }
    }
    let expected = fixed_environment();
    let environment = value
        .get("environment")
        .and_then(Value::as_array)
        .ok_or_else(|| "effective environment is absent".to_owned())?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| "effective environment entry is not text".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    if environment != expected {
        return Err("effective cleared environment drift".to_owned());
    }
    let mountinfo = value
        .get("mountinfo")
        .and_then(Value::as_str)
        .ok_or_else(|| "effective mount table is absent".to_owned())?;
    for required in [
        " /proc ",
        " /tmp/run ",
        " /tmp/fixture ",
        " /tmp/rules/rule.yml ",
    ] {
        if !mountinfo.contains(required) {
            return Err(format!("effective mount table omits {required}"));
        }
    }
    Ok(())
}

fn run_attempt(
    root: &Path,
    attempt: &PlanAttempt,
    case: &CaseSpec,
) -> Result<Observation, Phase24Error> {
    let fixture = root.join(safe_relative(&case.fixture_path)?);
    if !fixture.is_dir() {
        return Err(Phase24Error::Execution(format!(
            "fixture is absent for {}",
            case.case_id
        )));
    }
    let relative = attempt_directory(attempt);
    let output = root.join(&relative);
    if output.exists() {
        return Err(Phase24Error::Execution(format!(
            "attempt evidence already exists: {}",
            attempt.sequence
        )));
    }
    fs::create_dir_all(&output)?;
    let arguments = attempt_arguments(root, &fixture, &output);
    if arguments.iter().any(|argument| {
        argument.contains("secure-engine")
            || argument.contains("opengrep")
            || argument.contains("native")
    }) {
        return Err(Phase24Error::Contract(
            "attempt command referenced excluded scanner/lane".to_owned(),
        ));
    }
    let command = std::iter::once("/usr/bin/bwrap".to_owned())
        .chain(arguments.iter().cloned())
        .collect::<Vec<_>>();
    let evidence = run_process(&arguments, &output)?;
    let signal = evidence
        .signal
        .or_else(|| resource_signal(&evidence.resource));
    let effective_error = validate_effective_environment(evidence.effective.as_deref()).err();
    let mut failure = None;
    let mut finding_count = None;
    let (state, process_decision) = if let Some(error) = evidence.launch_error.as_deref() {
        failure = Some(format!("scanner process unavailable: {error}; no retry"));
        (AttemptState::Unavailable, "launch-failure")
    } else if let Some(error) = effective_error {
        failure = Some(format!("effective execution contract rejected: {error}"));
        (AttemptState::Failed, "effective-environment-failure")
    } else if evidence.timed_out {
        failure = Some("wall-clock timeout; no retry".to_owned());
        (AttemptState::Timeout, "timeout")
    } else if signal.is_some() {
        failure = Some(format!("scanner terminated by signal {signal:?}; no retry"));
        (AttemptState::Failed, "signal-failure")
    } else if let Some(raw) = evidence.raw.as_deref() {
        match adapt_raw(root, &fixture, raw) {
            Ok(count)
                if evidence.exit_code == Some(0)
                    || (evidence.exit_code == Some(1) && count > 0) =>
            {
                finding_count = Some(count);
                (
                    AttemptState::Completed,
                    if count == 0 {
                        "clean-successful-report"
                    } else {
                        "successful-findings-report"
                    },
                )
            }
            Ok(count) => {
                failure = Some(format!(
                    "process policy rejected exit {:?} with {count} findings",
                    evidence.exit_code
                ));
                (AttemptState::Failed, "process-policy-failure")
            }
            Err(error) => {
                failure = Some(format!("adapter rejected raw output: {error}"));
                (
                    if serde_json::from_slice::<Value>(raw).is_err() {
                        AttemptState::Malformed
                    } else {
                        AttemptState::Failed
                    },
                    "adapter-failure",
                )
            }
        }
    } else {
        failure = Some("scanner produced no raw output; no retry".to_owned());
        (AttemptState::Unavailable, "missing-output")
    };
    let environment = fixed_environment();
    Ok(Observation {
        sequence: attempt.sequence,
        attempt_id: format!(
            "phase24-semgrep-{:03}-{}",
            attempt.sequence, attempt.case_id
        ),
        scanner: "semgrep-ce".to_owned(),
        lane: "capability-normalized".to_owned(),
        case_id: attempt.case_id.clone(),
        state,
        process_decision: process_decision.to_owned(),
        exit_code: evidence.exit_code,
        signal,
        timed_out: evidence.timed_out,
        duration_ms: evidence.duration_ms,
        command_sha256: sha256(&canonical(&command)?),
        command,
        environment_sha256: sha256(&canonical(&environment)?),
        environment,
        stdout_path: format!("{relative}/stdout.bin"),
        stdout_sha256: sha256(&evidence.stdout),
        stderr_path: format!("{relative}/stderr.bin"),
        stderr_sha256: sha256(&evidence.stderr),
        raw_output_path: evidence
            .raw
            .as_ref()
            .map(|_| format!("{relative}/raw.json")),
        raw_output_sha256: evidence.raw.as_deref().map(sha256),
        resource_path: format!("{relative}/resource.txt"),
        resource_sha256: sha256(&evidence.resource),
        effective_environment_path: evidence
            .effective
            .as_ref()
            .map(|_| format!("{relative}/effective-environment.json")),
        effective_environment_sha256: evidence.effective.as_deref().map(sha256),
        finding_count,
        failure,
    })
}

fn append_ledger(
    path: &Path,
    observation: &Observation,
    previous: &str,
) -> Result<String, Phase24Error> {
    let payload_sha256 = sha256(&canonical(observation)?);
    let projection = json!({
        "schema_version": "secure-bench-phase24-ledger-v1",
        "sequence": observation.sequence,
        "event": "semgrep-recovery-attempt-completed",
        "payload_sha256": payload_sha256,
        "previous_entry_hash": previous,
    });
    let entry_hash = sha256(&canonical(&projection)?);
    let entry = LedgerEntry {
        schema_version: "secure-bench-phase24-ledger-v1".to_owned(),
        sequence: observation.sequence,
        event: "semgrep-recovery-attempt-completed".to_owned(),
        payload_sha256,
        previous_entry_hash: previous.to_owned(),
        entry_hash: entry_hash.clone(),
    };
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(&canonical(&entry)?)?;
    file.sync_all()?;
    Ok(entry_hash)
}

fn gcd(mut left: u64, mut right: u64) -> u64 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left.max(1)
}

fn ratio(numerator: u64, denominator: u64) -> Option<Ratio> {
    if denominator == 0 {
        return None;
    }
    let divisor = gcd(numerator, denominator);
    Some(Ratio {
        numerator: numerator / divisor,
        denominator: denominator / divisor,
        decimal: format!("{:.6}", numerator as f64 / denominator as f64),
    })
}

fn metrics(decisions: &[CaseDecision]) -> Metrics {
    let mut counts = [0_u64; 4];
    for decision in decisions {
        match decision.outcome.as_str() {
            "tp" => counts[0] += 1,
            "fp" => counts[1] += 1,
            "tn" => counts[2] += 1,
            "fn" => counts[3] += 1,
            _ => {}
        }
    }
    let [tp, fp, tn, fn_count] = counts;
    Metrics {
        tp,
        fp,
        tn,
        fn_count,
        precision: ratio(tp, tp + fp),
        recall: ratio(tp, tp + fn_count),
        specificity: ratio(tn, tn + fp),
        f1: ratio(2 * tp, 2 * tp + fp + fn_count),
        balanced_accuracy: if tp + fn_count == 0 || tn + fp == 0 {
            None
        } else {
            ratio(
                tp * (tn + fp) + tn * (tp + fn_count),
                2 * (tp + fn_count) * (tn + fp),
            )
        },
    }
}

fn decisions_by<F>(decisions: &[CaseDecision], key: F) -> BTreeMap<String, Metrics>
where
    F: Fn(&CaseDecision) -> &str,
{
    let mut groups = BTreeMap::<String, Vec<CaseDecision>>::new();
    for decision in decisions {
        groups
            .entry(key(decision).to_owned())
            .or_default()
            .push(decision.clone());
    }
    groups
        .into_iter()
        .map(|(name, members)| (name, metrics(&members)))
        .collect()
}

fn percentile(sorted: &[u64], numerator: usize, denominator: usize) -> Option<u64> {
    if sorted.is_empty() {
        return None;
    }
    let index = sorted
        .len()
        .saturating_mul(numerator)
        .div_ceil(denominator)
        .saturating_sub(1)
        .min(sorted.len() - 1);
    sorted.get(index).copied()
}

fn summarize_operations(observations: &[Observation]) -> Operations {
    let mut durations = observations
        .iter()
        .map(|observation| observation.duration_ms)
        .collect::<Vec<_>>();
    durations.sort_unstable();
    let count = |state: AttemptState| {
        u64::try_from(
            observations
                .iter()
                .filter(|observation| observation.state == state)
                .count(),
        )
        .unwrap_or(u64::MAX)
    };
    Operations {
        attempts: u64::try_from(observations.len()).unwrap_or(u64::MAX),
        completed: count(AttemptState::Completed),
        failed: count(AttemptState::Failed),
        timeouts: count(AttemptState::Timeout),
        malformed: count(AttemptState::Malformed),
        unavailable: count(AttemptState::Unavailable),
        total_duration_ms: durations.iter().sum(),
        min_duration_ms: durations.first().copied(),
        median_duration_ms: percentile(&durations, 50, 100),
        p95_duration_ms: percentile(&durations, 95, 100),
        max_duration_ms: durations.last().copied(),
    }
}

fn case_decision(case: &CaseSpec, finding_count: u64) -> CaseDecision {
    let predicted_positive = finding_count > 0;
    let vulnerable = case.classification == "vulnerable";
    let outcome = match (vulnerable, predicted_positive) {
        (true, true) => "tp",
        (true, false) => "fn",
        (false, true) => "fp",
        (false, false) => "tn",
    };
    CaseDecision {
        case_id: case.case_id.clone(),
        pair_id: case.pair_id.clone(),
        expected: case.classification.clone(),
        finding_count,
        predicted_positive,
        outcome: outcome.to_owned(),
        family: case.family.clone(),
        framework: case.framework.clone(),
        source_format: case.source_format.clone(),
        topology: case.topology.clone(),
        adversarial_variant: case
            .adversarial_variant
            .clone()
            .unwrap_or_else(|| "none".to_owned()),
    }
}

fn pair_decisions(decisions: &[CaseDecision]) -> Result<Vec<PairDecision>, Phase24Error> {
    let mut grouped = BTreeMap::<String, Vec<&CaseDecision>>::new();
    for decision in decisions {
        grouped
            .entry(decision.pair_id.clone())
            .or_default()
            .push(decision);
    }
    let mut output = Vec::new();
    for (pair_id, members) in grouped {
        if members.len() != 2 {
            return Err(Phase24Error::Execution(format!(
                "pair {pair_id} does not have two decisions"
            )));
        }
        let vulnerable = members
            .iter()
            .find(|member| member.expected == "vulnerable")
            .ok_or_else(|| Phase24Error::Execution(format!("pair {pair_id} has no vulnerable")))?;
        let control = members
            .iter()
            .find(|member| member.expected == "control")
            .ok_or_else(|| Phase24Error::Execution(format!("pair {pair_id} has no control")))?;
        output.push(PairDecision {
            pair_id,
            vulnerable_case_id: vulnerable.case_id.clone(),
            control_case_id: control.case_id.clone(),
            vulnerable_flagged: vulnerable.predicted_positive,
            control_flagged: control.predicted_positive,
            pair_exact: vulnerable.predicted_positive && !control.predicted_positive,
        });
    }
    Ok(output)
}

fn semgrep_lane(
    cases: &BTreeMap<String, CaseSpec>,
    observations: &[Observation],
) -> Result<LaneResult, Phase24Error> {
    let operations = summarize_operations(observations);
    let mut decisions = Vec::new();
    for observation in observations {
        if observation.state == AttemptState::Completed {
            let case = cases.get(&observation.case_id).ok_or_else(|| {
                Phase24Error::Execution(format!("unknown case {}", observation.case_id))
            })?;
            let finding_count = observation.finding_count.ok_or_else(|| {
                Phase24Error::Execution(format!(
                    "completed observation {} has no finding count",
                    observation.sequence
                ))
            })?;
            decisions.push(case_decision(case, finding_count));
        }
    }
    decisions.sort_by(|left, right| left.case_id.cmp(&right.case_id));
    let complete = operations.attempts == 112 && operations.completed == 112;
    let grouped = |key| {
        if complete { key } else { BTreeMap::new() }
    };
    let by_family = grouped(decisions_by(&decisions, |decision| &decision.family));
    let by_framework = grouped(decisions_by(&decisions, |decision| &decision.framework));
    let by_source_format = grouped(decisions_by(&decisions, |decision| &decision.source_format));
    let by_topology = grouped(decisions_by(&decisions, |decision| &decision.topology));
    let by_adversarial_variant = grouped(decisions_by(&decisions, |decision| {
        &decision.adversarial_variant
    }));
    let by_classification = grouped(decisions_by(&decisions, |decision| &decision.expected));
    Ok(LaneResult {
        phase: 24,
        scanner: "semgrep-ce".to_owned(),
        lane: "capability-normalized".to_owned(),
        environment: "phase23-stack-bounded-v1".to_owned(),
        state: if complete {
            "completed"
        } else if operations.completed > 0 {
            "partial"
        } else {
            "failed"
        }
        .to_owned(),
        metrics: complete.then(|| metrics(&decisions)),
        pairs: if complete {
            pair_decisions(&decisions)?
        } else {
            Vec::new()
        },
        by_family,
        by_framework,
        by_source_format,
        by_topology,
        by_adversarial_variant,
        by_classification,
        cases: decisions,
        operations,
    })
}

fn phase22_opengrep(root: &Path) -> Result<Value, Phase24Error> {
    if sha_file(&root.join(PHASE22_RESULTS))? != PHASE22_RESULTS_SHA256 {
        return Err(Phase24Error::Contract(
            "immutable Phase 22 results drift".to_owned(),
        ));
    }
    let results: Value = serde_json::from_slice(&fs::read(root.join(PHASE22_RESULTS))?)?;
    let mut lane = results
        .get("lanes")
        .and_then(Value::as_array)
        .and_then(|lanes| {
            lanes.iter().find(|lane| {
                lane.get("scanner").and_then(Value::as_str) == Some("opengrep")
                    && lane.get("lane").and_then(Value::as_str) == Some("capability-normalized")
            })
        })
        .cloned()
        .ok_or_else(|| Phase24Error::Contract("Phase 22 OpenGrep lane is absent".to_owned()))?;
    let object = lane.as_object_mut().ok_or_else(|| {
        Phase24Error::Contract("Phase 22 OpenGrep lane is not an object".to_owned())
    })?;
    object.insert("phase".to_owned(), json!(22));
    object.insert(
        "environment".to_owned(),
        json!("phase21-corrected-recovery-v1"),
    );
    object.insert(
        "source_results_sha256".to_owned(),
        json!(PHASE22_RESULTS_SHA256),
    );
    Ok(lane)
}

fn ratio_from(value: &Value, metric: &str) -> Option<Ratio> {
    serde_json::from_value(value.get("metrics")?.get(metric)?.clone()).ok()
}

fn absolute(left: &Ratio, right: &Ratio) -> Ratio {
    ratio(
        (left.numerator * right.denominator).abs_diff(right.numerator * left.denominator),
        left.denominator * right.denominator,
    )
    .unwrap_or(Ratio {
        numerator: 0,
        denominator: 1,
        decimal: "0.000000".to_owned(),
    })
}

fn paired_comparison(left: &Value, right: &LaneResult, independently_valid: bool) -> Value {
    if left.get("state").and_then(Value::as_str) != Some("completed")
        || right.state != "completed"
        || !independently_valid
    {
        return json!({
            "schema_version": "secure-bench-phase24-normalized-comparison-v1",
            "state": "unavailable",
            "lane": "capability-normalized",
            "left": {"phase":22,"scanner":"opengrep","environment":"phase21-corrected-recovery-v1"},
            "right": {"phase":24,"scanner":"semgrep-ce","environment":"phase23-stack-bounded-v1"},
            "reason": "all 112 Phase 24 attempts and independent recalculation must be valid",
            "overall_three_scanner_winner_declared": false,
        });
    }
    let left_cases = left
        .get("cases")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let right_cases = right
        .cases
        .iter()
        .map(|case| (case.case_id.as_str(), case))
        .collect::<BTreeMap<_, _>>();
    let mut agreements = 0_u64;
    let mut both_correct = 0_u64;
    let mut left_only = 0_u64;
    let mut right_only = 0_u64;
    let mut both_incorrect = 0_u64;
    let mut disagreements = Vec::new();
    for left_case in &left_cases {
        let Some(case_id) = left_case.get("case_id").and_then(Value::as_str) else {
            continue;
        };
        let Some(right_case) = right_cases.get(case_id) else {
            continue;
        };
        let left_positive = left_case
            .get("predicted_positive")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let left_outcome = left_case
            .get("outcome")
            .and_then(Value::as_str)
            .unwrap_or("invalid");
        let left_correct = matches!(left_outcome, "tp" | "tn");
        let right_correct = matches!(right_case.outcome.as_str(), "tp" | "tn");
        if left_positive == right_case.predicted_positive {
            agreements += 1;
        } else {
            disagreements.push(json!({
                "case_id": case_id,
                "pair_id": right_case.pair_id,
                "expected": right_case.expected,
                "opengrep_phase22_positive": left_positive,
                "semgrep_phase24_positive": right_case.predicted_positive,
                "opengrep_phase22_findings": left_case.get("finding_count").and_then(Value::as_u64),
                "semgrep_phase24_findings": right_case.finding_count,
                "opengrep_phase22_outcome": left_outcome,
                "semgrep_phase24_outcome": right_case.outcome,
                "family": right_case.family,
                "framework": right_case.framework,
                "source_format": right_case.source_format,
                "topology": right_case.topology,
                "adversarial_variant": right_case.adversarial_variant,
            }));
        }
        match (left_correct, right_correct) {
            (true, true) => both_correct += 1,
            (true, false) => left_only += 1,
            (false, true) => right_only += 1,
            (false, false) => both_incorrect += 1,
        }
    }
    let right_json = serde_json::to_value(right).unwrap_or(Value::Null);
    let left_pairs = left
        .get("pairs")
        .and_then(Value::as_array)
        .map(|pairs| {
            pairs
                .iter()
                .filter_map(|pair| {
                    pair.get("pair_id")
                        .and_then(Value::as_str)
                        .map(|pair_id| (pair_id, pair))
                })
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();
    let mut pair_agreements = 0_u64;
    let mut pair_disagreements = Vec::new();
    for pair in &right.pairs {
        let Some(left_pair) = left_pairs.get(pair.pair_id.as_str()) else {
            continue;
        };
        let left_vulnerable = left_pair
            .get("vulnerable_flagged")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let left_control = left_pair
            .get("control_flagged")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if left_vulnerable == pair.vulnerable_flagged && left_control == pair.control_flagged {
            pair_agreements += 1;
        } else {
            pair_disagreements.push(json!({
                "pair_id": pair.pair_id,
                "vulnerable_case_id": pair.vulnerable_case_id,
                "control_case_id": pair.control_case_id,
                "opengrep_phase22_vulnerable_flagged": left_vulnerable,
                "opengrep_phase22_control_flagged": left_control,
                "semgrep_phase24_vulnerable_flagged": pair.vulnerable_flagged,
                "semgrep_phase24_control_flagged": pair.control_flagged,
                "opengrep_phase22_pair_exact": left_pair.get("pair_exact").and_then(Value::as_bool),
                "semgrep_phase24_pair_exact": pair.pair_exact,
            }));
        }
    }
    let mut differences = BTreeMap::new();
    for name in [
        "precision",
        "recall",
        "specificity",
        "f1",
        "balanced_accuracy",
    ] {
        if let (Some(left_ratio), Some(right_ratio)) =
            (ratio_from(left, name), ratio_from(&right_json, name))
        {
            differences.insert(name, absolute(&left_ratio, &right_ratio));
        }
    }
    json!({
        "schema_version": "secure-bench-phase24-normalized-comparison-v1",
        "state": "paired-complete",
        "lane": "capability-normalized",
        "left": {"phase":22,"scanner":"opengrep","environment":"phase21-corrected-recovery-v1"},
        "right": {"phase":24,"scanner":"semgrep-ce","environment":"phase23-stack-bounded-v1"},
        "paired_cases": 112,
        "agreements": agreements,
        "disagreements_count": disagreements.len(),
        "both_correct": both_correct,
        "opengrep_only_correct": left_only,
        "semgrep_only_correct": right_only,
        "both_incorrect": both_incorrect,
        "absolute_metric_differences": differences,
        "disagreements": disagreements,
        "paired_pairs": 56,
        "pair_agreements": pair_agreements,
        "pair_disagreements_count": pair_disagreements.len(),
        "pair_disagreements": pair_disagreements,
        "independent_recalculation_valid": true,
        "secure_engine_native_excluded": true,
        "overall_three_scanner_winner_declared": false,
    })
}

fn independently_recalculate(
    root: &Path,
    cases: &BTreeMap<String, CaseSpec>,
    observations: &[Observation],
    lane: &LaneResult,
) -> Result<Value, Phase24Error> {
    if observations.len() != 112 || lane.operations.completed != 112 {
        return Ok(json!({
            "valid": false,
            "reason": "112 completed observations are required",
            "scanner_processes_started": 0,
        }));
    }
    let mut counts = [0_u64; 4];
    for observation in observations {
        let case = cases.get(&observation.case_id).ok_or_else(|| {
            Phase24Error::Verification(format!("unknown case {}", observation.case_id))
        })?;
        let raw_path = observation.raw_output_path.as_deref().ok_or_else(|| {
            Phase24Error::Verification(format!(
                "completed observation {} has no raw output",
                observation.sequence
            ))
        })?;
        let raw = fs::read(root.join(safe_relative(raw_path)?))?;
        let finding_count = adapt_raw(root, &root.join(&case.fixture_path), &raw)
            .map_err(Phase24Error::Verification)?;
        if observation.finding_count != Some(finding_count) {
            return Err(Phase24Error::Verification(format!(
                "finding count drift at sequence {}",
                observation.sequence
            )));
        }
        match (case.classification.as_str(), finding_count > 0) {
            ("vulnerable", true) => counts[0] += 1,
            ("control", true) => counts[1] += 1,
            ("control", false) => counts[2] += 1,
            ("vulnerable", false) => counts[3] += 1,
            _ => {
                return Err(Phase24Error::Verification(format!(
                    "invalid classification for {}",
                    case.case_id
                )));
            }
        }
    }
    let actual = lane
        .metrics
        .as_ref()
        .ok_or_else(|| Phase24Error::Verification("complete lane has no metrics".to_owned()))?;
    if counts != [actual.tp, actual.fp, actual.tn, actual.fn_count] {
        return Err(Phase24Error::Verification(
            "independent confusion matrix differs".to_owned(),
        ));
    }
    Ok(json!({
        "schema_version": "secure-bench-phase24-independent-recalculation-v1",
        "valid": true,
        "attempts_recalculated": 112,
        "raw_reports_read": 112,
        "tp": counts[0],
        "fp": counts[1],
        "tn": counts[2],
        "fn": counts[3],
        "scanner_processes_started": 0,
        "network": false,
        "imputation": false,
    }))
}

fn state_name(state: &AttemptState) -> &'static str {
    match state {
        AttemptState::Completed => "completed",
        AttemptState::Failed => "failed",
        AttemptState::Timeout => "timeout",
        AttemptState::Malformed => "malformed",
        AttemptState::Unavailable => "unavailable",
    }
}

fn show_ratio(value: Option<&Ratio>) -> String {
    value.map_or_else(
        || "unavailable".to_owned(),
        |ratio| {
            format!(
                "{}/{} ({})",
                ratio.numerator, ratio.denominator, ratio.decimal
            )
        },
    )
}

fn report(lane: &LaneResult, comparison: &Value) -> String {
    let mut output = String::from(
        "# Phase 24 Semgrep post-open normalized recovery\n\nPhase 24 is additive. It neither replaces nor retries the 112 historical Phase 22 Semgrep failures.\n\n## Phase 24 Semgrep lane\n\n| Phase | Scanner | Lane | Environment | State | Attempts | Completed | Failed | Timeout | Malformed | Unavailable | TP | FP | TN | FN | Precision | Recall | Specificity | F1 | Balanced accuracy |\n|---:|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n",
    );
    let metric = lane.metrics.as_ref();
    output.push_str(&format!(
        "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
        lane.phase,
        lane.scanner,
        lane.lane,
        lane.environment,
        lane.state,
        lane.operations.attempts,
        lane.operations.completed,
        lane.operations.failed,
        lane.operations.timeouts,
        lane.operations.malformed,
        lane.operations.unavailable,
        metric.map_or_else(|| "—".to_owned(), |value| value.tp.to_string()),
        metric.map_or_else(|| "—".to_owned(), |value| value.fp.to_string()),
        metric.map_or_else(|| "—".to_owned(), |value| value.tn.to_string()),
        metric.map_or_else(|| "—".to_owned(), |value| value.fn_count.to_string()),
        show_ratio(metric.and_then(|value| value.precision.as_ref())),
        show_ratio(metric.and_then(|value| value.recall.as_ref())),
        show_ratio(metric.and_then(|value| value.specificity.as_ref())),
        show_ratio(metric.and_then(|value| value.f1.as_ref())),
        show_ratio(metric.and_then(|value| value.balanced_accuracy.as_ref())),
    ));
    output.push_str(&format!(
        "\n## Paired normalized comparison\n\nState: `{}`. Phase 22 OpenGrep/normalized is compared only with Phase 24 Semgrep/normalized. Case agreements: `{}`; case disagreements: `{}`; pair agreements: `{}`; pair disagreements: `{}`; OpenGrep-only correct: `{}`; Semgrep-only correct: `{}`; both incorrect: `{}`.\n",
        comparison.get("state").and_then(Value::as_str).unwrap_or("invalid"),
        comparison.get("agreements").and_then(Value::as_u64).map_or_else(|| "unavailable".to_owned(), |value| value.to_string()),
        comparison.get("disagreements_count").and_then(Value::as_u64).map_or_else(|| "unavailable".to_owned(), |value| value.to_string()),
        comparison.get("pair_agreements").and_then(Value::as_u64).map_or_else(|| "unavailable".to_owned(), |value| value.to_string()),
        comparison.get("pair_disagreements_count").and_then(Value::as_u64).map_or_else(|| "unavailable".to_owned(), |value| value.to_string()),
        comparison.get("opengrep_only_correct").and_then(Value::as_u64).map_or_else(|| "unavailable".to_owned(), |value| value.to_string()),
        comparison.get("semgrep_only_correct").and_then(Value::as_u64).map_or_else(|| "unavailable".to_owned(), |value| value.to_string()),
        comparison.get("both_incorrect").and_then(Value::as_u64).map_or_else(|| "unavailable".to_owned(), |value| value.to_string()),
    ));
    output.push_str("\n## Breakdowns\n\nCanonical case and pair decisions are in `results.json`; all requested family, framework, source-format, topology, adversarial-variant, and vulnerable/control metrics with exact numerators and denominators are in `strata.json`. Paired disagreements are in `comparison.json` and `disagreements.json`.\n\n## Validity boundary\n\nNo native or Secure Engine result is merged with normalized metrics, and no overall three-scanner winner is declared. Phase 24 cannot restore blind-holdout or one-shot validity.\n");
    output
}

const LIMITATIONS: &str = "# Phase 24 methodological limitations\n\nPhase 24 is post-open and additive. It cannot restore blind-holdout or one-shot validity. It preserves the 112 failed Semgrep observations from Phase 22 unchanged and does not reinterpret, replace, repair, or retry them. The paired comparison is restricted to OpenGrep capability-normalized Phase 22 and Semgrep capability-normalized Phase 24. Secure Engine and native evidence are excluded; no overall three-scanner winner is declared. Process failures are explicit, are not imputed, and make Phase 24 detection metrics and the normalized comparison unavailable unless all 112 attempts complete and independent recalculation succeeds.\n";

fn write_outputs(
    root: &Path,
    plan: &ExecutionPlan,
    cases: &BTreeMap<String, CaseSpec>,
    observations: &[Observation],
    ledger_head: &str,
) -> Result<Value, Phase24Error> {
    let output = root.join(OUTPUT);
    let lane = semgrep_lane(cases, observations)?;
    let independent = independently_recalculate(root, cases, observations, &lane)?;
    let independent_valid = independent.get("valid").and_then(Value::as_bool) == Some(true);
    let opengrep = phase22_opengrep(root)?;
    let comparison = paired_comparison(&opengrep, &lane, independent_valid);
    let results = json!({
        "schema_version": "secure-bench-phase24-results-v1",
        "study": "semgrep post-open normalized recovery",
        "base_phase23_commit": PHASE23,
        "total_phase24_attempts": observations.len(),
        "retries": 0,
        "opengrep_attempts": 0,
        "secure_engine_attempts": 0,
        "native_attempts": 0,
        "repeated_attempts": observations.iter().map(|observation| observation.case_id.as_str()).collect::<BTreeSet<_>>().len() != observations.len(),
        "phase22_opengrep_normalized": opengrep,
        "phase24_semgrep_normalized": lane,
        "comparison": comparison,
        "historical_phase22_semgrep": {
            "phase": 22,
            "scanner": "semgrep-ce",
            "lane": "capability-normalized",
            "attempts": 112,
            "state": "failed",
            "immutable": true,
            "replaced_repaired_retried": false,
            "source_results_sha256": PHASE22_RESULTS_SHA256,
        },
    });
    write_atomic(&output.join("results.json"), &canonical(&results)?)?;
    write_atomic(&output.join("comparison.json"), &canonical(&comparison)?)?;
    write_atomic(
        &output.join("disagreements.json"),
        &canonical(&json!({
            "schema_version": "secure-bench-phase24-disagreements-v1",
            "cases": comparison.get("disagreements").cloned().unwrap_or_else(|| json!([])),
            "pairs": comparison.get("pair_disagreements").cloned().unwrap_or_else(|| json!([])),
        }))?,
    )?;
    let strata = json!({
        "schema_version": "secure-bench-phase24-strata-v1",
        "phase": 24,
        "scanner": "semgrep-ce",
        "lane": "capability-normalized",
        "environment": "phase23-stack-bounded-v1",
        "by_family": lane.by_family,
        "by_framework": lane.by_framework,
        "by_source_format": lane.by_source_format,
        "by_topology": lane.by_topology,
        "by_adversarial_variant": lane.by_adversarial_variant,
        "by_classification": lane.by_classification,
    });
    write_atomic(&output.join("strata.json"), &canonical(&strata)?)?;
    write_atomic(
        &output.join("report.md"),
        report(&lane, &comparison).as_bytes(),
    )?;
    write_atomic(&output.join("limitations.md"), LIMITATIONS.as_bytes())?;
    let failures = observations
        .iter()
        .filter(|observation| observation.state != AttemptState::Completed)
        .collect::<Vec<_>>();
    let mut by_state = BTreeMap::<&str, u64>::new();
    for observation in &failures {
        *by_state.entry(state_name(&observation.state)).or_default() += 1;
    }
    let failure_analysis = json!({
        "schema_version": "secure-bench-phase24-failure-analysis-v1",
        "non_completed_attempts": failures.len(),
        "by_state": by_state,
        "failures": failures,
        "imputation": false,
        "retries": 0,
    });
    write_atomic(
        &output.join("failure-analysis.json"),
        &canonical(&failure_analysis)?,
    )?;
    write_atomic(
        &output.join("independent-verification.json"),
        &canonical(&independent)?,
    )?;
    let provenance = json!({
        "schema_version": "secure-bench-phase24-provenance-v1",
        "run_id": plan.run_id,
        "phase23_commit": PHASE23,
        "phase22_commit": PHASE22,
        "phase20_subtree": PHASE20_TREE,
        "phase22_subtree": PHASE22_TREE,
        "phase23_subtree": PHASE23_TREE,
        "corpus_tree": CORPUS_TREE,
        "execution_plan_sha256": sha_file(&root.join(PLAN))?,
        "execution_contract_sha256": sha_file(&root.join(CONTRACT))?,
        "implementation_sha256": implementation_digest(root)?,
        "preflight_sha256s_sha256": sha_file(&root.join(PREFLIGHT).join("SHA256SUMS"))?,
        "corpus_opened_marker_sha256": sha_file(&output.join("CORPUS_OPENED.json"))?,
        "phase22_results_sha256": PHASE22_RESULTS_SHA256,
        "ruleset_sha256": RULESET_SHA256,
        "semgrep_adapter_sha256": ADAPTER_SHA256,
        "scoring_methodology_sha256": SCORING_SHA256,
        "semgrep_entrypoint_source": SEMGREP_SOURCE,
        "semgrep_entrypoint_sha256": SEMGREP_ENTRYPOINT_SHA256,
        "semgrep_wheel_sha256": SEMGREP_WHEEL_SHA256,
        "semgrep_wheel_closure_sha256": SEMGREP_CLOSURE_SHA256,
        "semgrep_dependency_lock_sha256": SEMGREP_LOCK_SHA256,
        "results_sha256": sha_file(&output.join("results.json"))?,
        "comparison_sha256": sha_file(&output.join("comparison.json"))?,
        "strata_sha256": sha_file(&output.join("strata.json"))?,
        "failure_analysis_sha256": sha_file(&output.join("failure-analysis.json"))?,
        "independent_verification_sha256": sha_file(&output.join("independent-verification.json"))?,
        "report_sha256": sha_file(&output.join("report.md"))?,
        "limitations_sha256": sha_file(&output.join("limitations.md"))?,
        "ledger_head": ledger_head,
        "attempts": observations.len(),
        "retries": 0,
        "opengrep_secure_engine_native_attempts": 0,
        "network_ai_telemetry_credentials": "forbidden",
    });
    write_atomic(&output.join("provenance.json"), &canonical(&provenance)?)?;
    write_sums(&output)?;
    Ok(json!({
        "state": if independent_valid {"completed"} else {"operationally-complete-quality-unavailable"},
        "executed_attempts": observations.len(),
        "retries": 0,
        "ledger_head": ledger_head,
        "independent_recalculation_valid": independent_valid,
    }))
}

/// Execute the frozen plan exactly once after writing the irreversible marker.
pub fn execute_once(root: &Path) -> Result<Value, Phase24Error> {
    let plan = verify_saved_preflight(root)?;
    let output = root.join(OUTPUT);
    if output.exists() {
        return Err(Phase24Error::Contract(
            "Phase 24 output already exists; retries are forbidden".to_owned(),
        ));
    }
    fs::create_dir_all(&output)?;
    let marker = json!({
        "schema_version": "secure-bench-phase24-corpus-opened-v1",
        "run_id": plan.run_id,
        "opened_at_unix_ms": now_ms()?,
        "plan_sha256": sha_file(&root.join(PLAN))?,
        "contract_sha256": sha_file(&root.join(CONTRACT))?,
        "preflight_sha256s_sha256": sha_file(&root.join(PREFLIGHT).join("SHA256SUMS"))?,
        "implementation_sha256": implementation_digest(root)?,
        "planned_attempts": 112,
        "retries": 0,
        "opengrep_attempts": 0,
        "secure_engine_attempts": 0,
        "native_attempts": 0,
        "statement": "irreversible marker written immediately before the first Phase 19 manifest or case read",
    });
    create_irreversible(&output.join("CORPUS_OPENED.json"), &canonical(&marker)?)?;
    let cases = load_cases_post_open(root)?;
    let planned = plan
        .attempts
        .iter()
        .map(|attempt| attempt.case_id.as_str())
        .collect::<BTreeSet<_>>();
    let manifested = cases.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if planned != manifested {
        return Err(Phase24Error::Execution(
            "post-open case IDs differ from frozen plan".to_owned(),
        ));
    }
    let mut observations = Vec::with_capacity(112);
    let mut previous = ZERO_HASH.to_owned();
    let ledger = output.join("ledger.jsonl");
    for attempt in &plan.attempts {
        let case = cases.get(&attempt.case_id).ok_or_else(|| {
            Phase24Error::Execution(format!("unknown planned case {}", attempt.case_id))
        })?;
        let observation = run_attempt(root, attempt, case)?;
        let observation_path = root
            .join(attempt_directory(attempt))
            .join("observation.json");
        write_atomic(&observation_path, &canonical(&observation)?)?;
        previous = append_ledger(&ledger, &observation, &previous)?;
        println!(
            "attempt {}/112 {} {:?} findings={:?} duration_ms={}",
            attempt.sequence,
            attempt.case_id,
            observation.state,
            observation.finding_count,
            observation.duration_ms
        );
        observations.push(observation);
    }
    if observations.len() != 112 {
        return Err(Phase24Error::Execution(format!(
            "executed {} attempts, expected 112",
            observations.len()
        )));
    }
    write_outputs(root, &plan, &cases, &observations, &previous)
}

fn verify_evidence_file(root: &Path, path: &str, expected: &str) -> Result<Vec<u8>, Phase24Error> {
    let relative = safe_relative(path)?;
    if !path.starts_with("phase24/output/") {
        return Err(Phase24Error::Verification(format!(
            "evidence path escaped Phase 24 output: {path}"
        )));
    }
    let bytes = fs::read(root.join(relative))?;
    if sha256(&bytes) != expected {
        return Err(Phase24Error::Verification(format!(
            "evidence hash mismatch: {path}"
        )));
    }
    Ok(bytes)
}

fn read_observations(root: &Path, plan: &ExecutionPlan) -> Result<Vec<Observation>, Phase24Error> {
    let mut observations = Vec::with_capacity(112);
    for attempt in &plan.attempts {
        let path = root
            .join(attempt_directory(attempt))
            .join("observation.json");
        let observation: Observation = serde_json::from_slice(&fs::read(&path)?)?;
        if observation.sequence != attempt.sequence
            || observation.case_id != attempt.case_id
            || observation.scanner != "semgrep-ce"
            || observation.lane != "capability-normalized"
            || observation.attempt_id
                != format!(
                    "phase24-semgrep-{:03}-{}",
                    attempt.sequence, attempt.case_id
                )
            || observation.environment != fixed_environment()
            || observation.environment_sha256 != sha256(&canonical(&observation.environment)?)
            || observation.command_sha256 != sha256(&canonical(&observation.command)?)
            || observation.command.first().map(String::as_str) != Some("/usr/bin/bwrap")
            || observation.command.windows(7).all(|window| {
                window
                    != [
                        "/usr/bin/prlimit",
                        "--as=4294967296",
                        "--nproc=64",
                        "--stack=8388608",
                        "--",
                        "/usr/bin/python3.14",
                        "/tmp/runtime-wrapper.py",
                    ]
            })
            || observation.command.iter().any(|argument| {
                argument.contains("secure-engine")
                    || argument.contains("opengrep")
                    || argument.contains("native")
            })
        {
            return Err(Phase24Error::Verification(format!(
                "observation contract drift at sequence {}",
                attempt.sequence
            )));
        }
        let _ = verify_evidence_file(root, &observation.stdout_path, &observation.stdout_sha256)?;
        let _ = verify_evidence_file(root, &observation.stderr_path, &observation.stderr_sha256)?;
        let _ = verify_evidence_file(
            root,
            &observation.resource_path,
            &observation.resource_sha256,
        )?;
        match (
            observation.effective_environment_path.as_deref(),
            observation.effective_environment_sha256.as_deref(),
        ) {
            (Some(path), Some(hash)) => {
                let effective = verify_evidence_file(root, path, hash)?;
                validate_effective_environment(Some(&effective))
                    .map_err(Phase24Error::Verification)?;
            }
            (None, None) if observation.state != AttemptState::Completed => {}
            _ => {
                return Err(Phase24Error::Verification(format!(
                    "attempt {} has inconsistent effective environment evidence",
                    attempt.sequence
                )));
            }
        }
        match (&observation.state, observation.finding_count) {
            (AttemptState::Completed, Some(_)) => {
                let raw_path = observation.raw_output_path.as_deref().ok_or_else(|| {
                    Phase24Error::Verification(format!(
                        "completed attempt {} has no raw path",
                        attempt.sequence
                    ))
                })?;
                let raw_hash = observation.raw_output_sha256.as_deref().ok_or_else(|| {
                    Phase24Error::Verification(format!(
                        "completed attempt {} has no raw hash",
                        attempt.sequence
                    ))
                })?;
                let _ = verify_evidence_file(root, raw_path, raw_hash)?;
                if observation.failure.is_some() {
                    return Err(Phase24Error::Verification(format!(
                        "completed attempt {} has failure text",
                        attempt.sequence
                    )));
                }
            }
            (AttemptState::Completed, None) | (_, Some(_)) => {
                return Err(Phase24Error::Verification(format!(
                    "attempt {} has inconsistent numeric scoring state",
                    attempt.sequence
                )));
            }
            (_, None) => {
                if observation.failure.is_none() {
                    return Err(Phase24Error::Verification(format!(
                        "failed attempt {} omits explicit failure",
                        attempt.sequence
                    )));
                }
                if let (Some(path), Some(hash)) = (
                    observation.raw_output_path.as_deref(),
                    observation.raw_output_sha256.as_deref(),
                ) {
                    let _ = verify_evidence_file(root, path, hash)?;
                }
            }
        }
        observations.push(observation);
    }
    Ok(observations)
}

fn verify_ledger(root: &Path, observations: &[Observation]) -> Result<String, Phase24Error> {
    let content = fs::read_to_string(root.join(OUTPUT).join("ledger.jsonl"))?;
    let lines = content.lines().collect::<Vec<_>>();
    if lines.len() != 112 || observations.len() != 112 {
        return Err(Phase24Error::Verification(format!(
            "ledger/observation count is {}/{}, expected 112/112",
            lines.len(),
            observations.len()
        )));
    }
    let mut previous = ZERO_HASH.to_owned();
    for (index, (line, observation)) in lines.iter().zip(observations).enumerate() {
        let entry: LedgerEntry = serde_json::from_str(line)?;
        let sequence = u64::try_from(index + 1).unwrap_or(u64::MAX);
        let payload = sha256(&canonical(observation)?);
        let projection = json!({
            "schema_version": "secure-bench-phase24-ledger-v1",
            "sequence": sequence,
            "event": "semgrep-recovery-attempt-completed",
            "payload_sha256": payload,
            "previous_entry_hash": previous,
        });
        let expected = sha256(&canonical(&projection)?);
        if entry.sequence != sequence
            || entry.event != "semgrep-recovery-attempt-completed"
            || entry.payload_sha256 != payload
            || entry.previous_entry_hash != previous
            || entry.entry_hash != expected
        {
            return Err(Phase24Error::Verification(format!(
                "ledger chain drift at sequence {sequence}"
            )));
        }
        previous = expected;
    }
    Ok(previous)
}

fn verify_output_sums(output: &Path) -> Result<u64, Phase24Error> {
    let sums_path = output.join("SHA256SUMS");
    let mut expected = BTreeMap::new();
    for line in fs::read_to_string(&sums_path)?.lines() {
        let (hash, name) = line.split_once("  ").ok_or_else(|| {
            Phase24Error::Verification("malformed Phase 24 checksum line".to_owned())
        })?;
        let name = safe_relative(name)?;
        if expected
            .insert(name.to_path_buf(), hash.to_owned())
            .is_some()
        {
            return Err(Phase24Error::Verification(
                "duplicate Phase 24 checksum path".to_owned(),
            ));
        }
    }
    let mut files = Vec::new();
    collect_files(output, &mut files)?;
    files.retain(|path| path != &sums_path);
    let actual = files
        .iter()
        .map(|path| {
            path.strip_prefix(output)
                .map(Path::to_path_buf)
                .map_err(|_| Phase24Error::Verification("output path escaped".to_owned()))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if actual != expected.keys().cloned().collect() {
        return Err(Phase24Error::Verification(
            "Phase 24 SHA256SUMS is not exhaustive".to_owned(),
        ));
    }
    for (relative, hash) in &expected {
        if sha_file(&output.join(relative))? != *hash {
            return Err(Phase24Error::Verification(format!(
                "Phase 24 checksum drift: {}",
                relative.display()
            )));
        }
    }
    Ok(u64::try_from(expected.len()).unwrap_or(u64::MAX))
}

fn verify_history_post_open(root: &Path) -> Result<(), Phase24Error> {
    if git(root, &["rev-parse", &format!("{PHASE23}^")])? != PHASE22
        || git(root, &["rev-parse", &format!("{PHASE23}:phase20")])? != PHASE20_TREE
        || git(root, &["rev-parse", &format!("{PHASE23}:phase22")])? != PHASE22_TREE
        || git(root, &["rev-parse", &format!("{PHASE23}:phase23")])? != PHASE23_TREE
    {
        return Err(Phase24Error::Verification(
            "historical commit or subtree drift".to_owned(),
        ));
    }
    let status = git(
        root,
        &[
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--",
            "phase19",
            "phase20",
            "phase22",
            "phase23",
        ],
    )?;
    if !status.is_empty() {
        return Err(Phase24Error::Verification(format!(
            "historical worktree drift: {status}"
        )));
    }
    for (path, expected) in [
        (RULESET, RULESET_SHA256),
        (ADAPTER, ADAPTER_SHA256),
        (SCORING, SCORING_SHA256),
        (PHASE22_PLAN, PHASE22_PLAN_SHA256),
        (PHASE22_RESULTS, PHASE22_RESULTS_SHA256),
        (PHASE23_CONTRACT, PHASE23_CONTRACT_SHA256),
        ("phase23/SHA256SUMS", PHASE23_SUMS_SHA256),
    ] {
        if sha_file(&root.join(path))? != expected {
            return Err(Phase24Error::Verification(format!(
                "historical file drift: {path}"
            )));
        }
    }
    let phase23 = verify_signature(root, PHASE23)?;
    if phase23.get("parent").and_then(Value::as_str) != Some(PHASE22)
        || phase23.get("tree").and_then(Value::as_str) != Some(PHASE23_ROOT_TREE)
    {
        return Err(Phase24Error::Verification(
            "Phase 23 signature, parent, or tree drift".to_owned(),
        ));
    }
    let head = git(root, &["rev-parse", "HEAD"])?;
    if head != PHASE23 {
        if git(root, &["rev-parse", "HEAD^"])? != PHASE23 {
            return Err(Phase24Error::Verification(
                "Phase 24 commit is not a direct child of Phase 23".to_owned(),
            ));
        }
        let signed = verify_signature(root, &head)?;
        if signed.get("parent").and_then(Value::as_str) != Some(PHASE23) {
            return Err(Phase24Error::Verification(
                "Phase 24 signed commit parent drift".to_owned(),
            ));
        }
    }
    Ok(())
}

/// Recalculate and verify all Phase 24 evidence without starting scanners.
pub fn verify(root: &Path) -> Result<Value, Phase24Error> {
    if !root.join(OUTPUT).join("CORPUS_OPENED.json").is_file() {
        return Err(Phase24Error::Verification(
            "irreversible corpus marker is absent".to_owned(),
        ));
    }
    let plan = validate_contract(root)?;
    verify_history_post_open(root)?;
    let observations = read_observations(root, &plan)?;
    let ledger_head = verify_ledger(root, &observations)?;
    let cases = load_cases_post_open(root)?;
    let lane = semgrep_lane(&cases, &observations)?;
    let independent = independently_recalculate(root, &cases, &observations, &lane)?;
    let opengrep = phase22_opengrep(root)?;
    let comparison = paired_comparison(
        &opengrep,
        &lane,
        independent.get("valid").and_then(Value::as_bool) == Some(true),
    );
    let results: Value =
        serde_json::from_slice(&fs::read(root.join(OUTPUT).join("results.json"))?)?;
    let expected_disagreements = json!({
        "schema_version": "secure-bench-phase24-disagreements-v1",
        "cases": comparison.get("disagreements").cloned().unwrap_or_else(|| json!([])),
        "pairs": comparison.get("pair_disagreements").cloned().unwrap_or_else(|| json!([])),
    });
    let expected_strata = json!({
        "schema_version": "secure-bench-phase24-strata-v1",
        "phase": 24,
        "scanner": "semgrep-ce",
        "lane": "capability-normalized",
        "environment": "phase23-stack-bounded-v1",
        "by_family": lane.by_family,
        "by_framework": lane.by_framework,
        "by_source_format": lane.by_source_format,
        "by_topology": lane.by_topology,
        "by_adversarial_variant": lane.by_adversarial_variant,
        "by_classification": lane.by_classification,
    });
    let failures = observations
        .iter()
        .filter(|observation| observation.state != AttemptState::Completed)
        .collect::<Vec<_>>();
    let mut by_state = BTreeMap::<&str, u64>::new();
    for observation in &failures {
        *by_state.entry(state_name(&observation.state)).or_default() += 1;
    }
    let expected_failures = json!({
        "schema_version": "secure-bench-phase24-failure-analysis-v1",
        "non_completed_attempts": failures.len(),
        "by_state": by_state,
        "failures": failures,
        "imputation": false,
        "retries": 0,
    });
    if results.get("phase24_semgrep_normalized") != Some(&serde_json::to_value(&lane)?)
        || results.get("phase22_opengrep_normalized") != Some(&opengrep)
        || results.get("comparison") != Some(&comparison)
        || serde_json::from_slice::<Value>(&fs::read(root.join(OUTPUT).join("comparison.json"))?)?
            != comparison
        || serde_json::from_slice::<Value>(&fs::read(
            root.join(OUTPUT).join("independent-verification.json"),
        )?)? != independent
        || serde_json::from_slice::<Value>(&fs::read(
            root.join(OUTPUT).join("disagreements.json"),
        )?)? != expected_disagreements
        || serde_json::from_slice::<Value>(&fs::read(root.join(OUTPUT).join("strata.json"))?)?
            != expected_strata
        || serde_json::from_slice::<Value>(&fs::read(
            root.join(OUTPUT).join("failure-analysis.json"),
        )?)? != expected_failures
        || fs::read_to_string(root.join(OUTPUT).join("report.md"))? != report(&lane, &comparison)
        || fs::read_to_string(root.join(OUTPUT).join("limitations.md"))? != LIMITATIONS
    {
        return Err(Phase24Error::Verification(
            "canonical results differ from raw-evidence recalculation".to_owned(),
        ));
    }
    let provenance: Value =
        serde_json::from_slice(&fs::read(root.join(OUTPUT).join("provenance.json"))?)?;
    if provenance.get("ledger_head").and_then(Value::as_str) != Some(&ledger_head)
        || provenance.get("attempts").and_then(Value::as_u64) != Some(112)
        || provenance.get("retries").and_then(Value::as_u64) != Some(0)
        || provenance
            .get("opengrep_secure_engine_native_attempts")
            .and_then(Value::as_u64)
            != Some(0)
    {
        return Err(Phase24Error::Verification(
            "provenance attempt or ledger drift".to_owned(),
        ));
    }
    let checksum_entries = verify_output_sums(&root.join(OUTPUT))?;
    if !no_scanner_processes()? {
        return Err(Phase24Error::Verification(
            "forbidden scanner process exists during verification".to_owned(),
        ));
    }
    Ok(json!({
        "schema_version": "secure-bench-phase24-verification-v1",
        "valid": true,
        "scanner_processes_started": 0,
        "attempts": 112,
        "retries": 0,
        "semgrep_attempts": 112,
        "opengrep_attempts": 0,
        "secure_engine_attempts": 0,
        "native_attempts": 0,
        "independent_recalculation_valid": independent.get("valid"),
        "comparison_state": comparison.get("state"),
        "ledger_head": ledger_head,
        "checksum_entries_verified": checksum_entries,
        "historical_phases_20_through_23_immutable": true,
        "network_ai_telemetry_credentials": "forbidden",
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_metrics_include_requested_ratios() {
        let cases = [
            ("tp", "vulnerable", 1),
            ("fn", "vulnerable", 0),
            ("tn", "control", 0),
            ("fp", "control", 1),
        ]
        .into_iter()
        .map(|(outcome, expected, finding_count)| CaseDecision {
            case_id: outcome.to_owned(),
            pair_id: "pair".to_owned(),
            expected: expected.to_owned(),
            finding_count,
            predicted_positive: finding_count > 0,
            outcome: outcome.to_owned(),
            family: "SE1001".to_owned(),
            framework: "node".to_owned(),
            source_format: "javascript".to_owned(),
            topology: "direct".to_owned(),
            adversarial_variant: "none".to_owned(),
        })
        .collect::<Vec<_>>();
        let result = metrics(&cases);
        assert_eq!(
            (result.tp, result.fp, result.tn, result.fn_count),
            (1, 1, 1, 1)
        );
        assert_eq!(
            result
                .balanced_accuracy
                .and_then(|value| value.decimal.parse::<f64>().ok()),
            Some(0.5)
        );
    }

    #[test]
    fn unsafe_paths_fail_closed() {
        assert!(safe_relative("../phase22/output/results.json").is_err());
        assert!(portable_relative("/etc/passwd").is_err());
        assert!(portable_relative("fixture/../secret").is_err());
    }

    #[test]
    fn command_uses_phase23_profile_verbatim() {
        let arguments = attempt_arguments(
            Path::new("/repository"),
            Path::new("/repository/fixture"),
            Path::new("/repository/output"),
        );
        assert!(arguments.windows(7).any(|window| {
            window
                == [
                    "/usr/bin/prlimit",
                    "--as=4294967296",
                    "--nproc=64",
                    "--stack=8388608",
                    "--",
                    "/usr/bin/python3.14",
                    "/tmp/runtime-wrapper.py",
                ]
        }));
        assert!(arguments.iter().any(|argument| {
            argument == "/tmp/secure-bench-tools/semgrep/1.170.0/venv/bin/semgrep"
        }));
        assert!(!arguments.iter().any(|argument| {
            argument.contains("opengrep")
                || argument.contains("secure-engine")
                || argument.contains("native")
        }));
    }

    #[test]
    fn frozen_semgrep_adapter_is_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .canonicalize()?;
        let fixture = tempfile::tempdir()?;
        fs::write(fixture.path().join("app.js"), b"eval(input);\n")?;
        let report = json!({
            "version": "1.170.0",
            "engine_requested": "OSS",
            "errors": [],
            "skipped_rules": [],
            "paths": {"scanned": ["app.js"]},
            "results": [{
                "check_id": ALLOWED_RULES[2],
                "path": "app.js",
                "start": {"line": 1, "col": 1, "offset": 0},
                "end": {"line": 1, "col": 5, "offset": 4},
                "extra": {"engine_kind": "OSS"},
            }],
        });
        assert_eq!(
            adapt_raw(&root, fixture.path(), &serde_json::to_vec(&report)?),
            Ok(1)
        );
        let mut traversal = report;
        traversal["results"][0]["path"] = json!("../app.js");
        assert!(adapt_raw(&root, fixture.path(), &serde_json::to_vec(&traversal)?).is_err());
        Ok(())
    }
}
