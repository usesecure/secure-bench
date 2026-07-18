use crate::model::{ExecutionPlan, PlanAttempt};
use crate::runner::run_process;
use crate::{
    Phase22Error, canonical_json, collect_files, implementation_digest, safe_relative, sha256,
    sha256_file, write_atomic,
};
use secure_bench_phase21::independent_verify as verify_phase21;
use secure_bench_phase21::sandbox::{
    Scanner, base_arguments, fixed_environment, scanner_command, scanner_sandbox, validate_tools,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

const PLAN_PATH: &str = "phase22/config/execution-plan-v1.json";
const CONTRACT_PATH: &str = "phase22/config/execution-contract-v1.json";
const PREFLIGHT: &str = "phase22/preflight";
const PHASE19: &str = "b3e983891e4ae3e12cd727f6bdb460962f876a30";
const PHASE20: &str = "6c27c9bb26b96855228d1a8e6483483ff4174907";
const PHASE21: &str = "be1ce9327c5c2acab25abe5af7a4f923d1623c48";
const PHASE20_TREE: &str = "05cd69281777263a4f9286069767d870014cab52";
const CORPUS_GIT_TREE: &str = "ddfe1134b007aa52a6c5e351d535c9ed4c0cd76a";
const PHASE21_CONTRACT_SHA256: &str =
    "186011766acc155a66c4a965094baf8fca335b56338363610a4d713d41876cae";
const RULESET_SHA256: &str = "06af4cf6d10da30ad585d57b781cf6aef734add03b90ea36c78e920c4c10a07c";
const CORPUS_SHA256: &str = "d059653d836647296bef93a43d9e9f046899ad4fa0a87d561b4463ce0db2781c";
const MERKLE_ROOT: &str = "2bcc11f20b0f9d06eeb10f05130b752fa8125421ebf37d6050cd3119aef4452e";
const OPENGREP_ADAPTER_SHA256: &str =
    "6a922a0ecac31b55f1591782df548822caa62064aaf7f8b9c1b0addc07cd0998";
const SEMGREP_ADAPTER_SHA256: &str =
    "53317a4e71b14548d618fd79430b74b8fc906edebbf7180cbea418df98b1afc3";
const PHASE20_SCORING_SHA256: &str =
    "0e0a767e8b1df51ca8018d27956e1d0f4ba943d520888923221bbf67f9a7b2a6";

fn git(root: &Path, arguments: &[&str]) -> Result<String, Phase22Error> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()?;
    if !output.status.success() {
        return Err(Phase22Error::Preflight(format!(
            "git {} failed: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|error| Phase22Error::Preflight(error.to_string()))
}

fn commit_audit(root: &Path, commit: &str, parent: &str) -> Result<Value, Phase22Error> {
    let actual_parent = git(root, &["rev-parse", &format!("{commit}^")])?;
    if actual_parent != parent {
        return Err(Phase22Error::Preflight(format!(
            "commit {commit} parent drift: {actual_parent}"
        )));
    }
    let tree = git(root, &["rev-parse", &format!("{commit}^{{tree}}")])?;
    let signature = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["verify-commit", commit])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()?;
    if !signature.status.success()
        || !String::from_utf8_lossy(&signature.stderr).contains("Good \"git\" signature")
    {
        return Err(Phase22Error::Preflight(format!(
            "commit {commit} signature is not a trusted good signature"
        )));
    }
    let message = git(root, &["show", "-s", "--format=%B", commit])?;
    let dco = message
        .lines()
        .filter(|line| line.starts_with("Signed-off-by: "))
        .count();
    if dco != 1 {
        return Err(Phase22Error::Preflight(format!(
            "commit {commit} has {dco} DCO trailers"
        )));
    }
    Ok(json!({
        "commit": commit,
        "parent": parent,
        "tree": tree,
        "signature": "good-ed25519",
        "dco_trailers": 1,
    }))
}

fn phase20_case_ids(root: &Path) -> Result<Vec<String>, Phase22Error> {
    let results: Value =
        serde_json::from_slice(&fs::read(root.join("phase20/output/results.json"))?)?;
    if results
        .get("total_scanner_process_attempts")
        .and_then(Value::as_u64)
        != Some(336)
        || results.get("repeated_attempts").and_then(Value::as_bool) != Some(false)
        || results
            .get("aggregate_corpus_sha256")
            .and_then(Value::as_str)
            != Some(CORPUS_SHA256)
        || results.get("contract_merkle_root").and_then(Value::as_str) != Some(MERKLE_ROOT)
    {
        return Err(Phase22Error::Contract(
            "immutable Phase 20 result identity drift".to_owned(),
        ));
    }
    let lanes = results
        .get("lanes")
        .and_then(Value::as_array)
        .ok_or_else(|| Phase22Error::Contract("Phase 20 results have no lanes".to_owned()))?;
    let lane = lanes
        .iter()
        .find(|lane| {
            lane.get("scanner").and_then(Value::as_str) == Some("secure-engine")
                && lane.get("lane").and_then(Value::as_str) == Some("native")
                && lane.get("state").and_then(Value::as_str) == Some("completed")
        })
        .ok_or_else(|| {
            Phase22Error::Contract("Phase 20 completed native lane is absent".to_owned())
        })?;
    let mut ids = lane
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| Phase22Error::Contract("Phase 20 native lane has no cases".to_owned()))?
        .iter()
        .map(|case| {
            case.get("case_id")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| Phase22Error::Contract("Phase 20 case has no ID".to_owned()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    ids.sort();
    ids.dedup();
    if ids.len() != 112 {
        return Err(Phase22Error::Contract(format!(
            "Phase 20 exposes {} opaque case IDs, expected 112",
            ids.len()
        )));
    }
    Ok(ids)
}

fn verify_frozen_inputs(root: &Path) -> Result<(String, String), Phase22Error> {
    let sensitive_status = git(
        root,
        &[
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignored=matching",
            "--",
            "phase19/holdout",
            "phase19/rules/capability-normalized-v1.yml",
            "phase20",
            "phase21",
        ],
    )?;
    if !sensitive_status.is_empty() {
        return Err(Phase22Error::Preflight(format!(
            "frozen input worktree drift: {sensitive_status}"
        )));
    }
    let phase20_tree = git(root, &["rev-parse", &format!("{PHASE20}:phase20")])?;
    let corpus_tree = git(
        root,
        &["rev-parse", &format!("{PHASE19}:phase19/holdout/cases")],
    )?;
    if phase20_tree != PHASE20_TREE
        || corpus_tree != CORPUS_GIT_TREE
        || sha256_file(&root.join("phase21/output/corrected-environment-contract.json"))?
            != PHASE21_CONTRACT_SHA256
        || sha256_file(&root.join("phase19/rules/capability-normalized-v1.yml"))? != RULESET_SHA256
        || sha256_file(&root.join("phase20/config/opengrep-normalized-adapter-v1.json"))?
            != OPENGREP_ADAPTER_SHA256
        || sha256_file(&root.join("phase20/config/semgrep-normalized-adapter-v1.json"))?
            != SEMGREP_ADAPTER_SHA256
        || sha256_file(&root.join("phase20/config/scoring-methodology-v1.json"))?
            != PHASE20_SCORING_SHA256
    {
        return Err(Phase22Error::Preflight(
            "immutable Phase 20, Phase 21 contract, corpus tree, or ruleset drift".to_owned(),
        ));
    }
    phase20_case_ids(root)?;
    Ok((phase20_tree, corpus_tree))
}

fn validate_plan(plan: &ExecutionPlan) -> Result<(), Phase22Error> {
    if plan.schema_version != "secure-bench-phase22-execution-plan-v1"
        || plan.study != "post-open recovery study"
        || plan.total_attempts != 224
        || plan.retries != 0
        || plan.secure_engine_attempts != 0
        || plan.attempts.len() != 224
    {
        return Err(Phase22Error::Contract(
            "Phase 22 execution plan header drift".to_owned(),
        ));
    }
    let mut keys = BTreeSet::new();
    let mut scanner_counts = BTreeMap::<&str, usize>::new();
    for (index, attempt) in plan.attempts.iter().enumerate() {
        if attempt.sequence != u64::try_from(index + 1).unwrap_or(u64::MAX)
            || attempt.lane != "capability-normalized"
            || !matches!(attempt.scanner.as_str(), "opengrep" | "semgrep-ce")
            || !keys.insert((attempt.scanner.as_str(), attempt.case_id.as_str()))
        {
            return Err(Phase22Error::Contract(format!(
                "invalid or repeated plan key at sequence {}",
                attempt.sequence
            )));
        }
        *scanner_counts.entry(&attempt.scanner).or_default() += 1;
    }
    if scanner_counts.get("opengrep") != Some(&112)
        || scanner_counts.get("semgrep-ce") != Some(&112)
    {
        return Err(Phase22Error::Contract(format!(
            "scanner plan counts drift: {scanner_counts:?}"
        )));
    }
    Ok(())
}

/// Load and validate the frozen plan.
pub(crate) fn load_plan(root: &Path) -> Result<ExecutionPlan, Phase22Error> {
    let plan: ExecutionPlan = serde_json::from_slice(&fs::read(root.join(PLAN_PATH))?)?;
    validate_plan(&plan)?;
    Ok(plan)
}

fn contract_value_with_implementation(
    root: &Path,
    plan_hash: &str,
    implementation_sha256: &str,
) -> Result<Value, Phase22Error> {
    Ok(json!({
        "schema_version": "secure-bench-phase22-execution-contract-v1",
        "study": "post-open recovery study",
        "methodological_classification": {
            "blind_holdout": false,
            "one_shot_restored": false,
            "retroactive_phase20_correction": false,
            "overall_three_scanner_ranking": false,
            "cross_lane_metric_merging": false,
        },
        "base": {
            "phase19_commit": PHASE19,
            "phase20_commit": PHASE20,
            "phase21_commit": PHASE21,
            "phase20_subtree": PHASE20_TREE,
            "phase21_corrected_contract_sha256": PHASE21_CONTRACT_SHA256,
        },
        "frozen_inputs": {
            "manifest_sha256": "c035f9de14e2a1cb7c65562f9a643f0eefafc682d23c90e520770c7183068cb6",
            "aggregate_corpus_sha256": CORPUS_SHA256,
            "corpus_git_tree": CORPUS_GIT_TREE,
            "contract_merkle_root": MERKLE_ROOT,
            "ruleset_sha256": RULESET_SHA256,
            "ruleset_path": "phase19/rules/capability-normalized-v1.yml",
            "phase20_opengrep_adapter_sha256": OPENGREP_ADAPTER_SHA256,
            "phase20_semgrep_adapter_sha256": SEMGREP_ADAPTER_SHA256,
            "phase20_scoring_methodology_sha256": PHASE20_SCORING_SHA256,
            "corpus_open_during_prepare": false,
        },
        "plan": {
            "path": PLAN_PATH,
            "sha256": plan_hash,
            "attempts": 224,
            "opengrep_attempts": 112,
            "semgrep_attempts": 112,
            "secure_engine_attempts": 0,
            "retries": 0,
            "order": "opengrep-lexical-cases-then-semgrep-ce-lexical-cases",
        },
        "scanners": [
            {"id":"opengrep","version":"1.22.0","lane":"capability-normalized","sha256":"45bcd58440e397ed52c50e953ccf5948909ea77087c9186fc7d277216f62e319"},
            {"id":"semgrep-ce","version":"1.170.0","engine":"OSS","lane":"capability-normalized","wheel_sha256":"09a7e8eeff5e2549161124957184f3566f484370aa6127e425897cef725eb99b","wheel_closure_sha256":"5371b438dc6e3c5529794b21c668057164f52fa1375e0e91ee6c8f241fb74181"},
        ],
        "sandbox": {
            "profile": "phase21-null-device-v1",
            "network": false,
            "new_pid_namespace": true,
            "fresh_proc": true,
            "read_only_root": true,
            "devices": ["/dev/null"],
            "null_semantics": "character-1:3-mode-0666-eof-read-discard-write",
            "masked_paths": ["/home","/root","/run/user","/var/tmp"],
            "environment": fixed_environment(),
            "address_space_bytes": 4294967296_u64,
            "process_limit": 64,
            "timeout_ms": 120000,
            "max_raw_output_bytes": 10485760,
        },
        "process_policy": {
            "zero_exit_valid_zero_or_findings": "completed",
            "one_exit_valid_findings": "completed",
            "timeout": "timeout-no-retry",
            "crash": "failed-no-retry",
            "empty_output": "unavailable-no-retry",
            "malformed_json": "malformed-no-retry",
            "adapter_error": "failed-no-retry",
            "missing_values_imputed": false,
        },
        "scoring": {
            "eligible_lanes": ["opengrep/capability-normalized","semgrep-ce/capability-normalized"],
            "metrics": ["tp","fp","tn","fn","precision","recall","specificity","f1","balanced_accuracy"],
            "dimensions": ["case","pair","family","framework","source_format","topology","adversarial_variant","classification"],
            "paired_comparison": true,
            "operational_quality_performance_separated": true,
            "native_metrics_combined": false,
        },
        "implementation_sha256": implementation_sha256,
        "methodology_sha256": sha256_file(&root.join("phase22/METHODOLOGY.md"))?,
    }))
}

fn contract_value(root: &Path, plan_hash: &str) -> Result<Value, Phase22Error> {
    contract_value_with_implementation(root, plan_hash, &implementation_digest(root)?)
}

pub(crate) fn execution_implementation_digest(root: &Path) -> Result<String, Phase22Error> {
    let contract: Value = serde_json::from_slice(&fs::read(root.join(CONTRACT_PATH))?)?;
    let digest = contract
        .get("implementation_sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            Phase22Error::Contract("contract has no implementation digest".to_owned())
        })?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Phase22Error::Contract(
            "contract implementation digest is malformed".to_owned(),
        ));
    }
    Ok(digest.to_owned())
}

fn verify_post_open_repair(
    root: &Path,
    execution_digest: &str,
    current_digest: &str,
) -> Result<(), Phase22Error> {
    let repair: Value =
        serde_json::from_slice(&fs::read(root.join("phase22/output/verifier-repair.json"))?)?;
    if repair.get("schema_version").and_then(Value::as_str)
        != Some("secure-bench-phase22-verifier-repair-v1")
        || repair.get("state").and_then(Value::as_str)
            != Some("post-open-scanner-free-verifier-repair")
        || repair
            .get("execution_implementation_sha256")
            .and_then(Value::as_str)
            != Some(execution_digest)
        || repair
            .get("repaired_verifier_implementation_sha256")
            .and_then(Value::as_str)
            != Some(current_digest)
        || repair.get("observations_preserved").and_then(Value::as_u64) != Some(224)
        || repair.get("retries").and_then(Value::as_u64) != Some(0)
        || repair
            .get("scanner_processes_started_by_repair")
            .and_then(Value::as_u64)
            != Some(0)
        || repair.get("ledger_sha256").and_then(Value::as_str)
            != Some(sha256_file(&root.join("phase22/output/ledger.jsonl"))?.as_str())
        || repair
            .get("corpus_opened_marker_sha256")
            .and_then(Value::as_str)
            != Some(sha256_file(&root.join("phase22/output/CORPUS_OPENED.json"))?.as_str())
    {
        return Err(Phase22Error::Verification(
            "post-open verifier repair authorization is invalid".to_owned(),
        ));
    }
    Ok(())
}

/// Freeze the exact opaque 224-attempt plan and execution contract pre-open.
pub fn prepare(root: &Path) -> Result<Value, Phase22Error> {
    let config = root.join("phase22/config");
    if config.exists() || root.join(PREFLIGHT).exists() || root.join("phase22/output").exists() {
        return Err(Phase22Error::Contract(
            "Phase 22 lifecycle artifacts already exist".to_owned(),
        ));
    }
    let case_ids = phase20_case_ids(root)?;
    let mut attempts = Vec::with_capacity(224);
    for scanner in ["opengrep", "semgrep-ce"] {
        for case_id in &case_ids {
            attempts.push(PlanAttempt {
                sequence: u64::try_from(attempts.len() + 1).unwrap_or(u64::MAX),
                scanner: scanner.to_owned(),
                lane: "capability-normalized".to_owned(),
                case_id: case_id.clone(),
            });
        }
    }
    let plan = ExecutionPlan {
        schema_version: "secure-bench-phase22-execution-plan-v1".to_owned(),
        study: "post-open recovery study".to_owned(),
        total_attempts: 224,
        retries: 0,
        secure_engine_attempts: 0,
        attempts,
    };
    validate_plan(&plan)?;
    fs::create_dir_all(&config)?;
    let plan_bytes = canonical_json(&plan)?;
    write_atomic(&root.join(PLAN_PATH), &plan_bytes)?;
    let plan_hash = sha256(&plan_bytes);
    let contract = contract_value(root, &plan_hash)?;
    write_atomic(&root.join(CONTRACT_PATH), &canonical_json(&contract)?)?;
    Ok(json!({
        "state": "frozen-before-corpus-opening",
        "study": "post-open recovery study",
        "plan_sha256": plan_hash,
        "contract_sha256": sha256_file(&root.join(CONTRACT_PATH))?,
        "attempts": 224,
        "retries": 0,
        "secure_engine_attempts": 0,
        "corpus_opened": false,
    }))
}

fn verify_contract(root: &Path) -> Result<(ExecutionPlan, Value), Phase22Error> {
    verify_frozen_inputs(root)?;
    let plan = load_plan(root)?;
    let plan_hash = sha256_file(&root.join(PLAN_PATH))?;
    let actual: Value = serde_json::from_slice(&fs::read(root.join(CONTRACT_PATH))?)?;
    let execution_digest = execution_implementation_digest(root)?;
    let current_digest = implementation_digest(root)?;
    if execution_digest != current_digest {
        verify_post_open_repair(root, &execution_digest, &current_digest)?;
    }
    let expected = contract_value_with_implementation(root, &plan_hash, &execution_digest)?;
    if actual != expected {
        return Err(Phase22Error::Contract(
            "execution contract does not match current frozen inputs and implementation".to_owned(),
        ));
    }
    Ok((plan, actual))
}

fn synthetic_scanner(
    root: &Path,
    output: &Path,
    scanner: Scanner,
    fixture_name: &str,
    expected_findings: usize,
) -> Result<Value, Phase22Error> {
    let id = format!("{}-{fixture_name}", scanner.id());
    let directory = output.join(&id);
    fs::create_dir_all(&directory)?;
    let fixture = root.join(format!("phase21/fixtures/{fixture_name}"));
    let rule = root.join("phase21/rules/synthetic-eval-v1.yml");
    let mut arguments = scanner_sandbox(scanner, true, &fixture, &rule, &directory);
    arguments.extend([
        "--".to_owned(),
        "/usr/bin/prlimit".to_owned(),
        "--as=4294967296".to_owned(),
        "--nproc=64".to_owned(),
        "--".to_owned(),
    ]);
    arguments.extend(scanner_command(scanner));
    let evidence = run_process(&arguments, &directory, Duration::from_secs(30))?;
    let raw = evidence
        .raw
        .as_deref()
        .ok_or_else(|| Phase22Error::Preflight(format!("synthetic {id} emitted no raw output")))?;
    let value: Value = serde_json::from_slice(raw)?;
    let findings = value
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(|| Phase22Error::Preflight(format!("synthetic {id} has no results")))?;
    let expected_exit = i32::from(expected_findings > 0);
    if evidence.exit_code != Some(expected_exit)
        || value.get("version").and_then(Value::as_str) != Some(scanner.version())
        || value
            .get("errors")
            .and_then(Value::as_array)
            .is_none_or(|errors| !errors.is_empty())
        || findings.len() != expected_findings
        || findings.iter().any(|finding| {
            finding.get("check_id").and_then(Value::as_str)
                != Some("secure-bench.phase21.synthetic-eval")
        })
        || (scanner == Scanner::Semgrep
            && value.get("engine_requested").and_then(Value::as_str) != Some("OSS"))
    {
        return Err(Phase22Error::Preflight(format!(
            "synthetic scanner qualification failed: {id}"
        )));
    }
    Ok(json!({
        "id": id,
        "scanner": scanner.id(),
        "version": scanner.version(),
        "fixture": fixture_name,
        "exit_code": evidence.exit_code,
        "findings": findings.len(),
        "duration_ms": evidence.duration_ms,
        "command_sha256": sha256(&canonical_json(&evidence.command)?),
        "stdout_sha256": sha256(&evidence.stdout),
        "stderr_sha256": sha256(&evidence.stderr),
        "raw_sha256": sha256(raw),
        "passed": true,
    }))
}

fn synthetic_probe(root: &Path, output: &Path) -> Result<Value, Phase22Error> {
    let directory = output.join("sandbox-probe");
    fs::create_dir_all(&directory)?;
    let mut arguments = base_arguments(true);
    arguments.extend([
        "--ro-bind".to_owned(),
        root.join("phase21/canaries/sandbox_probe.py")
            .to_string_lossy()
            .into_owned(),
        "/tmp/probe.py".to_owned(),
        "--clearenv".to_owned(),
    ]);
    for entry in fixed_environment() {
        let (name, value) = entry.split_once('=').unwrap_or((entry.as_str(), ""));
        arguments.extend(["--setenv".to_owned(), name.to_owned(), value.to_owned()]);
    }
    arguments.extend([
        "--".to_owned(),
        "/usr/bin/python3.14".to_owned(),
        "/tmp/probe.py".to_owned(),
    ]);
    let evidence = run_process(&arguments, &directory, Duration::from_secs(5))?;
    let value: Value = serde_json::from_slice(&evidence.stdout)?;
    let no_default_route = value
        .get("network_route")
        .and_then(Value::as_str)
        .is_some_and(|route| route.lines().count() <= 1);
    if evidence.exit_code != Some(0)
        || value.pointer("/null/type").and_then(Value::as_str) != Some("character")
        || value.pointer("/null/major").and_then(Value::as_u64) != Some(1)
        || value.pointer("/null/minor").and_then(Value::as_u64) != Some(3)
        || value.pointer("/null/read_bytes").and_then(Value::as_u64) != Some(0)
        || value.pointer("/null/write_bytes").and_then(Value::as_u64) != Some(1)
        || value
            .get("dev_entries")
            .and_then(Value::as_array)
            .is_none_or(|entries| entries != &[Value::String("null".to_owned())])
        || value.get("network_connect_errno").and_then(Value::as_u64) != Some(101)
        || value.get("outside_write_errno").and_then(Value::as_u64) != Some(30)
        || !no_default_route
        || [
            "home_entries",
            "root_entries",
            "run_user_entries",
            "var_tmp_entries",
        ]
        .iter()
        .any(|field| {
            value
                .get(field)
                .and_then(Value::as_array)
                .is_none_or(|v| !v.is_empty())
        })
    {
        return Err(Phase22Error::Preflight(
            "corrected sandbox containment probe failed".to_owned(),
        ));
    }
    Ok(json!({
        "id": "sandbox-probe",
        "passed": true,
        "stdout_sha256": sha256(&evidence.stdout),
        "stderr_sha256": sha256(&evidence.stderr),
        "null": value.get("null"),
        "dev_entries": value.get("dev_entries"),
        "network_connect_errno": value.get("network_connect_errno"),
        "outside_write_errno": value.get("outside_write_errno"),
        "no_default_route": no_default_route,
        "masked_credentials": true,
        "fresh_proc": true,
    }))
}

fn write_sums(path: &Path) -> Result<(), Phase22Error> {
    let sums = path.join("SHA256SUMS");
    let mut files = Vec::new();
    collect_files(path, &mut files)?;
    let mut content = String::new();
    for file in files {
        if file == sums {
            continue;
        }
        let relative = file.strip_prefix(path).map_err(|_| {
            Phase22Error::Preflight(format!("preflight file escaped: {}", file.display()))
        })?;
        content.push_str(&format!(
            "{}  {}\n",
            sha256_file(&file)?,
            relative.to_string_lossy()
        ));
    }
    write_atomic(&sums, content.as_bytes())
}

/// Execute all pre-open gates and bounded synthetic scanner canaries.
pub fn preflight(root: &Path) -> Result<Value, Phase22Error> {
    let preflight = root.join(PREFLIGHT);
    if preflight.exists() || root.join("phase22/output").exists() {
        return Err(Phase22Error::Contract(
            "preflight or output already exists".to_owned(),
        ));
    }
    let (plan, contract) = verify_contract(root)?;
    if git(root, &["rev-parse", "main"])? != PHASE21
        || git(root, &["branch", "--show-current"])?
            != "codex/phase-22-post-open-normalized-recovery"
        || git(root, &["rev-parse", "HEAD"])? != PHASE21
    {
        return Err(Phase22Error::Preflight(
            "Phase 22 did not start from fast-forwarded Phase 21 main".to_owned(),
        ));
    }
    let phase19 = commit_audit(root, PHASE19, "aee2c7094983cfb8bdc16cf59b1962add82ca1db")?;
    let phase20 = commit_audit(root, PHASE20, PHASE19)?;
    let phase21 = commit_audit(root, PHASE21, PHASE20)?;
    let (phase20_tree, corpus_tree) = verify_frozen_inputs(root)?;
    let phase21_verification = verify_phase21(root)
        .map_err(|error| Phase22Error::Preflight(format!("Phase 21 verifier: {error}")))?;
    let tools = validate_tools(root)
        .map_err(|error| Phase22Error::Preflight(format!("tool closure: {error}")))?;
    let ids = phase20_case_ids(root)?;
    let planned_ids = plan
        .attempts
        .iter()
        .map(|attempt| attempt.case_id.as_str())
        .collect::<BTreeSet<_>>();
    if planned_ids != ids.iter().map(String::as_str).collect::<BTreeSet<_>>() {
        return Err(Phase22Error::Preflight(
            "opaque plan IDs drift from immutable Phase 20 results".to_owned(),
        ));
    }
    fs::create_dir_all(&preflight)?;
    let synthetic = preflight.join("synthetic");
    fs::create_dir_all(&synthetic)?;
    let probe = synthetic_probe(root, &synthetic)?;
    let mut scanner_canaries = Vec::new();
    for scanner in [Scanner::OpenGrep, Scanner::Semgrep] {
        scanner_canaries.push(synthetic_scanner(root, &synthetic, scanner, "clean", 0)?);
        scanner_canaries.push(synthetic_scanner(root, &synthetic, scanner, "finding", 1)?);
    }
    let synthetic_summary = json!({
        "schema_version": "secure-bench-phase22-synthetic-preflight-v1",
        "study_attempts": 0,
        "synthetic_scanner_processes": 4,
        "retries": 0,
        "probe": probe,
        "scanner_canaries": scanner_canaries,
        "all_passed": true,
        "corpus_opened": false,
    });
    write_atomic(
        &preflight.join("synthetic-qualification.json"),
        &canonical_json(&synthetic_summary)?,
    )?;
    let audit = json!({
        "schema_version": "secure-bench-phase22-preflight-v1",
        "state": "passed-before-corpus-opening",
        "study": "post-open recovery study",
        "phase19": phase19,
        "phase20": phase20,
        "phase21": phase21,
        "phase20_subtree": phase20_tree,
        "corpus_git_tree": corpus_tree,
        "phase21_corrected_contract_sha256": PHASE21_CONTRACT_SHA256,
        "phase21_independent_verification": phase21_verification,
        "tools": tools,
        "ruleset_sha256": RULESET_SHA256,
        "aggregate_corpus_sha256": CORPUS_SHA256,
        "contract_merkle_root": MERKLE_ROOT,
        "execution_plan_sha256": sha256_file(&root.join(PLAN_PATH))?,
        "execution_contract_sha256": sha256_file(&root.join(CONTRACT_PATH))?,
        "implementation_sha256": implementation_digest(root)?,
        "planned_recovery_attempts": 224,
        "retries": 0,
        "secure_engine_attempts": 0,
        "recovery_attempts_before_opening": 0,
        "synthetic_scanner_processes": 4,
        "network_ai_telemetry_credentials": "forbidden",
        "corpus_opened": false,
        "contract": contract,
    });
    write_atomic(&preflight.join("preflight.json"), &canonical_json(&audit)?)?;
    write_sums(&preflight)?;
    Ok(audit)
}

fn verify_sums(path: &Path) -> Result<(), Phase22Error> {
    let content = fs::read_to_string(path.join("SHA256SUMS"))?;
    let mut seen = BTreeSet::new();
    for line in content.lines() {
        let (expected, relative) = line
            .split_once("  ")
            .ok_or_else(|| Phase22Error::Preflight("malformed preflight SHA256SUMS".to_owned()))?;
        let relative = safe_relative(relative)?;
        if !seen.insert(relative.to_path_buf()) || sha256_file(&path.join(relative))? != expected {
            return Err(Phase22Error::Preflight(format!(
                "preflight hash drift: {}",
                relative.display()
            )));
        }
    }
    if seen.is_empty() {
        return Err(Phase22Error::Preflight(
            "preflight SHA256SUMS is empty".to_owned(),
        ));
    }
    let sums = path.join("SHA256SUMS");
    let mut files = Vec::new();
    collect_files(path, &mut files)?;
    let actual = files
        .into_iter()
        .filter(|file| file != &sums)
        .map(|file| {
            file.strip_prefix(path).map(Path::to_path_buf).map_err(|_| {
                Phase22Error::Preflight(format!("preflight file escaped: {}", file.display()))
            })
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if seen != actual {
        return Err(Phase22Error::Preflight(
            "preflight SHA256SUMS does not enumerate every artifact exactly once".to_owned(),
        ));
    }
    Ok(())
}

/// Verify the saved preflight without executing synthetic or recovery scanners.
pub(crate) fn verify_saved_preflight(root: &Path) -> Result<(), Phase22Error> {
    let (_plan, _contract) = verify_contract(root)?;
    let preflight = root.join(PREFLIGHT);
    verify_sums(&preflight)?;
    let value: Value = serde_json::from_slice(&fs::read(preflight.join("preflight.json"))?)?;
    let synthetic: Value =
        serde_json::from_slice(&fs::read(preflight.join("synthetic-qualification.json"))?)?;
    if value.get("state").and_then(Value::as_str) != Some("passed-before-corpus-opening")
        || value
            .get("planned_recovery_attempts")
            .and_then(Value::as_u64)
            != Some(224)
        || value
            .get("recovery_attempts_before_opening")
            .and_then(Value::as_u64)
            != Some(0)
        || value.get("corpus_opened").and_then(Value::as_bool) != Some(false)
        || value.get("retries").and_then(Value::as_u64) != Some(0)
        || value.get("secure_engine_attempts").and_then(Value::as_u64) != Some(0)
        || value
            .get("synthetic_scanner_processes")
            .and_then(Value::as_u64)
            != Some(4)
        || synthetic.get("all_passed").and_then(Value::as_bool) != Some(true)
        || synthetic.get("corpus_opened").and_then(Value::as_bool) != Some(false)
        || synthetic.get("study_attempts").and_then(Value::as_u64) != Some(0)
        || synthetic.get("retries").and_then(Value::as_u64) != Some(0)
        || synthetic
            .get("synthetic_scanner_processes")
            .and_then(Value::as_u64)
            != Some(4)
        || synthetic
            .get("scanner_canaries")
            .and_then(Value::as_array)
            .is_none_or(|canaries| {
                canaries.len() != 4
                    || canaries
                        .iter()
                        .any(|canary| canary.get("passed").and_then(Value::as_bool) != Some(true))
            })
        || synthetic.pointer("/probe/passed").and_then(Value::as_bool) != Some(true)
    {
        return Err(Phase22Error::Preflight(
            "saved preflight is incomplete or not pre-open".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repository_root() -> Result<std::path::PathBuf, std::io::Error> {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .canonicalize()
    }

    #[test]
    fn frozen_inputs_match_the_phase21_worktree() -> Result<(), Box<dyn std::error::Error>> {
        let (phase20_tree, corpus_tree) = verify_frozen_inputs(&repository_root()?)?;
        assert_eq!(phase20_tree, PHASE20_TREE);
        assert_eq!(corpus_tree, CORPUS_GIT_TREE);
        Ok(())
    }

    #[test]
    fn plan_requires_exact_population() {
        let mut attempts = Vec::new();
        for scanner in ["opengrep", "semgrep-ce"] {
            for index in 1..=112 {
                attempts.push(PlanAttempt {
                    sequence: u64::try_from(attempts.len() + 1).unwrap_or(u64::MAX),
                    scanner: scanner.to_owned(),
                    lane: "capability-normalized".to_owned(),
                    case_id: format!("case-p19-{index:04}"),
                });
            }
        }
        let plan = ExecutionPlan {
            schema_version: "secure-bench-phase22-execution-plan-v1".to_owned(),
            study: "post-open recovery study".to_owned(),
            total_attempts: 224,
            retries: 0,
            secure_engine_attempts: 0,
            attempts,
        };
        assert!(validate_plan(&plan).is_ok());

        let mut repeated = plan.clone();
        repeated.attempts[1].case_id = repeated.attempts[0].case_id.clone();
        assert!(validate_plan(&repeated).is_err());

        let mut wrong_lane = plan.clone();
        wrong_lane.attempts[0].lane = "native".to_owned();
        assert!(validate_plan(&wrong_lane).is_err());

        let mut secure_engine = plan;
        secure_engine.attempts[0].scanner = "secure-engine".to_owned();
        assert!(validate_plan(&secure_engine).is_err());
    }

    #[test]
    fn preflight_sums_require_exact_artifact_enumeration() -> Result<(), Box<dyn std::error::Error>>
    {
        let preflight = tempfile::tempdir()?;
        fs::write(preflight.path().join("one.json"), b"one\n")?;
        let one = sha256_file(&preflight.path().join("one.json"))?;
        fs::write(
            preflight.path().join("SHA256SUMS"),
            format!("{one}  one.json\n"),
        )?;
        assert!(verify_sums(preflight.path()).is_ok());

        fs::write(preflight.path().join("two.json"), b"two\n")?;
        assert!(verify_sums(preflight.path()).is_err());

        let two = sha256_file(&preflight.path().join("two.json"))?;
        fs::write(
            preflight.path().join("SHA256SUMS"),
            format!("{one}  one.json\n{two}  two.json\n"),
        )?;
        assert!(verify_sums(preflight.path()).is_ok());

        fs::write(
            preflight.path().join("SHA256SUMS"),
            format!("{one}  one.json\n{one}  one.json\n{two}  two.json\n"),
        )?;
        assert!(verify_sums(preflight.path()).is_err());
        Ok(())
    }
}
