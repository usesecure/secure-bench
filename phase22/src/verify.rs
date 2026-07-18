use crate::contract::{execution_implementation_digest, load_plan, verify_saved_preflight};
use crate::independent_score::compute as independent_compute;
use crate::model::{AttemptState, CaseSpec, LedgerEntry, Observation, Results};
use crate::runner::load_cases_post_open;
use crate::{
    Phase22Error, canonical_json, collect_files, implementation_digest, safe_relative, sha256,
    sha256_file, write_atomic,
};
use secure_bench_phase21::sandbox::{Scanner, fixed_environment, scanner_command, scanner_sandbox};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::process::Command;

const OUTPUT: &str = "phase22/output";
const PHASE20_TREE: &str = "05cd69281777263a4f9286069767d870014cab52";
const PHASE21_CONTRACT_SHA256: &str =
    "186011766acc155a66c4a965094baf8fca335b56338363610a4d713d41876cae";
const RULESET: &str = "phase19/rules/capability-normalized-v1.yml";

/// Scanner-free independent verification report.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationReport {
    /// Verifier schema identity.
    pub schema_version: String,
    /// Overall state.
    pub state: String,
    /// Required study label.
    pub study: String,
    /// Recovery observations independently verified.
    pub observations_verified: u64,
    /// Retry count verified.
    pub retries_verified: u64,
    /// Secure Engine processes verified.
    pub secure_engine_attempts_verified: u64,
    /// Final execution-ledger head.
    pub ledger_head: String,
    /// Recomputed checks.
    pub checks: Vec<String>,
    /// Whether verification starts scanners.
    pub scanner_execution: bool,
}

fn scanner(value: &str) -> Result<Scanner, Phase22Error> {
    match value {
        "opengrep" => Ok(Scanner::OpenGrep),
        "semgrep-ce" => Ok(Scanner::Semgrep),
        _ => Err(Phase22Error::Verification(format!(
            "ineligible scanner in observation: {value}"
        ))),
    }
}

fn independent_source(fixture: &Path, value: &str) -> Result<(String, Vec<u8>), Phase22Error> {
    let relative = value.strip_prefix("./").unwrap_or(value);
    if relative.is_empty()
        || relative.starts_with('/')
        || relative.contains('\\')
        || relative
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
    {
        return Err(Phase22Error::Verification(format!(
            "independent adapter rejected path `{value}`"
        )));
    }
    let root = fixture.canonicalize()?;
    let mut candidate = root.clone();
    for part in relative.split('/') {
        candidate.push(part);
        if fs::symlink_metadata(&candidate)?.file_type().is_symlink() {
            return Err(Phase22Error::Verification(format!(
                "independent adapter found symlink in `{relative}`"
            )));
        }
    }
    let canonical = candidate.canonicalize()?;
    if !canonical.starts_with(root) || !canonical.is_file() {
        return Err(Phase22Error::Verification(format!(
            "independent adapter path escaped `{relative}`"
        )));
    }
    Ok((relative.to_owned(), fs::read(canonical)?))
}

fn independent_position(value: &Value, side: &str, field: &str) -> Result<u64, Phase22Error> {
    value
        .pointer(&format!("/{side}/{field}"))
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            Phase22Error::Verification(format!("independent adapter found no {side}.{field}"))
        })
}

fn independent_coordinate(file: &[u8], line: u64, column: u64) -> Option<u64> {
    let line = usize::try_from(line).ok()?;
    let column = usize::try_from(column).ok()?;
    let starts = std::iter::once(0_usize)
        .chain(
            file.iter()
                .enumerate()
                .filter(|(_, byte)| **byte == b'\n')
                .map(|(index, _)| index + 1),
        )
        .collect::<Vec<_>>();
    let start = *starts.get(line.checked_sub(1)?)?;
    let end = file[start..]
        .iter()
        .position(|byte| *byte == b'\n')
        .map_or(file.len(), |relative| start + relative);
    let offset = start.checked_add(column.checked_sub(1)?)?;
    (offset <= end)
        .then(|| u64::try_from(offset).ok())
        .flatten()
}

fn independent_adapt(scanner: Scanner, fixture: &Path, raw: &[u8]) -> Result<u64, Phase22Error> {
    if raw.len() > 10 * 1024 * 1024 {
        return Err(Phase22Error::Verification(
            "independent adapter raw output limit exceeded".to_owned(),
        ));
    }
    let value: Value = serde_json::from_slice(raw)?;
    if value.get("version").and_then(Value::as_str) != Some(scanner.version())
        || value
            .get("errors")
            .and_then(Value::as_array)
            .is_none_or(|errors| !errors.is_empty())
    {
        return Err(Phase22Error::Verification(
            "independent adapter rejected scanner identity/errors".to_owned(),
        ));
    }
    let allowed = [
        "secure-bench.phase19.SE1001.resource-authorization",
        "secure-bench.phase19.SE1002.command-injection",
        "secure-bench.phase19.SE1003.dynamic-code",
        "secure-bench.phase19.SE1004.path-traversal",
        "secure-bench.phase19.SE1005.outbound-request",
        "secure-bench.phase19.SE1006.open-redirect",
        "secure-bench.phase19.SE1007.sql-injection",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let scanned_paths = if scanner == Scanner::Semgrep {
        if value.get("engine_requested").and_then(Value::as_str) != Some("OSS")
            || value
                .get("skipped_rules")
                .and_then(Value::as_array)
                .is_none_or(|rules| !rules.is_empty())
        {
            return Err(Phase22Error::Verification(
                "independent adapter rejected Semgrep CE provenance".to_owned(),
            ));
        }
        let paths = value
            .pointer("/paths/scanned")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                Phase22Error::Verification("Semgrep paths.scanned is absent".to_owned())
            })?;
        let mut normalized = BTreeSet::new();
        for path in paths {
            let path = path.as_str().ok_or_else(|| {
                Phase22Error::Verification("Semgrep scanned path is not text".to_owned())
            })?;
            if !normalized.insert(independent_source(fixture, path)?.0) {
                return Err(Phase22Error::Verification(
                    "Semgrep scanned path repeats".to_owned(),
                ));
            }
        }
        Some(normalized)
    } else {
        if value
            .get("skipped_rules")
            .is_some_and(|rules| rules.as_array().is_none_or(|rules| !rules.is_empty()))
        {
            return Err(Phase22Error::Verification(
                "OpenGrep skipped rules are not empty".to_owned(),
            ));
        }
        None
    };
    let findings = value
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(|| Phase22Error::Verification("results array is absent".to_owned()))?;
    for finding in findings {
        let rule = finding
            .get("check_id")
            .and_then(Value::as_str)
            .ok_or_else(|| Phase22Error::Verification("finding has no rule ID".to_owned()))?;
        if !allowed.contains(rule) {
            return Err(Phase22Error::Verification(format!(
                "independent adapter rejected rule `{rule}`"
            )));
        }
        if scanner == Scanner::Semgrep
            && finding
                .pointer("/extra/engine_kind")
                .and_then(Value::as_str)
                != Some("OSS")
        {
            return Err(Phase22Error::Verification(
                "Semgrep finding lacks OSS provenance".to_owned(),
            ));
        }
        let path = finding
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| Phase22Error::Verification("finding has no path".to_owned()))?;
        let (path, file) = independent_source(fixture, path)?;
        if scanned_paths
            .as_ref()
            .is_some_and(|paths| !paths.contains(&path))
        {
            return Err(Phase22Error::Verification(
                "finding path absent from Semgrep scanned paths".to_owned(),
            ));
        }
        let start_line = independent_position(finding, "start", "line")?;
        let start_col = independent_position(finding, "start", "col")?;
        let end_line = independent_position(finding, "end", "line")?;
        let end_col = independent_position(finding, "end", "col")?;
        if start_line == 0
            || start_col == 0
            || end_line == 0
            || end_col == 0
            || (start_line, start_col) >= (end_line, end_col)
        {
            return Err(Phase22Error::Verification(format!(
                "independent adapter rejected span for {path}"
            )));
        }
        let expected_start =
            independent_coordinate(&file, start_line, start_col).ok_or_else(|| {
                Phase22Error::Verification(format!(
                    "independent adapter rejected start coordinate for {path}"
                ))
            })?;
        let expected_end = independent_coordinate(&file, end_line, end_col).ok_or_else(|| {
            Phase22Error::Verification(format!(
                "independent adapter rejected end coordinate for {path}"
            ))
        })?;
        let start_offset = finding.pointer("/start/offset").and_then(Value::as_u64);
        let end_offset = finding.pointer("/end/offset").and_then(Value::as_u64);
        match (start_offset, end_offset) {
            (Some(start), Some(end))
                if start < end
                    && end <= u64::try_from(file.len()).unwrap_or(u64::MAX)
                    && (scanner != Scanner::Semgrep
                        || (start == expected_start && end == expected_end)) => {}
            (None, None) => {}
            _ => {
                return Err(Phase22Error::Verification(format!(
                    "independent adapter rejected offsets for {path}"
                )));
            }
        }
    }
    Ok(u64::try_from(findings.len()).unwrap_or(u64::MAX))
}

fn read_observations(root: &Path) -> Result<Vec<Observation>, Phase22Error> {
    let attempts = root.join(OUTPUT).join("attempts");
    let mut directories = fs::read_dir(&attempts)?.collect::<Result<Vec<_>, _>>()?;
    directories.sort_by_key(std::fs::DirEntry::file_name);
    let mut observations: Vec<Observation> = Vec::new();
    for directory in directories {
        if !directory.file_type()?.is_dir() {
            return Err(Phase22Error::Verification(format!(
                "non-directory in attempts: {}",
                directory.path().display()
            )));
        }
        let path = directory.path().join("observation.json");
        if !path.is_file() {
            return Err(Phase22Error::Verification(format!(
                "attempt has no observation: {}",
                directory.path().display()
            )));
        }
        observations.push(serde_json::from_slice(&fs::read(path)?)?);
    }
    observations.sort_by_key(|observation| observation.sequence);
    Ok(observations)
}

fn attempt_directory(observation: &Observation) -> String {
    format!(
        "phase22/output/attempts/{:03}-{}-{}",
        observation.sequence, observation.scanner, observation.case_id
    )
}

fn normalize_mount_sources(command: &[String]) -> Result<Vec<String>, Phase22Error> {
    let mut normalized = command.to_vec();
    for (target, anchor, required_flag) in [
        ("/tmp/fixture", "phase19/holdout/cases/", "--ro-bind"),
        (
            "/tmp/rules/rule.yml",
            "phase19/rules/capability-normalized-v1.yml",
            "--ro-bind",
        ),
        ("/tmp/run", "phase22/output/attempts/", "--bind"),
    ] {
        let index = normalized
            .windows(3)
            .position(|window| window[0] == required_flag && window[2] == target)
            .map(|index| index + 2)
            .ok_or_else(|| {
                Phase22Error::Verification(format!("command omits mount target {target}"))
            })?;
        if index < 2 || normalized[index - 2] != required_flag {
            return Err(Phase22Error::Verification(format!(
                "command has invalid source for mount target {target}"
            )));
        }
        let source = normalized[index - 1]
            .strip_prefix("./")
            .unwrap_or(&normalized[index - 1]);
        let anchor_start = source.rfind(anchor).ok_or_else(|| {
            Phase22Error::Verification(format!(
                "command source for {target} does not contain frozen anchor {anchor}"
            ))
        })?;
        if anchor_start > 0 && source.as_bytes()[anchor_start - 1] != b'/' {
            return Err(Phase22Error::Verification(format!(
                "command source for {target} has an ambiguous frozen anchor"
            )));
        }
        let suffix = &source[anchor_start..];
        safe_relative(suffix).map_err(|_| {
            Phase22Error::Verification(format!(
                "command source for {target} is not a safe frozen path"
            ))
        })?;
        normalized[index - 1] = format!("{{repository}}/{suffix}");
    }
    Ok(normalized)
}

fn verify_attempt_files(root: &Path, directory: &str, has_raw: bool) -> Result<(), Phase22Error> {
    let actual = fs::read_dir(root.join(safe_relative(directory)?))?
        .map(|entry| {
            entry.map_err(Phase22Error::from).and_then(|entry| {
                if !entry.file_type()?.is_file() {
                    return Err(Phase22Error::Verification(format!(
                        "attempt contains non-file evidence: {}",
                        entry.path().display()
                    )));
                }
                entry.file_name().into_string().map_err(|_| {
                    Phase22Error::Verification(
                        "attempt contains a non-Unicode evidence name".to_owned(),
                    )
                })
            })
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let mut expected = BTreeSet::from([
        "observation.json".to_owned(),
        "stderr.bin".to_owned(),
        "stdout.bin".to_owned(),
    ]);
    if has_raw {
        expected.insert("raw.json".to_owned());
    }
    if actual != expected {
        return Err(Phase22Error::Verification(format!(
            "attempt evidence set drift in {directory}: {actual:?}"
        )));
    }
    Ok(())
}

fn verify_observation(
    root: &Path,
    case: &CaseSpec,
    observation: &Observation,
) -> Result<(), Phase22Error> {
    let scanner = scanner(&observation.scanner)?;
    let directory = attempt_directory(observation);
    let expected_stdout = format!("{directory}/stdout.bin");
    let expected_stderr = format!("{directory}/stderr.bin");
    let expected_raw = format!("{directory}/raw.json");
    if observation.lane != "capability-normalized"
        || observation.stdout_path != expected_stdout
        || observation.stderr_path != expected_stderr
        || observation
            .raw_output_path
            .as_ref()
            .is_some_and(|path| path != &expected_raw)
        || sha256(&canonical_json(&observation.command)?) != observation.command_sha256
        || observation.environment != fixed_environment()
        || sha256(&canonical_json(&observation.environment)?) != observation.environment_sha256
    {
        return Err(Phase22Error::Verification(format!(
            "observation {} command/environment contract drift",
            observation.sequence
        )));
    }
    let fixture = root.join(safe_relative(&case.fixture_path)?);
    let output = root.join(safe_relative(&directory)?);
    let mut arguments = scanner_sandbox(scanner, true, &fixture, &root.join(RULESET), &output);
    arguments.extend([
        "--".to_owned(),
        "/usr/bin/prlimit".to_owned(),
        "--as=4294967296".to_owned(),
        "--nproc=64".to_owned(),
        "--".to_owned(),
    ]);
    arguments.extend(scanner_command(scanner));
    let expected_command = std::iter::once("/usr/bin/bwrap".to_owned())
        .chain(arguments)
        .collect::<Vec<_>>();
    if normalize_mount_sources(&observation.command)? != normalize_mount_sources(&expected_command)?
    {
        return Err(Phase22Error::Verification(format!(
            "observation {} sandbox command drift",
            observation.sequence
        )));
    }
    let stdout = root.join(safe_relative(&observation.stdout_path)?);
    let stderr = root.join(safe_relative(&observation.stderr_path)?);
    if sha256_file(&stdout)? != observation.stdout_sha256
        || sha256_file(&stderr)? != observation.stderr_sha256
    {
        return Err(Phase22Error::Verification(format!(
            "observation {} stream hash drift",
            observation.sequence
        )));
    }
    let raw = match (
        observation.raw_output_path.as_deref(),
        observation.raw_output_sha256.as_deref(),
    ) {
        (Some(path), Some(expected)) => {
            let bytes = fs::read(root.join(safe_relative(path)?))?;
            if sha256(&bytes) != expected {
                return Err(Phase22Error::Verification(format!(
                    "observation {} raw hash drift",
                    observation.sequence
                )));
            }
            Some(bytes)
        }
        (None, None) => None,
        _ => {
            return Err(Phase22Error::Verification(format!(
                "observation {} raw path/hash mismatch",
                observation.sequence
            )));
        }
    };
    verify_attempt_files(root, &directory, raw.is_some())?;
    let adapted = raw
        .as_deref()
        .map(|bytes| independent_adapt(scanner, &fixture, bytes));
    let (expected_state, expected_decision, expected_count) = if observation.timed_out {
        (AttemptState::Timeout, "timeout", None)
    } else if raw.is_none() {
        (AttemptState::Unavailable, "missing-output", None)
    } else {
        let adapted = adapted.as_ref().ok_or_else(|| {
            Phase22Error::Verification("raw adaptation state is inconsistent".to_owned())
        })?;
        match adapted {
            Ok(count)
                if observation.exit_code == Some(0)
                    || (observation.exit_code == Some(1) && *count > 0) =>
            {
                (
                    AttemptState::Completed,
                    if *count == 0 {
                        "clean-successful-report"
                    } else {
                        "successful-findings-report"
                    },
                    Some(*count),
                )
            }
            Ok(_) => (AttemptState::Failed, "process-policy-failure", None),
            Err(_)
                if raw
                    .as_deref()
                    .is_some_and(|bytes| serde_json::from_slice::<Value>(bytes).is_err()) =>
            {
                (AttemptState::Malformed, "adapter-failure", None)
            }
            Err(_) => (AttemptState::Failed, "adapter-failure", None),
        }
    };
    if observation.state != expected_state
        || observation.process_decision != expected_decision
        || observation.finding_count != expected_count
        || (expected_state == AttemptState::Completed) != observation.failure.is_none()
    {
        return Err(Phase22Error::Verification(format!(
            "observation {} process policy or finding state drift",
            observation.sequence
        )));
    }
    Ok(())
}

fn verify_ledger(root: &Path, observations: &[Observation]) -> Result<String, Phase22Error> {
    let content = fs::read_to_string(root.join(OUTPUT).join("ledger.jsonl"))?;
    let entries = content
        .lines()
        .map(serde_json::from_str::<LedgerEntry>)
        .collect::<Result<Vec<_>, _>>()?;
    if entries.len() != observations.len() {
        return Err(Phase22Error::Verification(
            "ledger and observation cardinality differ".to_owned(),
        ));
    }
    let mut previous = "0".repeat(64);
    for (index, (entry, observation)) in entries.iter().zip(observations).enumerate() {
        let sequence = u64::try_from(index + 1).unwrap_or(u64::MAX);
        let payload = sha256(&canonical_json(observation)?);
        let unsigned = serde_json::json!({
            "schema_version": "secure-bench-phase22-ledger-v1",
            "sequence": sequence,
            "event": "recovery-attempt-completed",
            "payload_sha256": payload,
            "previous_entry_hash": previous,
        });
        let expected_hash = sha256(&canonical_json(&unsigned)?);
        if observation.sequence != sequence
            || entry.sequence != sequence
            || entry.payload_sha256 != payload
            || entry.previous_entry_hash != previous
            || entry.entry_hash != expected_hash
        {
            return Err(Phase22Error::Verification(format!(
                "ledger chain failed at sequence {sequence}"
            )));
        }
        previous = expected_hash;
    }
    Ok(previous)
}

fn git_phase20_tree(root: &Path) -> Result<String, Phase22Error> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "HEAD:phase20"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()?;
    if !output.status.success() {
        return Err(Phase22Error::Verification(
            "cannot resolve Phase 20 subtree".to_owned(),
        ));
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|error| Phase22Error::Verification(error.to_string()))
}

fn state_name(state: &AttemptState) -> &'static str {
    match state {
        AttemptState::Completed => "completed",
        AttemptState::Failed => "failed",
        AttemptState::Timeout => "timeout",
        AttemptState::Malformed => "malformed",
        AttemptState::Unsupported => "unsupported",
        AttemptState::Unavailable => "unavailable",
    }
}

fn independent_strata(results: &Results) -> Value {
    json!({
        "schema_version": "secure-bench-phase22-strata-v1",
        "study": "post-open recovery study",
        "lanes": results.lanes.iter().map(|lane| json!({
            "scanner": lane.scanner,
            "lane": lane.lane,
            "by_family": lane.by_family,
            "by_framework": lane.by_framework,
            "by_source_format": lane.by_source_format,
            "by_topology": lane.by_topology,
            "by_adversarial_variant": lane.by_adversarial_variant,
            "by_classification": lane.by_classification,
        })).collect::<Vec<_>>(),
    })
}

fn independent_failure_analysis(observations: &[Observation]) -> Value {
    let failures = observations
        .iter()
        .filter(|observation| observation.state != AttemptState::Completed)
        .collect::<Vec<_>>();
    let mut by_state = BTreeMap::<&str, u64>::new();
    let mut by_scanner = BTreeMap::<&str, u64>::new();
    for observation in &failures {
        *by_state.entry(state_name(&observation.state)).or_default() += 1;
        *by_scanner.entry(observation.scanner.as_str()).or_default() += 1;
    }
    json!({
        "schema_version": "secure-bench-phase22-failure-analysis-v1",
        "study": "post-open recovery study",
        "non_completed_attempts": failures.len(),
        "by_state": by_state,
        "by_scanner": by_scanner,
        "failures": failures,
        "imputation": false,
        "retries": 0,
    })
}

fn verify_provenance(
    root: &Path,
    observations: &[Observation],
    ledger_head: &str,
) -> Result<(), Phase22Error> {
    let output = root.join(OUTPUT);
    let execution_digest = execution_implementation_digest(root)?;
    let mut expected = json!({
        "schema_version": "secure-bench-phase22-provenance-v1",
        "study": "post-open recovery study",
        "phase19_commit": "b3e983891e4ae3e12cd727f6bdb460962f876a30",
        "phase20_commit": "6c27c9bb26b96855228d1a8e6483483ff4174907",
        "phase21_commit": "be1ce9327c5c2acab25abe5af7a4f923d1623c48",
        "phase20_subtree": PHASE20_TREE,
        "execution_plan_sha256": sha256_file(&root.join("phase22/config/execution-plan-v1.json"))?,
        "execution_contract_sha256": sha256_file(&root.join("phase22/config/execution-contract-v1.json"))?,
        "implementation_sha256": execution_digest,
        "preflight_sha256s_sha256": sha256_file(&root.join("phase22/preflight/SHA256SUMS"))?,
        "phase21_corrected_contract_sha256": PHASE21_CONTRACT_SHA256,
        "phase19_manifest_sha256": "c035f9de14e2a1cb7c65562f9a643f0eefafc682d23c90e520770c7183068cb6",
        "aggregate_corpus_sha256": "d059653d836647296bef93a43d9e9f046899ad4fa0a87d561b4463ce0db2781c",
        "contract_merkle_root": "2bcc11f20b0f9d06eeb10f05130b752fa8125421ebf37d6050cd3119aef4452e",
        "ruleset_sha256": "06af4cf6d10da30ad585d57b781cf6aef734add03b90ea36c78e920c4c10a07c",
        "opengrep_binary_sha256": "45bcd58440e397ed52c50e953ccf5948909ea77087c9186fc7d277216f62e319",
        "semgrep_wheel_sha256": "09a7e8eeff5e2549161124957184f3566f484370aa6127e425897cef725eb99b",
        "semgrep_wheel_closure_sha256": "5371b438dc6e3c5529794b21c668057164f52fa1375e0e91ee6c8f241fb74181",
        "phase20_opengrep_adapter_sha256": "6a922a0ecac31b55f1591782df548822caa62064aaf7f8b9c1b0addc07cd0998",
        "phase20_semgrep_adapter_sha256": "53317a4e71b14548d618fd79430b74b8fc906edebbf7180cbea418df98b1afc3",
        "phase20_scoring_methodology_sha256": "0e0a767e8b1df51ca8018d27956e1d0f4ba943d520888923221bbf67f9a7b2a6",
        "corpus_opened_marker_sha256": sha256_file(&output.join("CORPUS_OPENED.json"))?,
        "results_sha256": sha256_file(&output.join("results.json"))?,
        "report_sha256": sha256_file(&output.join("report.md"))?,
        "comparison_sha256": sha256_file(&output.join("comparison.json"))?,
        "disagreements_sha256": sha256_file(&output.join("disagreements.json"))?,
        "strata_sha256": sha256_file(&output.join("strata.json"))?,
        "failure_analysis_sha256": sha256_file(&output.join("failure-analysis.json"))?,
        "limitations_sha256": sha256_file(&output.join("limitations.md"))?,
        "ledger_head": ledger_head,
        "attempts": observations.len(),
        "retries": 0,
        "secure_engine_attempts": 0,
        "network_ai_telemetry_credentials": "forbidden",
    });
    let repair = output.join("verifier-repair.json");
    if repair.exists() {
        expected["post_open_verifier_repair"] = Value::Bool(true);
        expected["verifier_repair_sha256"] = Value::String(sha256_file(&repair)?);
        expected["repaired_verifier_implementation_sha256"] =
            Value::String(implementation_digest(root)?);
    }
    let actual: Value = serde_json::from_slice(&fs::read(output.join("provenance.json"))?)?;
    if actual != expected {
        return Err(Phase22Error::Verification(
            "provenance artifact differs from independent reconstruction".to_owned(),
        ));
    }
    Ok(())
}

fn verify_readable_artifacts(root: &Path) -> Result<(), Phase22Error> {
    let output = root.join(OUTPUT);
    let report = fs::read_to_string(output.join("report.md"))?;
    for required in [
        "# Phase 22 post-open normalized recovery study",
        "## Normalized recovery lanes",
        "## Performance (separate from detection quality)",
        "## Paired normalized comparison",
        "### Absolute metric differences",
        "### Disagreement table",
        "## Stratified detection quality",
        "## Pair results",
        "## Case results",
        "## Historical phase-separated table",
        "## Limitations",
    ] {
        if !report.contains(required) {
            return Err(Phase22Error::Verification(format!(
                "readable report omits required section `{required}`"
            )));
        }
    }
    let limitations = fs::read_to_string(output.join("limitations.md"))?;
    for required in [
        "post-open recovery study",
        "cannot restore one-shot or blind-holdout validity",
        "cannot replace or reinterpret",
        "Secure Engine/native was not executed",
        "no overall three-scanner or cross-lane winner",
        "never imputed as zero findings",
    ] {
        if !limitations.contains(required) {
            return Err(Phase22Error::Verification(format!(
                "limitations artifact omits `{required}`"
            )));
        }
    }
    Ok(())
}

pub(crate) fn verify_without_sums(root: &Path) -> Result<VerificationReport, Phase22Error> {
    verify_saved_preflight(root)?;
    let execution_digest = execution_implementation_digest(root)?;
    if git_phase20_tree(root)? != PHASE20_TREE
        || sha256_file(&root.join("phase21/output/corrected-environment-contract.json"))?
            != PHASE21_CONTRACT_SHA256
    {
        return Err(Phase22Error::Verification(
            "Phase 20 or Phase 21 immutable identity drift".to_owned(),
        ));
    }
    let marker: Value =
        serde_json::from_slice(&fs::read(root.join(OUTPUT).join("CORPUS_OPENED.json"))?)?;
    if marker.get("study").and_then(Value::as_str) != Some("post-open recovery study")
        || marker
            .get("opened_at_unix_ms")
            .and_then(Value::as_u64)
            .is_none_or(|value| value == 0)
        || marker.get("plan_sha256").and_then(Value::as_str)
            != Some(sha256_file(&root.join("phase22/config/execution-plan-v1.json"))?.as_str())
        || marker.get("contract_sha256").and_then(Value::as_str)
            != Some(sha256_file(&root.join("phase22/config/execution-contract-v1.json"))?.as_str())
        || marker
            .get("preflight_sha256s_sha256")
            .and_then(Value::as_str)
            != Some(sha256_file(&root.join("phase22/preflight/SHA256SUMS"))?.as_str())
        || marker.get("implementation_sha256").and_then(Value::as_str)
            != Some(execution_digest.as_str())
        || marker.get("planned_attempts").and_then(Value::as_u64) != Some(224)
        || marker.get("retries").and_then(Value::as_u64) != Some(0)
        || marker.get("secure_engine_attempts").and_then(Value::as_u64) != Some(0)
    {
        return Err(Phase22Error::Verification(
            "irreversible corpus-open marker is invalid".to_owned(),
        ));
    }
    let plan = load_plan(root)?;
    let cases = load_cases_post_open(root)?;
    let observations = read_observations(root)?;
    if observations.len() != 224 {
        return Err(Phase22Error::Verification(format!(
            "observed {} recovery attempts, expected 224",
            observations.len()
        )));
    }
    for (attempt, observation) in plan.attempts.iter().zip(&observations) {
        if attempt.sequence != observation.sequence
            || attempt.scanner != observation.scanner
            || attempt.lane != observation.lane
            || attempt.case_id != observation.case_id
        {
            return Err(Phase22Error::Verification(format!(
                "observation does not match plan at sequence {}",
                attempt.sequence
            )));
        }
        let case = cases.get(&observation.case_id).ok_or_else(|| {
            Phase22Error::Verification(format!(
                "observation references unknown case {}",
                observation.case_id
            ))
        })?;
        verify_observation(root, case, observation)?;
    }
    let keys = observations
        .iter()
        .map(|observation| (observation.scanner.as_str(), observation.case_id.as_str()))
        .collect::<BTreeSet<_>>();
    if keys.len() != 224
        || observations
            .iter()
            .filter(|observation| observation.scanner == "opengrep")
            .count()
            != 112
        || observations
            .iter()
            .filter(|observation| observation.scanner == "semgrep-ce")
            .count()
            != 112
    {
        return Err(Phase22Error::Verification(
            "attempt keys repeat or scanner counts drift".to_owned(),
        ));
    }
    let ledger_head = verify_ledger(root, &observations)?;
    let recomputed = independent_compute(&cases, &observations)?;
    let committed: Results =
        serde_json::from_slice(&fs::read(root.join(OUTPUT).join("results.json"))?)?;
    if canonical_json(&recomputed)? != canonical_json(&committed)?
        || committed.total_recovery_attempts != 224
        || committed.retries != 0
        || committed.secure_engine_attempts != 0
        || committed.repeated_attempts
        || committed.study != "post-open recovery study"
    {
        return Err(Phase22Error::Verification(
            "canonical results differ from independent recomputation".to_owned(),
        ));
    }
    let comparison: Value =
        serde_json::from_slice(&fs::read(root.join(OUTPUT).join("comparison.json"))?)?;
    let disagreements: Value =
        serde_json::from_slice(&fs::read(root.join(OUTPUT).join("disagreements.json"))?)?;
    let strata: Value = serde_json::from_slice(&fs::read(root.join(OUTPUT).join("strata.json"))?)?;
    let failure_analysis: Value =
        serde_json::from_slice(&fs::read(root.join(OUTPUT).join("failure-analysis.json"))?)?;
    if comparison != serde_json::to_value(&recomputed.comparison)?
        || disagreements != serde_json::to_value(&recomputed.comparison.disagreements)?
        || strata != independent_strata(&recomputed)
        || failure_analysis != independent_failure_analysis(&observations)
    {
        return Err(Phase22Error::Verification(
            "comparison, disagreement, strata, or failure artifact drift".to_owned(),
        ));
    }
    verify_provenance(root, &observations, &ledger_head)?;
    verify_readable_artifacts(root)?;
    Ok(VerificationReport {
        schema_version: "secure-bench-phase22-independent-verification-v1".to_owned(),
        state: "verified".to_owned(),
        study: "post-open recovery study".to_owned(),
        observations_verified: 224,
        retries_verified: 0,
        secure_engine_attempts_verified: 0,
        ledger_head,
        checks: vec![
            "frozen 224-key plan matched every observation".to_owned(),
            "112 OpenGrep and 112 Semgrep CE attempts enforced".to_owned(),
            "zero retries and zero Secure Engine processes enforced".to_owned(),
            "corrected sandbox command and cleared environment enforced".to_owned(),
            "stdout, stderr, raw, observation, and ledger hashes recomputed".to_owned(),
            "all adapter-valid reports independently re-adapted".to_owned(),
            "all metrics, strata, pairs, comparison, and disagreements recomputed".to_owned(),
            "failure analysis and provenance independently reconstructed".to_owned(),
            "readable report and limitations boundary validated".to_owned(),
            "Phase 20 and Phase 21 immutable identities enforced".to_owned(),
            "historical and recovery studies kept phase-separated".to_owned(),
        ],
        scanner_execution: false,
    })
}

fn verify_sums(root: &Path) -> Result<(), Phase22Error> {
    let output = root.join(OUTPUT);
    let content = fs::read_to_string(output.join("SHA256SUMS"))?;
    let mut seen = BTreeSet::new();
    for line in content.lines() {
        let (expected, relative) = line
            .split_once("  ")
            .ok_or_else(|| Phase22Error::Verification("malformed output SHA256SUMS".to_owned()))?;
        let relative = safe_relative(relative)?;
        if !seen.insert(relative.to_path_buf()) || sha256_file(&output.join(relative))? != expected
        {
            return Err(Phase22Error::Verification(format!(
                "output SHA256SUMS drift: {}",
                relative.display()
            )));
        }
    }
    if seen.is_empty() {
        return Err(Phase22Error::Verification(
            "output SHA256SUMS is empty".to_owned(),
        ));
    }
    let sums = output.join("SHA256SUMS");
    let mut files = Vec::new();
    collect_files(&output, &mut files)?;
    let actual = files
        .into_iter()
        .filter(|file| file != &sums)
        .map(|file| {
            file.strip_prefix(&output)
                .map(Path::to_path_buf)
                .map_err(|_| {
                    Phase22Error::Verification(format!(
                        "output file escaped evidence root: {}",
                        file.display()
                    ))
                })
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if seen != actual {
        return Err(Phase22Error::Verification(
            "output SHA256SUMS does not enumerate every artifact exactly once".to_owned(),
        ));
    }
    Ok(())
}

/// Independently verify all sealed Phase 22 evidence without starting scanners.
pub fn independent_verify(root: &Path) -> Result<VerificationReport, Phase22Error> {
    let report = verify_without_sums(root)?;
    verify_sums(root)?;
    let saved: VerificationReport = serde_json::from_slice(&fs::read(
        root.join(OUTPUT).join("independent-verification.json"),
    )?)?;
    if canonical_json(&saved)? != canonical_json(&report)? {
        return Err(Phase22Error::Verification(
            "saved independent-verification artifact drift".to_owned(),
        ));
    }
    Ok(report)
}

fn write_final_sums(output: &Path) -> Result<(), Phase22Error> {
    let sums = output.join("SHA256SUMS");
    if sums.exists() {
        return Err(Phase22Error::Verification(
            "final SHA256SUMS already exists".to_owned(),
        ));
    }
    let mut files = Vec::new();
    collect_files(output, &mut files)?;
    files.sort();
    let mut content = String::new();
    for file in files {
        let relative = file.strip_prefix(output).map_err(|_| {
            Phase22Error::Verification(format!("final artifact escaped output: {}", file.display()))
        })?;
        content.push_str(&format!(
            "{}  {}\n",
            sha256_file(&file)?,
            relative.to_string_lossy()
        ));
    }
    write_atomic(&sums, content.as_bytes())
}

/// Recover only the scanner-free final verifier after all 224 attempts finished.
pub fn recover_verification(root: &Path) -> Result<VerificationReport, Phase22Error> {
    let output = root.join(OUTPUT);
    let repair_path = output.join("verifier-repair.json");
    for forbidden in [
        &repair_path,
        &output.join("independent-verification.json"),
        &output.join("SHA256SUMS"),
    ] {
        if forbidden.exists() {
            return Err(Phase22Error::Verification(format!(
                "recovery refuses existing final artifact: {}",
                forbidden.display()
            )));
        }
    }
    let execution_digest = execution_implementation_digest(root)?;
    let current_digest = implementation_digest(root)?;
    if execution_digest == current_digest {
        return Err(Phase22Error::Verification(
            "recovery requires an exact post-open verifier implementation change".to_owned(),
        ));
    }
    let marker: Value = serde_json::from_slice(&fs::read(output.join("CORPUS_OPENED.json"))?)?;
    let preflight: Value =
        serde_json::from_slice(&fs::read(root.join("phase22/preflight/preflight.json"))?)?;
    if marker.get("implementation_sha256").and_then(Value::as_str)
        != Some(execution_digest.as_str())
        || preflight
            .get("implementation_sha256")
            .and_then(Value::as_str)
            != Some(execution_digest.as_str())
    {
        return Err(Phase22Error::Verification(
            "execution, preflight, and contract implementation digests diverge".to_owned(),
        ));
    }
    let observations = read_observations(root)?;
    if observations.len() != 224
        || fs::read_to_string(output.join("ledger.jsonl"))?
            .lines()
            .count()
            != 224
    {
        return Err(Phase22Error::Verification(
            "recovery requires all 224 preserved observations and ledger entries".to_owned(),
        ));
    }
    let repair = json!({
        "schema_version": "secure-bench-phase22-verifier-repair-v1",
        "state": "post-open-scanner-free-verifier-repair",
        "study": "post-open recovery study",
        "reason": "the frozen verifier rejected safe repository-relative bind sources after all 224 scanner attempts completed",
        "scope": "command-source normalization and scanner-free final artifact reconstruction only",
        "execution_implementation_sha256": execution_digest,
        "repaired_verifier_implementation_sha256": current_digest,
        "corpus_opened_marker_sha256": sha256_file(&output.join("CORPUS_OPENED.json"))?,
        "ledger_sha256": sha256_file(&output.join("ledger.jsonl"))?,
        "observations_preserved": 224,
        "retries": 0,
        "scanner_processes_started_by_repair": 0,
    });
    write_atomic(&repair_path, &canonical_json(&repair)?)?;

    let repair_note = "\n## Post-open verifier repair\n\nAfter all 224 scanner attempts completed, the scanner-free verifier was repaired to accept the safe repository-relative bind sources recorded by the frozen runner. No scanner was started, no attempt or ledger entry was changed, and no retry occurred. See `verifier-repair.json`.\n";
    for name in ["report.md", "limitations.md"] {
        let path = output.join(name);
        let mut content = fs::read_to_string(&path)?;
        if content.contains("## Post-open verifier repair") {
            return Err(Phase22Error::Verification(format!(
                "recovery note already exists in {name}"
            )));
        }
        content.push_str(repair_note);
        write_atomic(&path, content.as_bytes())?;
    }

    let provenance_path = output.join("provenance.json");
    let mut provenance: Value = serde_json::from_slice(&fs::read(&provenance_path)?)?;
    provenance["implementation_sha256"] = Value::String(
        repair
            .get("execution_implementation_sha256")
            .and_then(Value::as_str)
            .ok_or_else(|| Phase22Error::Verification("repair has no execution digest".to_owned()))?
            .to_owned(),
    );
    provenance["report_sha256"] = Value::String(sha256_file(&output.join("report.md"))?);
    provenance["limitations_sha256"] = Value::String(sha256_file(&output.join("limitations.md"))?);
    provenance["post_open_verifier_repair"] = Value::Bool(true);
    provenance["verifier_repair_sha256"] = Value::String(sha256_file(&repair_path)?);
    provenance["repaired_verifier_implementation_sha256"] = Value::String(
        repair
            .get("repaired_verifier_implementation_sha256")
            .and_then(Value::as_str)
            .ok_or_else(|| Phase22Error::Verification("repair has no verifier digest".to_owned()))?
            .to_owned(),
    );
    write_atomic(&provenance_path, &canonical_json(&provenance)?)?;

    let report = verify_without_sums(root)?;
    write_atomic(
        &output.join("independent-verification.json"),
        &canonical_json(&report)?,
    )?;
    write_final_sums(&output)?;
    independent_verify(root)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expected_command(root: &Path, scanner: Scanner) -> Vec<String> {
        let mut command = scanner_sandbox(
            scanner,
            true,
            &root.join("phase19/holdout/cases/case-p19-0001"),
            &root.join("phase19/rules/capability-normalized-v1.yml"),
            &root.join("phase22/output/attempts/001-opengrep-case-p19-0001"),
        );
        command.extend([
            "--".to_owned(),
            "/usr/bin/prlimit".to_owned(),
            "--as=4294967296".to_owned(),
            "--nproc=64".to_owned(),
            "--".to_owned(),
        ]);
        command.extend(scanner_command(scanner));
        command
    }

    #[test]
    fn command_normalization_is_checkout_portable_and_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let first = tempfile::tempdir()?;
        let second = tempfile::tempdir()?;
        for scanner in [Scanner::OpenGrep, Scanner::Semgrep] {
            let command = expected_command(first.path(), scanner);
            assert_eq!(
                normalize_mount_sources(&command)?,
                normalize_mount_sources(&expected_command(second.path(), scanner))?
            );

            let mut missing_target = command.clone();
            let target = missing_target
                .windows(3)
                .position(|window| window[0] == "--ro-bind" && window[2] == "/tmp/fixture")
                .ok_or("fixture target missing from generated command")?
                + 2;
            missing_target[target] = "/tmp/not-fixture".to_owned();
            assert!(normalize_mount_sources(&missing_target).is_err());

            let mut relative_source = command.clone();
            let source = relative_source
                .windows(3)
                .position(|window| window[0] == "--ro-bind" && window[2] == "/tmp/fixture")
                .ok_or("fixture binding missing from generated command")?
                + 1;
            relative_source[source] = "relative-fixture".to_owned();
            assert!(normalize_mount_sources(&relative_source).is_err());

            let mut traversing_source = command;
            let source = traversing_source
                .windows(3)
                .position(|window| window[0] == "--ro-bind" && window[2] == "/tmp/fixture")
                .ok_or("fixture binding missing from generated command")?
                + 1;
            traversing_source[source] = "./phase19/holdout/cases/../case-p19-0001".to_owned();
            assert!(normalize_mount_sources(&traversing_source).is_err());
        }
        Ok(())
    }

    #[test]
    fn output_sums_require_exact_artifact_enumeration() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let output = root.path().join(OUTPUT);
        fs::create_dir_all(&output)?;
        fs::write(output.join("one.json"), b"one\n")?;
        let one = sha256_file(&output.join("one.json"))?;
        fs::write(output.join("SHA256SUMS"), format!("{one}  one.json\n"))?;
        assert!(verify_sums(root.path()).is_ok());

        fs::write(output.join("two.json"), b"two\n")?;
        assert!(verify_sums(root.path()).is_err());

        let two = sha256_file(&output.join("two.json"))?;
        fs::write(
            output.join("SHA256SUMS"),
            format!("{one}  one.json\n{two}  two.json\n"),
        )?;
        assert!(verify_sums(root.path()).is_ok());

        fs::write(
            output.join("SHA256SUMS"),
            format!("{one}  one.json\n{one}  one.json\n{two}  two.json\n"),
        )?;
        assert!(verify_sums(root.path()).is_err());
        Ok(())
    }
}
