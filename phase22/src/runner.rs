use crate::contract::{load_plan, verify_saved_preflight};
use crate::model::{
    AttemptState, CaseSpec, ExecutionPlan, LedgerEntry, Observation, PlanAttempt, Results,
};
use crate::score::compute;
use crate::{
    Phase22Error, canonical_json, collect_files, create_irreversible, now_ms, safe_relative,
    sha256, sha256_file, write_atomic,
};
use secure_bench_phase21::sandbox::{Scanner, fixed_environment, scanner_command, scanner_sandbox};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const OUTPUT: &str = "phase22/output";
const MANIFEST: &str = "phase19/holdout/manifest.json";
const MANIFEST_SHA256: &str = "c035f9de14e2a1cb7c65562f9a643f0eefafc682d23c90e520770c7183068cb6";
const CORPUS_SHA256: &str = "d059653d836647296bef93a43d9e9f046899ad4fa0a87d561b4463ce0db2781c";
const CONTRACT_MERKLE_ROOT: &str =
    "2bcc11f20b0f9d06eeb10f05130b752fa8125421ebf37d6050cd3119aef4452e";
const RULESET: &str = "phase19/rules/capability-normalized-v1.yml";
const TIMEOUT: Duration = Duration::from_mins(2);
const MAX_OUTPUT: u64 = 10 * 1024 * 1024;
const LIMITATIONS: &str = "# Phase 22 limitations and validity boundary\n\nPhase 22 is exclusively a **post-open recovery study**. The Phase 19 corpus ceased to be globally blind when Phase 20 opened it, so these results cannot restore one-shot or blind-holdout validity and cannot replace or reinterpret the 224 historical Phase 20 normalized-lane failures.\n\nThe infrastructure correction changes only sandbox operability. The corpus, manifest, expectations, rules, adapters, scoring methodology, scanner versions, and lane definitions remain frozen. Secure Engine/native was not executed in Phase 22. Native and capability-normalized evidence is not merged, cross-phase metrics are not combined, and no overall three-scanner or cross-lane winner is declared.\n\nOperational failures remain explicit states and are never imputed as zero findings. Complete-lane detection metrics exist only when all 112 attempts for that scanner have adapter-valid evidence. Performance is descriptive and separate from detection quality.\n";
const ALLOWED_RULES: [&str; 7] = [
    "secure-bench.phase19.SE1001.resource-authorization",
    "secure-bench.phase19.SE1002.command-injection",
    "secure-bench.phase19.SE1003.dynamic-code",
    "secure-bench.phase19.SE1004.path-traversal",
    "secure-bench.phase19.SE1005.outbound-request",
    "secure-bench.phase19.SE1006.open-redirect",
    "secure-bench.phase19.SE1007.sql-injection",
];

/// Captured child process evidence shared with synthetic preflight.
pub(crate) struct ProcessEvidence {
    /// Full command vector.
    pub command: Vec<String>,
    /// Normal exit code.
    pub exit_code: Option<i32>,
    /// Wall-clock duration.
    pub duration_ms: u64,
    /// Whether watchdog killed the namespace.
    pub timed_out: bool,
    /// Standard output bytes.
    pub stdout: Vec<u8>,
    /// Standard error bytes.
    pub stderr: Vec<u8>,
    /// Raw output bytes when emitted.
    pub raw: Option<Vec<u8>>,
}

/// Run one bubblewrap command with a hard external watchdog.
pub(crate) fn run_process(
    arguments: &[String],
    output: &Path,
    timeout: Duration,
) -> Result<ProcessEvidence, Phase22Error> {
    fs::create_dir_all(output)?;
    let stdout_path = output.join("stdout.bin");
    let stderr_path = output.join("stderr.bin");
    let stdout = File::create(&stdout_path)?;
    let stderr = File::create(&stderr_path)?;
    let started = Instant::now();
    let mut child = Command::new("/usr/bin/bwrap")
        .args(arguments)
        .env_clear()
        .env("LANG", "C.UTF-8")
        .env("LC_ALL", "C.UTF-8")
        .env("PATH", "/usr/bin:/bin")
        .env("TZ", "UTC")
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()?;
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() >= timeout {
            child.kill()?;
            timed_out = true;
            break child.wait()?;
        }
        thread::sleep(Duration::from_millis(10));
    };
    let raw_path = output.join("raw.json");
    Ok(ProcessEvidence {
        command: std::iter::once("/usr/bin/bwrap".to_owned())
            .chain(arguments.iter().cloned())
            .collect(),
        exit_code: status.code(),
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        timed_out,
        stdout: fs::read(stdout_path)?,
        stderr: fs::read(stderr_path)?,
        raw: raw_path.exists().then(|| fs::read(raw_path)).transpose()?,
    })
}

fn text(object: &Value, field: &str) -> Result<String, Phase22Error> {
    object
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| Phase22Error::Execution(format!("manifest object omits {field}")))
}

/// Open and validate the post-open manifest and case metadata.
pub(crate) fn load_cases_post_open(
    root: &Path,
) -> Result<BTreeMap<String, CaseSpec>, Phase22Error> {
    let manifest_path = root.join(MANIFEST);
    let bytes = fs::read(&manifest_path)?;
    if sha256(&bytes) != MANIFEST_SHA256 {
        return Err(Phase22Error::Execution(
            "Phase 19 manifest hash drift after corpus opening".to_owned(),
        ));
    }
    let manifest: Value = serde_json::from_slice(&bytes)?;
    if manifest
        .get("aggregate_corpus_sha256")
        .and_then(Value::as_str)
        != Some(CORPUS_SHA256)
        || manifest.get("contract_merkle_root").and_then(Value::as_str)
            != Some(CONTRACT_MERKLE_ROOT)
    {
        return Err(Phase22Error::Execution(
            "Phase 19 corpus commitments drift after opening".to_owned(),
        ));
    }
    let pairs = manifest
        .get("pairs")
        .and_then(Value::as_array)
        .ok_or_else(|| Phase22Error::Execution("manifest has no pairs".to_owned()))?;
    let mut cases = BTreeMap::new();
    for pair in pairs {
        let pair_id = text(pair, "pair_id")?;
        let assignment = pair
            .get("assignment")
            .ok_or_else(|| Phase22Error::Execution("pair has no assignment".to_owned()))?;
        for side in ["first", "second"] {
            let value = pair
                .get(side)
                .ok_or_else(|| Phase22Error::Execution(format!("pair {pair_id} has no {side}")))?;
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
            if cases.insert(case.case_id.clone(), case).is_some() {
                return Err(Phase22Error::Execution(
                    "manifest repeats a case ID".to_owned(),
                ));
            }
        }
    }
    if cases.len() != 112 {
        return Err(Phase22Error::Execution(format!(
            "manifest has {} cases, expected 112",
            cases.len()
        )));
    }
    Ok(cases)
}

fn scanner(value: &str) -> Result<Scanner, Phase22Error> {
    match value {
        "opengrep" => Ok(Scanner::OpenGrep),
        "semgrep-ce" => Ok(Scanner::Semgrep),
        _ => Err(Phase22Error::Contract(format!(
            "ineligible scanner in plan: {value}"
        ))),
    }
}

fn normalized_manifest(root: &Path, scanner: Scanner) -> Result<Value, String> {
    let path = match scanner {
        Scanner::OpenGrep => "phase20/config/opengrep-normalized-adapter-v1.json",
        Scanner::Semgrep => "phase20/config/semgrep-normalized-adapter-v1.json",
    };
    let manifest: Value =
        serde_json::from_slice(&fs::read(root.join(path)).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    let expected_id = match scanner {
        Scanner::OpenGrep => "opengrep",
        Scanner::Semgrep => "semgrep",
    };
    let expected_adapter = match scanner {
        Scanner::OpenGrep => ("secure-bench-opengrep-json", "opengrep-json-v1"),
        Scanner::Semgrep => ("secure-bench-semgrep-json", "semgrep-json-v1"),
    };
    let rule_ids = manifest
        .pointer("/ruleset/rule_ids")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .collect::<BTreeSet<_>>()
        });
    if manifest.get("schema_version").and_then(Value::as_str)
        != Some("secure-bench-scanner-manifest-v1")
        || manifest.get("protocol_version").and_then(Value::as_str) != Some("1.0.0")
        || manifest.pointer("/scanner/id").and_then(Value::as_str) != Some(expected_id)
        || manifest.pointer("/scanner/version").and_then(Value::as_str) != Some(scanner.version())
        || manifest.pointer("/ruleset/sha256").and_then(Value::as_str)
            != Some("06af4cf6d10da30ad585d57b781cf6aef734add03b90ea36c78e920c4c10a07c")
        || rule_ids != Some(ALLOWED_RULES.into_iter().collect::<BTreeSet<_>>())
        || manifest
            .pointer("/resources/timeout_ms")
            .and_then(Value::as_u64)
            != Some(u64::try_from(TIMEOUT.as_millis()).unwrap_or(u64::MAX))
        || manifest
            .pointer("/resources/max_output_bytes")
            .and_then(Value::as_u64)
            != Some(MAX_OUTPUT)
        || manifest
            .pointer("/resources/network_allowed")
            .and_then(Value::as_bool)
            != Some(false)
        || manifest
            .pointer("/adapter/adapter_id")
            .and_then(Value::as_str)
            != Some(expected_adapter.0)
        || manifest
            .pointer("/adapter/adapter_version")
            .and_then(Value::as_str)
            != Some("1.0.0")
        || manifest
            .pointer("/adapter/raw_output_format")
            .and_then(Value::as_str)
            != Some(expected_adapter.1)
    {
        return Err(format!(
            "frozen normalized adapter manifest drift for {}",
            scanner.id()
        ));
    }
    Ok(manifest)
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
    let canonical_root = fixture.canonicalize().map_err(|error| error.to_string())?;
    let mut cursor = canonical_root.clone();
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
    if !canonical.starts_with(&canonical_root) || !canonical.is_file() {
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

fn validate_result(fixture: &Path, result: &Value, strict_offsets: bool) -> Result<String, String> {
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
                && (!strict_offsets || (start == expected_start && end == expected_end)) => {}
        (None, None) => {}
        _ => return Err(format!("invalid scanner offsets for {relative}")),
    }
    Ok(relative)
}

/// Strictly adapt one raw normalized report.
pub(crate) fn adapt_raw(
    root: &Path,
    scanner: Scanner,
    fixture: &Path,
    raw: &[u8],
) -> Result<u64, String> {
    let manifest = normalized_manifest(root, scanner)?;
    if u64::try_from(raw.len()).unwrap_or(u64::MAX) > MAX_OUTPUT {
        return Err("raw output exceeded 10485760 bytes".to_owned());
    }
    let value: Value = serde_json::from_slice(raw).map_err(|error| error.to_string())?;
    if value.get("version").and_then(Value::as_str) != Some(scanner.version())
        || value
            .get("errors")
            .and_then(Value::as_array)
            .is_none_or(|errors| !errors.is_empty())
        || value
            .get("skipped_rules")
            .is_some_and(|rules| rules.as_array().is_none_or(|rules| !rules.is_empty()))
    {
        return Err("scanner identity, errors, or skipped rules are invalid".to_owned());
    }
    let scanned_paths = if scanner == Scanner::Semgrep {
        if value.get("engine_requested").and_then(Value::as_str) != Some("OSS")
            || value
                .get("skipped_rules")
                .and_then(Value::as_array)
                .is_none()
        {
            return Err("Semgrep report is not complete CE OSS output".to_owned());
        }
        let paths = value
            .pointer("/paths/scanned")
            .and_then(Value::as_array)
            .ok_or_else(|| "Semgrep report has no paths.scanned".to_owned())?;
        let mut output = BTreeSet::new();
        for path in paths {
            let path = path
                .as_str()
                .ok_or_else(|| "Semgrep scanned path is not text".to_owned())?;
            if !output.insert(source_bytes(fixture, path)?.0) {
                return Err("Semgrep repeats a scanned path".to_owned());
            }
        }
        Some(output)
    } else {
        None
    };
    let allowed = manifest
        .pointer("/ruleset/rule_ids")
        .and_then(Value::as_array)
        .ok_or_else(|| "adapter manifest has no rules".to_owned())?
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    let results = value
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(|| "raw report has no results array".to_owned())?;
    for finding in results {
        let rule = finding
            .get("check_id")
            .and_then(Value::as_str)
            .ok_or_else(|| "finding has no check_id".to_owned())?;
        if !allowed.contains(rule) {
            return Err(format!("scanner emitted unknown rule `{rule}`"));
        }
        if scanner == Scanner::Semgrep
            && finding
                .pointer("/extra/engine_kind")
                .and_then(Value::as_str)
                != Some("OSS")
        {
            return Err("Semgrep finding is not OSS engine output".to_owned());
        }
        let relative = validate_result(fixture, finding, scanner == Scanner::Semgrep)?;
        if scanned_paths
            .as_ref()
            .is_some_and(|paths| !paths.contains(&relative))
        {
            return Err("Semgrep finding path was not scanned".to_owned());
        }
    }
    Ok(u64::try_from(results.len()).unwrap_or(u64::MAX))
}

fn relative_attempt_directory(attempt: &PlanAttempt) -> String {
    format!(
        "phase22/output/attempts/{:03}-{}-{}",
        attempt.sequence, attempt.scanner, attempt.case_id
    )
}

fn run_attempt(
    root: &Path,
    attempt: &PlanAttempt,
    case: &CaseSpec,
) -> Result<Observation, Phase22Error> {
    let scanner = scanner(&attempt.scanner)?;
    let fixture = root.join(safe_relative(&case.fixture_path)?);
    if !fixture.is_dir() {
        return Err(Phase22Error::Execution(format!(
            "fixture is absent for {}",
            case.case_id
        )));
    }
    let relative_directory = relative_attempt_directory(attempt);
    let directory = root.join(&relative_directory);
    if directory.exists() {
        return Err(Phase22Error::Execution(format!(
            "attempt evidence already exists: {}",
            attempt.sequence
        )));
    }
    fs::create_dir_all(&directory)?;
    let mut arguments = scanner_sandbox(scanner, true, &fixture, &root.join(RULESET), &directory);
    arguments.extend([
        "--".to_owned(),
        "/usr/bin/prlimit".to_owned(),
        "--as=4294967296".to_owned(),
        "--nproc=64".to_owned(),
        "--".to_owned(),
    ]);
    arguments.extend(scanner_command(scanner));
    let evidence = run_process(&arguments, &directory, TIMEOUT)?;
    let raw_hash = evidence.raw.as_deref().map(sha256);
    let raw_path = evidence
        .raw
        .as_ref()
        .map(|_| format!("{relative_directory}/raw.json"));
    let mut failure = None;
    let mut finding_count = None;
    let (state, process_decision) = if evidence.timed_out {
        failure = Some("wall-clock timeout; no retry".to_owned());
        (AttemptState::Timeout, "timeout")
    } else if let Some(raw) = evidence.raw.as_deref() {
        match adapt_raw(root, scanner, &fixture, raw) {
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
                let state = if serde_json::from_slice::<Value>(raw).is_err() {
                    AttemptState::Malformed
                } else {
                    AttemptState::Failed
                };
                (state, "adapter-failure")
            }
        }
    } else {
        failure = Some("scanner produced no raw output".to_owned());
        (AttemptState::Unavailable, "missing-output")
    };
    let environment = fixed_environment();
    let observation = Observation {
        sequence: attempt.sequence,
        scanner: attempt.scanner.clone(),
        lane: attempt.lane.clone(),
        case_id: attempt.case_id.clone(),
        state,
        process_decision: process_decision.to_owned(),
        exit_code: evidence.exit_code,
        timed_out: evidence.timed_out,
        duration_ms: evidence.duration_ms,
        command_sha256: sha256(&canonical_json(&evidence.command)?),
        command: evidence.command,
        environment_sha256: sha256(&canonical_json(&environment)?),
        environment,
        stdout_path: format!("{relative_directory}/stdout.bin"),
        stdout_sha256: sha256(&evidence.stdout),
        stderr_path: format!("{relative_directory}/stderr.bin"),
        stderr_sha256: sha256(&evidence.stderr),
        raw_output_path: raw_path,
        raw_output_sha256: raw_hash,
        finding_count,
        failure,
    };
    write_atomic(
        &directory.join("observation.json"),
        &canonical_json(&observation)?,
    )?;
    Ok(observation)
}

fn append_ledger(
    path: &Path,
    observation: &Observation,
    previous: &str,
) -> Result<String, Phase22Error> {
    let payload_hash = sha256(&canonical_json(observation)?);
    let unsigned = json!({
        "schema_version": "secure-bench-phase22-ledger-v1",
        "sequence": observation.sequence,
        "event": "recovery-attempt-completed",
        "payload_sha256": payload_hash,
        "previous_entry_hash": previous,
    });
    let entry_hash = sha256(&canonical_json(&unsigned)?);
    let entry = LedgerEntry {
        schema_version: "secure-bench-phase22-ledger-v1".to_owned(),
        sequence: observation.sequence,
        event: "recovery-attempt-completed".to_owned(),
        payload_sha256: payload_hash,
        previous_entry_hash: previous.to_owned(),
        entry_hash: entry_hash.clone(),
    };
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(&canonical_json(&entry)?)?;
    file.sync_all()?;
    Ok(entry_hash)
}

fn show_ratio(value: Option<&crate::model::Ratio>) -> String {
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

fn append_metric_rows(
    output: &mut String,
    scanner: &str,
    dimension: &str,
    rows: &BTreeMap<String, crate::model::Metrics>,
) {
    for (value, metric) in rows {
        output.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
            scanner,
            dimension,
            value,
            metric.tp,
            metric.fp,
            metric.tn,
            metric.fn_count,
            show_ratio(metric.precision.as_ref()),
            show_ratio(metric.recall.as_ref()),
            show_ratio(metric.specificity.as_ref()),
            show_ratio(metric.f1.as_ref()),
            show_ratio(metric.balanced_accuracy.as_ref()),
        ));
    }
}

fn report(results: &Results) -> String {
    let mut output = String::from(
        "# Phase 22 post-open normalized recovery study\n\nPhase 22 is not a repetition or retroactive correction of Phase 20. It does not restore one-shot or blind-holdout validity.\n\n## Normalized recovery lanes\n\n| Scanner | State | Attempts | Completed | Failed | Timeouts | Malformed | Unsupported | Unavailable | TP | FP | TN | FN | Precision | Recall | Specificity | F1 | Balanced accuracy |\n|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n",
    );
    for lane in &results.lanes {
        let metric = |name: &str| {
            lane.metrics
                .as_ref()
                .and_then(|metrics| match name {
                    "precision" => metrics.precision.as_ref(),
                    "recall" => metrics.recall.as_ref(),
                    "specificity" => metrics.specificity.as_ref(),
                    "f1" => metrics.f1.as_ref(),
                    _ => metrics.balanced_accuracy.as_ref(),
                })
                .map_or_else(|| "unavailable".to_owned(), |value| show_ratio(Some(value)))
        };
        let (tp, fp, tn, fn_count) = lane.metrics.as_ref().map_or(
            (
                "—".to_owned(),
                "—".to_owned(),
                "—".to_owned(),
                "—".to_owned(),
            ),
            |metrics| {
                (
                    metrics.tp.to_string(),
                    metrics.fp.to_string(),
                    metrics.tn.to_string(),
                    metrics.fn_count.to_string(),
                )
            },
        );
        output.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
            lane.scanner,
            lane.state,
            lane.operations.attempts,
            lane.operations.completed,
            lane.operations.failed,
            lane.operations.timeouts,
            lane.operations.malformed,
            lane.operations.unsupported,
            lane.operations.unavailable,
            tp,
            fp,
            tn,
            fn_count,
            metric("precision"),
            metric("recall"),
            metric("specificity"),
            metric("f1"),
            metric("balanced_accuracy"),
        ));
    }
    output.push_str("\n## Performance (separate from detection quality)\n\n| Scanner | Total ms | Min ms | Median ms | P95 ms | Max ms |\n|---|---:|---:|---:|---:|---:|\n");
    for lane in &results.lanes {
        let show = |value: Option<u64>| value.map_or_else(|| "—".to_owned(), |v| v.to_string());
        output.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            lane.scanner,
            lane.operations.total_duration_ms,
            show(lane.operations.min_duration_ms),
            show(lane.operations.median_duration_ms),
            show(lane.operations.p95_duration_ms),
            show(lane.operations.max_duration_ms),
        ));
    }
    output.push_str("\n## Paired normalized comparison\n\n");
    output.push_str(&format!(
        "State: `{}`. Agreements: `{}`. OpenGrep-only correct: `{}`. Semgrep-only correct: `{}`. Both incorrect: `{}`. Disagreements: `{}`.\n",
        results.comparison.state,
        results.comparison.agreements.map_or_else(|| "unavailable".to_owned(), |value| value.to_string()),
        results.comparison.opengrep_only_correct.map_or_else(|| "unavailable".to_owned(), |value| value.to_string()),
        results.comparison.semgrep_only_correct.map_or_else(|| "unavailable".to_owned(), |value| value.to_string()),
        results.comparison.both_incorrect.map_or_else(|| "unavailable".to_owned(), |value| value.to_string()),
        results.comparison.disagreements.len(),
    ));
    output.push_str(
        "\n### Absolute metric differences\n\n| Metric | Absolute difference |\n|---|---:|\n",
    );
    if results.comparison.absolute_metric_differences.is_empty() {
        output.push_str("| _unavailable_ | — |\n");
    } else {
        for (metric, difference) in &results.comparison.absolute_metric_differences {
            output.push_str(&format!(
                "| {} | {} |\n",
                metric,
                show_ratio(Some(difference))
            ));
        }
    }
    output.push_str("\n### Disagreement table\n\n| Case | Expected | OpenGrep positive | Semgrep positive | OpenGrep findings | Semgrep findings | OpenGrep outcome | Semgrep outcome | Family | Framework | Format | Topology | Variant |\n|---|---|---:|---:|---:|---:|---|---|---|---|---|---|---|\n");
    if results.comparison.disagreements.is_empty() {
        output.push_str("| _none_ | — | — | — | — | — | — | — | — | — | — | — | — |\n");
    } else {
        for row in &results.comparison.disagreements {
            output.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
                row.case_id,
                row.expected,
                row.opengrep_positive,
                row.semgrep_positive,
                row.opengrep_findings,
                row.semgrep_findings,
                row.opengrep_outcome,
                row.semgrep_outcome,
                row.family,
                row.framework,
                row.source_format,
                row.topology,
                row.adversarial_variant,
            ));
        }
    }
    output.push_str("\n## Stratified detection quality\n\n| Scanner | Dimension | Value | TP | FP | TN | FN | Precision | Recall | Specificity | F1 | Balanced accuracy |\n|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n");
    for lane in &results.lanes {
        append_metric_rows(&mut output, &lane.scanner, "family", &lane.by_family);
        append_metric_rows(&mut output, &lane.scanner, "framework", &lane.by_framework);
        append_metric_rows(
            &mut output,
            &lane.scanner,
            "source_format",
            &lane.by_source_format,
        );
        append_metric_rows(&mut output, &lane.scanner, "topology", &lane.by_topology);
        append_metric_rows(
            &mut output,
            &lane.scanner,
            "adversarial_variant",
            &lane.by_adversarial_variant,
        );
        append_metric_rows(
            &mut output,
            &lane.scanner,
            "classification",
            &lane.by_classification,
        );
    }
    output.push_str("\n## Pair results\n\n| Scanner | Pair | Vulnerable case | Control case | Vulnerable flagged | Control flagged | Exact pair |\n|---|---|---|---|---:|---:|---:|\n");
    for lane in &results.lanes {
        for pair in &lane.pairs {
            output.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} |\n",
                lane.scanner,
                pair.pair_id,
                pair.vulnerable_case_id,
                pair.control_case_id,
                pair.vulnerable_flagged,
                pair.control_flagged,
                pair.pair_exact,
            ));
        }
    }
    output.push_str("\n## Case results\n\n| Scanner | Case | Pair | Expected | Findings | Positive | Outcome | Family | Framework | Format | Topology | Variant |\n|---|---|---|---|---:|---:|---|---|---|---|---|---|\n");
    for lane in &results.lanes {
        for case in &lane.cases {
            output.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
                lane.scanner,
                case.case_id,
                case.pair_id,
                case.expected,
                case.finding_count,
                case.predicted_positive,
                case.outcome,
                case.family,
                case.framework,
                case.source_format,
                case.topology,
                case.adversarial_variant,
            ));
        }
    }
    output.push_str("\n## Historical phase-separated table\n\n| Phase | Study | Scanner | Lane | State | Attempts | Note |\n|---|---|---|---|---|---:|---|\n");
    for row in &results.historical {
        output.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} |\n",
            row.phase, row.study, row.scanner, row.lane, row.state, row.attempts, row.note
        ));
    }
    output.push_str("\n## Limitations\n\nThe infrastructure correction changes only sandbox operability. Rules, corpus, expectations, and methodology are unchanged. Cross-phase results are not merged, native and normalized lanes are not ranked, and no overall winner is declared. See `limitations.md` for the complete validity boundary.\n");
    output
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

fn write_sums(output: &Path) -> Result<(), Phase22Error> {
    let sums = output.join("SHA256SUMS");
    if sums.exists() {
        fs::remove_file(&sums)?;
    }
    let mut files = Vec::new();
    collect_files(output, &mut files)?;
    let mut content = String::new();
    for file in files {
        if file == sums {
            continue;
        }
        let relative = file.strip_prefix(output).map_err(|_| {
            Phase22Error::Execution(format!("output escaped root: {}", file.display()))
        })?;
        content.push_str(&format!(
            "{}  {}\n",
            sha256_file(&file)?,
            relative.to_string_lossy()
        ));
    }
    write_atomic(&sums, content.as_bytes())
}

fn write_outputs(
    root: &Path,
    plan: &ExecutionPlan,
    cases: &BTreeMap<String, CaseSpec>,
    observations: &[Observation],
    ledger_head: &str,
) -> Result<Value, Phase22Error> {
    let output = root.join(OUTPUT);
    let results = compute(cases, observations)?;
    write_atomic(&output.join("results.json"), &canonical_json(&results)?)?;
    write_atomic(
        &output.join("comparison.json"),
        &canonical_json(&results.comparison)?,
    )?;
    write_atomic(
        &output.join("disagreements.json"),
        &canonical_json(&results.comparison.disagreements)?,
    )?;
    let strata = json!({
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
    });
    write_atomic(&output.join("strata.json"), &canonical_json(&strata)?)?;
    write_atomic(&output.join("report.md"), report(&results).as_bytes())?;
    write_atomic(&output.join("limitations.md"), LIMITATIONS.as_bytes())?;
    let failures = observations
        .iter()
        .filter(|observation| observation.state != AttemptState::Completed)
        .collect::<Vec<_>>();
    let mut failures_by_state = BTreeMap::<&str, u64>::new();
    let mut failures_by_scanner = BTreeMap::<&str, u64>::new();
    for observation in &failures {
        *failures_by_state
            .entry(state_name(&observation.state))
            .or_default() += 1;
        *failures_by_scanner
            .entry(observation.scanner.as_str())
            .or_default() += 1;
    }
    let failure_analysis = json!({
        "schema_version": "secure-bench-phase22-failure-analysis-v1",
        "study": "post-open recovery study",
        "non_completed_attempts": failures.len(),
        "by_state": failures_by_state,
        "by_scanner": failures_by_scanner,
        "failures": failures,
        "imputation": false,
        "retries": 0,
    });
    write_atomic(
        &output.join("failure-analysis.json"),
        &canonical_json(&failure_analysis)?,
    )?;
    let provenance = json!({
        "schema_version": "secure-bench-phase22-provenance-v1",
        "study": "post-open recovery study",
        "phase19_commit": "b3e983891e4ae3e12cd727f6bdb460962f876a30",
        "phase20_commit": "6c27c9bb26b96855228d1a8e6483483ff4174907",
        "phase21_commit": "be1ce9327c5c2acab25abe5af7a4f923d1623c48",
        "phase20_subtree": "05cd69281777263a4f9286069767d870014cab52",
        "execution_plan_sha256": sha256_file(&root.join("phase22/config/execution-plan-v1.json"))?,
        "execution_contract_sha256": sha256_file(&root.join("phase22/config/execution-contract-v1.json"))?,
        "implementation_sha256": crate::implementation_digest(root)?,
        "preflight_sha256s_sha256": sha256_file(&root.join("phase22/preflight/SHA256SUMS"))?,
        "phase21_corrected_contract_sha256": "186011766acc155a66c4a965094baf8fca335b56338363610a4d713d41876cae",
        "phase19_manifest_sha256": "c035f9de14e2a1cb7c65562f9a643f0eefafc682d23c90e520770c7183068cb6",
        "aggregate_corpus_sha256": CORPUS_SHA256,
        "contract_merkle_root": CONTRACT_MERKLE_ROOT,
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
    write_atomic(
        &output.join("provenance.json"),
        &canonical_json(&provenance)?,
    )?;
    let report = crate::verify::verify_without_sums(root)?;
    write_atomic(
        &output.join("independent-verification.json"),
        &canonical_json(&report)?,
    )?;
    write_sums(&output)?;
    Ok(json!({
        "state": "completed",
        "study": "post-open recovery study",
        "planned_attempts": plan.total_attempts,
        "executed_attempts": observations.len(),
        "retries": 0,
        "secure_engine_attempts": 0,
        "ledger_head": ledger_head,
    }))
}

/// Execute the frozen 224-attempt plan exactly once after an irreversible marker.
pub fn execute_once(root: &Path) -> Result<Value, Phase22Error> {
    verify_saved_preflight(root)?;
    let output = root.join(OUTPUT);
    if output.exists() {
        return Err(Phase22Error::Contract(format!(
            "Phase 22 output already exists: {}",
            output.display()
        )));
    }
    fs::create_dir_all(&output)?;
    let plan = load_plan(root)?;
    let opened = json!({
        "schema_version": "secure-bench-phase22-corpus-opened-v1",
        "study": "post-open recovery study",
        "opened_at_unix_ms": now_ms()?,
        "plan_sha256": sha256_file(&root.join("phase22/config/execution-plan-v1.json"))?,
        "contract_sha256": sha256_file(&root.join("phase22/config/execution-contract-v1.json"))?,
        "preflight_sha256s_sha256": sha256_file(&root.join("phase22/preflight/SHA256SUMS"))?,
        "implementation_sha256": crate::implementation_digest(root)?,
        "planned_attempts": 224,
        "retries": 0,
        "secure_engine_attempts": 0,
        "statement": "irreversible marker written before reading the Phase 19 manifest or any case",
    });
    create_irreversible(
        &output.join("CORPUS_OPENED.json"),
        &canonical_json(&opened)?,
    )?;
    let cases = load_cases_post_open(root)?;
    let plan_cases = plan
        .attempts
        .iter()
        .map(|attempt| attempt.case_id.as_str())
        .collect::<BTreeSet<_>>();
    let manifest_cases = cases.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if plan_cases != manifest_cases {
        return Err(Phase22Error::Execution(
            "post-open manifest IDs differ from the frozen opaque plan".to_owned(),
        ));
    }
    let mut observations = Vec::with_capacity(224);
    let ledger_path = output.join("ledger.jsonl");
    let mut previous = "0".repeat(64);
    for attempt in &plan.attempts {
        let case = cases.get(&attempt.case_id).ok_or_else(|| {
            Phase22Error::Execution(format!("plan references unknown case {}", attempt.case_id))
        })?;
        let observation = run_attempt(root, attempt, case)?;
        previous = append_ledger(&ledger_path, &observation, &previous)?;
        println!(
            "attempt {}/224 {} {} {:?} findings={:?} duration_ms={}",
            attempt.sequence,
            attempt.scanner,
            attempt.case_id,
            observation.state,
            observation.finding_count,
            observation.duration_ms
        );
        observations.push(observation);
    }
    if observations.len() != 224 {
        return Err(Phase22Error::Execution(format!(
            "executed {} attempts, expected 224",
            observations.len()
        )));
    }
    write_outputs(root, &plan, &cases, &observations, &previous)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repository_root() -> Result<std::path::PathBuf, std::io::Error> {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .canonicalize()
    }

    fn report(scanner: Scanner) -> Value {
        let mut value = json!({
            "version": scanner.version(),
            "errors": [],
            "results": [{
                "check_id": ALLOWED_RULES[0],
                "path": "app.js",
                "start": {"line": 1, "col": 1, "offset": 0},
                "end": {"line": 1, "col": 5, "offset": 4},
                "extra": {}
            }]
        });
        if scanner == Scanner::Semgrep {
            value["skipped_rules"] = json!([]);
            value["engine_requested"] = json!("OSS");
            value["paths"] = json!({"scanned": ["app.js"]});
            value["results"][0]["extra"]["engine_kind"] = json!("OSS");
        }
        value
    }

    #[test]
    fn normalized_adapters_match_frozen_phase20_fail_closed_semantics()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = repository_root()?;
        let fixture = tempfile::tempdir()?;
        fs::write(fixture.path().join("app.js"), b"eval(input);\n")?;
        for scanner in [Scanner::OpenGrep, Scanner::Semgrep] {
            let valid = serde_json::to_vec(&report(scanner))?;
            assert_eq!(adapt_raw(&root, scanner, fixture.path(), &valid), Ok(1));

            let mut traversal = report(scanner);
            traversal["results"][0]["path"] = json!("../app.js");
            assert!(
                adapt_raw(
                    &root,
                    scanner,
                    fixture.path(),
                    &serde_json::to_vec(&traversal)?
                )
                .is_err()
            );

            let mut invalid_span = report(scanner);
            invalid_span["results"][0]["end"]["col"] = json!(99);
            assert!(
                adapt_raw(
                    &root,
                    scanner,
                    fixture.path(),
                    &serde_json::to_vec(&invalid_span)?
                )
                .is_err()
            );

            let mut unknown_rule = report(scanner);
            unknown_rule["results"][0]["check_id"] = json!("unknown.rule");
            assert!(
                adapt_raw(
                    &root,
                    scanner,
                    fixture.path(),
                    &serde_json::to_vec(&unknown_rule)?
                )
                .is_err()
            );
        }

        let mut semgrep_offset_drift = report(Scanner::Semgrep);
        semgrep_offset_drift["results"][0]["end"]["offset"] = json!(5);
        assert!(
            adapt_raw(
                &root,
                Scanner::Semgrep,
                fixture.path(),
                &serde_json::to_vec(&semgrep_offset_drift)?
            )
            .is_err()
        );
        Ok(())
    }
}
