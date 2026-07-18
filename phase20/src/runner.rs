use crate::model::{CaseSpec, Comparison, ExecutionState, LaneResult, Observation, Ratio, Results};
use crate::preflight::{
    CORPUS_SHA256, MERKLE_ROOT, OPENGREP_BINARY, PHASE19_COMMIT, RULESET_SHA256, SECURE_BINARY,
    SEMGREP_BINARY, tool_mount, verify_saved,
};
use crate::score::{decide, grouped, metrics, pairs};
use crate::{
    Phase20Error, canonical_json, copy_tree, now_ms, read, sha256, validate_schema, write_atomic,
};
use secure_bench_core::taxonomy::load_taxonomy;
use secure_bench_phase16::{AdapterRoute, project_report};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const OUTPUT: &str = "phase20/output";
const RUN_ROOT: &str = "/var/tmp/secure-bench-phase20-one-shot";
const TIMEOUT: Duration = Duration::from_millis(120_000);
const MAX_OUTPUT: u64 = 10 * 1024 * 1024;
const NORMALIZED_RULE_IDS: [&str; 7] = [
    "secure-bench.phase19.SE1001.resource-authorization",
    "secure-bench.phase19.SE1002.command-injection",
    "secure-bench.phase19.SE1003.dynamic-code",
    "secure-bench.phase19.SE1004.path-traversal",
    "secure-bench.phase19.SE1005.outbound-request",
    "secure-bench.phase19.SE1006.open-redirect",
    "secure-bench.phase19.SE1007.sql-injection",
];

#[derive(Clone, Copy)]
pub(crate) struct Lane {
    pub(crate) scanner: &'static str,
    pub(crate) lane: &'static str,
    binary: &'static str,
    rules: bool,
}

const ELIGIBLE: [Lane; 3] = [
    Lane {
        scanner: "secure-engine",
        lane: "native",
        binary: SECURE_BINARY,
        rules: false,
    },
    Lane {
        scanner: "opengrep",
        lane: "capability-normalized",
        binary: OPENGREP_BINARY,
        rules: true,
    },
    Lane {
        scanner: "semgrep-ce",
        lane: "capability-normalized",
        binary: SEMGREP_BINARY,
        rules: true,
    },
];

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LedgerEntry {
    schema_version: String,
    sequence: u64,
    timestamp_unix_ms: u128,
    event: String,
    payload_sha256: String,
    previous_entry_hash: String,
    entry_hash: String,
}

fn load_cases(root: &Path) -> Result<Vec<CaseSpec>, Phase20Error> {
    let manifest: Value =
        serde_json::from_slice(&read(&root.join("phase19/holdout/manifest.json"))?)?;
    let pair_values = manifest
        .get("pairs")
        .and_then(Value::as_array)
        .ok_or_else(|| Phase20Error::Contract("Phase 19 manifest has no pairs".to_owned()))?;
    let mut cases = Vec::with_capacity(112);
    for pair in pair_values {
        let pair_id = pair
            .get("pair_id")
            .and_then(Value::as_str)
            .ok_or_else(|| Phase20Error::Contract("pair has no ID".to_owned()))?;
        let assignment = pair
            .get("assignment")
            .ok_or_else(|| Phase20Error::Contract("pair has no assignment".to_owned()))?;
        for side in ["first", "second"] {
            let case = pair
                .get(side)
                .ok_or_else(|| Phase20Error::Contract("pair member is absent".to_owned()))?;
            let text = |object: &Value, field: &str| {
                object
                    .get(field)
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .ok_or_else(|| Phase20Error::Contract(format!("case omits {field}")))
            };
            cases.push(CaseSpec {
                case_id: text(case, "case_id")?,
                pair_id: pair_id.to_owned(),
                classification: text(case, "classification")?,
                family: text(assignment, "family")?,
                framework: text(assignment, "framework")?,
                source_format: text(assignment, "source_format")?,
                topology: text(assignment, "topology")?,
                fixture_path: text(case, "fixture_path")?,
            });
        }
    }
    cases.sort_by(|left, right| left.case_id.cmp(&right.case_id));
    if cases.len() != 112
        || cases
            .iter()
            .map(|case| &case.case_id)
            .collect::<BTreeSet<_>>()
            .len()
            != 112
    {
        return Err(Phase20Error::Contract(
            "Phase 19 case population is not 112 unique IDs".to_owned(),
        ));
    }
    Ok(cases)
}

fn normalized_manifest(root: &Path, scanner: &str) -> Result<Value, Phase20Error> {
    let source = if scanner == "opengrep" {
        "phase20/config/opengrep-normalized-adapter-v1.json"
    } else {
        "phase20/config/semgrep-normalized-adapter-v1.json"
    };
    let manifest: Value = serde_json::from_slice(&read(&root.join(source))?)?;
    let expected_id = if scanner == "opengrep" {
        "opengrep"
    } else {
        "semgrep"
    };
    let expected_version = if scanner == "opengrep" {
        "1.22.0"
    } else {
        "1.170.0"
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
        || manifest.pointer("/scanner/version").and_then(Value::as_str) != Some(expected_version)
        || manifest.pointer("/ruleset/sha256").and_then(Value::as_str) != Some(RULESET_SHA256)
        || rule_ids != Some(NORMALIZED_RULE_IDS.into_iter().collect::<BTreeSet<_>>())
        || manifest
            .pointer("/resources/timeout_ms")
            .and_then(Value::as_u64)
            != Some(u64::try_from(TIMEOUT.as_millis()).unwrap_or(u64::MAX))
        || manifest
            .pointer("/resources/max_output_bytes")
            .and_then(Value::as_u64)
            != Some(MAX_OUTPUT)
        || manifest
            .pointer("/adapter/adapter_version")
            .and_then(Value::as_str)
            != Some("1.0.0")
        || manifest
            .pointer("/resources/network_allowed")
            .and_then(Value::as_bool)
            != Some(false)
    {
        return Err(Phase20Error::Contract(format!(
            "normalized adapter manifest drift for {scanner}"
        )));
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
            return Err(format!("scanner path traverses a symlink: `{relative}`"));
        }
    }
    let canonical = cursor.canonicalize().map_err(|error| error.to_string())?;
    if !canonical.starts_with(&canonical_root) || !canonical.is_file() {
        return Err(format!("scanner path escaped fixture: `{relative}`"));
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

fn adapt_normalized(root: &Path, scanner: &str, fixture: &Path, raw: &[u8]) -> Result<u64, String> {
    let manifest = normalized_manifest(root, scanner).map_err(|error| error.to_string())?;
    if u64::try_from(raw.len()).unwrap_or(u64::MAX) > MAX_OUTPUT {
        return Err("raw output exceeded the frozen maximum".to_owned());
    }
    let value: Value = serde_json::from_slice(raw).map_err(|error| error.to_string())?;
    let expected_version = if scanner == "opengrep" {
        "1.22.0"
    } else {
        "1.170.0"
    };
    let expected_adapter = if scanner == "opengrep" {
        ("opengrep", "secure-bench-opengrep-json", "opengrep-json-v1")
    } else {
        ("semgrep", "secure-bench-semgrep-json", "semgrep-json-v1")
    };
    if value.get("version").and_then(Value::as_str) != Some(expected_version)
        || manifest.pointer("/scanner/id").and_then(Value::as_str) != Some(expected_adapter.0)
        || manifest
            .pointer("/adapter/adapter_id")
            .and_then(Value::as_str)
            != Some(expected_adapter.1)
        || manifest
            .pointer("/adapter/raw_output_format")
            .and_then(Value::as_str)
            != Some(expected_adapter.2)
        || value
            .get("errors")
            .and_then(Value::as_array)
            .is_none_or(|items| !items.is_empty())
        || value
            .get("skipped_rules")
            .is_some_and(|items| items.as_array().is_none_or(|items| !items.is_empty()))
        || (scanner == "semgrep-ce" && value.get("skipped_rules").is_none())
    {
        return Err("scanner output or adapter identity is partial or mismatched".to_owned());
    }
    let scanned_paths = if scanner == "semgrep-ce" {
        if value.get("engine_requested").and_then(Value::as_str) != Some("OSS") {
            return Err("Semgrep output is not CE OSS output".to_owned());
        }
        let paths = value
            .pointer("/paths/scanned")
            .and_then(Value::as_array)
            .ok_or_else(|| "Semgrep output has no paths.scanned".to_owned())?;
        let mut unique_paths = BTreeSet::new();
        for path in paths {
            let path = path
                .as_str()
                .ok_or_else(|| "Semgrep scanned path is not a string".to_owned())?;
            let (relative, _) = source_bytes(fixture, path)?;
            if !unique_paths.insert(relative) {
                return Err("Semgrep output repeats a scanned path".to_owned());
            }
        }
        Some(unique_paths)
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
        .ok_or_else(|| "scanner output has no results array".to_owned())?;
    for result in results {
        let rule = result
            .get("check_id")
            .and_then(Value::as_str)
            .ok_or_else(|| "result has no rule ID".to_owned())?;
        if !allowed.contains(rule) {
            return Err(format!("scanner emitted unknown rule `{rule}`"));
        }
        if scanner == "semgrep-ce"
            && result.pointer("/extra/engine_kind").and_then(Value::as_str) != Some("OSS")
        {
            return Err("Semgrep result is not from the OSS engine".to_owned());
        }
        let relative = validate_result(fixture, result, scanner == "semgrep-ce")?;
        if scanned_paths
            .as_ref()
            .is_some_and(|paths| !paths.contains(&relative))
        {
            return Err("Semgrep result path is absent from paths.scanned".to_owned());
        }
    }
    Ok(u64::try_from(results.len()).unwrap_or(u64::MAX))
}

fn scanner_arguments(lane: Lane) -> Vec<String> {
    match lane.scanner {
        "secure-engine" => vec![
            lane.binary.to_owned(),
            "scan".to_owned(),
            ".".to_owned(),
            "--format".to_owned(),
            "secure-json-v1".to_owned(),
            "--output".to_owned(),
            "/tmp/run/raw.json".to_owned(),
        ],
        "opengrep" => vec![
            lane.binary.to_owned(),
            "scan".to_owned(),
            "--json".to_owned(),
            "--json-output=/tmp/run/raw.json".to_owned(),
            "--error".to_owned(),
            "--disable-version-check".to_owned(),
            "--no-rewrite-rule-ids".to_owned(),
            "--config=/tmp/rules/capability-normalized-v1.yml".to_owned(),
            ".".to_owned(),
        ],
        _ => vec![
            lane.binary.to_owned(),
            "scan".to_owned(),
            "--json".to_owned(),
            "--json-output=/tmp/run/raw.json".to_owned(),
            "--error".to_owned(),
            "--metrics=off".to_owned(),
            "--disable-version-check".to_owned(),
            "--no-rewrite-rule-ids".to_owned(),
            "--no-git-ignore".to_owned(),
            "--config=/tmp/rules/capability-normalized-v1.yml".to_owned(),
            ".".to_owned(),
        ],
    }
}

fn bwrap_arguments(
    root: &Path,
    lane: Lane,
    fixture: &Path,
    output: &Path,
) -> Result<Vec<String>, Phase20Error> {
    let (tool_source, tool_target) = tool_mount(lane.scanner)?;
    let scanner_args = scanner_arguments(lane);
    let mut args = vec![
        "--unshare-net".to_owned(),
        "--unshare-pid".to_owned(),
        "--die-with-parent".to_owned(),
        "--new-session".to_owned(),
        "--as-pid-1".to_owned(),
        "--ro-bind".to_owned(),
        "/".to_owned(),
        "/".to_owned(),
        "--tmpfs".to_owned(),
        "/tmp".to_owned(),
        "--dir".to_owned(),
        "/tmp/secure-bench-tools".to_owned(),
        "--dir".to_owned(),
        "/tmp/fixture".to_owned(),
        "--dir".to_owned(),
        "/tmp/run".to_owned(),
    ];
    let target_parent = tool_target.parent().ok_or_else(|| {
        Phase20Error::Execution("tool cache mount has no target parent".to_owned())
    })?;
    let mut prefix = PathBuf::from("/tmp/secure-bench-tools");
    for part in target_parent
        .strip_prefix("/tmp/secure-bench-tools")
        .map_err(|_| Phase20Error::Execution("tool cache escaped /tmp".to_owned()))?
        .components()
    {
        prefix.push(part);
        args.extend(["--dir".to_owned(), prefix.to_string_lossy().into_owned()]);
    }
    args.extend([
        "--ro-bind".to_owned(),
        tool_source.to_string_lossy().into_owned(),
        tool_target.to_string_lossy().into_owned(),
        "--ro-bind".to_owned(),
        fixture.to_string_lossy().into_owned(),
        "/tmp/fixture".to_owned(),
        "--bind".to_owned(),
        output.to_string_lossy().into_owned(),
        "/tmp/run".to_owned(),
    ]);
    if lane.rules {
        args.extend([
            "--dir".to_owned(),
            "/tmp/rules".to_owned(),
            "--ro-bind".to_owned(),
            root.join("phase19/rules/capability-normalized-v1.yml")
                .to_string_lossy()
                .into_owned(),
            "/tmp/rules/capability-normalized-v1.yml".to_owned(),
        ]);
    }
    args.extend([
        "--chdir".to_owned(),
        "/tmp/fixture".to_owned(),
        "--setenv".to_owned(),
        "HOME".to_owned(),
        "/tmp/home".to_owned(),
        "--setenv".to_owned(),
        "XDG_CACHE_HOME".to_owned(),
        "/tmp/cache".to_owned(),
        "--setenv".to_owned(),
        "SEMGREP_SEND_METRICS".to_owned(),
        "off".to_owned(),
        "--setenv".to_owned(),
        "SEMGREP_ENABLE_VERSION_CHECK".to_owned(),
        "0".to_owned(),
        "--".to_owned(),
        "/usr/bin/prlimit".to_owned(),
        "--as=4294967296".to_owned(),
        "--nproc=64".to_owned(),
        "--".to_owned(),
    ]);
    args.extend(scanner_args);
    Ok(args)
}

pub(crate) fn synthetic_containment(
    root: &Path,
    fixture: &Path,
    output: &Path,
) -> Result<(), Phase20Error> {
    let mut args = bwrap_arguments(root, ELIGIBLE[1], fixture, output)?;
    let scanner_separator = args
        .iter()
        .rposition(|argument| argument == "--")
        .ok_or_else(|| {
            Phase20Error::Preflight(
                "synthetic bwrap arguments have no scanner separator".to_owned(),
            )
        })?;
    args.truncate(scanner_separator + 1);
    args.extend([
        "/bin/sh".to_owned(),
        "-c".to_owned(),
        "/usr/bin/true & wait".to_owned(),
    ]);
    let result = Command::new("/usr/bin/bwrap")
        .args(&args)
        .env_clear()
        .env("LANG", "C.UTF-8")
        .env("LC_ALL", "C.UTF-8")
        .env("PATH", "/usr/bin:/bin")
        .env("TZ", "UTC")
        .stdin(Stdio::null())
        .output()
        .map_err(|error| Phase20Error::Preflight(format!("synthetic bwrap spawn: {error}")))?;
    if !result.status.success() {
        return Err(Phase20Error::Preflight(format!(
            "synthetic bwrap containment failed with {}: {}",
            result.status,
            String::from_utf8_lossy(&result.stderr).trim()
        )));
    }
    Ok(())
}

pub(crate) fn hash_vector(values: &[String]) -> String {
    let mut bytes = Vec::new();
    for value in values {
        bytes.extend_from_slice(value.as_bytes());
        bytes.push(0);
    }
    sha256(&bytes)
}

pub(crate) fn adapt(
    root: &Path,
    lane: Lane,
    case: &CaseSpec,
    fixture: &Path,
    raw: &[u8],
) -> Result<u64, String> {
    match lane.scanner {
        "secure-engine" => {
            let taxonomy = load_taxonomy(
                &read(&root.join("taxonomy/secure-bench-taxonomy-v1.json"))
                    .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
            let projection =
                project_report(&case.case_id, raw, AdapterRoute::AuthoritativeV2, &taxonomy)
                    .map_err(|error| error.to_string())?;
            Ok(u64::try_from(projection.findings.len()).unwrap_or(u64::MAX))
        }
        "opengrep" => adapt_normalized(root, lane.scanner, fixture, raw),
        _ => adapt_normalized(root, lane.scanner, fixture, raw),
    }
}

fn process_decision(
    lane: Lane,
    exit_code: Option<i32>,
    timed_out: bool,
    findings: Option<u64>,
) -> String {
    if timed_out {
        return "timeout".to_owned();
    }
    let Some(code) = exit_code else {
        return "genuine-crash".to_owned();
    };
    let Some(findings) = findings else {
        return "malformed-report".to_owned();
    };
    match (lane.scanner, code, findings) {
        (_, 0, 0) => "clean-successful-report",
        (_, 0, _) => "successful-findings-report",
        ("opengrep" | "semgrep-ce", 1, count) if count > 0 => "successful-findings-report",
        ("secure-engine", _, count) if count > 0 => "policy-exit-with-valid-findings-report",
        _ => "genuine-crash",
    }
    .to_owned()
}

fn run_attempt(
    root: &Path,
    lane: Lane,
    case: &CaseSpec,
    sequence: u64,
) -> Result<Observation, Phase20Error> {
    let fixture = Path::new(RUN_ROOT)
        .join(format!("{:03}", sequence))
        .join("fixture");
    copy_tree(&root.join(&case.fixture_path), &fixture)?;
    let relative_dir = format!(
        "{OUTPUT}/raw/{}/{}/{}",
        lane.scanner, lane.lane, case.case_id
    );
    let output = root.join(&relative_dir);
    fs::create_dir_all(&output)?;
    let raw_path = output.join("raw.json");
    let stdout_path = output.join("stdout.bin");
    let stderr_path = output.join("stderr.bin");
    let stdout = File::create(&stdout_path)?;
    let stderr = File::create(&stderr_path)?;
    let args = bwrap_arguments(root, lane, &fixture, &output)?;
    let mut full_command = vec!["/usr/bin/bwrap".to_owned()];
    full_command.extend(args.clone());
    let environment = vec![
        "HOME=/tmp/home".to_owned(),
        "LANG=C.UTF-8".to_owned(),
        "LC_ALL=C.UTF-8".to_owned(),
        "PATH=/usr/bin:/bin".to_owned(),
        "SEMGREP_ENABLE_VERSION_CHECK=0".to_owned(),
        "SEMGREP_SEND_METRICS=off".to_owned(),
        "TZ=UTC".to_owned(),
        "XDG_CACHE_HOME=/tmp/cache".to_owned(),
    ];
    let started_at_unix_ms = now_ms()?;
    let started = Instant::now();
    let spawn = Command::new("/usr/bin/bwrap")
        .args(&args)
        .env_clear()
        .env("LANG", "C.UTF-8")
        .env("LC_ALL", "C.UTF-8")
        .env("PATH", "/usr/bin:/bin")
        .env("TZ", "UTC")
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn();
    let (exit_code, timed_out, spawn_failure) = match spawn {
        Ok(mut child) => {
            let mut timed_out = false;
            let status = loop {
                if let Some(status) = child.try_wait()? {
                    break Some(status);
                }
                if started.elapsed() >= TIMEOUT {
                    timed_out = true;
                    child.kill()?;
                    break Some(child.wait()?);
                }
                thread::sleep(Duration::from_millis(10));
            };
            (status.and_then(|value| value.code()), timed_out, None)
        }
        Err(error) => (None, false, Some(error.to_string())),
    };
    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let stdout_bytes = read(&stdout_path)?;
    let stderr_bytes = read(&stderr_path)?;
    let raw_bytes = raw_path.exists().then(|| read(&raw_path)).transpose()?;
    let mut failure = spawn_failure;
    let finding_count = if failure.is_none() && !timed_out {
        match raw_bytes.as_deref() {
            Some(bytes) if u64::try_from(bytes.len()).unwrap_or(u64::MAX) <= MAX_OUTPUT => {
                match adapt(root, lane, case, &fixture, bytes) {
                    Ok(count) => Some(count),
                    Err(error) => {
                        failure = Some(format!("adapter rejected raw output: {error}"));
                        None
                    }
                }
            }
            Some(_) => {
                failure = Some("raw output exceeded 10485760 bytes".to_owned());
                None
            }
            None => {
                failure = Some("scanner produced no raw output".to_owned());
                None
            }
        }
    } else {
        if timed_out {
            failure = Some("wall-clock timeout".to_owned());
        }
        None
    };
    let decision = process_decision(lane, exit_code, timed_out, finding_count);
    let completed = matches!(
        decision.as_str(),
        "clean-successful-report"
            | "successful-findings-report"
            | "policy-exit-with-valid-findings-report"
    );
    if !completed && failure.is_none() {
        failure = Some(format!("process policy decision: {decision}"));
    }
    let observation = Observation {
        attempt_sequence: sequence,
        scanner: lane.scanner.to_owned(),
        lane: lane.lane.to_owned(),
        case_id: case.case_id.clone(),
        state: if completed {
            ExecutionState::Completed
        } else {
            ExecutionState::Failed
        },
        process_decision: decision,
        exit_code,
        timed_out,
        duration_ms,
        started_at_unix_ms,
        command_sha256: hash_vector(&full_command),
        command: full_command,
        environment: environment.clone(),
        environment_sha256: hash_vector(&environment),
        stdout_sha256: sha256(&stdout_bytes),
        stderr_sha256: sha256(&stderr_bytes),
        raw_output_sha256: raw_bytes.as_deref().map(sha256),
        finding_count: completed.then_some(finding_count).flatten(),
        raw_output_path: raw_bytes
            .as_ref()
            .map(|_| format!("{relative_dir}/raw.json")),
        stdout_path: format!("{relative_dir}/stdout.bin"),
        stderr_path: format!("{relative_dir}/stderr.bin"),
        failure,
    };
    let observation_path = output.join("observation.json");
    write_atomic(&observation_path, &canonical_json(&observation)?)?;
    Ok(observation)
}

fn append_ledger(
    path: &Path,
    sequence: u64,
    event: &str,
    payload_sha256: &str,
    previous: &str,
) -> Result<String, Phase20Error> {
    let timestamp = now_ms()?;
    let material = json!({
        "schema_version": "secure-bench-phase20-ledger-entry-v1",
        "sequence": sequence,
        "timestamp_unix_ms": timestamp,
        "event": event,
        "payload_sha256": payload_sha256,
        "previous_entry_hash": previous
    });
    let entry_hash = sha256(&serde_json::to_vec(&material)?);
    let entry = LedgerEntry {
        schema_version: "secure-bench-phase20-ledger-entry-v1".to_owned(),
        sequence,
        timestamp_unix_ms: timestamp,
        event: event.to_owned(),
        payload_sha256: payload_sha256.to_owned(),
        previous_entry_hash: previous.to_owned(),
        entry_hash: entry_hash.clone(),
    };
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(&serde_json::to_vec(&entry)?)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(entry_hash)
}

fn unsupported(scanner: &str, lane: &str, reason: &str) -> LaneResult {
    LaneResult {
        scanner: scanner.to_owned(),
        lane: lane.to_owned(),
        state: ExecutionState::Unsupported,
        reason: Some(reason.to_owned()),
        process_attempts: 0,
        completed_attempts: 0,
        failed_attempts: 0,
        total_duration_ms: 0,
        metrics: None,
        cases: Vec::new(),
        pairs: Vec::new(),
        by_family: BTreeMap::new(),
        by_framework: BTreeMap::new(),
        by_source_format: BTreeMap::new(),
        by_topology: BTreeMap::new(),
    }
}

fn completed_lane(lane: Lane, cases: &[CaseSpec], observations: &[Observation]) -> LaneResult {
    let selected = observations
        .iter()
        .filter(|item| item.scanner == lane.scanner && item.lane == lane.lane)
        .collect::<Vec<_>>();
    let completed_attempts = u64::try_from(
        selected
            .iter()
            .filter(|item| item.state == ExecutionState::Completed)
            .count(),
    )
    .unwrap_or(u64::MAX);
    let failed_attempts = u64::try_from(selected.len()).unwrap_or(u64::MAX) - completed_attempts;
    let findings = selected
        .iter()
        .filter_map(|item| {
            item.finding_count
                .map(|count| (item.case_id.clone(), count))
        })
        .collect::<BTreeMap<_, _>>();
    let decisions = (failed_attempts == 0 && findings.len() == cases.len())
        .then(|| decide(cases, &findings))
        .unwrap_or_default();
    let state = if failed_attempts == 0 && decisions.len() == cases.len() {
        ExecutionState::Completed
    } else {
        ExecutionState::Failed
    };
    let reason = (state == ExecutionState::Failed).then(|| {
        format!(
            "{failed_attempts} of {} one-shot attempts failed",
            selected.len()
        )
    });
    LaneResult {
        scanner: lane.scanner.to_owned(),
        lane: lane.lane.to_owned(),
        state: state.clone(),
        reason,
        process_attempts: u64::try_from(selected.len()).unwrap_or(u64::MAX),
        completed_attempts,
        failed_attempts,
        total_duration_ms: selected.iter().map(|item| item.duration_ms).sum(),
        metrics: (state == ExecutionState::Completed).then(|| metrics(&decisions)),
        pairs: (state == ExecutionState::Completed)
            .then(|| pairs(&decisions))
            .unwrap_or_default(),
        by_family: (state == ExecutionState::Completed)
            .then(|| grouped(&decisions, |item| &item.family))
            .unwrap_or_default(),
        by_framework: (state == ExecutionState::Completed)
            .then(|| grouped(&decisions, |item| &item.framework))
            .unwrap_or_default(),
        by_source_format: (state == ExecutionState::Completed)
            .then(|| grouped(&decisions, |item| &item.source_format))
            .unwrap_or_default(),
        by_topology: (state == ExecutionState::Completed)
            .then(|| grouped(&decisions, |item| &item.topology))
            .unwrap_or_default(),
        cases: decisions,
    }
}

fn abs_ratio(left: &Ratio, right: &Ratio) -> Ratio {
    let left_scaled = left.numerator.saturating_mul(right.denominator);
    let right_scaled = right.numerator.saturating_mul(left.denominator);
    let numerator = left_scaled.abs_diff(right_scaled);
    let denominator = left.denominator.saturating_mul(right.denominator);
    Ratio {
        numerator,
        denominator,
        decimal: if denominator == 0 {
            "undefined".to_owned()
        } else {
            format!("{:.6}", numerator as f64 / denominator as f64)
        },
    }
}

fn comparisons(lanes: &[LaneResult]) -> Vec<Comparison> {
    let open = lanes
        .iter()
        .find(|lane| lane.scanner == "opengrep" && lane.lane == "capability-normalized");
    let sem = lanes
        .iter()
        .find(|lane| lane.scanner == "semgrep-ce" && lane.lane == "capability-normalized");
    let normalized = match (open, sem) {
        (Some(left), Some(right))
            if left.state == ExecutionState::Completed
                && right.state == ExecutionState::Completed =>
        {
            let mut right_cases = BTreeMap::new();
            for item in &right.cases {
                right_cases.insert(item.case_id.as_str(), item);
            }
            let mut agreements = 0;
            let mut left_only_correct = 0;
            let mut right_only_correct = 0;
            for item in &left.cases {
                if let Some(other) = right_cases.get(item.case_id.as_str()) {
                    if item.predicted_positive == other.predicted_positive {
                        agreements += 1;
                    }
                    let left_correct = matches!(item.outcome.as_str(), "tp" | "tn");
                    let right_correct = matches!(other.outcome.as_str(), "tp" | "tn");
                    if left_correct && !right_correct {
                        left_only_correct += 1;
                    } else if !left_correct && right_correct {
                        right_only_correct += 1;
                    }
                }
            }
            let mut differences = BTreeMap::new();
            if let (Some(left_metrics), Some(right_metrics)) = (&left.metrics, &right.metrics) {
                for (name, a, b) in [
                    (
                        "precision",
                        &left_metrics.precision,
                        &right_metrics.precision,
                    ),
                    ("recall", &left_metrics.recall, &right_metrics.recall),
                    (
                        "specificity",
                        &left_metrics.specificity,
                        &right_metrics.specificity,
                    ),
                    ("f1", &left_metrics.f1, &right_metrics.f1),
                    (
                        "balanced_accuracy",
                        &left_metrics.balanced_accuracy,
                        &right_metrics.balanced_accuracy,
                    ),
                ] {
                    if let (Some(a), Some(b)) = (a, b) {
                        differences.insert(name.to_owned(), abs_ratio(a, b));
                    }
                }
            }
            Comparison {
                left: "opengrep/capability-normalized".to_owned(),
                right: "semgrep-ce/capability-normalized".to_owned(),
                comparability: "same-lane".to_owned(),
                agreements: Some(agreements),
                left_only_correct: Some(left_only_correct),
                right_only_correct: Some(right_only_correct),
                absolute_metric_differences: Some(differences),
                reason: None,
            }
        }
        _ => Comparison {
            left: "opengrep/capability-normalized".to_owned(),
            right: "semgrep-ce/capability-normalized".to_owned(),
            comparability: "same-lane-unavailable".to_owned(),
            agreements: None,
            left_only_correct: None,
            right_only_correct: None,
            absolute_metric_differences: None,
            reason: Some("one or both normalized lanes did not complete".to_owned()),
        },
    };
    vec![
        normalized,
        Comparison {
            left: "secure-engine/native".to_owned(),
            right: "opengrep/capability-normalized".to_owned(),
            comparability: "unavailable-cross-lane".to_owned(),
            agreements: None,
            left_only_correct: None,
            right_only_correct: None,
            absolute_metric_differences: None,
            reason: Some(
                "native and capability-normalized lanes are never compared as equivalent"
                    .to_owned(),
            ),
        },
        Comparison {
            left: "secure-engine/native".to_owned(),
            right: "semgrep-ce/capability-normalized".to_owned(),
            comparability: "unavailable-cross-lane".to_owned(),
            agreements: None,
            left_only_correct: None,
            right_only_correct: None,
            absolute_metric_differences: None,
            reason: Some(
                "native and capability-normalized lanes are never compared as equivalent"
                    .to_owned(),
            ),
        },
    ]
}

pub(crate) fn build_results(cases: &[CaseSpec], observations: &[Observation]) -> Results {
    let mut lanes = vec![
        completed_lane(ELIGIBLE[0], cases, observations),
        unsupported(
            "secure-engine",
            "capability-normalized",
            "Secure Engine 0.1.6 exposes no frozen public external-rule interface",
        ),
        unsupported(
            "opengrep",
            "native",
            "no eligible maintained offline native OpenGrep ruleset was frozen",
        ),
        completed_lane(ELIGIBLE[1], cases, observations),
        unsupported(
            "semgrep-ce",
            "native",
            "Semgrep CE has no offline built-in default security ruleset",
        ),
        completed_lane(ELIGIBLE[2], cases, observations),
    ];
    lanes.sort_by(|left, right| {
        (left.lane.as_str(), left.scanner.as_str())
            .cmp(&(right.lane.as_str(), right.scanner.as_str()))
    });
    let comparisons = comparisons(&lanes);
    let total = observations.len() as u64;
    Results {
        schema_version: "secure-bench-phase20-results-v1".to_owned(),
        phase19_commit: PHASE19_COMMIT.to_owned(),
        aggregate_corpus_sha256: CORPUS_SHA256.to_owned(),
        contract_merkle_root: MERKLE_ROOT.to_owned(),
        lanes,
        comparisons,
        total_scanner_process_attempts: total,
        repeated_attempts: observations
            .iter()
            .map(|item| (&item.scanner, &item.lane, &item.case_id))
            .collect::<BTreeSet<_>>()
            .len()
            != observations.len(),
    }
}

fn render_report(results: &Results) -> String {
    let mut report = String::from(
        "# Phase 20 neutral multi-scanner comparison\n\nNative and capability-normalized lanes are reported independently. Unsupported states are not zeros.\n\n| Scanner | Lane | State | TP | FP | TN | FN | Precision | Recall | Specificity | F1 | Balanced accuracy | Attempts | Time ms |\n|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n",
    );
    let metric = |value: &Option<Ratio>| {
        value.as_ref().map_or_else(
            || "Unavailable".to_owned(),
            |ratio| {
                format!(
                    "{} ({}/{})",
                    ratio.decimal, ratio.numerator, ratio.denominator
                )
            },
        )
    };
    for lane in &results.lanes {
        let (tp, fp, tn, fn_count, precision, recall, specificity, f1, balanced) =
            lane.metrics.as_ref().map_or_else(
                || {
                    (
                        "—".to_owned(),
                        "—".to_owned(),
                        "—".to_owned(),
                        "—".to_owned(),
                        "Unavailable".to_owned(),
                        "Unavailable".to_owned(),
                        "Unavailable".to_owned(),
                        "Unavailable".to_owned(),
                        "Unavailable".to_owned(),
                    )
                },
                |value| {
                    (
                        value.tp.to_string(),
                        value.fp.to_string(),
                        value.tn.to_string(),
                        value.fn_count.to_string(),
                        metric(&value.precision),
                        metric(&value.recall),
                        metric(&value.specificity),
                        metric(&value.f1),
                        metric(&value.balanced_accuracy),
                    )
                },
            );
        report.push_str(&format!(
            "| {} | {} | {:?} | {tp} | {fp} | {tn} | {fn_count} | {precision} | {recall} | {specificity} | {f1} | {balanced} | {} | {} |\n",
            lane.scanner, lane.lane, lane.state, lane.process_attempts, lane.total_duration_ms
        ));
    }
    report.push_str("\n## Limitations\n\n- Results describe only the frozen Phase 19 holdout and exact pinned artifacts.\n- Cross-lane quality deltas are intentionally unavailable.\n- Unsupported native or normalized capabilities receive no score and no imputed denominator.\n- Timing is descriptive process evidence and is not part of detection quality.\n");
    report
}

pub(crate) fn execute(root: &Path) -> Result<Results, Phase20Error> {
    let preflight = verify_saved(root)?;
    let output_root = root.join(OUTPUT);
    if output_root.exists() {
        return Err(Phase20Error::Execution(
            "Phase 20 output or opening marker already exists; retries are forbidden".to_owned(),
        ));
    }
    if Path::new(RUN_ROOT).exists() {
        return Err(Phase20Error::Execution(
            "external one-shot run root already exists".to_owned(),
        ));
    }
    fs::create_dir_all(&output_root)?;
    fs::create_dir_all(RUN_ROOT)?;
    let preflight_bytes = canonical_json(&preflight)?;
    let opening = json!({
        "schema_version": "secure-bench-phase20-holdout-opening-v1",
        "opened_at_unix_ms": now_ms()?,
        "phase19_commit": PHASE19_COMMIT,
        "preflight_sha256": sha256(&preflight_bytes),
        "irreversible": true,
        "retry_policy": "no retries after any scanner process start"
    });
    let opening_bytes = canonical_json(&opening)?;
    let marker = output_root.join("HOLDOUT_OPENED.json");
    let mut marker_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&marker)?;
    marker_file.write_all(&opening_bytes)?;
    marker_file.sync_all()?;
    let ledger = output_root.join("ledger.jsonl");
    let zeros = "0".repeat(64);
    let mut previous = append_ledger(
        &ledger,
        0,
        "holdout-opened",
        &sha256(&opening_bytes),
        &zeros,
    )?;
    let cases = load_cases(root)?;
    let mut observations = Vec::with_capacity(336);
    let mut sequence = 0_u64;
    for lane in ELIGIBLE {
        for case in &cases {
            sequence += 1;
            let observation = run_attempt(root, lane, case, sequence)?;
            let bytes = canonical_json(&observation)?;
            previous = append_ledger(
                &ledger,
                sequence,
                "scanner-case-attempt",
                &sha256(&bytes),
                &previous,
            )?;
            observations.push(observation);
        }
    }
    let results = build_results(&cases, &observations);
    validate_schema(root, "phase20/schemas/results-v1.schema.json", &results)?;
    let result_bytes = canonical_json(&results)?;
    write_atomic(&output_root.join("results.json"), &result_bytes)?;
    write_atomic(
        &output_root.join("report.md"),
        render_report(&results).as_bytes(),
    )?;
    previous = append_ledger(
        &ledger,
        sequence + 1,
        "results-written",
        &sha256(&result_bytes),
        &previous,
    )?;
    let artifacts = json!({
        "schema_version": "secure-bench-phase20-artifacts-v1",
        "opening_sha256": sha256(&opening_bytes),
        "ledger_sha256": sha256(&read(&ledger)?),
        "results_sha256": sha256(&result_bytes),
        "report_sha256": sha256(&read(&output_root.join("report.md"))?),
        "final_ledger_entry_hash": previous,
        "raw_observations": observations.len(),
        "scanner_process_attempts": results.total_scanner_process_attempts,
        "network_operations_during_execution": 0,
        "ai_provider_invocations": 0,
        "credential_flows": 0
    });
    write_atomic(
        &output_root.join("artifacts.json"),
        &canonical_json(&artifacts)?,
    )?;
    fs::remove_dir_all(RUN_ROOT)?;
    Ok(results)
}

pub(crate) fn observations(root: &Path) -> Result<Vec<Observation>, Phase20Error> {
    let mut paths = Vec::new();
    let raw_root = root.join(format!("{OUTPUT}/raw"));
    crate::collect_files(&raw_root, &mut paths)?;
    let mut values = paths
        .into_iter()
        .filter(|path| path.file_name().and_then(|name| name.to_str()) == Some("observation.json"))
        .map(|path| {
            serde_json::from_slice::<Observation>(&read(&path)?).map_err(Phase20Error::from)
        })
        .collect::<Result<Vec<_>, _>>()?;
    values.sort_by_key(|item| item.attempt_sequence);
    Ok(values)
}

pub(crate) fn cases(root: &Path) -> Result<Vec<CaseSpec>, Phase20Error> {
    load_cases(root)
}

pub(crate) fn verify_raw_hashes(
    root: &Path,
    observations: &[Observation],
) -> Result<(), Phase20Error> {
    for item in observations {
        let stdout = root.join(&item.stdout_path);
        let stderr = root.join(&item.stderr_path);
        if sha256(&read(&stdout)?) != item.stdout_sha256
            || sha256(&read(&stderr)?) != item.stderr_sha256
        {
            return Err(Phase20Error::Verification(format!(
                "stdout/stderr hash drift for {}",
                item.case_id
            )));
        }
        match (&item.raw_output_path, &item.raw_output_sha256) {
            (Some(path), Some(expected)) if sha256(&read(&root.join(path))?) == *expected => {}
            (None, None) => {}
            _ => {
                return Err(Phase20Error::Verification(format!(
                    "raw output hash drift for {}",
                    item.case_id
                )));
            }
        }
    }
    Ok(())
}

pub(crate) fn output_path(root: &Path, name: &str) -> PathBuf {
    root.join(OUTPUT).join(name)
}

pub(crate) fn lane(scanner: &str, lane: &str) -> Option<Lane> {
    ELIGIBLE
        .iter()
        .copied()
        .find(|value| value.scanner == scanner && value.lane == lane)
}

#[cfg(test)]
mod tests {
    use super::{ELIGIBLE, NORMALIZED_RULE_IDS, adapt_normalized, build_results, process_decision};
    use crate::model::{CaseSpec, ExecutionState, Observation};
    use serde_json::json;
    use std::fs;
    use tempfile::tempdir;

    fn case(id: &str, classification: &str) -> CaseSpec {
        CaseSpec {
            case_id: id.to_owned(),
            pair_id: "synthetic-pair".to_owned(),
            classification: classification.to_owned(),
            family: "synthetic-family".to_owned(),
            framework: "synthetic-framework".to_owned(),
            source_format: "synthetic-format".to_owned(),
            topology: "synthetic-topology".to_owned(),
            fixture_path: "synthetic-only".to_owned(),
        }
    }

    fn observation(sequence: u64, scanner: &str, lane: &str, case: &str) -> Observation {
        Observation {
            attempt_sequence: sequence,
            scanner: scanner.to_owned(),
            lane: lane.to_owned(),
            case_id: case.to_owned(),
            state: ExecutionState::Completed,
            process_decision: "clean-successful-report".to_owned(),
            exit_code: Some(0),
            timed_out: false,
            duration_ms: 1,
            started_at_unix_ms: 1,
            command_sha256: "0".repeat(64),
            command: vec!["synthetic-only".to_owned()],
            environment: vec!["synthetic-only".to_owned()],
            environment_sha256: "0".repeat(64),
            stdout_sha256: "0".repeat(64),
            stderr_sha256: "0".repeat(64),
            raw_output_sha256: Some("0".repeat(64)),
            finding_count: Some(u64::from(case.ends_with('v'))),
            raw_output_path: Some("synthetic-only".to_owned()),
            stdout_path: "synthetic-only".to_owned(),
            stderr_path: "synthetic-only".to_owned(),
            failure: None,
        }
    }

    #[test]
    fn synthetic_adapters_fail_closed_without_holdout() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempdir()?;
        let config = root.path().join("phase20/config");
        let fixture = root.path().join("fixture");
        fs::create_dir_all(&config)?;
        fs::create_dir_all(&fixture)?;
        fs::write(fixture.join("app.js"), b"sink(source);\n")?;
        for (scanner, file, scanner_id, adapter, format) in [
            (
                "opengrep",
                "opengrep-normalized-adapter-v1.json",
                "opengrep",
                "secure-bench-opengrep-json",
                "opengrep-json-v1",
            ),
            (
                "semgrep-ce",
                "semgrep-normalized-adapter-v1.json",
                "semgrep",
                "secure-bench-semgrep-json",
                "semgrep-json-v1",
            ),
        ] {
            let manifest = json!({
                "schema_version": "secure-bench-scanner-manifest-v1",
                "protocol_version": "1.0.0",
                "scanner": {
                    "id": scanner_id,
                    "version": if scanner == "opengrep" { "1.22.0" } else { "1.170.0" }
                },
                "ruleset": {
                    "sha256": super::RULESET_SHA256,
                    "rule_ids": NORMALIZED_RULE_IDS
                },
                "resources": {
                    "network_allowed": false,
                    "timeout_ms": 120000,
                    "max_output_bytes": 10485760
                },
                "adapter": {
                    "adapter_id": adapter,
                    "adapter_version": "1.0.0",
                    "raw_output_format": format
                }
            });
            fs::write(config.join(file), serde_json::to_vec(&manifest)?)?;
            let report = if scanner == "opengrep" {
                json!({
                    "version": "1.22.0", "errors": [],
                    "results": [{"check_id": NORMALIZED_RULE_IDS[0], "path": "app.js",
                        "start": {"line": 1, "col": 1, "offset": 0},
                        "end": {"line": 1, "col": 5, "offset": 4}, "extra": {}}]
                })
            } else {
                json!({
                    "version": "1.170.0", "errors": [], "skipped_rules": [],
                    "engine_requested": "OSS", "paths": {"scanned": ["app.js"]},
                    "results": [{"check_id": NORMALIZED_RULE_IDS[0], "path": "app.js",
                        "start": {"line": 1, "col": 1, "offset": 0},
                        "end": {"line": 1, "col": 5, "offset": 4},
                        "extra": {"engine_kind": "OSS"}}]
                })
            };
            assert_eq!(
                adapt_normalized(
                    root.path(),
                    scanner,
                    &fixture,
                    &serde_json::to_vec(&report)?
                )?,
                1
            );
            let mut unsafe_report = report;
            unsafe_report["results"][0]["path"] = json!("../escape.js");
            assert!(
                adapt_normalized(
                    root.path(),
                    scanner,
                    &fixture,
                    &serde_json::to_vec(&unsafe_report)?
                )
                .is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn synthetic_runner_keeps_lanes_separate() {
        let cases = vec![
            case("synthetic-v", "vulnerable"),
            case("synthetic-c", "control"),
        ];
        let mut observations = Vec::new();
        let mut sequence = 0;
        for lane in ELIGIBLE {
            for case in &cases {
                sequence += 1;
                observations.push(observation(
                    sequence,
                    lane.scanner,
                    lane.lane,
                    &case.case_id,
                ));
            }
        }
        let results = build_results(&cases, &observations);
        assert_eq!(results.total_scanner_process_attempts, 6);
        assert_eq!(
            results
                .lanes
                .iter()
                .filter(|lane| lane.state == ExecutionState::Completed)
                .count(),
            3
        );
        assert_eq!(
            results
                .lanes
                .iter()
                .filter(|lane| lane.state == ExecutionState::Unsupported)
                .count(),
            3
        );
        assert!(results.comparisons.iter().any(|comparison| {
            comparison.comparability == "unavailable-cross-lane"
                && comparison.absolute_metric_differences.is_none()
        }));
        assert_eq!(
            process_decision(ELIGIBLE[1], Some(1), false, Some(1)),
            "successful-findings-report"
        );
        assert_eq!(
            process_decision(ELIGIBLE[1], Some(1), false, Some(0)),
            "genuine-crash"
        );
        assert_eq!(
            process_decision(ELIGIBLE[1], Some(0), true, Some(1)),
            "timeout"
        );
    }
}
