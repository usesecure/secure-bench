//! Corrected-profile qualification on new synthetic inputs only.

use crate::{Phase23Error, canonical_json, collect_files, sha256, sha256_file, write_atomic};
use secure_bench_phase21::sandbox::{
    Scanner, base_arguments, fixed_environment, scanner_command, scanner_sandbox,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const PHASE22: &str = "b8ef30bfcd9761644001b63ed9b9f717ebd09d93";
const RULESET: &str = "phase19/rules/capability-normalized-v1.yml";
const RULESET_SHA256: &str = "06af4cf6d10da30ad585d57b781cf6aef734add03b90ea36c78e920c4c10a07c";
const ADAPTER: &str = "phase20/config/semgrep-normalized-adapter-v1.json";
const ADAPTER_SHA256: &str = "53317a4e71b14548d618fd79430b74b8fc906edebbf7180cbea418df98b1afc3";
const SEMGREP: &str = "/tmp/secure-bench-tools/semgrep/1.170.0/venv/bin/semgrep";
const SEMGREP_SHA256: &str = "0280e5c6cca8d8e4cb2c41858b06697b957daf23d718cac411999c4c515507e1";
const STACK: u64 = 8_388_608;
const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

struct Evidence {
    exit_code: Option<i32>,
    timed_out: bool,
    duration_ms: u64,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    raw: Option<Vec<u8>>,
    resource: Vec<u8>,
}

fn validate(root: &Path) -> Result<(), Phase23Error> {
    let head = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(root)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()?;
    if !head.status.success() || String::from_utf8_lossy(&head.stdout).trim() != PHASE22 {
        return Err(Phase23Error::Contract(
            "qualification must start from exact Phase 22".to_owned(),
        ));
    }
    for (path, expected) in [
        (root.join(RULESET), RULESET_SHA256),
        (root.join(ADAPTER), ADAPTER_SHA256),
        (PathBuf::from(SEMGREP), SEMGREP_SHA256),
    ] {
        let actual = sha256_file(&path)?;
        if actual != expected {
            return Err(Phase23Error::Contract(format!(
                "frozen input drift at {}: {actual}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn run(arguments: &[String], output: &Path, timeout_ms: u64) -> Result<Evidence, Phase23Error> {
    let stdout = File::create(output.join("stdout.bin"))?;
    let stderr = File::create(output.join("stderr.bin"))?;
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
        if started.elapsed() >= Duration::from_millis(timeout_ms) {
            child.kill()?;
            timed_out = true;
            break child.wait()?;
        }
        thread::sleep(Duration::from_millis(1));
    };
    let raw = output.join("raw.json");
    let resource = output.join("resource.txt");
    Ok(Evidence {
        exit_code: status.code(),
        timed_out,
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        stdout: fs::read(output.join("stdout.bin"))?,
        stderr: fs::read(output.join("stderr.bin"))?,
        raw: raw.exists().then(|| fs::read(raw)).transpose()?,
        resource: if resource.exists() {
            fs::read(resource)?
        } else {
            Vec::new()
        },
    })
}

fn corrected_arguments(
    fixture: &Path,
    rule: &Path,
    output: &Path,
    command: Vec<String>,
) -> Vec<String> {
    let mut arguments = scanner_sandbox(Scanner::Semgrep, true, fixture, rule, output);
    arguments.extend([
        "--".to_owned(),
        "/usr/bin/time".to_owned(),
        "--verbose".to_owned(),
        "--output=/tmp/run/resource.txt".to_owned(),
        "--".to_owned(),
        "/usr/bin/prlimit".to_owned(),
        "--as=4294967296".to_owned(),
        "--nproc=64".to_owned(),
        format!("--stack={STACK}"),
        "--".to_owned(),
    ]);
    arguments.extend(command);
    arguments
}

fn portable(value: &str) -> Result<String, Phase23Error> {
    let value = value.strip_prefix("./").unwrap_or(value);
    if value.is_empty()
        || value.starts_with('/')
        || value.contains('\\')
        || value
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
    {
        return Err(Phase23Error::Execution(format!(
            "frozen adapter rejected path `{value}`"
        )));
    }
    Ok(value.to_owned())
}

fn source(fixture: &Path, value: &str) -> Result<(String, Vec<u8>), Phase23Error> {
    let relative = portable(value)?;
    let root = fixture.canonicalize()?;
    let mut cursor = root.clone();
    for component in Path::new(&relative).components() {
        let std::path::Component::Normal(part) = component else {
            return Err(Phase23Error::Execution(
                "frozen adapter rejected non-normal path".to_owned(),
            ));
        };
        cursor.push(part);
        if fs::symlink_metadata(&cursor)?.file_type().is_symlink() {
            return Err(Phase23Error::Execution(
                "frozen adapter rejected symlink".to_owned(),
            ));
        }
    }
    let canonical = cursor.canonicalize()?;
    if !canonical.starts_with(&root) || !canonical.is_file() {
        return Err(Phase23Error::Execution(
            "frozen adapter path escaped fixture".to_owned(),
        ));
    }
    Ok((relative, fs::read(canonical)?))
}

fn adapter_projection(fixture: &Path, raw: &[u8]) -> Result<Value, Phase23Error> {
    if raw.len() > 10 * 1024 * 1024 {
        return Err(Phase23Error::Execution(
            "frozen adapter rejected oversized output".to_owned(),
        ));
    }
    let value: Value = serde_json::from_slice(raw)?;
    if value.get("version").and_then(Value::as_str) != Some("1.170.0")
        || value.get("engine_requested").and_then(Value::as_str) != Some("OSS")
        || value
            .get("errors")
            .and_then(Value::as_array)
            .is_none_or(|items| !items.is_empty())
        || value
            .get("skipped_rules")
            .and_then(Value::as_array)
            .is_none_or(|items| !items.is_empty())
    {
        return Err(Phase23Error::Execution(
            "frozen adapter rejected identity/provenance".to_owned(),
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
    let mut scanned = BTreeSet::new();
    for path in value
        .pointer("/paths/scanned")
        .and_then(Value::as_array)
        .ok_or_else(|| Phase23Error::Execution("adapter found no scanned paths".to_owned()))?
    {
        let path = path
            .as_str()
            .ok_or_else(|| Phase23Error::Execution("adapter found non-text path".to_owned()))?;
        if !scanned.insert(source(fixture, path)?.0) {
            return Err(Phase23Error::Execution(
                "adapter found repeated scanned path".to_owned(),
            ));
        }
    }
    let mut findings = Vec::new();
    for finding in value
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(|| Phase23Error::Execution("adapter found no results".to_owned()))?
    {
        let rule = finding
            .get("check_id")
            .and_then(Value::as_str)
            .ok_or_else(|| Phase23Error::Execution("finding omitted rule".to_owned()))?;
        let path = finding
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| Phase23Error::Execution("finding omitted path".to_owned()))?;
        let (path, bytes) = source(fixture, path)?;
        let start = finding
            .get("start")
            .ok_or_else(|| Phase23Error::Execution("finding omitted start".to_owned()))?;
        let end = finding
            .get("end")
            .ok_or_else(|| Phase23Error::Execution("finding omitted end".to_owned()))?;
        let start_offset = start
            .get("offset")
            .and_then(Value::as_u64)
            .unwrap_or(u64::MAX);
        let end_offset = end.get("offset").and_then(Value::as_u64).unwrap_or(0);
        if !allowed.contains(rule)
            || finding
                .pointer("/extra/engine_kind")
                .and_then(Value::as_str)
                != Some("OSS")
            || !scanned.contains(&path)
            || start_offset >= end_offset
            || end_offset > u64::try_from(bytes.len()).unwrap_or(u64::MAX)
        {
            return Err(Phase23Error::Execution(
                "frozen adapter rejected finding".to_owned(),
            ));
        }
        findings.push(json!({"check_id": rule, "path": path, "start": start, "end": end}));
    }
    findings.sort_by_key(|item| serde_json::to_string(item).unwrap_or_default());
    Ok(json!({
        "adapter_id": "secure-bench-semgrep-json",
        "adapter_version": "1.0.0",
        "engine": "OSS",
        "findings": findings,
        "scanned_paths": scanned,
    }))
}

fn append_ledger(
    path: &Path,
    sequence: u64,
    previous: &str,
    payload: &Value,
    event: &str,
) -> Result<String, Phase23Error> {
    let payload_sha256 = sha256(&canonical_json(payload)?);
    let projection = json!({
        "schema_version": "secure-bench-phase23-qualification-ledger-v1",
        "sequence": sequence,
        "event": event,
        "payload_sha256": payload_sha256,
        "previous_entry_hash": previous,
    });
    let entry_hash = sha256(&canonical_json(&projection)?);
    let entry = json!({
        "schema_version": "secure-bench-phase23-qualification-ledger-v1",
        "sequence": sequence,
        "event": event,
        "payload_sha256": payload_sha256,
        "previous_entry_hash": previous,
        "entry_hash": entry_hash,
    });
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(&canonical_json(&entry)?)?;
    file.sync_all()?;
    Ok(entry_hash)
}

fn write_sums(output: &Path) -> Result<(), Phase23Error> {
    let mut files = Vec::new();
    collect_files(output, &mut files)?;
    files.retain(|path| path.file_name().and_then(|name| name.to_str()) != Some("SHA256SUMS"));
    files.sort();
    let mut sums = String::new();
    for file in files {
        let relative = file
            .strip_prefix(output)
            .map_err(|_| Phase23Error::Contract("qualification hash path escaped".to_owned()))?;
        sums.push_str(&format!(
            "{}  {}\n",
            sha256_file(&file)?,
            relative.display()
        ));
    }
    write_atomic(&output.join("SHA256SUMS"), sums.as_bytes())
}

fn segfault(evidence: &Evidence) -> bool {
    let raw = evidence.raw.as_deref().map_or_else(String::new, |bytes| {
        String::from_utf8_lossy(bytes).into_owned()
    });
    let stderr = String::from_utf8_lossy(&evidence.stderr);
    [raw.as_str(), stderr.as_ref()].iter().any(|text| {
        text.contains("Segmentation fault")
            || text.contains("received signal")
            || text.contains("signal 11")
    })
}

fn declared_cleanup(output: &Path) -> Result<bool, Phase23Error> {
    let allowed = ["raw.json", "resource.txt", "stderr.bin", "stdout.bin"]
        .into_iter()
        .collect::<BTreeSet<_>>();
    let actual = fs::read_dir(output)?
        .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
        .collect::<Result<BTreeSet<_>, _>>()?;
    Ok(actual.iter().all(|name| allowed.contains(name.as_str())))
}

fn probe_arguments(root: &Path, output: &Path) -> Vec<String> {
    let mut arguments = base_arguments(true);
    arguments.extend([
        "--ro-bind".to_owned(),
        root.join("phase23/reproducer/qualification_probe.py")
            .to_string_lossy()
            .into_owned(),
        "/tmp/probe.py".to_owned(),
        "--bind".to_owned(),
        output.to_string_lossy().into_owned(),
        "/tmp/run".to_owned(),
        "--clearenv".to_owned(),
    ]);
    for entry in fixed_environment() {
        let (name, value) = entry.split_once('=').unwrap_or((entry.as_str(), ""));
        arguments.extend(["--setenv".to_owned(), name.to_owned(), value.to_owned()]);
    }
    arguments.extend([
        "--".to_owned(),
        "/usr/bin/time".to_owned(),
        "--verbose".to_owned(),
        "--output=/tmp/run/resource.txt".to_owned(),
        "--".to_owned(),
        "/usr/bin/prlimit".to_owned(),
        "--as=4294967296".to_owned(),
        "--nproc=64".to_owned(),
        format!("--stack={STACK}"),
        "--".to_owned(),
        "/usr/bin/python3.14".to_owned(),
        "/tmp/probe.py".to_owned(),
    ]);
    arguments
}

/// Qualifies the corrected Semgrep CE profile on new synthetic fixtures only.
pub fn qualify(root: &Path) -> Result<String, Phase23Error> {
    validate(root)?;
    let output = root.join("phase23/output/qualification");
    if output.join("qualification-report.json").exists() {
        return Err(Phase23Error::Execution(
            "qualification evidence already exists; reruns are forbidden".to_owned(),
        ));
    }
    let recovering = output.exists();
    fs::create_dir_all(&output)?;
    let frozen_rule = root.join(RULESET);
    let invalid_rule = root.join("phase23/rules/invalid-rule.yml");
    let fixtures = root.join("phase23/fixtures/qualification");
    let cases = [
        (1_u64, "startup", "clean", "frozen", 60_000_u64),
        (2, "clean", "clean", "frozen", 60_000),
        (3, "finding", "finding", "frozen", 60_000),
        (4, "multi-file", "multi", "frozen", 60_000),
        (5, "invalid-rule", "clean", "invalid", 60_000),
        (6, "malformed-source", "malformed", "frozen", 60_000),
        (7, "timeout", "multi", "frozen", 1),
        (8, "clean-repeat-a", "clean", "frozen", 60_000),
        (9, "clean-repeat-b", "clean", "frozen", 60_000),
        (10, "finding-repeat-a", "finding", "frozen", 60_000),
        (11, "finding-repeat-b", "finding", "frozen", 60_000),
    ];
    let plan = json!({
        "schema_version": "secure-bench-phase23-qualification-plan-v1",
        "scope": "new Phase 23 synthetic fixtures only",
        "retries": 0,
        "cases": cases.iter().map(|(sequence, id, fixture, rule, timeout_ms)| json!({
            "sequence": sequence, "id": id, "fixture": fixture,
            "rule": rule, "timeout_ms": timeout_ms,
        })).collect::<Vec<_>>(),
    });
    if !recovering {
        write_atomic(&output.join("execution-plan.json"), &canonical_json(&plan)?)?;
    } else if serde_json::from_slice::<Value>(&fs::read(output.join("execution-plan.json"))?)?
        != plan
    {
        return Err(Phase23Error::Execution(
            "retained qualification plan drifted".to_owned(),
        ));
    }
    let ledger = output.join("ledger.jsonl");
    let mut previous = ZERO_HASH.to_owned();
    let mut observations = Vec::new();
    let mut projections = BTreeMap::<String, Value>::new();
    if recovering {
        let entries = fs::read_to_string(&ledger)?
            .lines()
            .map(serde_json::from_str::<Value>)
            .collect::<Result<Vec<_>, _>>()?;
        if entries.len() != 5
            || entries
                .last()
                .and_then(|entry| entry.get("sequence"))
                .and_then(Value::as_u64)
                != Some(5)
            || (7..=11).any(|sequence| {
                fs::read_dir(output.join("attempts")).is_ok_and(|mut items| {
                    items.any(|item| {
                        item.is_ok_and(|item| {
                            item.file_name()
                                .to_string_lossy()
                                .starts_with(&format!("{sequence:02}-"))
                        })
                    })
                })
            })
        {
            return Err(Phase23Error::Execution(
                "retained qualification is not at the exact case-6 boundary".to_owned(),
            ));
        }
        entries
            .last()
            .and_then(|entry| entry.get("entry_hash"))
            .and_then(Value::as_str)
            .ok_or_else(|| Phase23Error::Execution("retained ledger has no head".to_owned()))?
            .clone_into(&mut previous);
        for (sequence, id, _, _, _) in cases.iter().take(5) {
            observations.push(serde_json::from_slice(&fs::read(
                output.join(format!("attempts/{sequence:02}-{id}/observation.json")),
            )?)?);
        }
    }
    for (sequence, id, fixture_name, rule_name, timeout_ms) in cases {
        if recovering && sequence <= 5 {
            continue;
        }
        let directory = output.join(format!("attempts/{sequence:02}-{id}"));
        fs::create_dir_all(&directory)?;
        let fixture = fixtures.join(fixture_name);
        let rule = if rule_name == "frozen" {
            &frozen_rule
        } else {
            &invalid_rule
        };
        let command = if id == "startup" {
            vec![SEMGREP.to_owned(), "--version".to_owned()]
        } else {
            scanner_command(Scanner::Semgrep)
        };
        let arguments = corrected_arguments(&fixture, rule, &directory, command);
        if arguments.iter().any(|value| value.contains("holdout")) {
            return Err(Phase23Error::Contract(
                "qualification command referenced holdout".to_owned(),
            ));
        }
        let command = std::iter::once("/usr/bin/bwrap".to_owned())
            .chain(arguments.iter().cloned())
            .collect::<Vec<_>>();
        let evidence = if recovering && sequence == 6 {
            let resource = fs::read(directory.join("resource.txt"))?;
            if !String::from_utf8_lossy(&resource).contains("Exit status: 0") {
                return Err(Phase23Error::Execution(
                    "retained malformed-source status is not zero".to_owned(),
                ));
            }
            Evidence {
                exit_code: Some(0),
                timed_out: false,
                duration_ms: 0,
                stdout: fs::read(directory.join("stdout.bin"))?,
                stderr: fs::read(directory.join("stderr.bin"))?,
                raw: Some(fs::read(directory.join("raw.json"))?),
                resource,
            }
        } else {
            run(&arguments, &directory, timeout_ms)?
        };
        let had_segfault = segfault(&evidence);
        let raw_json = evidence
            .raw
            .as_deref()
            .map(serde_json::from_slice::<Value>)
            .transpose()?;
        let projection = match id {
            "clean" | "clean-repeat-a" | "clean-repeat-b" | "finding" | "finding-repeat-a"
            | "finding-repeat-b" | "multi-file" | "malformed-source" => Some(adapter_projection(
                &fixture,
                evidence
                    .raw
                    .as_deref()
                    .ok_or_else(|| Phase23Error::Execution(format!("{id} produced no JSON")))?,
            )?),
            _ => None,
        };
        let finding_count = projection
            .as_ref()
            .and_then(|value| value.get("findings"))
            .and_then(Value::as_array)
            .map_or(0, Vec::len);
        let cleanup = declared_cleanup(&directory)?;
        let passed = !had_segfault
            && cleanup
            && match id {
                "startup" => {
                    evidence.exit_code == Some(0)
                        && String::from_utf8_lossy(&evidence.stdout).contains("1.170.0")
                }
                "clean" | "clean-repeat-a" | "clean-repeat-b" => {
                    evidence.exit_code == Some(0) && finding_count == 0
                }
                "finding" | "finding-repeat-a" | "finding-repeat-b" => {
                    evidence.exit_code == Some(1) && finding_count >= 1
                }
                "multi-file" => evidence.exit_code == Some(1) && finding_count >= 2,
                "invalid-rule" => {
                    !matches!(evidence.exit_code, Some(0 | 1))
                        && (!evidence.stderr.is_empty() || evidence.raw.is_some())
                }
                "malformed-source" => {
                    evidence.exit_code == Some(0)
                        && finding_count == 0
                        && raw_json
                            .as_ref()
                            .and_then(|value| value.get("errors"))
                            .and_then(Value::as_array)
                            .is_some_and(Vec::is_empty)
                }
                "timeout" => evidence.timed_out,
                _ => false,
            };
        if !passed {
            return Err(Phase23Error::Execution(format!(
                "qualification case {id} contradicted its expectation"
            )));
        }
        if let Some(projection) = &projection {
            projections.insert(id.to_owned(), projection.clone());
        }
        let relative = format!("phase23/output/qualification/attempts/{sequence:02}-{id}");
        let observation = json!({
            "schema_version": "secure-bench-phase23-qualification-observation-v1",
            "sequence": sequence,
            "id": id,
            "fixture": format!("phase23/fixtures/qualification/{fixture_name}"),
            "rule": if rule_name == "frozen" {RULESET} else {"phase23/rules/invalid-rule.yml"},
            "command": command,
            "command_sha256": sha256(&canonical_json(&command)?),
            "environment": fixed_environment(),
            "exit_code": evidence.exit_code,
            "timed_out": evidence.timed_out,
            "duration_ms": evidence.duration_ms,
            "segmentation_fault": had_segfault,
            "stdout_path": format!("{relative}/stdout.bin"),
            "stdout_sha256": sha256(&evidence.stdout),
            "stderr_path": format!("{relative}/stderr.bin"),
            "stderr_sha256": sha256(&evidence.stderr),
            "raw_output_path": evidence.raw.as_ref().map(|_| format!("{relative}/raw.json")),
            "raw_output_sha256": evidence.raw.as_deref().map(sha256),
            "resource_path": format!("{relative}/resource.txt"),
            "resource_sha256": sha256(&evidence.resource),
            "adapter_projection": projection,
            "valid_json": raw_json.is_some(),
            "cleanup": cleanup,
            "passed": true,
            "retained_after_expectation_mismatch": recovering && sequence == 6,
        });
        write_atomic(
            &directory.join("observation.json"),
            &canonical_json(&observation)?,
        )?;
        previous = append_ledger(
            &ledger,
            sequence,
            &previous,
            &observation,
            if recovering && sequence == 6 {
                "synthetic-semgrep-tolerant-malformed-source-sealed"
            } else {
                "synthetic-semgrep-qualification-completed"
            },
        )?;
        observations.push(observation);
    }
    for (left, right) in [
        ("clean-repeat-a", "clean-repeat-b"),
        ("finding-repeat-a", "finding-repeat-b"),
    ] {
        if projections.get(left) != projections.get(right) {
            return Err(Phase23Error::Execution(format!(
                "normalized results differed for {left}/{right}"
            )));
        }
    }
    let probe_directory = output.join("sandbox-probe");
    fs::create_dir_all(&probe_directory)?;
    let probe_arguments = probe_arguments(root, &probe_directory);
    let probe_evidence = run(&probe_arguments, &probe_directory, 60_000)?;
    let probe: Value = serde_json::from_slice(&probe_evidence.stdout)?;
    let probe_passed = probe_evidence.exit_code == Some(0)
        && probe.pointer("/network/blocked").and_then(Value::as_bool) == Some(true)
        && probe
            .pointer("/outside_write/blocked")
            .and_then(Value::as_bool)
            == Some(true)
        && probe.get("stack") == Some(&json!([STACK, STACK]))
        && probe.get("address_space") == Some(&json!([4_294_967_296_u64, 4_294_967_296_u64]))
        && probe.get("processes") == Some(&json!([64, 64]))
        && probe.get("null_write").and_then(Value::as_u64) == Some(7)
        && probe.get("credentials_visible").and_then(Value::as_bool) == Some(false);
    if !probe_passed {
        return Err(Phase23Error::Execution(
            "qualification sandbox confinement probe failed".to_owned(),
        ));
    }
    let probe_command = std::iter::once("/usr/bin/bwrap".to_owned())
        .chain(probe_arguments.iter().cloned())
        .collect::<Vec<_>>();
    let probe_observation = json!({
        "schema_version": "secure-bench-phase23-qualification-sandbox-probe-v1",
        "scanner_process": false,
        "command": probe_command,
        "command_sha256": sha256(&canonical_json(&probe_command)?),
        "exit_code": probe_evidence.exit_code,
        "timed_out": probe_evidence.timed_out,
        "stdout_sha256": sha256(&probe_evidence.stdout),
        "stderr_sha256": sha256(&probe_evidence.stderr),
        "resource_sha256": sha256(&probe_evidence.resource),
        "observations": probe,
        "passed": true,
    });
    write_atomic(
        &probe_directory.join("observation.json"),
        &canonical_json(&probe_observation)?,
    )?;
    previous = append_ledger(
        &ledger,
        12,
        &previous,
        &probe_observation,
        "synthetic-qualification-sandbox-probe-completed",
    )?;
    let report = json!({
        "schema_version": "secure-bench-phase23-qualification-report-v1",
        "state": "qualified-for-phase24-normalized-lane",
        "scope": "new Phase 23 synthetic fixtures only",
        "semgrep_version": "1.170.0",
        "correction": {"outer_prlimit_hard_stack_bytes": STACK},
        "synthetic_semgrep_executions": 11,
        "synthetic_non_scanner_probes": 1,
        "retries": 0,
        "segmentation_faults": 0,
        "holdout_accesses": 0,
        "network": false,
        "frozen_adapter_manifest_sha256": ADAPTER_SHA256,
        "frozen_ruleset_sha256": RULESET_SHA256,
        "deterministic_repeats": true,
        "malformed_source_behavior": "accepted by Semgrep parser; valid empty OSS JSON; retained without retry",
        "ledger_head": previous,
        "observations": observations,
        "sandbox_probe": probe_observation,
    });
    write_atomic(
        &output.join("qualification-report.json"),
        &canonical_json(&report)?,
    )?;
    write_sums(&output)?;
    Ok(serde_json::to_string(&json!({
        "state": "qualified-for-phase24-normalized-lane",
        "synthetic_semgrep_executions": 11,
        "synthetic_non_scanner_probes": 1,
        "retries": 0,
        "ledger_head": previous,
    }))?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corrected_profile_caps_stack_without_widening_other_limits() {
        let arguments = corrected_arguments(
            Path::new("/fixture"),
            Path::new("/rule"),
            Path::new("/output"),
            vec![SEMGREP.to_owned(), "--version".to_owned()],
        );
        assert!(arguments.contains(&"--as=4294967296".to_owned()));
        assert!(arguments.contains(&"--nproc=64".to_owned()));
        assert!(arguments.contains(&"--stack=8388608".to_owned()));
    }
}
