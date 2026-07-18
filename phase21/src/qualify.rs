use crate::model::{LedgerEntry, Observation};
use crate::sandbox::{
    CORRECTED_PROFILE, LEGACY_PROFILE, Scanner, base_arguments, fixed_environment, scanner_command,
    scanner_sandbox, validate_tools,
};
use crate::{
    Phase21Error, canonical_json, collect_files, sha256, sha256_file, tree_digest, write_atomic,
};
use serde_json::{Value, json};
use std::fs::{self, File};
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const OUTPUT: &str = "phase21/output";
const PHASE20_COMMIT: &str = "6c27c9bb26b96855228d1a8e6483483ff4174907";
const PHASE20_TREE: &str = "05cd69281777263a4f9286069767d870014cab52";
const RULE_ID: &str = "secure-bench.phase21.synthetic-eval";

struct ProcessEvidence {
    command: Vec<String>,
    exit_code: Option<i32>,
    duration_ms: u64,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    raw: Option<Vec<u8>>,
    watchdog_killed: bool,
}

struct Scenario<'a> {
    id: String,
    subject: &'a str,
    profile: &'a str,
    kind: &'a str,
    scanner_attempt: bool,
    expectation: &'a str,
}

fn git_value(root: &Path, argument: &str) -> Result<String, Phase21Error> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["rev-parse", argument])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()?;
    if !output.status.success() {
        return Err(Phase21Error::Contract(format!(
            "git rev-parse failed for {argument}"
        )));
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|error| Phase21Error::Contract(error.to_string()))
}

fn preflight(root: &Path) -> Result<Value, Phase21Error> {
    let main = git_value(root, "main")?;
    let phase20_tree = git_value(root, &format!("{PHASE20_COMMIT}:phase20"))?;
    if main != PHASE20_COMMIT || phase20_tree != PHASE20_TREE {
        return Err(Phase21Error::Contract(format!(
            "Phase 20 integration/immutability drift: main={main}, tree={phase20_tree}"
        )));
    }
    let fixture_clean = root.join("phase21/fixtures/clean");
    let fixture_finding = root.join("phase21/fixtures/finding");
    let rule = root.join("phase21/rules/synthetic-eval-v1.yml");
    let invalid_rule = root.join("phase21/rules/invalid-rule.yml");
    for path in [&fixture_clean, &fixture_finding, &rule, &invalid_rule] {
        if !path.exists() {
            return Err(Phase21Error::Contract(format!(
                "synthetic input absent: {}",
                path.display()
            )));
        }
    }
    Ok(json!({
        "schema_version": "secure-bench-phase21-preflight-v1",
        "phase20_commit": PHASE20_COMMIT,
        "phase20_tree": PHASE20_TREE,
        "main_fast_forward_target": main,
        "holdout_access": "forbidden-and-not-performed",
        "tools": validate_tools(root)?,
        "synthetic_inputs": {
            "clean_tree_sha256": tree_digest(&fixture_clean)?,
            "finding_tree_sha256": tree_digest(&fixture_finding)?,
            "valid_rule_sha256": sha256_file(&rule)?,
            "invalid_rule_sha256": sha256_file(&invalid_rule)?,
        },
        "scanner_process_attempts_before_preflight": 0,
    }))
}

fn run_process(
    arguments: &[String],
    directory: &Path,
    external_timeout: Duration,
    expected_watchdog: bool,
) -> Result<ProcessEvidence, Phase21Error> {
    fs::create_dir_all(directory)?;
    let stdout_path = directory.join("stdout.bin");
    let stderr_path = directory.join("stderr.bin");
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
    let mut watchdog_killed = false;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() >= external_timeout {
            child.kill()?;
            let status = child.wait()?;
            if !expected_watchdog {
                return Err(Phase21Error::Qualification(
                    "unexpected external watchdog timeout".to_owned(),
                ));
            }
            watchdog_killed = true;
            break status;
        }
        thread::sleep(Duration::from_millis(5));
    };
    let raw_path = directory.join("raw.json");
    Ok(ProcessEvidence {
        command: std::iter::once("/usr/bin/bwrap".to_owned())
            .chain(arguments.iter().cloned())
            .collect(),
        exit_code: status.code(),
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        stdout: fs::read(stdout_path)?,
        stderr: fs::read(stderr_path)?,
        raw: raw_path.exists().then(|| fs::read(raw_path)).transpose()?,
        watchdog_killed,
    })
}

fn validate_raw(scanner: Scanner, raw: &[u8], expected: u64) -> Result<u64, String> {
    let value: Value = serde_json::from_slice(raw).map_err(|error| error.to_string())?;
    if value.get("version").and_then(Value::as_str) != Some(scanner.version()) {
        return Err("scanner version mismatch".to_owned());
    }
    if value
        .get("errors")
        .and_then(Value::as_array)
        .is_none_or(|errors| !errors.is_empty())
    {
        return Err("successful report has scanner errors".to_owned());
    }
    let results = value
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(|| "raw report has no results array".to_owned())?;
    let count = u64::try_from(results.len()).unwrap_or(u64::MAX);
    if count != expected {
        return Err(format!("expected {expected} findings, observed {count}"));
    }
    for finding in results {
        if finding.get("check_id").and_then(Value::as_str) != Some(RULE_ID)
            || finding.get("path").and_then(Value::as_str) != Some("app.js")
            || finding.pointer("/start/line").and_then(Value::as_u64) != Some(2)
        {
            return Err("finding identity, path, or span drifted".to_owned());
        }
    }
    if scanner == Scanner::Semgrep {
        if value.get("engine_requested").and_then(Value::as_str) != Some("OSS")
            || value
                .get("skipped_rules")
                .and_then(Value::as_array)
                .is_none()
            || value
                .pointer("/paths/scanned")
                .and_then(Value::as_array)
                .is_none()
        {
            return Err("Semgrep CE OSS provenance is incomplete".to_owned());
        }
    }
    Ok(count)
}

fn observation(
    sequence: u64,
    scenario: &Scenario<'_>,
    output_directory: &Path,
    evidence: ProcessEvidence,
) -> Result<Observation, Phase21Error> {
    let stdout_text = String::from_utf8_lossy(&evidence.stdout);
    let stderr_text = String::from_utf8_lossy(&evidence.stderr);
    let scanner = match scenario.subject {
        "opengrep" => Some(Scanner::OpenGrep),
        "semgrep-ce" => Some(Scanner::Semgrep),
        _ => None,
    };
    let mut finding_count = None;
    let (passed, decision) = match scenario.kind {
        "sandbox-probe-corrected" => {
            let value: Value = serde_json::from_slice(&evidence.stdout)?;
            let no_default_route = value
                .get("network_route")
                .and_then(Value::as_str)
                .is_some_and(|route| route.lines().count() <= 1);
            let passed = evidence.exit_code == Some(0)
                && value.pointer("/null/type").and_then(Value::as_str) == Some("character")
                && value.pointer("/null/mode").and_then(Value::as_str) == Some("0o666")
                && value.pointer("/null/major").and_then(Value::as_u64) == Some(1)
                && value.pointer("/null/minor").and_then(Value::as_u64) == Some(3)
                && value.pointer("/null/read_bytes").and_then(Value::as_u64) == Some(0)
                && value.pointer("/null/write_bytes").and_then(Value::as_u64) == Some(1)
                && value
                    .pointer("/null/open_errno")
                    .is_some_and(Value::is_null)
                && value
                    .get("dev_entries")
                    .and_then(Value::as_array)
                    .is_some_and(|entries| entries == &[Value::String("null".to_owned())])
                && [
                    "home_entries",
                    "root_entries",
                    "run_user_entries",
                    "var_tmp_entries",
                ]
                .iter()
                .all(|field| {
                    value
                        .get(field)
                        .and_then(Value::as_array)
                        .is_some_and(Vec::is_empty)
                })
                && value.get("proc_1_comm").and_then(Value::as_str) == Some("python3.14")
                && value.get("outside_write_errno").and_then(Value::as_u64) == Some(30)
                && value.get("network_connect_errno").and_then(Value::as_u64) == Some(101)
                && no_default_route;
            (
                passed,
                "null-eof-discard-and-containment-confirmed".to_owned(),
            )
        }
        "sandbox-probe-legacy" => {
            let value: Value = serde_json::from_slice(&evidence.stdout)?;
            let passed = evidence.exit_code == Some(0)
                && value.pointer("/null/type").and_then(Value::as_str) == Some("character")
                && value.pointer("/null/mode").and_then(Value::as_str) == Some("0o666")
                && value.pointer("/null/major").and_then(Value::as_u64) == Some(1)
                && value.pointer("/null/minor").and_then(Value::as_u64) == Some(3)
                && value.pointer("/null/open_errno").and_then(Value::as_u64) == Some(13);
            (passed, "nodev-eacces-reproduced".to_owned())
        }
        "legacy-startup" => {
            let passed = evidence.exit_code.is_some_and(|code| code != 0)
                && stderr_text.contains("/dev/null")
                && (stderr_text.contains("PermissionError")
                    || stderr_text.contains("Permission denied"));
            (passed, "scanner-dev-null-eacces-reproduced".to_owned())
        }
        "startup" => {
            let scanner = scanner.ok_or_else(|| {
                Phase21Error::Contract("startup scenario has no scanner".to_owned())
            })?;
            (
                evidence.exit_code == Some(0) && stdout_text.contains(scanner.version()),
                "scanner-startup-and-version-confirmed".to_owned(),
            )
        }
        "clean" | "finding" => {
            let expected = u64::from(scenario.kind == "finding");
            let adapted = evidence
                .raw
                .as_deref()
                .ok_or_else(|| "scanner emitted no raw JSON".to_owned())
                .and_then(|raw| {
                    validate_raw(
                        scanner.ok_or_else(|| "scan scenario has no scanner".to_owned())?,
                        raw,
                        expected,
                    )
                });
            finding_count = adapted.as_ref().ok().copied();
            let expected_exit = if expected == 0 { 0 } else { 1 };
            (
                adapted.is_ok() && evidence.exit_code == Some(expected_exit),
                if adapted.is_ok() {
                    format!("adapter-valid-report-with-{expected}-findings")
                } else {
                    format!("adapter-rejected: {}", adapted.err().unwrap_or_default())
                },
            )
        }
        "rule-error" => {
            let raw_valid_success = evidence.raw.as_deref().is_some_and(|raw| {
                validate_raw(scanner.unwrap_or(Scanner::OpenGrep), raw, 0).is_ok()
            });
            (
                evidence.exit_code.is_some_and(|code| code != 0) && !raw_valid_success,
                "explicit-rule-parse-error".to_owned(),
            )
        }
        "timeout" => (
            evidence.watchdog_killed && evidence.exit_code.is_none(),
            "external-watchdog-killed-pid-namespace-no-retry".to_owned(),
        ),
        "malformed-output" => (
            evidence.exit_code == Some(0)
                && evidence
                    .raw
                    .as_deref()
                    .is_some_and(|raw| serde_json::from_slice::<Value>(raw).is_err()),
            "adapter-rejected-malformed-json".to_owned(),
        ),
        other => {
            return Err(Phase21Error::Contract(format!(
                "unknown scenario kind: {other}"
            )));
        }
    };
    let relative = |name: &str| format!("phase21/output/attempts/{}/{name}", scenario.id);
    let raw_path = evidence.raw.as_ref().map(|_| relative("raw.json"));
    let raw_hash = evidence.raw.as_deref().map(sha256);
    let observation = Observation {
        sequence,
        id: scenario.id.clone(),
        subject: scenario.subject.to_owned(),
        sandbox_profile: scenario.profile.to_owned(),
        scenario: scenario.kind.to_owned(),
        scanner_process_attempt: scenario.scanner_attempt,
        command_sha256: sha256(&canonical_json(&evidence.command)?),
        command: evidence.command,
        environment: fixed_environment(),
        exit_code: evidence.exit_code,
        timed_out: scenario.kind == "timeout",
        duration_ms: evidence.duration_ms,
        stdout_path: relative("stdout.bin"),
        stdout_sha256: sha256(&evidence.stdout),
        stderr_path: relative("stderr.bin"),
        stderr_sha256: sha256(&evidence.stderr),
        raw_output_path: raw_path,
        raw_output_sha256: raw_hash,
        finding_count,
        adapter_decision: decision,
        expectation: scenario.expectation.to_owned(),
        passed,
    };
    write_atomic(
        &output_directory.join("observation.json"),
        &canonical_json(&observation)?,
    )?;
    if !observation.passed {
        return Err(Phase21Error::Qualification(format!(
            "scenario {} failed: stdout=`{}`, stderr=`{}`",
            scenario.id,
            stdout_text.trim(),
            stderr_text.trim()
        )));
    }
    Ok(observation)
}

fn terminate(arguments: &mut Vec<String>, command: Vec<String>) {
    arguments.extend([
        "--".to_owned(),
        "/usr/bin/prlimit".to_owned(),
        "--as=4294967296".to_owned(),
        "--nproc=64".to_owned(),
        "--".to_owned(),
    ]);
    arguments.extend(command);
}

fn scanner_scenario(
    root: &Path,
    output: &Path,
    scanner: Scanner,
    kind: &str,
) -> Result<(Scenario<'static>, ProcessEvidence), Phase21Error> {
    let corrected = kind != "legacy-startup";
    let fixture_name = if kind == "finding" {
        "finding"
    } else {
        "clean"
    };
    let fixture = root.join(format!("phase21/fixtures/{fixture_name}"));
    let rule_name = if kind == "rule-error" {
        "invalid-rule.yml"
    } else {
        "synthetic-eval-v1.yml"
    };
    let rule = root.join(format!("phase21/rules/{rule_name}"));
    let id = format!("{}-{kind}", scanner.id());
    let directory = output.join("attempts").join(&id);
    let mut arguments = scanner_sandbox(scanner, corrected, &fixture, &rule, &directory);
    let command = if kind == "startup" {
        vec![scanner.mount().1.to_owned(), "--version".to_owned()]
    } else {
        scanner_command(scanner)
    };
    terminate(&mut arguments, command);
    let expectation = match kind {
        "legacy-startup" => "scanner proves `/dev/null` EACCES under inherited nodev",
        "startup" => "scanner starts and reports the frozen version",
        "clean" => "valid JSON, successful exit, zero findings, fixture read",
        "finding" => "valid JSON, policy exit, exact synthetic finding",
        "rule-error" => "invalid rule fails explicitly without valid success output",
        "timeout" => "scanner is killed at the frozen canary deadline without retry",
        _ => "unknown",
    };
    let scenario = Scenario {
        id,
        subject: scanner.id(),
        profile: if corrected {
            CORRECTED_PROFILE
        } else {
            LEGACY_PROFILE
        },
        kind: Box::leak(kind.to_owned().into_boxed_str()),
        scanner_attempt: true,
        expectation,
    };
    let evidence = if kind == "timeout" {
        run_process(&arguments, &directory, Duration::from_millis(100), true)?
    } else {
        run_process(&arguments, &directory, Duration::from_secs(30), false)?
    };
    Ok((scenario, evidence))
}

fn probe_scenario(
    root: &Path,
    output: &Path,
    corrected: bool,
) -> Result<(Scenario<'static>, ProcessEvidence), Phase21Error> {
    let kind = if corrected {
        "sandbox-probe-corrected"
    } else {
        "sandbox-probe-legacy"
    };
    let id = kind.to_owned();
    let directory = output.join("attempts").join(&id);
    fs::create_dir_all(&directory)?;
    let mut arguments = base_arguments(corrected);
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
    let evidence = run_process(&arguments, &directory, Duration::from_secs(5), false)?;
    Ok((
        Scenario {
            id,
            subject: "sandbox",
            profile: if corrected {
                CORRECTED_PROFILE
            } else {
                LEGACY_PROFILE
            },
            kind,
            scanner_attempt: false,
            expectation: if corrected {
                "only `/dev/null` is exposed with EOF-read/discard-write semantics and containment controls"
            } else {
                "mode 0666 character device remains inaccessible because `/dev` is nodev"
            },
        },
        evidence,
    ))
}

fn malformed_scenario(
    output: &Path,
    scanner: Scanner,
) -> Result<(Scenario<'static>, ProcessEvidence), Phase21Error> {
    let id = format!("{}-malformed-output", scanner.id());
    let directory = output.join("attempts").join(&id);
    fs::create_dir_all(&directory)?;
    let mut arguments = base_arguments(true);
    arguments.extend([
        "--bind".to_owned(),
        directory.to_string_lossy().into_owned(),
        "/tmp/run".to_owned(),
        "--clearenv".to_owned(),
        "--setenv".to_owned(),
        "PATH".to_owned(),
        "/usr/bin:/bin".to_owned(),
        "--".to_owned(),
        "/usr/bin/python3.14".to_owned(),
        "-c".to_owned(),
        "open('/tmp/run/raw.json','wb').write(b'{malformed')".to_owned(),
    ]);
    let evidence = run_process(&arguments, &directory, Duration::from_secs(5), false)?;
    Ok((
        Scenario {
            id,
            subject: scanner.id(),
            profile: CORRECTED_PROFILE,
            kind: "malformed-output",
            scanner_attempt: false,
            expectation: "synthetic mock malformed JSON is rejected; no scanner process starts",
        },
        evidence,
    ))
}

fn ledger(output: &Path, observations: &[Observation]) -> Result<(), Phase21Error> {
    let mut bytes = Vec::new();
    let mut previous = "0".repeat(64);
    for observation in observations {
        let payload = canonical_json(observation)?;
        let payload_hash = sha256(&payload);
        let unsigned = json!({
            "schema_version": "secure-bench-phase21-ledger-v1",
            "sequence": observation.sequence,
            "event": "synthetic-canary-completed",
            "payload_sha256": payload_hash,
            "previous_entry_hash": previous,
        });
        let entry_hash = sha256(&canonical_json(&unsigned)?);
        let entry = LedgerEntry {
            schema_version: "secure-bench-phase21-ledger-v1".to_owned(),
            sequence: observation.sequence,
            event: "synthetic-canary-completed".to_owned(),
            payload_sha256: payload_hash,
            previous_entry_hash: previous,
            entry_hash: entry_hash.clone(),
        };
        bytes.extend(canonical_json(&entry)?);
        previous = entry_hash;
    }
    write_atomic(&output.join("ledger.jsonl"), &bytes)
}

fn write_contract(root: &Path, output: &Path, preflight: &Value) -> Result<(), Phase21Error> {
    let contract = json!({
        "schema_version": "secure-bench-phase21-corrected-environment-v1",
        "profile": CORRECTED_PROFILE,
        "phase20_commit": PHASE20_COMMIT,
        "phase20_tree": PHASE20_TREE,
        "reuse_status": "frozen-for-phase22-after-independent-verification",
        "network": "new-network-namespace-with-loopback-only-and-no-default-route",
        "root_filesystem": "read-only-host-root-with-sensitive-path-masks",
        "process_namespace": "new-pid-namespace-and-fresh-procfs",
        "device_policy": {
            "dev_mount": "fresh-tmpfs",
            "allowed_devices": ["/dev/null"],
            "null_bind": "bubblewrap --dev-bind /dev/null /dev/null",
            "semantics": "character-device-1:3-mode-0666-EOF-read-discard-write",
            "all_other_devices": "absent",
        },
        "masked_paths": ["/home", "/root", "/run/user", "/var/tmp"],
        "resource_limits": {"address_space_bytes": 4294967296_u64, "processes": 64},
        "environment": fixed_environment(),
        "frozen_inputs": preflight,
        "phase21_implementation_tree_sha256": tree_digest(&root.join("phase21/src"))?,
        "sandbox_probe_sha256": sha256_file(&root.join("phase21/canaries/sandbox_probe.py"))?,
        "scanner_attempt_policy": {
            "retries": 0,
            "qualification_inputs": "phase21 synthetic fixtures only",
            "malformed_output": "mock only and not a scanner attempt",
            "phase20_attempts": "immutable and never reclassified",
            "phase22_attempts": "not started",
        },
    });
    write_atomic(
        &output.join("corrected-environment-contract.json"),
        &canonical_json(&contract)?,
    )
}

fn write_sums(output: &Path) -> Result<(), Phase21Error> {
    let sums = output.join("SHA256SUMS");
    if sums.exists() {
        fs::remove_file(&sums)?;
    }
    let mut files = Vec::new();
    collect_files(output, &mut files)?;
    let mut lines = String::new();
    for file in files {
        if file == sums {
            continue;
        }
        let relative = file.strip_prefix(output).map_err(|_| {
            Phase21Error::Contract(format!("output escaped root: {}", file.display()))
        })?;
        lines.push_str(&format!(
            "{}  {}\n",
            sha256_file(&file)?,
            relative.to_string_lossy()
        ));
    }
    write_atomic(&sums, lines.as_bytes())
}

/// Execute the bounded synthetic qualification exactly once.
pub fn qualify(root: &Path) -> Result<Value, Phase21Error> {
    let output = root.join(OUTPUT);
    if output.exists() {
        return Err(Phase21Error::Contract(format!(
            "qualification output already exists: {}",
            output.display()
        )));
    }
    fs::create_dir_all(&output)?;
    let preflight_value = preflight(root)?;
    write_atomic(
        &output.join("preflight.json"),
        &canonical_json(&preflight_value)?,
    )?;

    let mut observations = Vec::new();
    for corrected in [false, true] {
        let (scenario, evidence) = probe_scenario(root, &output, corrected)?;
        observations.push(observation(
            u64::try_from(observations.len() + 1).unwrap_or(u64::MAX),
            &scenario,
            &output.join("attempts").join(&scenario.id),
            evidence,
        )?);
    }
    for scanner in [Scanner::OpenGrep, Scanner::Semgrep] {
        for kind in [
            "legacy-startup",
            "startup",
            "clean",
            "finding",
            "rule-error",
            "timeout",
        ] {
            let (scenario, evidence) = scanner_scenario(root, &output, scanner, kind)?;
            observations.push(observation(
                u64::try_from(observations.len() + 1).unwrap_or(u64::MAX),
                &scenario,
                &output.join("attempts").join(&scenario.id),
                evidence,
            )?);
        }
        let (scenario, evidence) = malformed_scenario(&output, scanner)?;
        observations.push(observation(
            u64::try_from(observations.len() + 1).unwrap_or(u64::MAX),
            &scenario,
            &output.join("attempts").join(&scenario.id),
            evidence,
        )?);
    }
    ledger(&output, &observations)?;
    let scanner_attempts = observations
        .iter()
        .filter(|observation| observation.scanner_process_attempt)
        .count();
    let summary = json!({
        "schema_version": "secure-bench-phase21-qualification-v1",
        "state": "qualified",
        "phase20_commit": PHASE20_COMMIT,
        "phase20_tree": PHASE20_TREE,
        "corrected_profile": CORRECTED_PROFILE,
        "observations": observations.len(),
        "scanner_process_attempts": scanner_attempts,
        "mock_adapter_attempts": 2,
        "sandbox_probe_attempts": 2,
        "all_passed": observations.iter().all(|observation| observation.passed),
        "scanners": [
            {"id": "opengrep", "version": "1.22.0", "qualified": true},
            {"id": "semgrep-ce", "version": "1.170.0", "engine": "OSS", "qualified": true},
        ],
        "scope": {
            "fixtures": "phase21 synthetic canaries only",
            "holdout_opened": false,
            "phase20_attempts_modified": false,
            "phase20_attempts_reinterpreted": false,
            "phase22_attempts_started": false,
        },
        "limitations": [
            "Synthetic qualification establishes scanner operability, output adaptation, and containment; it does not establish holdout accuracy.",
            "Phase 20 remains an immutable unavailable comparison because its scanner attempts failed.",
        ],
    });
    write_atomic(
        &output.join("qualification.json"),
        &canonical_json(&summary)?,
    )?;
    write_contract(root, &output, &preflight_value)?;
    let report = crate::verify::verify_without_sums(root)?;
    write_atomic(
        &output.join("independent-verification.json"),
        &canonical_json(&report)?,
    )?;
    write_sums(&output)?;
    Ok(summary)
}
