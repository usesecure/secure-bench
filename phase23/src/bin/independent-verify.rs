//! Scanner-free independent verification of sealed Phase 23 evidence.

#![allow(clippy::doc_markdown, clippy::format_collect, clippy::too_many_lines)]

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

const PHASE22: &str = "b8ef30bfcd9761644001b63ed9b9f717ebd09d93";
const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn fail<T>(message: impl Into<String>) -> Result<T, String> {
    Err(message.into())
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn sha_file(path: &Path) -> Result<String, String> {
    fs::read(path)
        .map(|bytes| sha256(&bytes))
        .map_err(|error| format!("cannot hash {}: {error}", path.display()))
}

fn canonical(value: &Value) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn json_file(path: &Path) -> Result<Value, String> {
    serde_json::from_slice(&fs::read(path).map_err(|error| error.to_string())?)
        .map_err(|error| format!("invalid JSON {}: {error}", path.display()))
}

fn git(root: &Path, arguments: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .args(arguments)
        .current_dir(root)
        .env_clear()
        .env(
            "HOME",
            env::var("HOME").unwrap_or_else(|_| "/tmp".to_owned()),
        )
        .env("PATH", "/usr/bin:/bin")
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err(format!(
            "git {} failed: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn verify_history(root: &Path) -> Result<(), String> {
    let commits = [
        "b3e983891e4ae3e12cd727f6bdb460962f876a30",
        "6c27c9bb26b96855228d1a8e6483483ff4174907",
        "be1ce9327c5c2acab25abe5af7a4f923d1623c48",
        PHASE22,
    ];
    for commit in commits {
        if git(root, &["log", "-1", "--format=%G?", commit])? != "G" {
            return fail(format!("historical commit signature is invalid: {commit}"));
        }
        let message = git(root, &["log", "-1", "--format=%B", commit])?;
        if message
            .lines()
            .filter(|line| line.starts_with("Signed-off-by:"))
            .count()
            != 1
        {
            return fail(format!("historical commit DCO count is not one: {commit}"));
        }
    }
    if git(root, &["rev-parse", "HEAD^"])? != PHASE22 {
        return fail("Phase 23 parent is not exact Phase 22");
    }
    if git(root, &["rev-parse", "HEAD:phase20"])? != "05cd69281777263a4f9286069767d870014cab52"
        || git(root, &["rev-parse", "HEAD:phase22"])? != "048b3c30e0864ca6e61e2af40de11016050a1ca3"
    {
        return fail("Phase 20 or Phase 22 subtree changed");
    }
    if git(root, &["log", "-1", "--format=%G?", "HEAD"])? != "G" {
        return fail("Phase 23 signature is not valid");
    }
    let message = git(root, &["log", "-1", "--format=%B", "HEAD"])?;
    if message
        .lines()
        .filter(|line| line.starts_with("Signed-off-by:"))
        .count()
        != 1
    {
        return fail("Phase 23 must contain exactly one DCO trailer");
    }
    Ok(())
}

fn collect(path: &Path, root: &Path, output: &mut BTreeSet<String>) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() {
        return Err(format!("symlink is forbidden: {}", path.display()));
    }
    if metadata.is_file() {
        output.insert(
            path.strip_prefix(root)
                .map_err(|error| error.to_string())?
                .to_string_lossy()
                .into_owned(),
        );
        return Ok(());
    }
    if path.file_name().and_then(|value| value.to_str()) == Some("target") {
        return Ok(());
    }
    let mut entries = fs::read_dir(path)
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        collect(&entry.path(), root, output)?;
    }
    Ok(())
}

fn sums(path: &Path) -> Result<Vec<(String, String)>, String> {
    fs::read_to_string(path)
        .map_err(|error| error.to_string())?
        .lines()
        .map(|line| {
            let (hash, relative) = line
                .split_once("  ")
                .ok_or_else(|| format!("malformed checksum line in {}", path.display()))?;
            if hash.len() != 64 || relative.is_empty() {
                return Err("malformed checksum fields".to_owned());
            }
            Ok((hash.to_owned(), relative.to_owned()))
        })
        .collect()
}

fn verify_sums(path: &Path, scope: &Path, exhaustive: bool) -> Result<(), String> {
    let entries = sums(path)?;
    let declared = entries
        .iter()
        .map(|(_, relative)| relative.clone())
        .collect::<BTreeSet<_>>();
    for (expected, relative) in entries {
        if relative.starts_with('/') || relative.split('/').any(|part| matches!(part, "." | "..")) {
            return fail("unsafe path in SHA256SUMS");
        }
        let actual = sha_file(&scope.join(&relative))?;
        if actual != expected {
            return fail(format!("checksum mismatch: {relative}"));
        }
    }
    if exhaustive {
        let mut actual = BTreeSet::new();
        collect(scope, scope, &mut actual)?;
        actual.remove("SHA256SUMS");
        if actual != declared {
            return fail("top-level Phase 23 SHA256SUMS is not exhaustive");
        }
    }
    Ok(())
}

fn verify_ledger(path: &Path) -> Result<(usize, String), String> {
    let entries = fs::read_to_string(path)
        .map_err(|error| error.to_string())?
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    let mut previous = ZERO_HASH.to_owned();
    for (index, entry) in entries.iter().enumerate() {
        let sequence = entry.get("sequence").and_then(Value::as_u64);
        if sequence != Some(u64::try_from(index + 1).map_err(|error| error.to_string())?)
            || entry.get("previous_entry_hash").and_then(Value::as_str) != Some(&previous)
        {
            return fail(format!("ledger sequence/chain failure: {}", path.display()));
        }
        let projection = json!({
            "schema_version": entry.get("schema_version").cloned().unwrap_or(Value::Null),
            "sequence": sequence,
            "event": entry.get("event").cloned().unwrap_or(Value::Null),
            "payload_sha256": entry.get("payload_sha256").cloned().unwrap_or(Value::Null),
            "previous_entry_hash": previous,
        });
        let expected = sha256(&canonical(&projection)?);
        if entry.get("entry_hash").and_then(Value::as_str) != Some(expected.as_str()) {
            return fail(format!("ledger entry hash failure: {}", path.display()));
        }
        previous = expected;
    }
    Ok((entries.len(), previous))
}

fn verify_reports(root: &Path) -> Result<(), String> {
    let phase = root.join("phase23");
    let diagnostic = json_file(&phase.join("output/diagnostic/diagnosis.json"))?;
    let thresholds = json_file(&phase.join("output/thresholds/diagnosis.json"))?;
    let qualification = json_file(&phase.join("output/qualification/qualification-report.json"))?;
    let expected = [
        (
            &diagnostic,
            16,
            12,
            "59f5d45b546e169e8981c430605c7d8dc9fef1c3298b87a1324b697645c4f2a8",
        ),
        (
            &thresholds,
            12,
            4,
            "20c26cf22926c8f94dbda344e90e0d92612e5a32c9666d7e6942274bb7d9d58b",
        ),
    ];
    for (report, executions, crashes, head) in expected {
        if report
            .get("synthetic_semgrep_executions")
            .and_then(Value::as_u64)
            != Some(executions)
            || report.get("segmentation_faults").and_then(Value::as_u64) != Some(crashes)
            || report.get("holdout_accesses").and_then(Value::as_u64) != Some(0)
            || report.get("retries").and_then(Value::as_u64) != Some(0)
            || report.get("ledger_head").and_then(Value::as_str) != Some(head)
        {
            return fail("diagnostic report accounting drift");
        }
    }
    if qualification
        .get("synthetic_semgrep_executions")
        .and_then(Value::as_u64)
        != Some(11)
        || qualification
            .get("synthetic_non_scanner_probes")
            .and_then(Value::as_u64)
            != Some(1)
        || qualification
            .get("segmentation_faults")
            .and_then(Value::as_u64)
            != Some(0)
        || qualification
            .get("holdout_accesses")
            .and_then(Value::as_u64)
            != Some(0)
        || qualification.get("retries").and_then(Value::as_u64) != Some(0)
        || qualification
            .get("deterministic_repeats")
            .and_then(Value::as_bool)
            != Some(true)
    {
        return fail("qualification accounting drift");
    }
    let observations = qualification
        .get("observations")
        .and_then(Value::as_array)
        .ok_or_else(|| "qualification observations absent".to_owned())?;
    if observations.len() != 11
        || observations.iter().any(|observation| {
            observation.get("passed").and_then(Value::as_bool) != Some(true)
                || observation
                    .get("segmentation_fault")
                    .and_then(Value::as_bool)
                    != Some(false)
                || observation
                    .get("command")
                    .is_some_and(|value| value.to_string().contains("holdout"))
        })
    {
        return fail("qualification observation failure");
    }
    let ledgers = [
        (phase.join("output/diagnostic/ledger.jsonl"), 16),
        (phase.join("output/thresholds/ledger.jsonl"), 12),
        (phase.join("output/probes/ledger.jsonl"), 1),
        (phase.join("output/stack-probes/ledger.jsonl"), 2),
        (phase.join("output/qualification/ledger.jsonl"), 12),
    ];
    for (path, count) in ledgers {
        if verify_ledger(&path)?.0 != count {
            return fail(format!("ledger count mismatch: {}", path.display()));
        }
    }
    let contract = json_file(&phase.join("config/corrected-environment-contract-v1.json"))?;
    if contract
        .pointer("/resource_limits/stack_soft_bytes")
        .and_then(Value::as_u64)
        != Some(8_388_608)
        || contract
            .pointer("/resource_limits/stack_hard_bytes")
            .and_then(Value::as_u64)
            != Some(8_388_608)
        || contract
            .pointer("/isolation/network_namespace")
            .and_then(Value::as_str)
            != Some("unshared")
    {
        return fail("corrected environment contract drift");
    }
    Ok(())
}

fn verify(root: &Path) -> Result<Value, String> {
    verify_history(root)?;
    verify_reports(root)?;
    let phase = root.join("phase23");
    for scope in [
        "diagnostic",
        "thresholds",
        "probes",
        "stack-probes",
        "qualification",
    ] {
        verify_sums(
            &phase.join(format!("output/{scope}/SHA256SUMS")),
            &phase.join(format!("output/{scope}")),
            false,
        )?;
    }
    verify_sums(&phase.join("SHA256SUMS"), &phase, true)?;
    Ok(json!({
        "state": "verified",
        "scanner_processes_started": 0,
        "holdout_files_opened": 0,
        "phase20_subtree": "05cd69281777263a4f9286069767d870014cab52",
        "phase22_subtree": "048b3c30e0864ca6e61e2af40de11016050a1ca3",
        "synthetic_scanner_executions": 39,
        "synthetic_probe_processes": 4,
    }))
}

fn main() {
    let arguments = env::args().collect::<Vec<_>>();
    let [_, root] = arguments.as_slice() else {
        eprintln!("usage: independent-verify <repository-root>");
        std::process::exit(2);
    };
    match verify(Path::new(root)) {
        Ok(report) => println!("{report}"),
        Err(error) => {
            eprintln!("Phase 23 independent verification failed: {error}");
            std::process::exit(1);
        }
    }
}
