use crate::model::{LedgerEntry, Observation};
use crate::{Phase21Error, canonical_json, sha256, sha256_file, tree_digest};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path};
use std::process::Command;

const OUTPUT: &str = "phase21/output";
const PHASE20_TREE: &str = "05cd69281777263a4f9286069767d870014cab52";

/// Scanner-free independent verification result.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationReport {
    /// Verifier schema identity.
    pub schema_version: String,
    /// Overall state.
    pub state: String,
    /// Number of observation records checked.
    pub observations_verified: u64,
    /// Number of actual scanner processes represented.
    pub scanner_process_attempts_verified: u64,
    /// Final ledger hash.
    pub ledger_head: String,
    /// Checks recomputed from raw evidence.
    pub checks: Vec<String>,
    /// Whether this verifier launches scanners.
    pub scanner_execution: bool,
    /// Whether this verifier opens the holdout.
    pub holdout_access: bool,
}

fn safe_relative(value: &str) -> Result<&Path, Phase21Error> {
    let path = Path::new(value);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(Phase21Error::Verification(format!(
            "unsafe evidence path: {value}"
        )));
    }
    Ok(path)
}

fn read_observations(root: &Path) -> Result<Vec<Observation>, Phase21Error> {
    let attempts = root.join(OUTPUT).join("attempts");
    let mut directories = fs::read_dir(&attempts)?.collect::<Result<Vec<_>, _>>()?;
    directories.sort_by_key(std::fs::DirEntry::file_name);
    let mut observations: Vec<Observation> = Vec::new();
    for directory in directories {
        let path = directory.path().join("observation.json");
        if !path.is_file() {
            return Err(Phase21Error::Verification(format!(
                "attempt has no observation: {}",
                directory.path().display()
            )));
        }
        observations.push(serde_json::from_slice(&fs::read(path)?)?);
    }
    observations.sort_by_key(|observation| observation.sequence);
    Ok(observations)
}

fn verify_raw(observation: &Observation, raw: &[u8]) -> Result<(), Phase21Error> {
    match observation.scenario.as_str() {
        "clean" | "finding" => {
            let value: Value = serde_json::from_slice(raw)?;
            let expected_version = if observation.subject == "opengrep" {
                "1.22.0"
            } else {
                "1.170.0"
            };
            let expected = usize::from(observation.scenario == "finding");
            let results = value
                .get("results")
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    Phase21Error::Verification(format!(
                        "{} raw output has no results",
                        observation.id
                    ))
                })?;
            if value.get("version").and_then(Value::as_str) != Some(expected_version)
                || value
                    .get("errors")
                    .and_then(Value::as_array)
                    .is_none_or(|errors| !errors.is_empty())
                || results.len() != expected
                || results.iter().any(|finding| {
                    finding.get("check_id").and_then(Value::as_str)
                        != Some("secure-bench.phase21.synthetic-eval")
                        || finding.get("path").and_then(Value::as_str) != Some("app.js")
                })
            {
                return Err(Phase21Error::Verification(format!(
                    "{} raw report failed independent adaptation",
                    observation.id
                )));
            }
            if observation.subject == "semgrep-ce"
                && value.get("engine_requested").and_then(Value::as_str) != Some("OSS")
            {
                return Err(Phase21Error::Verification(
                    "Semgrep report is not CE OSS output".to_owned(),
                ));
            }
        }
        "malformed-output" => {
            if serde_json::from_slice::<Value>(raw).is_ok() {
                return Err(Phase21Error::Verification(format!(
                    "{} mock output is not malformed",
                    observation.id
                )));
            }
        }
        _ => {}
    }
    Ok(())
}

fn verify_observation(root: &Path, observation: &Observation) -> Result<(), Phase21Error> {
    if !observation.passed
        || sha256(&canonical_json(&observation.command)?) != observation.command_sha256
    {
        return Err(Phase21Error::Verification(format!(
            "{} is failed or has command drift",
            observation.id
        )));
    }
    let stdout = root.join(safe_relative(&observation.stdout_path)?);
    let stderr = root.join(safe_relative(&observation.stderr_path)?);
    if sha256_file(&stdout)? != observation.stdout_sha256
        || sha256_file(&stderr)? != observation.stderr_sha256
    {
        return Err(Phase21Error::Verification(format!(
            "{} stream hash mismatch",
            observation.id
        )));
    }
    match (
        observation.raw_output_path.as_deref(),
        observation.raw_output_sha256.as_deref(),
    ) {
        (Some(path), Some(expected)) => {
            let raw_path = root.join(safe_relative(path)?);
            let raw = fs::read(&raw_path)?;
            if sha256(&raw) != expected {
                return Err(Phase21Error::Verification(format!(
                    "{} raw hash mismatch",
                    observation.id
                )));
            }
            verify_raw(observation, &raw)?;
        }
        (None, None) => {}
        _ => {
            return Err(Phase21Error::Verification(format!(
                "{} raw path/hash presence mismatch",
                observation.id
            )));
        }
    }
    Ok(())
}

fn verify_ledger(root: &Path, observations: &[Observation]) -> Result<String, Phase21Error> {
    let content = fs::read_to_string(root.join(OUTPUT).join("ledger.jsonl"))?;
    let entries = content
        .lines()
        .map(serde_json::from_str::<LedgerEntry>)
        .collect::<Result<Vec<_>, _>>()?;
    if entries.len() != observations.len() {
        return Err(Phase21Error::Verification(
            "ledger/observation cardinality mismatch".to_owned(),
        ));
    }
    let mut previous = "0".repeat(64);
    for (index, (entry, observation)) in entries.iter().zip(observations).enumerate() {
        let sequence = u64::try_from(index + 1).unwrap_or(u64::MAX);
        let payload = sha256(&canonical_json(observation)?);
        let unsigned = json!({
            "schema_version": "secure-bench-phase21-ledger-v1",
            "sequence": sequence,
            "event": "synthetic-canary-completed",
            "payload_sha256": payload,
            "previous_entry_hash": previous,
        });
        let expected_hash = sha256(&canonical_json(&unsigned)?);
        if entry.sequence != sequence
            || observation.sequence != sequence
            || entry.payload_sha256 != payload
            || entry.previous_entry_hash != previous
            || entry.entry_hash != expected_hash
        {
            return Err(Phase21Error::Verification(format!(
                "ledger chain failed at sequence {sequence}"
            )));
        }
        previous = expected_hash;
    }
    Ok(previous)
}

fn git_tree(root: &Path) -> Result<String, Phase21Error> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "HEAD:phase20"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()?;
    if !output.status.success() {
        return Err(Phase21Error::Verification(
            "cannot resolve immutable Phase 20 tree".to_owned(),
        ));
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|error| Phase21Error::Verification(error.to_string()))
}

pub(crate) fn verify_without_sums(root: &Path) -> Result<VerificationReport, Phase21Error> {
    if git_tree(root)? != PHASE20_TREE {
        return Err(Phase21Error::Verification(
            "Phase 20 tree is not byte-identical".to_owned(),
        ));
    }
    let observations = read_observations(root)?;
    let expected = [
        "opengrep-clean",
        "opengrep-finding",
        "opengrep-legacy-startup",
        "opengrep-malformed-output",
        "opengrep-rule-error",
        "opengrep-startup",
        "opengrep-timeout",
        "sandbox-probe-corrected",
        "sandbox-probe-legacy",
        "semgrep-ce-clean",
        "semgrep-ce-finding",
        "semgrep-ce-legacy-startup",
        "semgrep-ce-malformed-output",
        "semgrep-ce-rule-error",
        "semgrep-ce-startup",
        "semgrep-ce-timeout",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let actual = observations
        .iter()
        .map(|observation| observation.id.as_str())
        .collect::<BTreeSet<_>>();
    let scanner_attempts = observations
        .iter()
        .filter(|observation| observation.scanner_process_attempt)
        .count();
    if actual != expected || observations.len() != 16 || scanner_attempts != 12 {
        return Err(Phase21Error::Verification(format!(
            "qualification population drift: observations={}, scanner_attempts={scanner_attempts}",
            observations.len()
        )));
    }
    for observation in &observations {
        verify_observation(root, observation)?;
    }
    let head = verify_ledger(root, &observations)?;
    let summary: Value =
        serde_json::from_slice(&fs::read(root.join(OUTPUT).join("qualification.json"))?)?;
    if summary.get("state").and_then(Value::as_str) != Some("qualified")
        || summary.get("all_passed").and_then(Value::as_bool) != Some(true)
        || summary
            .pointer("/scope/holdout_opened")
            .and_then(Value::as_bool)
            != Some(false)
        || summary
            .pointer("/scope/phase22_attempts_started")
            .and_then(Value::as_bool)
            != Some(false)
    {
        return Err(Phase21Error::Verification(
            "qualification summary is not fail-closed".to_owned(),
        ));
    }
    let contract: Value = serde_json::from_slice(&fs::read(
        root.join(OUTPUT)
            .join("corrected-environment-contract.json"),
    )?)?;
    let source_digest = tree_digest(&root.join("phase21/src"))?;
    let probe_digest = sha256_file(&root.join("phase21/canaries/sandbox_probe.py"))?;
    if contract
        .pointer("/frozen_inputs/tools/semgrep-wheel-closure")
        .and_then(Value::as_str)
        != Some("5371b438dc6e3c5529794b21c668057164f52fa1375e0e91ee6c8f241fb74181")
        || contract
            .pointer("/device_policy/allowed_devices")
            .and_then(Value::as_array)
            .is_none_or(|devices| devices != &[Value::String("/dev/null".to_owned())])
        || contract
            .get("phase21_implementation_tree_sha256")
            .and_then(Value::as_str)
            != Some(source_digest.as_str())
        || contract.get("sandbox_probe_sha256").and_then(Value::as_str)
            != Some(probe_digest.as_str())
    {
        return Err(Phase21Error::Verification(
            "corrected environment contract is incomplete".to_owned(),
        ));
    }
    Ok(VerificationReport {
        schema_version: "secure-bench-phase21-independent-verification-v1".to_owned(),
        state: "verified".to_owned(),
        observations_verified: 16,
        scanner_process_attempts_verified: 12,
        ledger_head: head,
        checks: vec![
            "Phase 20 Git tree identity recomputed without reading holdout contents".to_owned(),
            "observation stream/raw hashes recomputed".to_owned(),
            "successful OpenGrep and Semgrep JSON independently adapted".to_owned(),
            "Semgrep CE OSS engine provenance enforced".to_owned(),
            "malformed mock outputs independently rejected".to_owned(),
            "hash-chained Phase 21 ledger recomputed".to_owned(),
            "scanner and mock attempt cardinalities enforced".to_owned(),
            "frozen Semgrep wheel closure and single-device policy enforced".to_owned(),
            "implementation and sandbox-probe hashes recomputed".to_owned(),
        ],
        scanner_execution: false,
        holdout_access: false,
    })
}

fn verify_sums(root: &Path) -> Result<(), Phase21Error> {
    let output = root.join(OUTPUT);
    let content = fs::read_to_string(output.join("SHA256SUMS"))?;
    let mut seen = BTreeSet::new();
    for line in content.lines() {
        let (expected, relative) = line
            .split_once("  ")
            .ok_or_else(|| Phase21Error::Verification("malformed SHA256SUMS line".to_owned()))?;
        if expected.len() != 64 || !seen.insert(relative.to_owned()) {
            return Err(Phase21Error::Verification(
                "invalid or duplicate SHA256SUMS entry".to_owned(),
            ));
        }
        let path = output.join(safe_relative(relative)?);
        if sha256_file(&path)? != expected {
            return Err(Phase21Error::Verification(format!(
                "SHA256SUMS mismatch: {relative}"
            )));
        }
    }
    if seen.is_empty() {
        return Err(Phase21Error::Verification("SHA256SUMS is empty".to_owned()));
    }
    Ok(())
}

/// Independently verify sealed evidence without executing a scanner.
pub fn independent_verify(root: &Path) -> Result<VerificationReport, Phase21Error> {
    let report = verify_without_sums(root)?;
    verify_sums(root)?;
    Ok(report)
}
