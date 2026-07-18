use crate::model::{ExecutionState, Observation, Results};
use crate::runner::{
    adapt, build_results, cases, hash_vector, lane, observations, output_path, verify_raw_hashes,
};
use crate::{Phase20Error, canonical_json, read, sha256, validate_schema, write_atomic};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::Path;

fn write_or_verify(path: &Path, bytes: &[u8]) -> Result<(), Phase20Error> {
    if path.exists() {
        if read(path)? != bytes {
            return Err(Phase20Error::Verification(format!(
                "committed verification artifact differs: {}",
                path.display()
            )));
        }
        return Ok(());
    }
    write_atomic(path, bytes)
}

fn output_checksums(root: &Path) -> Result<Vec<u8>, Phase20Error> {
    let output = output_path(root, "");
    let mut files = Vec::new();
    crate::collect_files(&output, &mut files)?;
    files.retain(|path| path.file_name().and_then(|name| name.to_str()) != Some("SHA256SUMS"));
    files.sort();
    let mut sums = String::new();
    for path in files {
        let relative = path.strip_prefix(root).map_err(|_| {
            Phase20Error::Verification("output checksum path escaped repository".to_owned())
        })?;
        sums.push_str(&sha256(&read(&path)?));
        sums.push_str("  ");
        sums.push_str(&relative.to_string_lossy());
        sums.push('\n');
    }
    Ok(sums.into_bytes())
}

#[derive(Debug, Deserialize)]
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

fn verify_ledger(
    root: &Path,
    observations: &[Observation],
    result_bytes: &[u8],
) -> Result<(u64, String), Phase20Error> {
    let bytes = read(&output_path(root, "ledger.jsonl"))?;
    let entries = serde_json::Deserializer::from_slice(&bytes)
        .into_iter::<LedgerEntry>()
        .collect::<Result<Vec<_>, _>>()?;
    if entries.len() != observations.len() + 2 {
        return Err(Phase20Error::Verification(format!(
            "ledger has {} entries, expected {}",
            entries.len(),
            observations.len() + 2
        )));
    }
    let mut previous = "0".repeat(64);
    for (index, entry) in entries.iter().enumerate() {
        if entry.schema_version != "secure-bench-phase20-ledger-entry-v1"
            || entry.sequence != index as u64
            || entry.previous_entry_hash != previous
        {
            return Err(Phase20Error::Verification(
                "ledger sequence or previous hash drift".to_owned(),
            ));
        }
        let material = json!({
            "schema_version": entry.schema_version,
            "sequence": entry.sequence,
            "timestamp_unix_ms": entry.timestamp_unix_ms,
            "event": entry.event,
            "payload_sha256": entry.payload_sha256,
            "previous_entry_hash": entry.previous_entry_hash
        });
        if sha256(&serde_json::to_vec(&material)?) != entry.entry_hash {
            return Err(Phase20Error::Verification(
                "ledger entry hash drift".to_owned(),
            ));
        }
        let expected_payload = if index == 0 {
            sha256(&read(&output_path(root, "HOLDOUT_OPENED.json"))?)
        } else if index <= observations.len() {
            sha256(&canonical_json(&observations[index - 1])?)
        } else {
            sha256(result_bytes)
        };
        if entry.payload_sha256 != expected_payload {
            return Err(Phase20Error::Verification(
                "ledger payload hash drift".to_owned(),
            ));
        }
        previous.clone_from(&entry.entry_hash);
    }
    Ok((entries.len() as u64, previous))
}

pub(crate) fn independent(root: &Path) -> Result<Value, Phase20Error> {
    let preflight_bytes = read(&root.join("phase20/preflight/preflight.json"))?;
    let preflight_value: Value = serde_json::from_slice(&preflight_bytes)?;
    validate_schema(
        root,
        "phase20/schemas/preflight-v1.schema.json",
        &preflight_value,
    )?;
    let opening_bytes = read(&output_path(root, "HOLDOUT_OPENED.json"))?;
    let opening: Value = serde_json::from_slice(&opening_bytes)?;
    if opening.get("preflight_sha256").and_then(Value::as_str)
        != Some(sha256(&preflight_bytes).as_str())
        || opening.get("irreversible").and_then(Value::as_bool) != Some(true)
    {
        return Err(Phase20Error::Verification(
            "opening marker does not bind the frozen preflight".to_owned(),
        ));
    }
    let cases = cases(root)?;
    let observations = observations(root)?;
    if observations.len() != 336
        || observations
            .iter()
            .map(|item| (&item.scanner, &item.lane, &item.case_id))
            .collect::<BTreeSet<_>>()
            .len()
            != 336
        || observations
            .iter()
            .enumerate()
            .any(|(index, item)| item.attempt_sequence != (index + 1) as u64)
    {
        return Err(Phase20Error::Verification(
            "attempt population is not exactly 336 unique ordered observations".to_owned(),
        ));
    }
    verify_raw_hashes(root, &observations)?;
    for observation in &observations {
        if hash_vector(&observation.command) != observation.command_sha256
            || hash_vector(&observation.environment) != observation.environment_sha256
        {
            return Err(Phase20Error::Verification(format!(
                "command or environment hash differs for {}",
                observation.case_id
            )));
        }
        if observation.state != ExecutionState::Completed {
            if observation.finding_count.is_some() {
                return Err(Phase20Error::Verification(
                    "failed attempt contains an imputed finding count".to_owned(),
                ));
            }
            continue;
        }
        let case = cases
            .iter()
            .find(|case| case.case_id == observation.case_id)
            .ok_or_else(|| Phase20Error::Verification("observation case is unknown".to_owned()))?;
        let lane = lane(&observation.scanner, &observation.lane).ok_or_else(|| {
            Phase20Error::Verification("observation scanner/lane is ineligible".to_owned())
        })?;
        let raw_path = observation.raw_output_path.as_ref().ok_or_else(|| {
            Phase20Error::Verification("completed observation has no raw path".to_owned())
        })?;
        let count = adapt(
            root,
            lane,
            case,
            &root.join(&case.fixture_path),
            &read(&root.join(raw_path))?,
        )
        .map_err(Phase20Error::Verification)?;
        if observation.finding_count != Some(count) {
            return Err(Phase20Error::Verification(format!(
                "independent finding count differs for {}",
                observation.case_id
            )));
        }
    }
    let recomputed = build_results(&cases, &observations);
    let recomputed_bytes = canonical_json(&recomputed)?;
    let committed_bytes = read(&output_path(root, "results.json"))?;
    let committed: Results = serde_json::from_slice(&committed_bytes)?;
    validate_schema(root, "phase20/schemas/results-v1.schema.json", &committed)?;
    if committed != recomputed || committed_bytes != recomputed_bytes {
        return Err(Phase20Error::Verification(
            "canonical results differ from independent recomputation".to_owned(),
        ));
    }
    if recomputed.total_scanner_process_attempts != 336 || recomputed.repeated_attempts {
        return Err(Phase20Error::Verification(
            "one-shot count or retry invariant failed".to_owned(),
        ));
    }
    let (ledger_entries, final_entry_hash) = verify_ledger(root, &observations, &committed_bytes)?;
    let artifacts: Value = serde_json::from_slice(&read(&output_path(root, "artifacts.json"))?)?;
    if artifacts.get("opening_sha256").and_then(Value::as_str)
        != Some(sha256(&opening_bytes).as_str())
        || artifacts.get("ledger_sha256").and_then(Value::as_str)
            != Some(sha256(&read(&output_path(root, "ledger.jsonl"))?).as_str())
        || artifacts.get("results_sha256").and_then(Value::as_str)
            != Some(sha256(&committed_bytes).as_str())
        || artifacts.get("report_sha256").and_then(Value::as_str)
            != Some(sha256(&read(&output_path(root, "report.md"))?).as_str())
        || artifacts.get("raw_observations").and_then(Value::as_u64) != Some(336)
        || artifacts
            .get("scanner_process_attempts")
            .and_then(Value::as_u64)
            != Some(336)
        || artifacts
            .get("network_operations_during_execution")
            .and_then(Value::as_u64)
            != Some(0)
        || artifacts
            .get("ai_provider_invocations")
            .and_then(Value::as_u64)
            != Some(0)
        || artifacts.get("credential_flows").and_then(Value::as_u64) != Some(0)
        || artifacts
            .get("final_ledger_entry_hash")
            .and_then(Value::as_str)
            != Some(final_entry_hash.as_str())
    {
        return Err(Phase20Error::Verification(
            "artifact index does not bind recomputed evidence".to_owned(),
        ));
    }
    let proof = json!({
        "schema_version": "secure-bench-phase20-independent-verification-v1",
        "status": "verified",
        "raw_observations_rehashed": observations.len(),
        "raw_reports_readapted": observations.iter().filter(|item| item.state == ExecutionState::Completed).count(),
        "results_sha256": sha256(&committed_bytes),
        "ledger_sha256": sha256(&read(&output_path(root, "ledger.jsonl"))?),
        "ledger_entries": ledger_entries,
        "final_ledger_entry_hash": final_entry_hash,
        "scanner_process_attempts": 336,
        "repeated_attempts": false,
        "cross_lane_aggregation": false
    });
    write_or_verify(
        &output_path(root, "independent-verification.json"),
        &canonical_json(&proof)?,
    )?;
    write_or_verify(&output_path(root, "SHA256SUMS"), &output_checksums(root)?)?;
    Ok(proof)
}
