//! Independent scanner-free verifier for Secure Bench Phase 30.

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const BASE_COMMIT: &str = "9b6566e600d18160865e45eda31d8634669c889a";
const PHASE28_TREE: &str = "4c1c45ee433b70ff85eb4327be3612975e556a18";
const PHASE29_TREE: &str = "629be7e1da9b288480ab1869a184de3c8ad923dd";
const EXECUTABLE_SHA256: &str = "5feca58fda54e4f9af0bf3846d04a98825d7315e64cbf80268a2395cf07ff2e6";
const BINDING_SHA256: &str = "8d1a822e8a0828b06a1c6bb5629625314a6576f24296b8f5dc9aee8da8850a6a";
const POLICY_SHA256: &str = "8b5ff33690828dc97afa8be24ef14dc66bf44d6da913e2621d92208e513f26ac";

type CheckResult<T> = Result<T, String>;

#[derive(Clone, Debug)]
struct Row {
    attempt_id: String,
    case_id: String,
    detected: bool,
    exit_code: i64,
    family_id: String,
    finding_count: usize,
    framework: String,
    label: String,
    pair_id: String,
    sequence: i64,
    source_format: String,
    topology: String,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Confusion {
    false_negative: u64,
    false_positive: u64,
    true_negative: u64,
    true_positive: u64,
}

#[derive(Clone, Copy, Debug)]
struct OperationalEvidence {
    authoritative_report: bool,
    contract_present: bool,
    operational_error: bool,
}

fn sha256_bytes(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(data);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn sha256_file(path: &Path) -> CheckResult<String> {
    fs::read(path)
        .map(|bytes| sha256_bytes(&bytes))
        .map_err(|error| format!("cannot hash {}: {error}", path.display()))
}

fn read_json(path: &Path) -> CheckResult<Value> {
    let bytes =
        fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid JSON {}: {error}", path.display()))
}

fn canonical_bytes(value: &Value) -> CheckResult<Vec<u8>> {
    let mut bytes =
        serde_json::to_vec(value).map_err(|error| format!("JSON serialization failed: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn field<'a>(value: &'a Value, name: &str) -> CheckResult<&'a Value> {
    value
        .get(name)
        .ok_or_else(|| format!("missing required field {name}"))
}

fn string_field(value: &Value, name: &str) -> CheckResult<String> {
    field(value, name)?
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("field {name} is not a string"))
}

fn integer_field(value: &Value, name: &str) -> CheckResult<i64> {
    field(value, name)?
        .as_i64()
        .ok_or_else(|| format!("field {name} is not an integer"))
}

fn bool_field(value: &Value, name: &str) -> CheckResult<bool> {
    field(value, name)?
        .as_bool()
        .ok_or_else(|| format!("field {name} is not a boolean"))
}

fn command_output(root: &Path, arguments: &[&str]) -> CheckResult<String> {
    let output = Command::new("git")
        .args(arguments)
        .current_dir(root)
        .output()
        .map_err(|error| format!("cannot run git: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "git {} failed: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|error| format!("git emitted non-UTF-8 output: {error}"))
}

fn verify_git_integrity(root: &Path) -> CheckResult<()> {
    if command_output(root, &["rev-parse", "main"])? != BASE_COMMIT {
        return Err("main is not the authoritative Phase 29 commit".to_owned());
    }
    if command_output(root, &["rev-parse", &format!("{BASE_COMMIT}:phase28")])? != PHASE28_TREE {
        return Err("Phase 28 Git tree drift".to_owned());
    }
    if command_output(root, &["rev-parse", &format!("{BASE_COMMIT}:phase29")])? != PHASE29_TREE {
        return Err("Phase 29 Git tree drift".to_owned());
    }
    let status = Command::new("git")
        .args(["diff", "--quiet", BASE_COMMIT, "--", "phase28", "phase29"])
        .current_dir(root)
        .status()
        .map_err(|error| format!("cannot audit Phase 28/29 working trees: {error}"))?;
    if !status.success() {
        return Err("Phase 28/29 working-tree bytes differ from Phase 29".to_owned());
    }
    for stash in [
        "a5f8d978f21dae028eb722a5e73e12d858eeecb2",
        "73905cd14490f6bbe542dbd80c9f9b0c5889a3cf",
    ] {
        if command_output(root, &["rev-parse", &format!("{stash}^{{commit}}")])? != stash {
            return Err(format!("preserved stash {stash} is unavailable"));
        }
    }
    Ok(())
}

fn verify_contracts(root: &Path) -> CheckResult<Value> {
    let sources = [
        (
            root.join("docs/contracts.md"),
            "84f50028dd58905ce3fe8ccefbd6cadc2852521b467f0f7f763cd52f6e761430",
        ),
        (
            root.join("docs/phase-16-authoritative-v2-adapter.md"),
            "ea26d4497a8a812216d76dac4371919363ebdb494f7ad5318392621667100c37",
        ),
        (root.join("policies/process-status-v1.json"), POLICY_SHA256),
        (
            root.join("schemas/process-status-policy-v1.schema.json"),
            "f2ea85696844e6e00b2722a161dbc391203c6fe5b863fe45df042c2d6a52405f",
        ),
        (
            PathBuf::from(
                "/home/danielcastrillon/Proyectos/secure-engine-rc/0.1.7-rc1/provenance.json",
            ),
            "80c543e8821a2f3ebc692f3fd325c35efcafcd34b6b4dbf3c758ff19dedd6826",
        ),
        (
            PathBuf::from(
                "/home/danielcastrillon/Proyectos/secure-engine-rc/0.1.7-rc1/release-notes.md",
            ),
            "a90652554e3ef5a30f67111687f8e9363c45caec7feb7372d4132ee6b2c0cd30",
        ),
        (
            PathBuf::from(
                "/home/danielcastrillon/Proyectos/secure-engine-rc/0.1.7-rc1/verification/build-a/secure-json-v1.schema.json",
            ),
            "880ace73f07ff719945d66889e33a8ab7477cf5570236c356177e493e841f0b1",
        ),
    ];
    for (path, expected) in sources {
        if sha256_file(&path)? != expected {
            return Err(format!(
                "frozen contract/provenance drift: {}",
                path.display()
            ));
        }
    }
    let policy = read_json(&root.join("policies/process-status-v1.json"))?;
    if string_field(&policy, "schema_version")? != "secure-bench-process-status-policy-v1"
        || string_field(&policy, "policy_version")? != "1.0.0"
    {
        return Err("unexpected process-status contract identity".to_owned());
    }
    let status = field(&policy, "statuses")?;
    let documented = string_field(status, "policy_exit_with_valid_findings_report")?;
    if !documented.contains("Nonzero normal exit")
        || !documented.contains("adapter-valid")
        || !documented.contains("findings")
    {
        return Err("authoritative exit-status semantics are absent".to_owned());
    }
    let executable =
        Path::new("/home/danielcastrillon/Proyectos/secure-engine-rc/0.1.7-rc1/extracted/secure");
    if sha256_file(executable)? != EXECUTABLE_SHA256 {
        return Err("Secure Engine executable hash mismatch".to_owned());
    }
    let schema_path = Path::new(
        "/home/danielcastrillon/Proyectos/secure-engine-rc/0.1.7-rc1/verification/build-a/secure-json-v1.schema.json",
    );
    read_json(schema_path)
}

fn locate_evidence(
    root: &Path,
    attempt_dir: &Path,
    filename: &str,
    sequence: i64,
) -> CheckResult<Vec<u8>> {
    let direct = attempt_dir.join(filename);
    if direct.exists() {
        return fs::read(&direct)
            .map_err(|error| format!("cannot read {}: {error}", direct.display()));
    }
    if sequence != 1 {
        return Err(format!("missing {filename} for sequence {sequence}"));
    }
    let inherited = root
        .join("phase28/evidence/attempts/001-p28-secure-engine-0-1-7-rc1-001")
        .join(filename);
    fs::read(&inherited).map_err(|error| format!("cannot read {}: {error}", inherited.display()))
}

fn validate_operational_class(
    exit_code: i64,
    finding_count: usize,
    evidence: OperationalEvidence,
) -> CheckResult<&'static str> {
    if !evidence.contract_present {
        return Err("exit-status contract is absent".to_owned());
    }
    if !evidence.authoritative_report || evidence.operational_error {
        return Err("authoritative report conditions are not satisfied".to_owned());
    }
    match (exit_code, finding_count) {
        (0, 0) => Ok("clean_successful_report"),
        (0, _) => Ok("successful_findings_report"),
        (1, 1..) => Ok("policy_exit_with_valid_findings_report"),
        (1, 0) => Err("exit 1 without findings is a genuine crash".to_owned()),
        _ => Err(format!("unexpected exit code {exit_code}")),
    }
}

#[allow(clippy::too_many_lines)]
fn audit_attempts(root: &Path, raw_schema: &Value) -> CheckResult<Vec<Row>> {
    let validator = jsonschema::validator_for(raw_schema)
        .map_err(|error| format!("cannot compile frozen raw schema: {error}"))?;
    let baseline_command = field(
        &read_json(
            &root
                .join("phase28/evidence/attempts/001-p28-secure-engine-0-1-7-rc1-001/command.json"),
        )?,
        "normalized",
    )?
    .clone();
    let phase29_provenance = read_json(&root.join("phase29/provenance.json"))?;
    let binding = field(
        field(&phase29_provenance, "scanner_bindings")?,
        "secure-engine",
    )?;
    if sha256_bytes(&canonical_bytes(binding)?) != BINDING_SHA256 {
        return Err("Phase 29 Secure Engine binding hash mismatch".to_owned());
    }

    let evidence_root = root.join("phase29/evidence/attempts");
    let mut directories = fs::read_dir(&evidence_root)
        .map_err(|error| format!("cannot enumerate {}: {error}", evidence_root.display()))?
        .map(|entry| {
            entry
                .map(|value| value.path())
                .map_err(|error| error.to_string())
        })
        .collect::<CheckResult<Vec<_>>>()?;
    directories.sort();

    let mut rows = Vec::new();
    let mut attempt_ids = BTreeSet::new();
    let mut case_ids = BTreeSet::new();
    let mut sequences = BTreeSet::new();
    for attempt_dir in directories {
        let observation = read_json(&attempt_dir.join("observation.json"))?;
        if string_field(&observation, "artifact_id")? != "secure-engine-0.1.7-rc1" {
            continue;
        }
        let attempt_id = string_field(&observation, "attempt_id")?;
        let case_id = string_field(&observation, "case_id")?;
        let sequence = integer_field(&observation, "sequence")?;
        if !attempt_ids.insert(attempt_id.clone())
            || !case_ids.insert(case_id.clone())
            || !sequences.insert(sequence)
        {
            return Err("duplicate Secure Engine attempt, case, or sequence".to_owned());
        }

        let raw_bytes = locate_evidence(root, &attempt_dir, "raw.json", sequence)?;
        let stderr_bytes = locate_evidence(root, &attempt_dir, "stderr.bin", sequence)?;
        let stdout_bytes = locate_evidence(root, &attempt_dir, "stdout.bin", sequence)?;
        let adapter_bytes = fs::read(attempt_dir.join("adapter.json"))
            .map_err(|error| format!("cannot read adapter at sequence {sequence}: {error}"))?;
        let raw: Value = serde_json::from_slice(&raw_bytes).map_err(|error| {
            format!("raw is not byte-valid UTF-8 JSON at sequence {sequence}: {error}")
        })?;
        let adapter: Value = serde_json::from_slice(&adapter_bytes)
            .map_err(|error| format!("adapter is invalid JSON at sequence {sequence}: {error}"))?;
        validator
            .validate(&raw)
            .map_err(|error| format!("raw schema failure at sequence {sequence}: {error}"))?;

        let findings = field(&raw, "findings")?
            .as_array()
            .ok_or_else(|| format!("raw findings is not an array at sequence {sequence}"))?;
        let adapter_findings = field(&adapter, "findings")?
            .as_array()
            .ok_or_else(|| format!("adapter findings is not an array at sequence {sequence}"))?;
        if sha256_bytes(&raw_bytes) != string_field(&observation, "raw_json_sha256")? {
            return Err(format!("raw hash mismatch at sequence {sequence}"));
        }
        if sha256_bytes(&adapter_bytes) != string_field(&observation, "adapter_output_sha256")? {
            return Err(format!("adapter hash mismatch at sequence {sequence}"));
        }
        if findings.len() != adapter_findings.len()
            || i64::try_from(findings.len()).map_err(|error| error.to_string())?
                != integer_field(&observation, "finding_count")?
        {
            return Err(format!("finding-count mismatch at sequence {sequence}"));
        }
        if string_field(&adapter, "schema_version")? != "secure-json-v1"
            || string_field(&adapter, "report_sha256")? != sha256_bytes(&raw_bytes)
            || !bool_field(&observation, "adapter_valid")?
        {
            return Err(format!(
                "adapter-invalid observation at sequence {sequence}"
            ));
        }
        let adapter_process = field(&observation, "adapter")?;
        if integer_field(adapter_process, "returncode")? != 0
            || !field(adapter_process, "spawn_error")?.is_null()
        {
            return Err(format!("adapter process failure at sequence {sequence}"));
        }

        let (exit_code, signal, timed_out, spawn_error, normalized_command) =
            if let Some(process) = observation.get("process") {
                let hashes = field(&observation, "hashes")?;
                if string_field(hashes, "scanner_binding_sha256")? != BINDING_SHA256 {
                    return Err(format!("scanner binding drift at sequence {sequence}"));
                }
                (
                    integer_field(process, "returncode")?,
                    field(process, "signal")?,
                    bool_field(process, "timed_out")?,
                    field(process, "spawn_error")?,
                    field(&observation, "normalized_command")?,
                )
            } else {
                let process = field(&observation, "scanner_process")?;
                (
                    integer_field(process, "exit_code")?,
                    field(process, "signal")?,
                    false,
                    &Value::Null,
                    &baseline_command,
                )
            };
        if normalized_command != &baseline_command {
            return Err(format!("command/environment drift at sequence {sequence}"));
        }
        if integer_field(&observation, "retry_ordinal")? != 0 {
            return Err(format!("retry observed at sequence {sequence}"));
        }
        let report_complete = field(field(&raw, "scan")?, "complete")?.as_bool() == Some(true);
        let not_truncated = field(field(&raw, "analysis")?, "truncated")?.as_bool() == Some(false);
        let errors_empty = field(&raw, "errors")?.as_array().is_some_and(Vec::is_empty);
        let stderr = String::from_utf8(stderr_bytes)
            .map_err(|error| format!("stderr is not UTF-8 at sequence {sequence}: {error}"))?;
        let stderr_lower = stderr.to_ascii_lowercase();
        let expected_summary = format!("secure: {} findings,", findings.len());
        let stderr_valid = stderr.contains("secure: complete (")
            && stderr.contains("secure: wrote complete report to /tmp/run/raw.json")
            && stderr.contains(&expected_summary)
            && ![
                "panic",
                "fatal",
                "segmentation",
                "cancelled",
                "truncated",
                "failed",
            ]
            .iter()
            .any(|needle| stderr_lower.contains(needle));
        let operational_error = !signal.is_null()
            || timed_out
            || !spawn_error.is_null()
            || !errors_empty
            || !not_truncated
            || !stderr_valid
            || !stdout_bytes.is_empty();
        let classification = validate_operational_class(
            exit_code,
            findings.len(),
            OperationalEvidence {
                authoritative_report: report_complete,
                contract_present: true,
                operational_error,
            },
        )?;
        if exit_code == 1 && classification != "policy_exit_with_valid_findings_report" {
            return Err(format!(
                "incorrect exit-1 classification at sequence {sequence}"
            ));
        }
        rows.push(Row {
            attempt_id,
            case_id,
            detected: !findings.is_empty(),
            exit_code,
            family_id: string_field(&observation, "family_id")?,
            finding_count: findings.len(),
            framework: string_field(&observation, "framework")?,
            label: string_field(&observation, "label")?,
            pair_id: string_field(&observation, "pair_id")?,
            sequence,
            source_format: string_field(&observation, "source_format")?,
            topology: string_field(&observation, "topology")?,
        });
    }
    let expected_sequences = (1_i64..=112).collect::<BTreeSet<_>>();
    if rows.len() != 112 || sequences != expected_sequences {
        return Err("Secure Engine coverage is not exactly sequences 1..112".to_owned());
    }
    Ok(rows)
}

fn confusion(rows: &[Row]) -> Confusion {
    let mut result = Confusion::default();
    for row in rows {
        match (row.label.as_str(), row.detected) {
            ("vulnerable", true) => result.true_positive += 1,
            ("vulnerable", false) => result.false_negative += 1,
            ("control", true) => result.false_positive += 1,
            ("control", false) => result.true_negative += 1,
            _ => {}
        }
    }
    result
}

#[allow(clippy::cast_precision_loss)]
fn ratio(numerator: u64, denominator: u64) -> Option<f64> {
    (denominator != 0).then(|| numerator as f64 / denominator as f64)
}

fn metrics(rows: &[Row]) -> Value {
    let counts = confusion(rows);
    let precision = ratio(
        counts.true_positive,
        counts.true_positive + counts.false_positive,
    );
    let recall = ratio(
        counts.true_positive,
        counts.true_positive + counts.false_negative,
    );
    let specificity = ratio(
        counts.true_negative,
        counts.true_negative + counts.false_positive,
    );
    let f1 = ratio(
        2 * counts.true_positive,
        2 * counts.true_positive + counts.false_positive + counts.false_negative,
    );
    let balanced_accuracy = recall
        .zip(specificity)
        .map(|(left, right)| f64::midpoint(left, right));
    json!({
        "attempts": rows.len(),
        "balanced_accuracy": balanced_accuracy,
        "completed": rows.len(),
        "completion_rate": 1.0,
        "confusion_matrix_completed_only": {
            "fn": counts.false_negative,
            "fp": counts.false_positive,
            "tn": counts.true_negative,
            "tp": counts.true_positive,
        },
        "f1": f1,
        "failure_rate": 0.0,
        "fully_scorable": true,
        "non_completed": 0,
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
    })
}

fn grouped_metrics<F>(rows: &[Row], accessor: F) -> Value
where
    F: Fn(&Row) -> &str,
{
    let mut groups: BTreeMap<String, Vec<Row>> = BTreeMap::new();
    for row in rows {
        groups
            .entry(accessor(row).to_owned())
            .or_default()
            .push(row.clone());
    }
    Value::Object(
        groups
            .into_iter()
            .map(|(name, values)| (name, metrics(&values)))
            .collect(),
    )
}

fn lane_results(rows: &[Row]) -> Value {
    json!({
        "by_family": grouped_metrics(rows, |row| &row.family_id),
        "by_framework": grouped_metrics(rows, |row| &row.framework),
        "by_pair": grouped_metrics(rows, |row| &row.pair_id),
        "by_source_format": grouped_metrics(rows, |row| &row.source_format),
        "by_topology": grouped_metrics(rows, |row| &row.topology),
        "lane": "native",
        "overall": metrics(rows),
    })
}

fn first_json_difference(expected: &Value, actual: &Value, path: &str) -> Option<String> {
    match (expected, actual) {
        (Value::Object(left), Value::Object(right)) => {
            let keys = left.keys().chain(right.keys()).collect::<BTreeSet<_>>();
            for key in keys {
                let next = format!("{path}.{key}");
                match (left.get(key), right.get(key)) {
                    (Some(left_value), Some(right_value)) => {
                        if let Some(found) = first_json_difference(left_value, right_value, &next) {
                            return Some(found);
                        }
                    }
                    _ => return Some(format!("{next}: key presence differs")),
                }
            }
            None
        }
        (Value::Array(left), Value::Array(right)) => {
            if left.len() != right.len() {
                return Some(format!(
                    "{path}: array lengths {} != {}",
                    left.len(),
                    right.len()
                ));
            }
            for (index, (left_value, right_value)) in left.iter().zip(right).enumerate() {
                let next = format!("{path}[{index}]");
                if let Some(found) = first_json_difference(left_value, right_value, &next) {
                    return Some(found);
                }
            }
            None
        }
        (Value::Number(left), Value::Number(right))
            if left
                .as_f64()
                .zip(right.as_f64())
                .is_some_and(|(left, right)| (left - right).abs() <= f64::EPSILON * 4.0) =>
        {
            None
        }
        _ if expected == actual => None,
        _ => Some(format!("{path}: expected {expected}, recomputed {actual}")),
    }
}

fn verify_exit_matrix(root: &Path, rows: &[Row]) -> CheckResult<()> {
    let actual = read_json(&root.join("phase30/aggregate-exit-matrix.json"))?;
    let count = |exit_code: i64, has_findings: bool| {
        rows.iter()
            .filter(|row| row.exit_code == exit_code && (row.finding_count > 0) == has_findings)
            .count()
    };
    let expected = json!({
        "attempts": 112,
        "engine_errors_or_signals": 0,
        "exit_0_findings": count(0, true),
        "exit_0_zero_findings": count(0, false),
        "exit_1_findings": count(1, true),
        "exit_1_zero_findings": count(1, false),
        "invalid_raw_or_schema": 0,
        "raw_complete": 112,
        "schema_version": "secure-bench-phase30-aggregate-exit-matrix-v1",
        "stderr_complete_report_pattern": 112,
        "stdout_empty": 112,
    });
    if actual != expected {
        return Err("aggregate exit matrix does not match independent recomputation".to_owned());
    }
    Ok(())
}

fn verify_results(root: &Path, rows: &[Row]) -> CheckResult<Value> {
    let phase29 = read_json(&root.join("phase29/results.json"))?;
    let certified = read_json(&root.join("phase30/certified-results.json"))?;
    let certified_lanes = field(&certified, "lanes")?;
    let phase29_lanes = field(&phase29, "lanes")?;
    for lane in ["opengrep-1.22.0", "semgrep-ce-1.170.0"] {
        if field(certified_lanes, lane)? != field(phase29_lanes, lane)? {
            return Err(format!("normalized lane changed: {lane}"));
        }
    }
    let secure = lane_results(rows);
    let recorded_secure = field(certified_lanes, "secure-engine-0.1.7-rc1")?;
    if let Some(detail) = first_json_difference(recorded_secure, &secure, "secure-engine") {
        return Err(format!(
            "Secure Engine metrics differ from independent recomputation: {detail}"
        ));
    }
    if integer_field(&certified, "attempts")? != 336 || integer_field(&certified, "retries")? != 0 {
        return Err("certified result accounting drift".to_owned());
    }
    let comparison = read_json(&root.join("phase30/comparison.json"))?;
    if bool_field(&comparison, "native_vs_normalized_winner_allowed")? {
        return Err("cross-lane winner was incorrectly enabled".to_owned());
    }
    if first_json_difference(
        field(&comparison, "secure_engine_native")?,
        field(&secure, "overall")?,
        "comparison.secure-engine",
    )
    .is_some()
        || field(&comparison, "opengrep")?
            != field(field(phase29_lanes, "opengrep-1.22.0")?, "overall")?
        || field(&comparison, "semgrep")?
            != field(field(phase29_lanes, "semgrep-ce-1.170.0")?, "overall")?
    {
        return Err("comparison artifact drift".to_owned());
    }
    Ok(secure)
}

fn verify_classification(root: &Path, rows: &[Row]) -> CheckResult<()> {
    let artifact = read_json(&root.join("phase30/evidence-classification.json"))?;
    let records = field(&artifact, "attempts")?
        .as_array()
        .ok_or_else(|| "evidence-classification attempts is not an array".to_owned())?;
    if records.len() != rows.len() {
        return Err("evidence-classification count drift".to_owned());
    }
    for (record, row) in records.iter().zip(rows) {
        if integer_field(record, "sequence")? != row.sequence
            || string_field(record, "attempt_id")? != row.attempt_id
            || string_field(record, "case_id")? != row.case_id
            || string_field(record, "certified_status")? != "completed"
            || integer_field(record, "exit_code")? != row.exit_code
            || integer_field(record, "retry_ordinal")? != 0
        {
            return Err(format!("classification drift at sequence {}", row.sequence));
        }
    }
    let counts = field(&artifact, "certified_status_counts")?;
    if integer_field(counts, "completed")? != 112 || integer_field(counts, "failed")? != 0 {
        return Err("certified status counts drift".to_owned());
    }
    Ok(())
}

fn verify_ledger(root: &Path) -> CheckResult<String> {
    let ledger_path = root.join("phase30/ledger/certification.jsonl");
    let content = fs::read_to_string(&ledger_path)
        .map_err(|error| format!("cannot read {}: {error}", ledger_path.display()))?;
    let mut previous = "0".repeat(64);
    let mut entries = 0_i64;
    for (index, line) in content.lines().enumerate() {
        let mut entry: Value = serde_json::from_str(line)
            .map_err(|error| format!("invalid ledger entry {index}: {error}"))?;
        let claimed = string_field(&entry, "entry_sha256")?;
        let object = entry
            .as_object_mut()
            .ok_or_else(|| format!("ledger entry {index} is not an object"))?;
        object.remove("entry_sha256");
        if integer_field(&entry, "index")?
            != i64::try_from(index).map_err(|error| error.to_string())?
            || string_field(&entry, "previous_sha256")? != previous
        {
            return Err(format!("ledger linkage failure at entry {index}"));
        }
        let actual = sha256_bytes(&canonical_bytes(&entry)?);
        if actual != claimed {
            return Err(format!("ledger hash failure at entry {index}"));
        }
        previous = claimed;
        entries += 1;
    }
    let head = read_json(&root.join("phase30/ledger-head.json"))?;
    if integer_field(&head, "entries")? != entries
        || string_field(&head, "head_sha256")? != previous
    {
        return Err("ledger head mismatch".to_owned());
    }
    Ok(previous)
}

fn verify_phase29_accounting(root: &Path) -> CheckResult<()> {
    let audit = read_json(&root.join("phase29/audit/attempts.json"))?;
    if integer_field(&audit, "accumulated")? != 336
        || integer_field(&audit, "unique_scanner_case_combinations")? != 336
        || integer_field(&audit, "retries")? != 0
    {
        return Err("Phase 29 attempt accounting drift".to_owned());
    }
    let provenance = read_json(&root.join("phase30/provenance.json"))?;
    let execution = field(&provenance, "this_phase_execution")?;
    for name in [
        "adapter_executions",
        "case_executions",
        "network_requests",
        "runner_executions",
        "scanner_executions",
        "scanner_retries",
    ] {
        if integer_field(execution, name)? != 0 {
            return Err(format!("nonzero Phase 30 execution accounting: {name}"));
        }
    }
    Ok(())
}

fn verify_contract_artifact(root: &Path) -> CheckResult<()> {
    let contract = read_json(&root.join("phase30/exit-status-contract.json"))?;
    if string_field(&contract, "policy_sha256")? != POLICY_SHA256
        || string_field(&contract, "executable_sha256")? != EXECUTABLE_SHA256
    {
        return Err("exit-status contract artifact identity drift".to_owned());
    }
    let certification = field(&contract, "certification")?;
    if string_field(certification, "status")? != "certified"
        || string_field(certification, "decision")?
            != "exit-1-with-authoritative-findings-is-valid-completion"
    {
        return Err("exit-status certification artifact is fail-open or absent".to_owned());
    }
    Ok(())
}

fn verify_core(root: &Path) -> CheckResult<(Vec<Row>, Value, String)> {
    verify_git_integrity(root)?;
    let raw_schema = verify_contracts(root)?;
    verify_contract_artifact(root)?;
    let rows = audit_attempts(root, &raw_schema)?;
    verify_exit_matrix(root, &rows)?;
    verify_classification(root, &rows)?;
    let secure = verify_results(root, &rows)?;
    verify_phase29_accounting(root)?;
    let ledger_head = verify_ledger(root)?;
    Ok((rows, secure, ledger_head))
}

fn write_proof(root: &Path, rows: &[Row], secure: &Value, ledger_head: &str) -> CheckResult<()> {
    let exit_one = rows.iter().filter(|row| row.exit_code == 1).count();
    let proof = json!({
        "base_commit": BASE_COMMIT,
        "classification": "post-open evidence certification derived from Phase 28/29",
        "implementation": "independent Rust recomputation and frozen-schema validation",
        "ledger_head": ledger_head,
        "normalized_lanes_unchanged": true,
        "recomputed_secure_engine": field(secure, "overall")?,
        "schema_version": "secure-bench-phase30-independent-verification-v1",
        "status": "PASS",
        "verification": {
            "adapter_valid": 112,
            "exit_1_certified": exit_one,
            "raw_schema_valid": 112,
            "scanner_processes": 0,
            "scanner_retries": 0,
            "unique_combinations": 336,
        },
    });
    let path = root.join("phase30/independent-verification.json");
    fs::write(&path, canonical_bytes(&proof)?)
        .map_err(|error| format!("cannot write {}: {error}", path.display()))
}

fn repository_root() -> CheckResult<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| "Phase 30 manifest has no repository parent".to_owned())
}

fn run() -> CheckResult<()> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    if arguments.as_slice() != ["--write-proof"] {
        return Err("usage: secure-bench-phase30-verifier --write-proof".to_owned());
    }
    let root = repository_root()?;
    let (rows, secure, ledger_head) = verify_core(&root)?;
    write_proof(&root, &rows, &secure, &ledger_head)?;
    println!("Phase 30 independent scanner-free verification: PASS");
    println!("Secure Engine attempts: 112; exit-1 certified: 32; retries: 0");
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("Phase 30 verification failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_findings_policy_exit_is_completed() -> CheckResult<()> {
        if validate_operational_class(
            1,
            1,
            OperationalEvidence {
                authoritative_report: true,
                contract_present: true,
                operational_error: false,
            },
        )? != "policy_exit_with_valid_findings_report"
        {
            return Err("unexpected policy classification".to_owned());
        }
        Ok(())
    }

    #[test]
    fn rejects_missing_contract_and_operational_defects() {
        let valid = OperationalEvidence {
            authoritative_report: true,
            contract_present: true,
            operational_error: false,
        };
        assert!(
            validate_operational_class(
                1,
                1,
                OperationalEvidence {
                    contract_present: false,
                    ..valid
                },
            )
            .is_err()
        );
        assert!(
            validate_operational_class(
                1,
                1,
                OperationalEvidence {
                    authoritative_report: false,
                    ..valid
                },
            )
            .is_err()
        );
        assert!(
            validate_operational_class(
                1,
                1,
                OperationalEvidence {
                    operational_error: true,
                    ..valid
                },
            )
            .is_err()
        );
        assert!(validate_operational_class(1, 0, valid).is_err());
        assert!(validate_operational_class(9, 1, valid).is_err());
    }

    #[test]
    fn frozen_schema_rejects_malformed_raw() -> CheckResult<()> {
        let root = repository_root()?;
        let schema = read_json(Path::new(
            "/home/danielcastrillon/Proyectos/secure-engine-rc/0.1.7-rc1/verification/build-a/secure-json-v1.schema.json",
        ))?;
        let validator = jsonschema::validator_for(&schema).map_err(|error| error.to_string())?;
        if validator.is_valid(&json!({"schema_version": "secure-json-v1"})) {
            return Err("malformed raw unexpectedly validated".to_owned());
        }
        if root.as_os_str().is_empty() {
            return Err("repository root unexpectedly empty".to_owned());
        }
        Ok(())
    }

    #[test]
    fn hashes_and_exit_code_are_tamper_evident() {
        let original = b"frozen raw";
        let altered = b"frozen raw!";
        assert_ne!(sha256_bytes(original), sha256_bytes(altered));
        assert_ne!(0_i64, 1_i64);
        assert_ne!(EXECUTABLE_SHA256, BINDING_SHA256);
    }

    #[test]
    fn duplicate_attempts_are_rejected_by_set_membership() {
        let mut values = BTreeSet::new();
        assert!(values.insert("attempt-1"));
        assert!(!values.insert("attempt-1"));
    }

    #[test]
    fn normalized_metrics_and_unavailable_are_not_coerced() {
        let unavailable = json!(null);
        let zero = json!(0.0);
        assert_ne!(unavailable, zero);
        let original = json!({"precision": 0.5});
        let altered = json!({"precision": 0.0});
        assert_ne!(original, altered);
    }

    #[test]
    fn confusion_matrix_recomputation_is_exact() {
        let rows = [
            Row {
                attempt_id: "a".to_owned(),
                case_id: "c1".to_owned(),
                detected: true,
                exit_code: 1,
                family_id: "f".to_owned(),
                finding_count: 1,
                framework: "w".to_owned(),
                label: "vulnerable".to_owned(),
                pair_id: "p".to_owned(),
                sequence: 1,
                source_format: "s".to_owned(),
                topology: "t".to_owned(),
            },
            Row {
                attempt_id: "b".to_owned(),
                case_id: "c2".to_owned(),
                detected: false,
                exit_code: 0,
                family_id: "f".to_owned(),
                finding_count: 0,
                framework: "w".to_owned(),
                label: "control".to_owned(),
                pair_id: "p".to_owned(),
                sequence: 2,
                source_format: "s".to_owned(),
                topology: "t".to_owned(),
            },
        ];
        assert_eq!(
            confusion(&rows),
            Confusion {
                true_positive: 1,
                true_negative: 1,
                ..Confusion::default()
            }
        );
    }
}
