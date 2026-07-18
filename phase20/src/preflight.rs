use crate::{
    Phase20Error, canonical_json, collect_files, now_ms, read, sha256, validate_schema,
    write_atomic,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

pub(crate) const PHASE19_COMMIT: &str = "b3e983891e4ae3e12cd727f6bdb460962f876a30";
pub(crate) const CORPUS_SHA256: &str =
    "d059653d836647296bef93a43d9e9f046899ad4fa0a87d561b4463ce0db2781c";
pub(crate) const MERKLE_ROOT: &str =
    "2bcc11f20b0f9d06eeb10f05130b752fa8125421ebf37d6050cd3119aef4452e";
pub(crate) const RULESET_SHA256: &str =
    "06af4cf6d10da30ad585d57b781cf6aef734add03b90ea36c78e920c4c10a07c";
const MANIFEST_SHA256: &str = "c035f9de14e2a1cb7c65562f9a643f0eefafc682d23c90e520770c7183068cb6";
const COMMITMENTS_SHA256: &str = "6765cc235daab45d6ef6aae25184f4f80f5ae981afc6c812c81a94e255d623a8";
const SECURE_RPM_SHA256: &str = "0f336a262d1c1cac51a73c625a7398c392feb9f3ecad2aa81f62cbc128a62a64";
const SECURE_BINARY_SHA256: &str =
    "ad91499f3de9918963c9189bd236f5eb99b78cb99954e30f50bbc3098f18a5e0";
const OPENGREP_SHA256: &str = "45bcd58440e397ed52c50e953ccf5948909ea77087c9186fc7d277216f62e319";
const SEMGREP_WHEEL_SHA256: &str =
    "09a7e8eeff5e2549161124957184f3566f484370aa6127e425897cef725eb99b";
const PYTHON_SHA256: &str = "7af874aca05879e1823cd820913b42fb8d8b994738a05ec39ce4256d85b03861";
const WHEEL_CLOSURE_SHA256: &str =
    "5371b438dc6e3c5529794b21c668057164f52fa1375e0e91ee6c8f241fb74181";
const PHASE19_PARENT: &str = "aee2c7094983cfb8bdc16cf59b1962add82ca1db";
const PHASE19_TREE: &str = "70ef1aa5f90e3cc3496619893f07e5a800cf1a1a";
const EXECUTION_PLAN_SHA256: &str =
    "4c6e37941de2892a2b1c4aa05cd4afcb18286708e4186eb231fc08e7b92db326";
const OPENGREP_ADAPTER_SHA256: &str =
    "6a922a0ecac31b55f1591782df548822caa62064aaf7f8b9c1b0addc07cd0998";
const SEMGREP_ADAPTER_SHA256: &str =
    "53317a4e71b14548d618fd79430b74b8fc906edebbf7180cbea418df98b1afc3";
const SCORING_METHODOLOGY_SHA256: &str =
    "0e0a767e8b1df51ca8018d27956e1d0f4ba943d520888923221bbf67f9a7b2a6";
const BWRAP_SHA256: &str = "139bf12775025adf5c8523d119c5ad2950281335573708fd839c60181a3886dc";

pub(crate) const SECURE_BINARY: &str = "/tmp/secure-bench-tools/secure-engine/0.1.6/usr/bin/secure";
pub(crate) const SECURE_RPM: &str =
    "/tmp/secure-bench-tools/secure-engine/0.1.6/secure-engine-0.1.6-1.fc44.x86_64.rpm";
pub(crate) const OPENGREP_BINARY: &str =
    "/tmp/secure-bench-tools/opengrep/1.22.0/opengrep_manylinux_x86";
pub(crate) const SEMGREP_BINARY: &str = "/tmp/secure-bench-tools/semgrep/1.170.0/venv/bin/semgrep";
const SEMGREP_WHEELHOUSE: &str = "/tmp/secure-bench-tools/semgrep/1.170.0/wheelhouse";
const INSTALLED_DISTRIBUTIONS: &str =
    "/tmp/secure-bench-tools/semgrep/1.170.0/installed-distributions.json";

/// Frozen preflight evidence consumed by the irreversible execution.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Preflight {
    /// Schema identity.
    pub schema_version: String,
    /// Time at which every check had succeeded.
    pub verified_at_unix_ms: u128,
    /// Frozen Phase 19 commit.
    pub phase19_commit: String,
    /// Frozen aggregate corpus hash.
    pub aggregate_corpus_sha256: String,
    /// Frozen Evidence Contract Merkle root.
    pub contract_merkle_root: String,
    /// Hash of Phase 20 implementation files frozen before execution.
    pub implementation_sha256: String,
    /// Exact verified tool and contract hashes.
    pub verified: BTreeMap<String, String>,
    /// Number of frozen cases inspected as metadata only.
    pub case_count: u64,
    /// Number of eligible scanner/lane combinations.
    pub eligible_lanes: u64,
    /// Proof that execution has not started.
    pub scanner_process_attempts_before_opening: u64,
    /// Fixed execution policy.
    pub policy: Value,
}

fn verify_file(path: &Path, expected: &str, label: &str) -> Result<(), Phase20Error> {
    let actual = sha256(&read(path)?);
    if actual != expected {
        return Err(Phase20Error::Preflight(format!(
            "{label} hash mismatch: expected {expected}, found {actual}"
        )));
    }
    Ok(())
}

fn verify_executable(path: &Path, label: &str) -> Result<(), Phase20Error> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err(Phase20Error::Preflight(format!(
            "{label} is not an executable regular file"
        )));
    }
    Ok(())
}

fn git(root: &Path, arguments: &[&str]) -> Result<String, Phase20Error> {
    let output = Command::new("git")
        .args(arguments)
        .current_dir(root)
        .output()
        .map_err(|error| Phase20Error::Preflight(format!("git invocation failed: {error}")))?;
    if !output.status.success() {
        return Err(Phase20Error::Preflight(format!(
            "git {} failed: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|_| Phase20Error::Preflight("git output was not UTF-8".to_owned()))
}

fn verify_phase19_git(root: &Path) -> Result<(), Phase20Error> {
    if git(root, &["rev-parse", "main"])? != PHASE19_COMMIT
        || git(
            root,
            &["rev-parse", "codex/phase-19-multi-scanner-holdout-v1"],
        )? != PHASE19_COMMIT
        || git(root, &["show", "-s", "--format=%T", PHASE19_COMMIT])? != PHASE19_TREE
        || git(root, &["show", "-s", "--format=%P", PHASE19_COMMIT])? != PHASE19_PARENT
        || git(root, &["show", "-s", "--format=%G?", PHASE19_COMMIT])? != "G"
    {
        return Err(Phase20Error::Preflight(
            "Phase 19 Git topology or signature status drift".to_owned(),
        ));
    }
    git(root, &["verify-commit", PHASE19_COMMIT])?;
    let message = git(root, &["show", "-s", "--format=%B", PHASE19_COMMIT])?;
    if message
        .lines()
        .filter(|line| line.starts_with("Signed-off-by: "))
        .count()
        != 1
    {
        return Err(Phase20Error::Preflight(
            "Phase 19 commit does not contain exactly one DCO trailer".to_owned(),
        ));
    }
    git(root, &["diff", "--quiet", PHASE19_COMMIT, "--", "phase19"])?;
    Ok(())
}

fn verify_phase19_checksums(root: &Path) -> Result<(), Phase20Error> {
    let text = String::from_utf8(read(&root.join("phase19/holdout/SHA256SUMS"))?)
        .map_err(|_| Phase20Error::Preflight("Phase 19 SHA256SUMS is not UTF-8".to_owned()))?;
    let mut count = 0_u64;
    for line in text.lines() {
        let (digest, path) = line.split_once("  ").ok_or_else(|| {
            Phase20Error::Preflight("malformed Phase 19 SHA256SUMS line".to_owned())
        })?;
        if path.starts_with('/') || path.split('/').any(|part| part == "..") {
            return Err(Phase20Error::Preflight(
                "unsafe path in Phase 19 SHA256SUMS".to_owned(),
            ));
        }
        verify_file(&root.join(path), digest, path)?;
        count += 1;
    }
    if count != 270 {
        return Err(Phase20Error::Preflight(format!(
            "Phase 19 checksum population is {count}, expected 270"
        )));
    }
    Ok(())
}

fn verify_execution_plan(root: &Path) -> Result<(), Phase20Error> {
    let plan: Value =
        serde_json::from_slice(&read(&root.join("phase20/config/execution-plan-v1.json"))?)?;
    if plan.get("schema_version").and_then(Value::as_str)
        != Some("secure-bench-phase20-execution-plan-v1")
        || plan.get("phase19_commit").and_then(Value::as_str) != Some(PHASE19_COMMIT)
        || plan.get("phase19_tree").and_then(Value::as_str) != Some(PHASE19_TREE)
        || plan.get("cases").and_then(Value::as_u64) != Some(112)
        || plan
            .get("eligible_process_attempts")
            .and_then(Value::as_u64)
            != Some(336)
        || plan.get("lane_aggregation").and_then(Value::as_bool) != Some(false)
        || plan.get("rerun_valid_attempts").and_then(Value::as_bool) != Some(false)
        || plan
            .get("network_allowed_during_execution")
            .and_then(Value::as_bool)
            != Some(false)
        || plan.get("ai_providers_allowed").and_then(Value::as_bool) != Some(false)
        || plan.get("credentials_allowed").and_then(Value::as_bool) != Some(false)
    {
        return Err(Phase20Error::Preflight(
            "Phase 20 execution plan drift".to_owned(),
        ));
    }
    let lanes = plan
        .get("lanes")
        .and_then(Value::as_array)
        .ok_or_else(|| Phase20Error::Preflight("execution plan has no lanes".to_owned()))?;
    let actual = lanes
        .iter()
        .map(|lane| {
            (
                lane.get("scanner").and_then(Value::as_str),
                lane.get("lane").and_then(Value::as_str),
                lane.get("availability").and_then(Value::as_str),
                lane.get("attempts").and_then(Value::as_u64),
            )
        })
        .collect::<Vec<_>>();
    let expected = vec![
        (
            Some("secure-engine"),
            Some("native"),
            Some("available"),
            Some(112),
        ),
        (
            Some("secure-engine"),
            Some("capability-normalized"),
            Some("unsupported"),
            Some(0),
        ),
        (
            Some("opengrep"),
            Some("native"),
            Some("unsupported"),
            Some(0),
        ),
        (
            Some("opengrep"),
            Some("capability-normalized"),
            Some("available"),
            Some(112),
        ),
        (
            Some("semgrep-ce"),
            Some("native"),
            Some("unsupported"),
            Some(0),
        ),
        (
            Some("semgrep-ce"),
            Some("capability-normalized"),
            Some("available"),
            Some(112),
        ),
    ];
    if actual != expected {
        return Err(Phase20Error::Preflight(
            "Phase 20 lane plan drift".to_owned(),
        ));
    }
    Ok(())
}

fn implementation_sha256(root: &Path) -> Result<String, Phase20Error> {
    let phase20 = root.join("phase20");
    let mut files = Vec::new();
    collect_files(&phase20, &mut files)?;
    files.retain(|path| {
        path.strip_prefix(&phase20).is_ok_and(|relative| {
            !matches!(
                relative
                    .components()
                    .next()
                    .and_then(|value| value.as_os_str().to_str()),
                Some("target" | "preflight" | "output")
            )
        })
    });
    let mut bytes = Vec::new();
    for path in files {
        let relative = path
            .strip_prefix(root)
            .map_err(|_| Phase20Error::Preflight("implementation path escaped root".to_owned()))?;
        bytes.extend_from_slice(relative.to_string_lossy().as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(sha256(&read(&path)?).as_bytes());
        bytes.push(b'\n');
    }
    Ok(sha256(&bytes))
}

fn verify_semgrep_closure(root: &Path) -> Result<(), Phase20Error> {
    let lock: Value = serde_json::from_slice(&read(
        &root.join("phase18/provenance/semgrep-python314-linux-x86_64-lock.json"),
    )?)?;
    let packages = lock
        .get("packages")
        .and_then(Value::as_array)
        .ok_or_else(|| Phase20Error::Preflight("Semgrep wheel lock has no packages".to_owned()))?;
    if packages.len() != 66
        || lock.get("closure_sha256").and_then(Value::as_str) != Some(WHEEL_CLOSURE_SHA256)
    {
        return Err(Phase20Error::Preflight(
            "Semgrep wheel closure identity drift".to_owned(),
        ));
    }
    let installed: BTreeMap<String, String> =
        serde_json::from_slice(&read(Path::new(INSTALLED_DISTRIBUTIONS))?)?;
    if installed.len() != packages.len() {
        return Err(Phase20Error::Preflight(
            "installed Semgrep distribution count drift".to_owned(),
        ));
    }
    for package in packages {
        let name = package
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| Phase20Error::Preflight("wheel lock package has no name".to_owned()))?;
        let version = package
            .get("version")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                Phase20Error::Preflight("wheel lock package has no version".to_owned())
            })?;
        let filename = package
            .get("filename")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                Phase20Error::Preflight("wheel lock package has no filename".to_owned())
            })?;
        let digest = package
            .get("sha256")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                Phase20Error::Preflight("wheel lock package has no digest".to_owned())
            })?;
        verify_file(
            &Path::new(SEMGREP_WHEELHOUSE).join(filename),
            digest,
            filename,
        )?;
        let normalized = name.to_ascii_lowercase().replace('_', "-");
        if installed.get(&normalized).map(String::as_str) != Some(version) {
            return Err(Phase20Error::Preflight(format!(
                "installed distribution mismatch for {name}"
            )));
        }
    }
    Ok(())
}

pub(crate) fn current(root: &Path) -> Result<Preflight, Phase20Error> {
    verify_phase19_git(root)?;
    verify_execution_plan(root)?;
    verify_file(
        &root.join("phase20/config/execution-plan-v1.json"),
        EXECUTION_PLAN_SHA256,
        "Phase 20 execution plan",
    )?;
    verify_file(
        &root.join("phase20/config/opengrep-normalized-adapter-v1.json"),
        OPENGREP_ADAPTER_SHA256,
        "Phase 20 OpenGrep adapter manifest",
    )?;
    verify_file(
        &root.join("phase20/config/semgrep-normalized-adapter-v1.json"),
        SEMGREP_ADAPTER_SHA256,
        "Phase 20 Semgrep adapter manifest",
    )?;
    verify_file(
        &root.join("phase20/config/scoring-methodology-v1.json"),
        SCORING_METHODOLOGY_SHA256,
        "Phase 20 scoring methodology",
    )?;
    verify_file(
        &root.join("phase19/holdout/manifest.json"),
        MANIFEST_SHA256,
        "Phase 19 manifest",
    )?;
    verify_file(
        &root.join("phase19/holdout/commitments.json"),
        COMMITMENTS_SHA256,
        "Phase 19 commitments",
    )?;
    verify_file(
        &root.join("phase19/rules/capability-normalized-v1.yml"),
        RULESET_SHA256,
        "Phase 19 normalized rules",
    )?;
    verify_phase19_checksums(root)?;
    let manifest: Value =
        serde_json::from_slice(&read(&root.join("phase19/holdout/manifest.json"))?)?;
    if manifest
        .get("aggregate_corpus_sha256")
        .and_then(Value::as_str)
        != Some(CORPUS_SHA256)
        || manifest.get("contract_merkle_root").and_then(Value::as_str) != Some(MERKLE_ROOT)
        || manifest.pointer("/counts/cases").and_then(Value::as_u64) != Some(112)
    {
        return Err(Phase20Error::Preflight(
            "Phase 19 manifest commitments drift".to_owned(),
        ));
    }
    verify_file(
        Path::new(SECURE_RPM),
        SECURE_RPM_SHA256,
        "Secure Engine RPM",
    )?;
    verify_file(
        Path::new(SECURE_BINARY),
        SECURE_BINARY_SHA256,
        "Secure Engine executable",
    )?;
    verify_executable(Path::new(SECURE_BINARY), "Secure Engine executable")?;
    verify_file(
        Path::new(OPENGREP_BINARY),
        OPENGREP_SHA256,
        "OpenGrep executable",
    )?;
    verify_executable(Path::new(OPENGREP_BINARY), "OpenGrep executable")?;
    if !Path::new(SEMGREP_BINARY).is_file() {
        return Err(Phase20Error::Preflight(
            "Semgrep executable cache entry is absent".to_owned(),
        ));
    }
    verify_executable(Path::new(SEMGREP_BINARY), "Semgrep executable")?;
    verify_file(
        Path::new("/usr/bin/python3.14"),
        PYTHON_SHA256,
        "Python runtime",
    )?;
    verify_executable(Path::new("/usr/bin/python3.14"), "Python runtime")?;
    verify_executable(Path::new("/usr/bin/bwrap"), "bubblewrap executable")?;
    verify_file(
        Path::new("/usr/bin/bwrap"),
        BWRAP_SHA256,
        "bubblewrap executable",
    )?;
    verify_semgrep_closure(root)?;
    let semgrep_wheel = Path::new(SEMGREP_WHEELHOUSE).join(
        "semgrep-1.170.0-cp310.cp311.cp312.cp313.cp314.py310.py311.py312.py313.py314-none-manylinux_2_34_x86_64.whl",
    );
    verify_file(&semgrep_wheel, SEMGREP_WHEEL_SHA256, "Semgrep wheel")?;
    verify_file(
        &root.join("phase19/execution/secure-engine-v0.1.6.json"),
        "646a2c63225ec37ed6cd897856f282794c06e424feb9980dd5d00744090d8e02",
        "Secure Engine execution contract",
    )?;
    verify_file(
        &root.join("phase19/execution/opengrep-v1.22.0.json"),
        "197f9e0d3555a9fa5f3c3ffb23850a958ecd632f773aa43cc69e31d517ed8827",
        "OpenGrep execution contract",
    )?;
    verify_file(
        &root.join("phase19/execution/semgrep-ce-v1.170.0.json"),
        "0482ddcfac5db6cd9750b40077a0e01a2c797a6e862e95a2702996a81a50a2f4",
        "Semgrep execution contract",
    )?;
    let synthetic_path = root.join("phase20/preflight/synthetic-proof.json");
    let synthetic: Value = serde_json::from_slice(&read(&synthetic_path)?)?;
    if synthetic.get("status").and_then(Value::as_str) != Some("passed")
        || synthetic
            .get("holdout_cases_opened")
            .and_then(Value::as_u64)
            != Some(0)
        || synthetic
            .get("scanner_process_attempts")
            .and_then(Value::as_u64)
            != Some(0)
    {
        return Err(Phase20Error::Preflight(
            "synthetic proof is absent or invalid".to_owned(),
        ));
    }
    let verified = BTreeMap::from([
        ("phase19-manifest".to_owned(), MANIFEST_SHA256.to_owned()),
        (
            "phase19-commitments".to_owned(),
            COMMITMENTS_SHA256.to_owned(),
        ),
        ("phase19-tree".to_owned(), PHASE19_TREE.to_owned()),
        ("phase19-parent".to_owned(), PHASE19_PARENT.to_owned()),
        ("phase19-signature".to_owned(), "good".to_owned()),
        (
            "phase20-execution-plan".to_owned(),
            EXECUTION_PLAN_SHA256.to_owned(),
        ),
        (
            "phase20-opengrep-adapter".to_owned(),
            OPENGREP_ADAPTER_SHA256.to_owned(),
        ),
        (
            "phase20-semgrep-adapter".to_owned(),
            SEMGREP_ADAPTER_SHA256.to_owned(),
        ),
        (
            "phase20-scoring-methodology".to_owned(),
            SCORING_METHODOLOGY_SHA256.to_owned(),
        ),
        ("normalized-rules".to_owned(), RULESET_SHA256.to_owned()),
        ("secure-engine-rpm".to_owned(), SECURE_RPM_SHA256.to_owned()),
        (
            "secure-engine-executable".to_owned(),
            SECURE_BINARY_SHA256.to_owned(),
        ),
        ("opengrep-executable".to_owned(), OPENGREP_SHA256.to_owned()),
        ("semgrep-wheel".to_owned(), SEMGREP_WHEEL_SHA256.to_owned()),
        (
            "semgrep-wheel-closure".to_owned(),
            WHEEL_CLOSURE_SHA256.to_owned(),
        ),
        ("python-executable".to_owned(), PYTHON_SHA256.to_owned()),
        ("bwrap".to_owned(), BWRAP_SHA256.to_owned()),
    ]);
    Ok(Preflight {
        schema_version: "secure-bench-phase20-preflight-v1".to_owned(),
        verified_at_unix_ms: now_ms()?,
        phase19_commit: PHASE19_COMMIT.to_owned(),
        aggregate_corpus_sha256: CORPUS_SHA256.to_owned(),
        contract_merkle_root: MERKLE_ROOT.to_owned(),
        implementation_sha256: implementation_sha256(root)?,
        verified,
        case_count: 112,
        eligible_lanes: 3,
        scanner_process_attempts_before_opening: 0,
        policy: json!({
            "network": "disabled-by-bwrap-unshare-net",
            "environment": "cleared; fixed non-credential variables only",
            "retries": 0,
            "lane_aggregation": false,
            "unsupported_is_zero": false,
            "timeout_ms_per_case": 120000,
            "max_raw_output_bytes": 10485760
        }),
    })
}

pub(crate) fn write_preflight(root: &Path) -> Result<Preflight, Phase20Error> {
    if root.join("phase20/output/HOLDOUT_OPENED.json").exists() {
        return Err(Phase20Error::Preflight(
            "holdout was already opened; preflight cannot be rewritten".to_owned(),
        ));
    }
    let proof = current(root)?;
    validate_schema(root, "phase20/schemas/preflight-v1.schema.json", &proof)?;
    write_atomic(
        &root.join("phase20/preflight/preflight.json"),
        &canonical_json(&proof)?,
    )?;
    Ok(proof)
}

pub(crate) fn verify_saved(root: &Path) -> Result<Preflight, Phase20Error> {
    let saved: Preflight =
        serde_json::from_slice(&read(&root.join("phase20/preflight/preflight.json"))?)?;
    let current = current(root)?;
    if saved.phase19_commit != current.phase19_commit
        || saved.aggregate_corpus_sha256 != current.aggregate_corpus_sha256
        || saved.contract_merkle_root != current.contract_merkle_root
        || saved.implementation_sha256 != current.implementation_sha256
        || saved.verified != current.verified
        || saved.case_count != 112
        || saved.eligible_lanes != 3
    {
        return Err(Phase20Error::Preflight(
            "saved preflight differs from current immutable inputs".to_owned(),
        ));
    }
    Ok(saved)
}

pub(crate) fn synthetic_proof(root: &Path) -> Result<Value, Phase20Error> {
    if root.join("phase20/output/HOLDOUT_OPENED.json").exists() {
        return Err(Phase20Error::Preflight(
            "synthetic proof cannot run after holdout opening".to_owned(),
        ));
    }
    let synthetic_root = Path::new("/var/tmp/secure-bench-phase20-synthetic-preflight");
    if synthetic_root.exists() {
        return Err(Phase20Error::Preflight(
            "synthetic containment root already exists".to_owned(),
        ));
    }
    let fixture = synthetic_root.join("fixture");
    let output = synthetic_root.join("output");
    fs::create_dir_all(&fixture)?;
    fs::create_dir_all(&output)?;
    fs::write(fixture.join("synthetic.js"), b"const synthetic = true;\n")?;
    let containment = crate::runner::synthetic_containment(root, &fixture, &output);
    fs::remove_dir_all(synthetic_root)?;
    containment?;
    let proof = json!({
        "schema_version": "secure-bench-phase20-synthetic-proof-v1",
        "status": "passed",
        "verified_at_unix_ms": now_ms()?,
        "holdout_cases_opened": 0,
        "scanner_process_attempts": 0,
        "checks": [
            "pure scorer synthetic confusion matrix",
            "native/normalized state separation",
            "exact bwrap mount, resource-limit, and network namespace construction",
            "atomic one-shot marker semantics"
        ]
    });
    fs::create_dir_all(root.join("phase20/preflight"))?;
    write_atomic(
        &root.join("phase20/preflight/synthetic-proof.json"),
        &canonical_json(&proof)?,
    )?;
    Ok(proof)
}

pub(crate) fn tool_mount(scanner: &str) -> Result<(PathBuf, PathBuf), Phase20Error> {
    let path = match scanner {
        "secure-engine" => Path::new("/tmp/secure-bench-tools/secure-engine/0.1.6"),
        "opengrep" => Path::new("/tmp/secure-bench-tools/opengrep/1.22.0"),
        "semgrep-ce" => Path::new("/tmp/secure-bench-tools/semgrep/1.170.0"),
        _ => return Err(Phase20Error::Execution("unknown scanner".to_owned())),
    };
    Ok((path.to_path_buf(), path.to_path_buf()))
}
