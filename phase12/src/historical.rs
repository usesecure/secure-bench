//! Stable, content-addressed verification of the frozen Phase 0–11 payload.

use crate::{Phase12Error, canonical_json, io, safe_relative, sha256};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) const BASELINE_PATH: &str = "phase12/historical/phase0-11-baseline-v1.json";
const BASELINE_SCHEMA_PATH: &str = "phase12/schemas/phase12-historical-baseline-v1.schema.json";
const BASELINE_SCHEMA: &str = "secure-bench-historical-baseline-v1";
const SNAPSHOT_VERSION: &str = "1.0.0";
const CUTOFF_COMMIT: &str = "86aa6f439c14eaa7e2fd7122687aca35f5aadc18";
const BASELINE_SHA256: &str = "375ce87c5fce9be3caff282c821c796a9b56e3a1132404d92d40db7d89a7d52f";
const BASELINE_SCHEMA_SHA256: &str =
    "30a8709febdf11d500f071c212dfad5ba51395a3fc16fdf863b4a64df6be2d82";
const EXCLUDED_MUTABLE_SURFACES: [&str; 5] = [
    ".github and other repository governance added or changed prospectively",
    ".git and other version-control metadata",
    "phase12 and later prospective phase namespaces",
    "repository-root paths not explicitly protected by this manifest",
    "docs paths not explicitly protected by this manifest",
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct HistoricalBaseline {
    schema_version: String,
    snapshot_version: String,
    cutoff_commit: String,
    excluded_mutable_surfaces: Vec<String>,
    closed_roots: Vec<ClosedRoot>,
    protected_files: Vec<ProtectedFile>,
    aggregate_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ClosedRoot {
    path: String,
    file_count: u64,
    content_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProtectedFile {
    path: String,
    byte_length: u64,
    sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileRecord {
    byte_length: u64,
    sha256: String,
}

fn historical_error(detail: impl Into<String>) -> Phase12Error {
    Phase12Error::HistoricalIntegrity(detail.into())
}

fn checked_relative(relative: &str) -> Result<PathBuf, Phase12Error> {
    safe_relative(relative).map_err(|error| historical_error(error.to_string()))
}

fn expected_exclusions() -> Vec<String> {
    EXCLUDED_MUTABLE_SURFACES
        .iter()
        .map(ToString::to_string)
        .collect()
}

fn validate_sha256(value: &str, label: &str) -> Result<(), Phase12Error> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(historical_error(format!(
            "{label} is not a lowercase SHA-256 digest"
        )));
    }
    Ok(())
}

fn validate_manifest(manifest: &HistoricalBaseline) -> Result<(), Phase12Error> {
    if manifest.schema_version != BASELINE_SCHEMA
        || manifest.snapshot_version != SNAPSHOT_VERSION
        || manifest.cutoff_commit != CUTOFF_COMMIT
        || manifest.excluded_mutable_surfaces != expected_exclusions()
    {
        return Err(historical_error(
            "historical baseline identity or boundary declaration differs",
        ));
    }
    validate_sha256(&manifest.aggregate_sha256, "historical aggregate")?;

    let mut previous = None;
    let mut closed = BTreeSet::new();
    for root in &manifest.closed_roots {
        checked_relative(&root.path)?;
        validate_sha256(&root.content_sha256, &format!("root `{}`", root.path))?;
        if previous
            .as_deref()
            .is_some_and(|path| path >= root.path.as_str())
            || !closed.insert(root.path.clone())
        {
            return Err(historical_error(
                "closed historical roots are not unique and lexicographically ordered",
            ));
        }
        previous = Some(root.path.clone());
    }

    previous = None;
    let mut protected = BTreeSet::new();
    for file in &manifest.protected_files {
        checked_relative(&file.path)?;
        validate_sha256(&file.sha256, &format!("file `{}`", file.path))?;
        if previous
            .as_deref()
            .is_some_and(|path| path >= file.path.as_str())
            || !protected.insert(file.path.clone())
        {
            return Err(historical_error(
                "protected historical files are not unique and lexicographically ordered",
            ));
        }
        if closed.iter().any(|root| {
            Path::new(&file.path).starts_with(Path::new(root))
                || Path::new(root).starts_with(Path::new(&file.path))
        }) {
            return Err(historical_error(format!(
                "protected file `{}` conflicts with a closed historical root",
                file.path
            )));
        }
        previous = Some(file.path.clone());
    }
    Ok(())
}

fn regular_file(root: &Path, relative: &str) -> Result<FileRecord, Phase12Error> {
    let relative_path = checked_relative(relative)?;
    let mut current = root.to_path_buf();
    for component in relative_path.components() {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current).map_err(|error| io(&current, &error))?;
        if metadata.file_type().is_symlink() {
            return Err(historical_error(format!(
                "historical path `{relative}` traverses or is a symlink"
            )));
        }
    }
    let metadata = fs::symlink_metadata(&current).map_err(|error| io(&current, &error))?;
    if !metadata.is_file() {
        return Err(historical_error(format!(
            "historical path `{relative}` is not a regular file"
        )));
    }
    let bytes = fs::read(&current).map_err(|error| io(&current, &error))?;
    Ok(FileRecord {
        byte_length: u64::try_from(bytes.len())
            .map_err(|_| historical_error(format!("historical file `{relative}` is too large")))?,
        sha256: sha256(&bytes),
    })
}

fn collect_directory(
    root: &Path,
    absolute: &Path,
    relative: &Path,
    records: &mut BTreeMap<String, FileRecord>,
) -> Result<(), Phase12Error> {
    let metadata = fs::symlink_metadata(absolute).map_err(|error| io(absolute, &error))?;
    if metadata.file_type().is_symlink() {
        return Err(historical_error(format!(
            "historical path `{}` is a symlink",
            relative.display()
        )));
    }
    if metadata.is_file() {
        let portable = relative.to_string_lossy().replace('\\', "/");
        let bytes = fs::read(absolute).map_err(|error| io(absolute, &error))?;
        let record = FileRecord {
            byte_length: u64::try_from(bytes.len()).map_err(|_| {
                historical_error(format!("historical file `{portable}` is too large"))
            })?,
            sha256: sha256(&bytes),
        };
        if records.insert(portable.clone(), record).is_some() {
            return Err(historical_error(format!(
                "historical path `{portable}` appears more than once"
            )));
        }
        return Ok(());
    }
    if !metadata.is_dir() {
        return Err(historical_error(format!(
            "historical path `{}` has an unsupported file type",
            relative.display()
        )));
    }

    let mut entries = fs::read_dir(absolute)
        .map_err(|error| io(absolute, &error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| io(absolute, &error))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let child = entry.path();
        let child_metadata = fs::symlink_metadata(&child).map_err(|error| io(&child, &error))?;
        if entry.file_name() == "target" && child_metadata.is_dir() {
            continue;
        }
        collect_directory(root, &child, &relative.join(entry.file_name()), records)?;
    }
    let _ = root;
    Ok(())
}

fn record_digest(records: &BTreeMap<String, FileRecord>) -> String {
    let mut bytes = Vec::new();
    for (path, record) in records {
        bytes.extend_from_slice(path.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(record.sha256.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(record.byte_length.to_string().as_bytes());
        bytes.push(b'\n');
    }
    sha256(&bytes)
}

fn snapshot_from_boundary(
    root: &Path,
    template: &HistoricalBaseline,
) -> Result<HistoricalBaseline, Phase12Error> {
    validate_manifest(template)?;
    let mut all_records = BTreeMap::new();
    let mut closed_roots = Vec::with_capacity(template.closed_roots.len());
    for expected_root in &template.closed_roots {
        let relative = checked_relative(&expected_root.path)?;
        let absolute = root.join(&relative);
        let mut records = BTreeMap::new();
        collect_directory(root, &absolute, &relative, &mut records)?;
        let file_count = u64::try_from(records.len()).map_err(|_| {
            historical_error(format!(
                "historical root `{}` has too many files",
                expected_root.path
            ))
        })?;
        for (path, record) in &records {
            if all_records.insert(path.clone(), record.clone()).is_some() {
                return Err(historical_error(format!(
                    "historical path `{path}` is covered by conflicting roots"
                )));
            }
        }
        closed_roots.push(ClosedRoot {
            path: expected_root.path.clone(),
            file_count,
            content_sha256: record_digest(&records),
        });
    }

    let mut protected_files = Vec::with_capacity(template.protected_files.len());
    for expected_file in &template.protected_files {
        let record = regular_file(root, &expected_file.path)?;
        if all_records
            .insert(expected_file.path.clone(), record.clone())
            .is_some()
        {
            return Err(historical_error(format!(
                "historical path `{}` is covered more than once",
                expected_file.path
            )));
        }
        protected_files.push(ProtectedFile {
            path: expected_file.path.clone(),
            byte_length: record.byte_length,
            sha256: record.sha256,
        });
    }

    Ok(HistoricalBaseline {
        schema_version: BASELINE_SCHEMA.to_owned(),
        snapshot_version: SNAPSHOT_VERSION.to_owned(),
        cutoff_commit: CUTOFF_COMMIT.to_owned(),
        excluded_mutable_surfaces: expected_exclusions(),
        closed_roots,
        protected_files,
        aggregate_sha256: record_digest(&all_records),
    })
}

pub(crate) fn verify_committed_baseline(root: &Path) -> Result<String, Phase12Error> {
    let bytes = fs::read(root.join(BASELINE_PATH))
        .map_err(|error| io(&root.join(BASELINE_PATH), &error))?;
    let manifest_hash = sha256(&bytes);
    if manifest_hash != BASELINE_SHA256 {
        return Err(historical_error(format!(
            "baseline manifest is {manifest_hash}, expected {BASELINE_SHA256}"
        )));
    }
    let manifest: HistoricalBaseline = serde_json::from_slice(&bytes)
        .map_err(|error| historical_error(format!("baseline manifest is malformed: {error}")))?;
    let schema_path = root.join(BASELINE_SCHEMA_PATH);
    let schema_bytes = fs::read(&schema_path).map_err(|error| io(&schema_path, &error))?;
    let schema_hash = sha256(&schema_bytes);
    if schema_hash != BASELINE_SCHEMA_SHA256 {
        return Err(historical_error(format!(
            "historical baseline schema is {schema_hash}, expected {BASELINE_SCHEMA_SHA256}"
        )));
    }
    let schema: serde_json::Value = serde_json::from_slice(&schema_bytes).map_err(|error| {
        historical_error(format!("historical baseline schema is malformed: {error}"))
    })?;
    let instance = serde_json::to_value(&manifest)
        .map_err(|error| historical_error(format!("baseline serialization failed: {error}")))?;
    jsonschema::validator_for(&schema)
        .map_err(|error| historical_error(format!("historical schema is invalid: {error}")))?
        .validate(&instance)
        .map_err(|error| {
            historical_error(format!("historical schema rejected baseline: {error}"))
        })?;
    let reconstructed = snapshot_from_boundary(root, &manifest)?;
    if reconstructed != manifest || canonical_json(&reconstructed)? != bytes {
        return Err(historical_error(
            "frozen Phase 0–11 payload differs from its canonical baseline",
        ));
    }
    Ok(manifest.aggregate_sha256)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMPORARY: AtomicU64 = AtomicU64::new(0);

    struct TemporaryRepository {
        path: PathBuf,
    }

    impl TemporaryRepository {
        fn new() -> Result<Self, Phase12Error> {
            let sequence = NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "secure-bench-phase12-history-{}-{sequence}",
                std::process::id()
            ));
            if path.exists() {
                fs::remove_dir_all(&path).map_err(|error| io(&path, &error))?;
            }
            fs::create_dir_all(path.join("frozen"))
                .map_err(|error| io(&path.join("frozen"), &error))?;
            fs::create_dir_all(path.join("docs"))
                .map_err(|error| io(&path.join("docs"), &error))?;
            fs::write(path.join("frozen/result.json"), b"{\"result\":true}\n")
                .map_err(|error| io(&path.join("frozen/result.json"), &error))?;
            fs::write(path.join("docs/history.md"), b"historical\n")
                .map_err(|error| io(&path.join("docs/history.md"), &error))?;
            Ok(Self { path })
        }

        fn template(&self) -> Result<HistoricalBaseline, Phase12Error> {
            let provisional = HistoricalBaseline {
                schema_version: BASELINE_SCHEMA.to_owned(),
                snapshot_version: SNAPSHOT_VERSION.to_owned(),
                cutoff_commit: CUTOFF_COMMIT.to_owned(),
                excluded_mutable_surfaces: expected_exclusions(),
                closed_roots: vec![ClosedRoot {
                    path: "frozen".to_owned(),
                    file_count: 0,
                    content_sha256: sha256(b"provisional"),
                }],
                protected_files: vec![ProtectedFile {
                    path: "docs/history.md".to_owned(),
                    byte_length: 0,
                    sha256: sha256(b"provisional"),
                }],
                aggregate_sha256: sha256(b"provisional"),
            };
            snapshot_from_boundary(&self.path, &provisional)
        }
    }

    impl Drop for TemporaryRepository {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn untouched_baseline_and_unrelated_ci_change_pass() -> Result<(), Phase12Error> {
        let repository = TemporaryRepository::new()?;
        let baseline = repository.template()?;
        assert_eq!(
            snapshot_from_boundary(&repository.path, &baseline)?,
            baseline
        );
        fs::create_dir_all(repository.path.join(".github/workflows"))
            .map_err(|error| io(&repository.path.join(".github/workflows"), &error))?;
        fs::write(
            repository.path.join(".github/workflows/ci.yml"),
            b"name: CI\n",
        )
        .map_err(|error| io(&repository.path.join(".github/workflows/ci.yml"), &error))?;
        assert_eq!(
            snapshot_from_boundary(&repository.path, &baseline)?,
            baseline
        );
        Ok(())
    }

    #[test]
    fn mutation_and_deletion_fail_closed() -> Result<(), Phase12Error> {
        let repository = TemporaryRepository::new()?;
        let baseline = repository.template()?;
        fs::write(repository.path.join("frozen/result.json"), b"mutated\n")
            .map_err(|error| io(&repository.path.join("frozen/result.json"), &error))?;
        assert_ne!(
            snapshot_from_boundary(&repository.path, &baseline)?,
            baseline
        );
        fs::write(
            repository.path.join("frozen/result.json"),
            b"{\"result\":true}\n",
        )
        .map_err(|error| io(&repository.path.join("frozen/result.json"), &error))?;
        fs::remove_file(repository.path.join("docs/history.md"))
            .map_err(|error| io(&repository.path.join("docs/history.md"), &error))?;
        assert!(snapshot_from_boundary(&repository.path, &baseline).is_err());
        Ok(())
    }

    #[test]
    fn conflicting_addition_and_malformed_manifest_fail_closed() -> Result<(), Phase12Error> {
        let repository = TemporaryRepository::new()?;
        let baseline = repository.template()?;
        fs::write(repository.path.join("frozen/replacement.json"), b"{}\n")
            .map_err(|error| io(&repository.path.join("frozen/replacement.json"), &error))?;
        assert_ne!(
            snapshot_from_boundary(&repository.path, &baseline)?,
            baseline
        );
        assert!(serde_json::from_slice::<HistoricalBaseline>(b"{not-json").is_err());

        let mut traversal = baseline;
        traversal.protected_files[0].path = "../escape".to_owned();
        assert!(snapshot_from_boundary(&repository.path, &traversal).is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn symlink_substitution_fails_closed() -> Result<(), Phase12Error> {
        use std::os::unix::fs::symlink;

        let repository = TemporaryRepository::new()?;
        let baseline = repository.template()?;
        fs::remove_file(repository.path.join("frozen/result.json"))
            .map_err(|error| io(&repository.path.join("frozen/result.json"), &error))?;
        symlink(
            repository.path.join("docs/history.md"),
            repository.path.join("frozen/result.json"),
        )
        .map_err(|error| io(&repository.path.join("frozen/result.json"), &error))?;
        assert!(snapshot_from_boundary(&repository.path, &baseline).is_err());
        Ok(())
    }

    #[test]
    fn deterministic_reconstruction_is_byte_identical() -> Result<(), Phase12Error> {
        let repository = TemporaryRepository::new()?;
        let baseline = repository.template()?;
        let first = canonical_json(&snapshot_from_boundary(&repository.path, &baseline)?)?;
        let second = canonical_json(&snapshot_from_boundary(&repository.path, &baseline)?)?;
        assert_eq!(first, second);
        Ok(())
    }
}
