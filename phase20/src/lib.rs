//! Reproducible one-shot Phase 20 runner, neutral scorer, and independent verifier.

#![allow(
    clippy::doc_markdown,
    clippy::cast_precision_loss,
    clippy::duration_suboptimal_units,
    clippy::format_collect,
    clippy::format_push_string,
    clippy::match_same_arms,
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::obfuscated_if_else,
    clippy::struct_field_names,
    clippy::uninlined_format_args,
    clippy::unreadable_literal,
    clippy::too_many_lines
)]

mod model;
mod preflight;
mod runner;
mod score;
mod verify;

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Phase 20 failure, separated by lifecycle stage.
#[derive(Debug, Error)]
pub enum Phase20Error {
    /// Frozen contract or manifest is invalid.
    #[error("Phase 20 contract failure: {0}")]
    Contract(String),
    /// Preflight failed before scanner execution.
    #[error("Phase 20 preflight failed: {0}")]
    Preflight(String),
    /// Irreversible one-shot execution failed.
    #[error("Phase 20 execution failed: {0}")]
    Execution(String),
    /// Independent recomputation failed.
    #[error("Phase 20 verification failed: {0}")]
    Verification(String),
    /// Filesystem operation failed.
    #[error("Phase 20 filesystem failure: {0}")]
    Io(#[from] std::io::Error),
    /// JSON parsing or serialization failed.
    #[error("Phase 20 JSON failure: {0}")]
    Json(#[from] serde_json::Error),
}

pub(crate) fn read(path: &Path) -> Result<Vec<u8>, Phase20Error> {
    fs::read(path).map_err(Phase20Error::from)
}

pub(crate) fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(crate) fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, Phase20Error> {
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub(crate) fn validate_schema<T: Serialize>(
    root: &Path,
    schema_path: &str,
    value: &T,
) -> Result<(), Phase20Error> {
    let schema: serde_json::Value = serde_json::from_slice(&read(&root.join(schema_path))?)?;
    let instance = serde_json::to_value(value)?;
    jsonschema::validator_for(&schema)
        .map_err(|error| Phase20Error::Contract(format!("{schema_path}: {error}")))?
        .validate(&instance)
        .map_err(|error| Phase20Error::Contract(format!("{schema_path}: {error}")))
}

pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), Phase20Error> {
    let parent = path
        .parent()
        .ok_or_else(|| Phase20Error::Io(std::io::Error::other("output path has no parent")))?;
    fs::create_dir_all(parent)?;
    let temporary = path.with_extension("phase20-tmp");
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    Ok(())
}

pub(crate) fn now_ms() -> Result<u128, Phase20Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .map_err(|_| Phase20Error::Execution("system clock predates Unix epoch".to_owned()))
}

pub(crate) fn collect_files(path: &Path, output: &mut Vec<PathBuf>) -> Result<(), Phase20Error> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(Phase20Error::Contract(format!(
            "symlink is forbidden: {}",
            path.display()
        )));
    }
    if metadata.is_file() {
        output.push(path.to_path_buf());
        return Ok(());
    }
    if !metadata.is_dir() {
        return Err(Phase20Error::Contract(format!(
            "non-file input is forbidden: {}",
            path.display()
        )));
    }
    let mut entries = fs::read_dir(path)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        collect_files(&entry.path(), output)?;
    }
    Ok(())
}

pub(crate) fn copy_tree(source: &Path, destination: &Path) -> Result<(), Phase20Error> {
    if destination.exists() {
        return Err(Phase20Error::Execution(format!(
            "fixture copy destination already exists: {}",
            destination.display()
        )));
    }
    let mut files = Vec::new();
    collect_files(source, &mut files)?;
    for path in files {
        let relative = path
            .strip_prefix(source)
            .map_err(|_| Phase20Error::Execution("fixture path escaped source".to_owned()))?;
        let target = destination.join(relative);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(&path, &target)?;
        let mut permissions = fs::metadata(&target)?.permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&target, permissions)?;
    }
    Ok(())
}

/// Runs a synthetic, scanner-free containment and scorer proof without opening holdout cases.
pub fn synthetic_proof(root: &Path) -> Result<String, Phase20Error> {
    let value = preflight::synthetic_proof(root)?;
    Ok(serde_json::to_string(&value)?)
}

/// Performs the fail-closed preflight and writes its immutable evidence.
pub fn preflight(root: &Path) -> Result<String, Phase20Error> {
    let value = preflight::write_preflight(root)?;
    Ok(serde_json::to_string(&value)?)
}

/// Opens the holdout irreversibly and executes each eligible scanner/case exactly once.
pub fn execute_once(root: &Path) -> Result<String, Phase20Error> {
    let value = runner::execute(root)?;
    Ok(serde_json::to_string(&value)?)
}

/// Independently re-adapts raw evidence and recomputes every score.
pub fn independent_verify(root: &Path) -> Result<String, Phase20Error> {
    let value = verify::independent(root)?;
    Ok(serde_json::to_string(&value)?)
}

/// Verifies committed Phase 20 evidence through the independent recomputation path.
pub fn verify_committed(root: &Path) -> Result<String, Phase20Error> {
    independent_verify(root)
}

#[cfg(test)]
mod tests {
    use super::{canonical_json, write_atomic};
    use serde_json::json;
    use std::fs::OpenOptions;
    use tempfile::tempdir;

    #[test]
    fn atomic_writer_and_one_shot_marker_are_synthetic_only()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let output = directory.path().join("proof.json");
        write_atomic(&output, &canonical_json(&json!({"synthetic": true}))?)?;
        assert!(output.is_file());
        let marker = directory.path().join("HOLDOUT_OPENED.json");
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&marker)?;
        assert!(
            OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(marker)
                .is_err()
        );
        Ok(())
    }
}
