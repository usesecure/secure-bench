//! Phase 23 synthetic Semgrep CE crash diagnosis and qualification.

#![allow(
    clippy::doc_markdown,
    clippy::duration_suboptimal_units,
    clippy::format_collect,
    clippy::format_push_string,
    clippy::items_after_statements,
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unreadable_literal
)]

mod model;
mod qualification;
mod runner;

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use thiserror::Error;

pub use qualification::qualify;
pub use runner::{
    diagnose, diagnose_thresholds, finalize_probe_setup_failure, probe_stack_limits, seal_phase23,
};

/// Phase 23 fail-closed error.
#[derive(Debug, Error)]
pub enum Phase23Error {
    /// Frozen input or Phase 23 contract drift.
    #[error("Phase 23 contract failure: {0}")]
    Contract(String),
    /// Synthetic execution or expectation failure.
    #[error("Phase 23 execution failure: {0}")]
    Execution(String),
    /// Filesystem operation failed.
    #[error("Phase 23 filesystem failure: {0}")]
    Io(#[from] std::io::Error),
    /// JSON parsing or serialization failed.
    #[error("Phase 23 JSON failure: {0}")]
    Json(#[from] serde_json::Error),
}

pub(crate) fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(crate) fn sha256_file(path: &Path) -> Result<String, Phase23Error> {
    Ok(sha256(&fs::read(path)?))
}

pub(crate) fn canonical_json<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, Phase23Error> {
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), Phase23Error> {
    let parent = path
        .parent()
        .ok_or_else(|| Phase23Error::Contract("output path has no parent".to_owned()))?;
    fs::create_dir_all(parent)?;
    let temporary = path.with_extension("phase23-tmp");
    if temporary.exists() {
        fs::remove_file(&temporary)?;
    }
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(temporary, path)?;
    Ok(())
}

pub(crate) fn collect_files(path: &Path, output: &mut Vec<PathBuf>) -> Result<(), Phase23Error> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(Phase23Error::Contract(format!(
            "symlink is forbidden: {}",
            path.display()
        )));
    }
    if metadata.is_file() {
        output.push(path.to_path_buf());
        return Ok(());
    }
    if !metadata.is_dir() {
        return Err(Phase23Error::Contract(format!(
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
