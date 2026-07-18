//! Phase 21 sandbox remediation and synthetic scanner qualification.

#![allow(
    clippy::doc_markdown,
    clippy::bool_to_int_with_if,
    clippy::collapsible_if,
    clippy::collapsible_match,
    clippy::format_collect,
    clippy::format_push_string,
    clippy::items_after_statements,
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unreadable_literal
)]

mod model;
mod qualify;
/// Frozen bubblewrap profile and scanner command construction.
pub mod sandbox;
mod verify;

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use thiserror::Error;

pub use qualify::qualify;
pub use verify::{VerificationReport, independent_verify};

/// Phase 21 fail-closed error.
#[derive(Debug, Error)]
pub enum Phase21Error {
    /// Frozen input or sandbox contract drifted.
    #[error("Phase 21 contract failure: {0}")]
    Contract(String),
    /// Synthetic qualification did not satisfy its expectation.
    #[error("Phase 21 qualification failure: {0}")]
    Qualification(String),
    /// Independent verification rejected committed evidence.
    #[error("Phase 21 verification failure: {0}")]
    Verification(String),
    /// Filesystem operation failed.
    #[error("Phase 21 filesystem failure: {0}")]
    Io(#[from] std::io::Error),
    /// JSON parsing or serialization failed.
    #[error("Phase 21 JSON failure: {0}")]
    Json(#[from] serde_json::Error),
}

pub(crate) fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(crate) fn sha256_file(path: &Path) -> Result<String, Phase21Error> {
    Ok(sha256(&fs::read(path)?))
}

pub(crate) fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, Phase21Error> {
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), Phase21Error> {
    let parent = path
        .parent()
        .ok_or_else(|| Phase21Error::Contract("output path has no parent".to_owned()))?;
    fs::create_dir_all(parent)?;
    let temporary = path.with_extension("phase21-tmp");
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

pub(crate) fn collect_files(path: &Path, files: &mut Vec<PathBuf>) -> Result<(), Phase21Error> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(Phase21Error::Contract(format!(
            "symlink is forbidden: {}",
            path.display()
        )));
    }
    if metadata.is_file() {
        files.push(path.to_path_buf());
        return Ok(());
    }
    let mut entries = fs::read_dir(path)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        collect_files(&entry.path(), files)?;
    }
    Ok(())
}

pub(crate) fn tree_digest(path: &Path) -> Result<String, Phase21Error> {
    let mut files = Vec::new();
    collect_files(path, &mut files)?;
    let mut projection = Vec::new();
    for file in files {
        let relative = file.strip_prefix(path).map_err(|_| {
            Phase21Error::Contract(format!("file escaped tree: {}", file.display()))
        })?;
        projection.extend_from_slice(relative.to_string_lossy().as_bytes());
        projection.push(0);
        projection.extend_from_slice(sha256_file(&file)?.as_bytes());
        projection.push(b'\n');
    }
    Ok(sha256(&projection))
}
