//! Secure Bench Phase 22 post-open normalized recovery study.

#![allow(
    clippy::doc_markdown,
    clippy::cast_precision_loss,
    clippy::format_collect,
    clippy::format_push_string,
    clippy::items_after_statements,
    clippy::match_same_arms,
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::obfuscated_if_else,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::uninlined_format_args,
    clippy::unreadable_literal
)]

mod contract;
mod independent_score;
mod model;
mod runner;
mod score;
mod verify;

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use thiserror::Error;

pub use contract::{preflight, prepare};
pub use runner::execute_once;
pub use verify::{VerificationReport, independent_verify, recover_verification};

/// Phase 22 fail-closed error.
#[derive(Debug, Error)]
pub enum Phase22Error {
    /// Frozen input or methodological contract drift.
    #[error("Phase 22 contract failure: {0}")]
    Contract(String),
    /// Preflight failed before corpus opening.
    #[error("Phase 22 preflight failure: {0}")]
    Preflight(String),
    /// Post-open execution failed.
    #[error("Phase 22 execution failure: {0}")]
    Execution(String),
    /// Independent verification rejected evidence.
    #[error("Phase 22 verification failure: {0}")]
    Verification(String),
    /// Filesystem operation failed.
    #[error("Phase 22 filesystem failure: {0}")]
    Io(#[from] std::io::Error),
    /// JSON operation failed.
    #[error("Phase 22 JSON failure: {0}")]
    Json(#[from] serde_json::Error),
}

pub(crate) fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(crate) fn sha256_file(path: &Path) -> Result<String, Phase22Error> {
    Ok(sha256(&fs::read(path)?))
}

pub(crate) fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, Phase22Error> {
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), Phase22Error> {
    let parent = path
        .parent()
        .ok_or_else(|| Phase22Error::Contract("output path has no parent".to_owned()))?;
    fs::create_dir_all(parent)?;
    let temporary = path.with_extension("phase22-tmp");
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

pub(crate) fn create_irreversible(path: &Path, bytes: &[u8]) -> Result<(), Phase22Error> {
    let parent = path
        .parent()
        .ok_or_else(|| Phase22Error::Contract("marker path has no parent".to_owned()))?;
    fs::create_dir_all(parent)?;
    let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

pub(crate) fn collect_files(path: &Path, files: &mut Vec<PathBuf>) -> Result<(), Phase22Error> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(Phase22Error::Contract(format!(
            "symlink is forbidden: {}",
            path.display()
        )));
    }
    if metadata.is_file() {
        files.push(path.to_path_buf());
        return Ok(());
    }
    if !metadata.is_dir() {
        return Err(Phase22Error::Contract(format!(
            "non-file input is forbidden: {}",
            path.display()
        )));
    }
    let mut entries = fs::read_dir(path)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        collect_files(&entry.path(), files)?;
    }
    Ok(())
}

pub(crate) fn implementation_digest(root: &Path) -> Result<String, Phase22Error> {
    let phase = root.join("phase22");
    let mut files = Vec::new();
    collect_files(&phase, &mut files)?;
    files.retain(|file| {
        file.strip_prefix(&phase).is_ok_and(|relative| {
            !matches!(
                relative
                    .components()
                    .next()
                    .and_then(|component| component.as_os_str().to_str()),
                Some("config" | "preflight" | "output" | "target")
            )
        })
    });
    let mut projection = Vec::new();
    for file in files {
        let relative = file.strip_prefix(root).map_err(|_| {
            Phase22Error::Contract(format!("implementation escaped root: {}", file.display()))
        })?;
        projection.extend_from_slice(relative.to_string_lossy().as_bytes());
        projection.push(0);
        projection.extend_from_slice(sha256_file(&file)?.as_bytes());
        projection.push(b'\n');
    }
    Ok(sha256(&projection))
}

pub(crate) fn now_ms() -> Result<u128, Phase22Error> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .map_err(|_| Phase22Error::Execution("system clock predates Unix epoch".to_owned()))
}

pub(crate) fn safe_relative(value: &str) -> Result<&Path, Phase22Error> {
    let path = Path::new(value);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(Phase22Error::Contract(format!(
            "unsafe relative path: {value}"
        )));
    }
    Ok(path)
}
