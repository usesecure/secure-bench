//! Scanner-free Phase 18 repository verifier.

use secure_bench_semgrep_adapter::{AdapterError, verify_repository};
use std::path::Path;

fn usage() -> &'static str {
    "Usage: secure-bench-semgrep-adapter verify <repository-root>"
}

fn run() -> Result<(), AdapterError> {
    let mut arguments = std::env::args().skip(1);
    let command = arguments
        .next()
        .ok_or_else(|| AdapterError::Verification(usage().to_owned()))?;
    let root = arguments
        .next()
        .ok_or_else(|| AdapterError::Verification(usage().to_owned()))?;
    if command != "verify" || arguments.next().is_some() {
        return Err(AdapterError::Verification(usage().to_owned()));
    }
    let summary = verify_repository(Path::new(&root))?;
    println!(
        "Phase 18 verified {} valid reports, {} findings, {} malformed rejections, {} partial rejection, {} deterministic repeats, and {} raw hashes offline; no scanner was started.",
        summary.valid_reports,
        summary.valid_findings,
        summary.malformed_rejections,
        summary.partial_rejections,
        summary.deterministic_repeats,
        summary.raw_integrity_checks,
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
