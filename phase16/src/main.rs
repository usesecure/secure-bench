//! Scanner-free command-line verifier for the prospective Phase 16 adapter.

use secure_bench_phase16::{AdapterError, verify_repository};
use std::path::Path;

fn usage() -> &'static str {
    "Usage: secure-bench-phase16 verify <repository-root>"
}

fn run() -> Result<(), AdapterError> {
    let mut arguments = std::env::args().skip(1);
    let command = arguments
        .next()
        .ok_or_else(|| AdapterError::InvalidRequest(usage().to_owned()))?;
    let root = arguments
        .next()
        .ok_or_else(|| AdapterError::InvalidRequest(usage().to_owned()))?;
    if command != "verify" || arguments.next().is_some() {
        return Err(AdapterError::InvalidRequest(usage().to_owned()));
    }
    let summary = verify_repository(Path::new(&root))?;
    println!(
        "Phase 16 verified {} retained reports and {} authoritative v2 findings offline; diagnostic projection only: {} exact, {} partial, {} no-match; no scanner, AI, network, or subprocess was started.",
        summary.reports,
        summary.authoritative_findings,
        summary.diagnostic_exact,
        summary.diagnostic_partial,
        summary.diagnostic_no_match
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
