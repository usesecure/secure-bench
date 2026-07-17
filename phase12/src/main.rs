//! Scanner-free Phase 12 artifact generation, verification, and public summary CLI.

use secure_bench_phase12::{
    Phase12Error, generate_repository, summarize_repository, verify_repository,
};
use std::path::Path;

fn usage() -> &'static str {
    "usage: secure-bench-phase12 <generate|verify|summary> <repository-root>"
}

fn run() -> Result<(), Phase12Error> {
    let mut arguments = std::env::args().skip(1);
    let command = arguments
        .next()
        .ok_or_else(|| Phase12Error::InvalidRequest(usage().to_owned()))?;
    let root = arguments
        .next()
        .ok_or_else(|| Phase12Error::InvalidRequest(usage().to_owned()))?;
    if arguments.next().is_some() {
        return Err(Phase12Error::InvalidRequest(usage().to_owned()));
    }

    match command.as_str() {
        "generate" => {
            let summary = generate_repository(Path::new(&root))?;
            println!(
                "Generated Secure Bench {} public regression foundation: {} pairs, {} cases; scanner processes started: 0.",
                summary.benchmark_version, summary.pairs, summary.cases
            );
        }
        "verify" => {
            let summary = verify_repository(Path::new(&root))?;
            println!(
                "Verified Secure Bench {} prospective foundation: {} pairs, {} cases, {} conformance vectors; scanner processes started: 0.",
                summary.benchmark_version,
                summary.pairs,
                summary.cases,
                summary.conformance_vectors
            );
        }
        "summary" => println!("{}", summarize_repository(Path::new(&root))?),
        _ => return Err(Phase12Error::InvalidRequest(usage().to_owned())),
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}
