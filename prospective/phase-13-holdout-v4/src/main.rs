//! Scanner-free Phase 13 holdout authoring and validation CLI.

use secure_bench_phase13::{Phase13Error, generate_repository, summarize, validate_repository};
use std::path::Path;

fn usage() -> &'static str {
    "usage: secure-bench-phase13 <generate|validate|summary> <repository-root>"
}

fn run() -> Result<(), Phase13Error> {
    let mut arguments = std::env::args().skip(1);
    let command = arguments
        .next()
        .ok_or_else(|| Phase13Error::InvalidRequest(usage().to_owned()))?;
    let root = arguments
        .next()
        .ok_or_else(|| Phase13Error::InvalidRequest(usage().to_owned()))?;
    if arguments.next().is_some() {
        return Err(Phase13Error::InvalidRequest(usage().to_owned()));
    }
    match command.as_str() {
        "generate" => {
            let report = generate_repository(Path::new(&root))?;
            println!(
                "Frozen {} pairs and {} intentionally unexecuted cases; scanner processes started: 0.",
                report.pair_count, report.case_count
            );
        }
        "validate" => {
            let report = validate_repository(Path::new(&root))?;
            println!(
                "Validated Secure Bench {} holdout v4: {} pairs, {} cases, corpus {}, Merkle root {}; scanner processes started: 0.",
                report.benchmark_version,
                report.pair_count,
                report.case_count,
                report.aggregate_corpus_sha256,
                report.contract_merkle_root
            );
        }
        "summary" => println!("{}", summarize(Path::new(&root))?),
        _ => return Err(Phase13Error::InvalidRequest(usage().to_owned())),
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}
