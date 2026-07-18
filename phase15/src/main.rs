//! Command-line boundary for the scanner-free Phase 15 postmortem.

use secure_bench_phase15::{
    Phase15Error, generate_repository, summarize_repository, verify_repository,
};
use std::path::Path;

fn usage() -> &'static str {
    "Usage: secure-bench-phase15 <generate|verify|summary> <repository-root>"
}

fn run() -> Result<(), Phase15Error> {
    let mut arguments = std::env::args().skip(1);
    let command = arguments
        .next()
        .ok_or_else(|| Phase15Error::InvalidRequest(usage().to_owned()))?;
    let root = arguments
        .next()
        .ok_or_else(|| Phase15Error::InvalidRequest(usage().to_owned()))?;
    if arguments.next().is_some() {
        return Err(Phase15Error::InvalidRequest(usage().to_owned()));
    }
    match command.as_str() {
        "generate" => {
            let summary = generate_repository(Path::new(&root))?;
            println!(
                "Phase 15 generated diagnostics for {} cases and {} retained findings offline; no scanner or AI process was started.",
                summary.cases, summary.findings
            );
        }
        "verify" => {
            let summary = verify_repository(Path::new(&root))?;
            println!(
                "Phase 15 verified {} cases and {} retained findings deterministically; no scanner or AI process was started.",
                summary.cases, summary.findings
            );
        }
        "summary" => println!("{}", summarize_repository(Path::new(&root))?),
        _ => return Err(Phase15Error::InvalidRequest(usage().to_owned())),
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
