//! Command-line boundary for scanner-free Phase 11 diagnostics.

use secure_bench_phase11::{
    Phase11Error, generate_repository, summarize_repository, verify_repository,
};
use std::path::Path;

fn usage() -> &'static str {
    "Usage: secure-bench-phase11 <generate|verify|summary> <repository-root>"
}

fn run() -> Result<(), Phase11Error> {
    let mut arguments = std::env::args().skip(1);
    let command = arguments
        .next()
        .ok_or_else(|| Phase11Error::InvalidRequest(usage().to_owned()))?;
    let root = arguments
        .next()
        .ok_or_else(|| Phase11Error::InvalidRequest(usage().to_owned()))?;
    if arguments.next().is_some() {
        return Err(Phase11Error::InvalidRequest(usage().to_owned()));
    }
    match command.as_str() {
        "generate" => {
            let summary = generate_repository(Path::new(&root))?;
            println!(
                "Phase 11 generated {} retired-case diagnostics from retained reports only; no scanner process was started.",
                summary.cases
            );
        }
        "verify" => {
            let summary = verify_repository(Path::new(&root))?;
            println!(
                "Phase 11 verified {} retired-case diagnostics and {} retained findings offline; no scanner process was started.",
                summary.cases, summary.findings
            );
        }
        "summary" => println!("{}", summarize_repository(Path::new(&root))?),
        _ => return Err(Phase11Error::InvalidRequest(usage().to_owned())),
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
