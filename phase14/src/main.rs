//! Command-line boundary for the one-shot Phase 14 evaluation.

use secure_bench_phase14::{
    Phase14Error, execute_repository, isolated_exec, prepare_repository, summarize_repository,
    verify_repository,
};
use std::path::Path;

fn usage() -> &'static str {
    "Usage: secure-bench-phase14 <prepare|execute|verify|summary> <repository-root> <scanner-binary> <source-rpm>\n       secure-bench-phase14 isolated-exec <case-id>"
}

fn run() -> Result<(), Phase14Error> {
    let mut arguments = std::env::args().skip(1);
    let command = arguments
        .next()
        .ok_or_else(|| Phase14Error::InvalidRequest(usage().to_owned()))?;
    if command == "isolated-exec" {
        let case_id = arguments
            .next()
            .ok_or_else(|| Phase14Error::InvalidRequest(usage().to_owned()))?;
        if arguments.next().is_some() {
            return Err(Phase14Error::InvalidRequest(usage().to_owned()));
        }
        return isolated_exec(&case_id);
    }
    let root = arguments
        .next()
        .ok_or_else(|| Phase14Error::InvalidRequest(usage().to_owned()))?;
    let scanner = arguments
        .next()
        .ok_or_else(|| Phase14Error::InvalidRequest(usage().to_owned()))?;
    let rpm = arguments
        .next()
        .ok_or_else(|| Phase14Error::InvalidRequest(usage().to_owned()))?;
    if arguments.next().is_some() {
        return Err(Phase14Error::InvalidRequest(usage().to_owned()));
    }
    let root = Path::new(&root);
    let scanner = Path::new(&scanner);
    let rpm = Path::new(&rpm);
    match command.as_str() {
        "prepare" => {
            let contract = prepare_repository(root, scanner, rpm)?;
            println!(
                "Phase 14 pre-execution contract frozen for {} cases; no scanner process was started.",
                contract.holdout.cases
            );
        }
        "execute" => {
            let artifacts = execute_repository(root, scanner, rpm)?;
            println!(
                "Phase 14 one-shot execution completed: {} case records, result {}.",
                artifacts.case_records, artifacts.result_sha256
            );
        }
        "verify" => {
            let artifacts = verify_repository(root, scanner, rpm)?;
            println!(
                "Phase 14 artifacts verified offline: {} case records, completed ledger {}. No scanner process was started.",
                artifacts.case_records, artifacts.completed_ledger_sha256
            );
        }
        "summary" => {
            let summary = summarize_repository(root)?;
            println!("{summary}");
        }
        _ => return Err(Phase14Error::InvalidRequest(usage().to_owned())),
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
