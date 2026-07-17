//! Scanner-free command-line interface for Phase 9 holdout authoring and validation.

use secure_bench_phase9::{Phase9Error, author_holdout, summarize_holdout, validate_holdout};
use std::env;
use std::path::Path;

fn usage() -> &'static str {
    "Usage: secure-bench-phase9 <author|validate|summary> [repository-root]"
}

fn run() -> Result<(), Phase9Error> {
    let mut arguments = env::args().skip(1);
    let command = arguments
        .next()
        .ok_or_else(|| Phase9Error::InvalidRequest(usage().to_owned()))?;
    let root = arguments.next().unwrap_or_else(|| ".".to_owned());
    if arguments.next().is_some() {
        return Err(Phase9Error::InvalidRequest(usage().to_owned()));
    }
    let root = Path::new(&root);
    match command.as_str() {
        "author" => {
            let report = author_holdout(root)?;
            println!(
                "Authored frozen Phase 9 holdout v3: {} pairs, {} cases; no scanner process was started.",
                report.pairs, report.cases
            );
        }
        "validate" => {
            let report = validate_holdout(root)?;
            println!(
                "Validated frozen Phase 9 holdout v3: {} pairs, {} cases, corpus {}, Merkle root {}; no scanner process was started.",
                report.pairs,
                report.cases,
                report.aggregate_corpus_sha256,
                report.contract_merkle_root
            );
        }
        "summary" => {
            let report = summarize_holdout(root)?;
            println!(
                "Phase 9 public aggregate: pairs={}, cases={}, vulnerable={}, controls={}, JavaScript={}, TypeScript={}, Node.js={}, Express={}, Next.js App Router={}, Server Actions={}, direct={}, helper-mediated={}, inter-file aliased={}, control-flow-sensitive={}; evidence-contract-v2 reused; no scanner process was started.",
                report.pairs,
                report.cases,
                report.vulnerable,
                report.controls,
                report.java_script,
                report.type_script,
                report.node_js,
                report.express,
                report.next_app_router,
                report.server_actions,
                report.direct,
                report.helper_mediated,
                report.inter_file_aliased,
                report.control_flow_sensitive
            );
        }
        _ => return Err(Phase9Error::InvalidRequest(usage().to_owned())),
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
