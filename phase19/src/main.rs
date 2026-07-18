//! Scanner-free command-line verifier for the immutable Phase 19 binding.

use secure_bench_phase19_binding::holdout::{author, validate};
use secure_bench_phase19_binding::{verify_artifacts, verify_repository};
use std::env;
use std::path::Path;

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = env::args().collect::<Vec<_>>();
    match arguments.as_slice() {
        [_, command, root] if command == "verify" => {
            let summary = verify_repository(Path::new(root))?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
            Ok(())
        }
        [_, command, rpm, secure] if command == "verify-artifacts" => {
            let summary = verify_artifacts(Path::new(rpm), Path::new(secure))?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
            Ok(())
        }
        [_, command, root] if command == "author-holdout" => {
            let summary = author(Path::new(root))?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
            Ok(())
        }
        [_, command, root] if command == "validate-holdout" => {
            let summary = validate(Path::new(root))?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
            Ok(())
        }
        _ => Err(
            "usage: secure-bench-phase19-binding verify <repository-root> | verify-artifacts <rpm> <extracted-secure> | author-holdout <repository-root> | validate-holdout <repository-root>"
                .into(),
        ),
    }
}
