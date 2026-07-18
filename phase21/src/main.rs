//! Phase 21 qualification command line.

use secure_bench_phase21::sandbox::validate_tools;
use secure_bench_phase21::{independent_verify, qualify};
use std::env;
use std::path::Path;

fn main() {
    let arguments = env::args().collect::<Vec<_>>();
    let result = match arguments.as_slice() {
        [_, command, root] if command == "qualify" => qualify(Path::new(root)),
        [_, command, root] if command == "verify" => independent_verify(Path::new(root))
            .and_then(|report| serde_json::to_value(report).map_err(Into::into)),
        [_, command, root] if command == "verify-tools" => validate_tools(Path::new(root)),
        _ => {
            eprintln!("usage: secure-bench-phase21 qualify|verify|verify-tools <repository-root>");
            std::process::exit(2);
        }
    };
    match result {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
