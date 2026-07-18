//! Phase 20 lifecycle command-line interface.

use secure_bench_phase20::{execute_once, preflight, synthetic_proof, verify_committed};
use std::env;
use std::path::Path;

fn main() {
    let arguments = env::args().collect::<Vec<_>>();
    let result = match arguments.as_slice() {
        [_, command, root] if command == "synthetic-proof" => synthetic_proof(Path::new(root)),
        [_, command, root] if command == "preflight" => preflight(Path::new(root)),
        [_, command, root] if command == "execute-once" => execute_once(Path::new(root)),
        [_, command, root] if command == "verify" => verify_committed(Path::new(root)),
        _ => {
            eprintln!(
                "usage: secure-bench-phase20 synthetic-proof|preflight|execute-once|verify <repository-root>"
            );
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
