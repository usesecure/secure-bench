//! Phase 22 lifecycle command line.

use secure_bench_phase22::{
    execute_once, independent_verify, preflight, prepare, recover_verification,
};
use std::env;
use std::path::Path;

fn main() {
    let arguments = env::args().collect::<Vec<_>>();
    let result = match arguments.as_slice() {
        [_, command, root] if command == "prepare" => prepare(Path::new(root)),
        [_, command, root] if command == "preflight" => preflight(Path::new(root)),
        [_, command, root] if command == "execute-once" => execute_once(Path::new(root)),
        [_, command, root] if command == "recover-verification" => {
            recover_verification(Path::new(root))
                .and_then(|report| serde_json::to_value(report).map_err(Into::into))
        }
        [_, command, root] if command == "verify" => independent_verify(Path::new(root))
            .and_then(|report| serde_json::to_value(report).map_err(Into::into)),
        _ => {
            eprintln!(
                "usage: secure-bench-phase22 prepare|preflight|execute-once|recover-verification|verify <repository-root>"
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
