//! Secure Bench Phase 25 lifecycle command.

use secure_bench_phase25::{execute_once, preflight, prepare, qualify, verify};
use std::path::{Path, PathBuf};

fn usage() -> ! {
    eprintln!(
        "usage: secure-bench-phase25 <qualify|prepare|preflight|execute-once|verify> [repository-root]"
    );
    std::process::exit(2);
}

fn root(argument: Option<String>) -> Result<PathBuf, std::io::Error> {
    argument.map_or_else(
        || {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .canonicalize()
        },
        |value| PathBuf::from(value).canonicalize(),
    )
}

fn main() {
    let mut arguments = std::env::args().skip(1);
    let command = arguments.next().unwrap_or_else(|| usage());
    let repository = match root(arguments.next()) {
        Ok(path) => path,
        Err(error) => {
            eprintln!("repository error: {error}");
            std::process::exit(1);
        }
    };
    if arguments.next().is_some() {
        usage();
    }
    let result = match command.as_str() {
        "qualify" => qualify(&repository),
        "prepare" => prepare(&repository),
        "preflight" => preflight(&repository),
        "execute-once" => execute_once(&repository),
        "verify" => verify(&repository),
        _ => usage(),
    };
    match result {
        Ok(report) => match serde_json::to_string_pretty(&report) {
            Ok(json) => println!("{json}"),
            Err(error) => {
                eprintln!("serialization error: {error}");
                std::process::exit(1);
            }
        },
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
