//! Independent Phase 20 raw-evidence verifier.

use secure_bench_phase20::independent_verify;
use std::env;
use std::path::Path;

fn main() {
    let arguments = env::args().collect::<Vec<_>>();
    if let [_, root] = arguments.as_slice() {
        match independent_verify(Path::new(root)) {
            Ok(summary) => println!("{summary}"),
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(1);
            }
        }
    } else {
        eprintln!("usage: independent-verify <repository-root>");
        std::process::exit(2);
    }
}
