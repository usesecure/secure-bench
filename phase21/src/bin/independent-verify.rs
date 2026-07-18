//! Scanner-free Phase 21 evidence verifier.

use secure_bench_phase21::independent_verify;
use std::env;
use std::path::Path;

fn main() {
    let arguments = env::args().collect::<Vec<_>>();
    let [_, root] = arguments.as_slice() else {
        eprintln!("usage: independent-verify <repository-root>");
        std::process::exit(2);
    };
    match independent_verify(Path::new(root)) {
        Ok(report) => match serde_json::to_string(&report) {
            Ok(value) => println!("{value}"),
            Err(error) => {
                eprintln!("serialization failure: {error}");
                std::process::exit(1);
            }
        },
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
