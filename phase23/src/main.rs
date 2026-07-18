//! Phase 23 lifecycle command-line interface.

use secure_bench_phase23::{
    diagnose, diagnose_thresholds, finalize_probe_setup_failure, probe_stack_limits, qualify,
    seal_phase23,
};
use std::env;
use std::path::Path;

fn main() {
    let arguments = env::args().collect::<Vec<_>>();
    let result = match arguments.as_slice() {
        [_, command, root] if command == "diagnose" => diagnose(Path::new(root)),
        [_, command, root] if command == "diagnose-thresholds" => {
            diagnose_thresholds(Path::new(root))
        }
        [_, command, root] if command == "probe-stack" => probe_stack_limits(Path::new(root)),
        [_, command, root] if command == "finalize-probe-setup" => {
            finalize_probe_setup_failure(Path::new(root))
        }
        [_, command, root] if command == "qualify" => qualify(Path::new(root)),
        [_, command, root] if command == "seal" => seal_phase23(Path::new(root)),
        _ => {
            eprintln!(
                "usage: secure-bench-phase23 diagnose|diagnose-thresholds|probe-stack|finalize-probe-setup|qualify|seal <repository-root>"
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
