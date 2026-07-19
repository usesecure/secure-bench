#![forbid(unsafe_code)]
//! Scanner-free native adapter entry point for retained Phase 28 raw evidence.

use secure_bench_core::taxonomy::load_taxonomy;
use secure_bench_phase16::{AdapterRoute, project_report};
use serde_json::Value;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn read(path: &Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))
}

fn repository_root() -> Result<PathBuf, String> {
    env::var_os("SECURE_BENCH_ROOT")
        .map(PathBuf::from)
        .or_else(|| env::current_dir().ok())
        .ok_or_else(|| "repository root is unavailable".to_owned())
}

fn adapt(arguments: &[String]) -> Result<Value, String> {
    if arguments.len() != 5 {
        return Err(
            "usage: secure-bench-phase28-native-adapter secure-engine CASE RAW FIXTURE".to_owned(),
        );
    }
    let root = repository_root()?;
    let mode = &arguments[1];
    let case_id = &arguments[2];
    let raw = read(Path::new(&arguments[3]))?;
    let _fixture = Path::new(&arguments[4]);
    match mode.as_str() {
        "secure-engine" => {
            let taxonomy =
                load_taxonomy(&read(&root.join("taxonomy/secure-bench-taxonomy-v1.json"))?)
                    .map_err(|error| format!("frozen taxonomy is invalid: {error}"))?;
            let projection =
                project_report(case_id, &raw, AdapterRoute::AuthoritativeV2, &taxonomy)
                    .map_err(|error| format!("Secure Engine adapter rejected report: {error}"))?;
            serde_json::to_value(projection)
                .map_err(|error| format!("cannot serialize Secure Engine projection: {error}"))
        }
        _ => Err(format!("unsupported adapter mode: {mode}")),
    }
}

fn main() -> ExitCode {
    let arguments: Vec<String> = env::args().collect();
    match adapt(&arguments) {
        Ok(projection) => match serde_json::to_string(&projection) {
            Ok(encoded) => {
                println!("{encoded}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("cannot encode adapter output: {error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::adapt;

    #[test]
    fn rejects_unknown_mode_before_reading_evidence() {
        let arguments = vec![
            "adapter".to_owned(),
            "unknown".to_owned(),
            "aurora-000000000000000000".to_owned(),
            "/does/not/exist".to_owned(),
            "/does/not/exist".to_owned(),
        ];
        let result = adapt(&arguments);
        assert!(result.is_err());
    }
}
