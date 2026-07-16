//! Deterministic black-box helper used only by Secure Bench runner tests.

use serde_json::{Value, json};
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

fn main() -> ExitCode {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    match execute(&arguments) {
        Ok(()) => ExitCode::SUCCESS,
        Err(MockError::Crash) => ExitCode::from(42),
        Err(MockError::FindingsExit) => ExitCode::from(1),
        Err(MockError::Message(message)) => {
            eprintln!("Mock tool error: {message}");
            ExitCode::FAILURE
        }
    }
}

enum MockError {
    Crash,
    FindingsExit,
    Message(String),
}

fn execute(arguments: &[String]) -> Result<(), MockError> {
    if arguments == ["--version"] {
        println!("secure-bench-mock-tool 1.0.0");
        return Ok(());
    }
    let mode = option_value(arguments, "--mock-mode").unwrap_or("empty");
    let output = option_value(arguments, "--output")
        .map(PathBuf::from)
        .ok_or_else(|| MockError::Message("--output is required".to_owned()))?;
    match mode {
        "crash" => return Err(MockError::Crash),
        "timeout" => thread::sleep(Duration::from_mins(1)),
        "missing" => return Ok(()),
        "malformed" => return write_bytes(&output, b"{not-json"),
        "oversized" => return write_bytes(&output, &vec![b'x'; 3 * 1024 * 1024]),
        "streams" => {
            println!("{}", "x".repeat(8_192));
            eprintln!("{}", "y".repeat(8_192));
        }
        "environment" if env::var_os("SECURE_BENCH_PARENT_SECRET").is_some() => {
            return Err(MockError::Message(
                "parent environment was inherited".to_owned(),
            ));
        }
        _ => {}
    }
    let report = match mode {
        "unsupported" => json!({"schema_version": "secure-json-v2", "findings": []}),
        "finding-exit" => {
            let report = report_with_findings(&[finding(0)]);
            let mut bytes = serde_json::to_vec_pretty(&report)
                .map_err(|error| MockError::Message(error.to_string()))?;
            bytes.push(b'\n');
            write_bytes(&output, &bytes)?;
            return Err(MockError::FindingsExit);
        }
        "finding" => report_with_findings(&[finding(0)]),
        "duplicate" => report_with_findings(&[finding(0), finding(1)]),
        "empty" | "environment" | "streams" => report_with_findings(&[]),
        other => return Err(MockError::Message(format!("unknown mode `{other}`"))),
    };
    let mut bytes = serde_json::to_vec_pretty(&report)
        .map_err(|error| MockError::Message(error.to_string()))?;
    bytes.push(b'\n');
    write_bytes(&output, &bytes)
}

fn option_value<'a>(arguments: &'a [String], option: &str) -> Option<&'a str> {
    arguments
        .windows(2)
        .find(|pair| pair[0] == option)
        .map(|pair| pair[1].as_str())
}

fn report_with_findings(findings: &[Value]) -> Value {
    json!({
        "schema_version": "secure-json-v1",
        "scan": {"complete": true},
        "errors": [],
        "findings": findings,
    })
}

fn finding(index: u32) -> Value {
    json!({
        "rule_id": format!("mock.rule.{index}"),
        "category": "mock-category",
        "invariant": "mock invariant",
        "severity": "medium",
        "confidence": "medium",
        "source": {"path": "src/entry.js", "line": 1, "column": 1},
        "sink": {"path": "src/entry.js", "line": 1, "column": 1},
        "evidence_path": [
            {"kind": "source", "location": {"path": "src/entry.js", "line": 1, "column": 1}},
            {"kind": "sink", "location": {"path": "src/entry.js", "line": 1, "column": 1}}
        ],
        "message": "Deterministic runner-test output."
    })
}

fn write_bytes(path: &PathBuf, bytes: &[u8]) -> Result<(), MockError> {
    fs::write(path, bytes).map_err(|error| MockError::Message(error.to_string()))
}
