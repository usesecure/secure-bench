//! Secure Bench Phase 0 mock-only command-line interface.

use clap::{Parser, Subcommand};
use secure_bench_core::{
    BenchmarkResult, EvaluationInput, evaluate, load_run_manifest, load_suite,
};
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_REPORT_BYTES: u64 = 10 * 1024 * 1024;
const MAX_RESULT_BYTES: u64 = 20 * 1024 * 1024;

#[derive(Debug, Parser)]
#[command(name = "secure-bench")]
#[command(about = "Tool-neutral Secure Bench Phase 0 evaluation over committed mock reports")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Normalize and score a recorded mock report without executing its command.
    Evaluate {
        /// TOML benchmark suite.
        #[arg(long)]
        suite: PathBuf,
        /// JSON recorded-run manifest.
        #[arg(long)]
        run: PathBuf,
        /// Optional JSON result path; JSON is printed to standard output when omitted.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Validate suite, run, adapter, and matching contracts without retaining a result.
    Validate {
        /// TOML benchmark suite.
        #[arg(long)]
        suite: PathBuf,
        /// JSON recorded-run manifest.
        #[arg(long)]
        run: PathBuf,
    },
    /// Render the concise terminal projection of a machine-readable result.
    Summary {
        /// JSON result produced by `evaluate`.
        #[arg(long)]
        result: PathBuf,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("Secure Bench error: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Command::Evaluate { suite, run, output } => {
            let result = evaluate_files(&suite, &run)?;
            let json = stable_json(&result)?;
            if let Some(path) = output {
                atomic_write(&path, &json)?;
                println!("Wrote deterministic Phase 0 result to {}.", path.display());
                print_summary(&result);
            } else {
                io::stdout()
                    .write_all(&json)
                    .map_err(|error| format!("could not write JSON result: {error}"))?;
                eprintln!("{}", summary_text(&result));
            }
            Ok(())
        }
        Command::Validate { suite, run } => {
            let result = evaluate_files(&suite, &run)?;
            if result.errors.is_empty() {
                println!(
                    "Validated suite `{}` and recorded run `{}`; no scanner command was executed.",
                    result.suite_id, result.run_id
                );
                Ok(())
            } else {
                Err(format!(
                    "recorded run produced {} adapter error(s); inspect an evaluate result for failure accounting",
                    result.errors.len()
                ))
            }
        }
        Command::Summary { result } => {
            let bytes = read_bounded(&result, MAX_RESULT_BYTES, "result")?;
            let parsed: BenchmarkResult = serde_json::from_slice(&bytes)
                .map_err(|error| format!("result JSON is invalid at line {}", error.line()))?;
            print_summary(&parsed);
            Ok(())
        }
    }
}

fn evaluate_files(suite_path: &Path, run_path: &Path) -> Result<BenchmarkResult, String> {
    let suite = read_bounded(suite_path, MAX_MANIFEST_BYTES, "suite")?;
    let run = read_bounded(run_path, MAX_MANIFEST_BYTES, "recorded run")?;
    let recorded = load_run_manifest(&run).map_err(|error| error.to_string())?;
    load_suite(&suite).map_err(|error| error.to_string())?;
    let report_path = resolve_report_path(run_path, &recorded.report_path)?;
    let report = read_bounded(&report_path, MAX_REPORT_BYTES, "mock report")?;
    evaluate(EvaluationInput {
        suite: &suite,
        run_manifest: &run,
        report: &report,
    })
    .map_err(|error| error.to_string())
}

fn resolve_report_path(run_path: &Path, relative: &str) -> Result<PathBuf, String> {
    let relative_path = Path::new(relative);
    if relative_path.is_absolute() {
        return Err("recorded report_path must remain within the reports directory".to_owned());
    }
    let reports_root = run_path
        .ancestors()
        .find(|ancestor| ancestor.file_name().is_some_and(|name| name == "reports"))
        .ok_or_else(|| "recorded run must be stored beneath a reports directory".to_owned())?;
    let parent = run_path.parent().unwrap_or(reports_root);
    let base = parent.strip_prefix(reports_root).map_err(|_| {
        "recorded run could not be resolved beneath the reports directory".to_owned()
    })?;
    let mut segments = base
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(segment) => Some(segment.to_os_string()),
            _ => None,
        })
        .collect::<Vec<_>>();
    for component in relative_path.components() {
        match component {
            std::path::Component::Normal(segment) => segments.push(segment.to_os_string()),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if segments.pop().is_none() {
                    return Err("recorded report_path escapes the reports directory".to_owned());
                }
            }
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                return Err(
                    "recorded report_path must remain within the reports directory".to_owned(),
                );
            }
        }
    }
    Ok(segments
        .into_iter()
        .fold(reports_root.to_path_buf(), |path, segment| {
            path.join(segment)
        }))
}

fn read_bounded(path: &Path, limit: u64, label: &str) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("could not inspect {label} `{}`: {error}", path.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(format!(
            "{label} `{}` is not a regular file",
            path.display()
        ));
    }
    if metadata.len() > limit {
        return Err(format!(
            "{label} `{}` exceeds its {} byte limit",
            path.display(),
            limit
        ));
    }
    fs::read(path).map_err(|error| format!("could not read {label} `{}`: {error}", path.display()))
}

fn stable_json(result: &BenchmarkResult) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec_pretty(result)
        .map_err(|error| format!("could not serialize result: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .map_err(|error| format!("could not create output directory: {error}"))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| "output path must name a file".to_owned())?;
    let mut temporary_name = OsString::from(".");
    temporary_name.push(file_name);
    temporary_name.push(format!(".{}.tmp", std::process::id()));
    let temporary_path = parent.join(temporary_name);
    let write_result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary_path)
            .map_err(|error| format!("could not create temporary result: {error}"))?;
        file.write_all(bytes)
            .map_err(|error| format!("could not write temporary result: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("could not sync temporary result: {error}"))?;
        fs::rename(&temporary_path, path)
            .map_err(|error| format!("could not atomically replace result: {error}"))?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    write_result
}

fn print_summary(result: &BenchmarkResult) {
    println!("{}", summary_text(result));
}

fn summary_text(result: &BenchmarkResult) -> String {
    let score = &result.score;
    format!(
        concat!(
            "Secure Bench Phase 0 (mock data only; no scanner comparison)\n",
            "Suite: {} | Run: {} | Normalized findings: {}\n",
            "Vulnerable recall: {}/{} eligible; {}/{} attempted\n",
            "Safe-control false positives: {}/{} attempted; clean coverage: {}/{} eligible\n",
            "Evidence paths: {}/{} | Duplicates: {}/{}\n",
            "Calibration: severity {}/{}, confidence {}/{}\n",
            "Failures: crashes {}, timeouts {}, missing {}, parse failures {}, unsupported {}"
        ),
        result.suite_id,
        result.run_id,
        score.counts.normalized_findings,
        score.vulnerable_recall.numerator,
        score.vulnerable_recall.denominator,
        score.attempted_vulnerable_recall.numerator,
        score.attempted_vulnerable_recall.denominator,
        score.safe_control_false_positive_rate.numerator,
        score.safe_control_false_positive_rate.denominator,
        score.safe_control_clean_coverage.numerator,
        score.safe_control_clean_coverage.denominator,
        score.evidence_path_accuracy.numerator,
        score.evidence_path_accuracy.denominator,
        score.duplicate_rate.numerator,
        score.duplicate_rate.denominator,
        score.severity_calibration_accuracy.numerator,
        score.severity_calibration_accuracy.denominator,
        score.confidence_calibration_accuracy.numerator,
        score.confidence_calibration_accuracy.denominator,
        score.failures.crashes,
        score.failures.timeouts,
        score.failures.missing,
        score.failures.parse_failures,
        score.failures.unsupported,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_path_cannot_escape_manifest_directory() {
        assert!(
            resolve_report_path(Path::new("fixtures/reports/runs/run.json"), "../../secret")
                .is_err()
        );
        assert_eq!(
            resolve_report_path(Path::new("fixtures/reports/runs/run.json"), "../mock.json"),
            Ok(PathBuf::from("fixtures/reports/mock.json"))
        );
    }
}
