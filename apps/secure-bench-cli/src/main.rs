//! Secure Bench command-line interface for neutral recorded and live evaluation.

use clap::{Parser, Subcommand, ValueEnum};
use secure_bench_core::adapter::fingerprint;
use secure_bench_core::corpus::{inspect_corpus, validate_corpus};
use secure_bench_core::runner::{
    DEFAULT_SECURE_ENGINE_ARGUMENTS, RunnerRequest, load_live_run, run_secure_engine,
    valid_report_path,
};
use secure_bench_core::taxonomy::{
    canonical_taxonomy_json, inspect_taxonomy, load_taxonomy, taxonomy_content_hash,
};
use secure_bench_core::{
    BenchmarkResult, EvaluationInput, LiveEvaluationInput, RESULT_SCHEMA_V2, evaluate,
    evaluate_live_run, load_run_manifest, load_suite,
};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_REPORT_BYTES: u64 = 10 * 1024 * 1024;
const MAX_RESULT_BYTES: u64 = 20 * 1024 * 1024;

#[derive(Debug, Parser)]
#[command(name = "secure-bench")]
#[command(about = "Neutral Secure Bench contracts, corpus validation, and black-box evaluation")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Inspect or validate the first-party benchmark corpus.
    Corpus {
        #[command(subcommand)]
        command: CorpusCommand,
    },
    /// Validate, inspect, or canonically serialize the frozen neutral taxonomy.
    Taxonomy {
        #[command(subcommand)]
        command: TaxonomyCommand,
    },
    /// Execute an explicitly supplied Secure Engine binary as a black box.
    Run {
        /// Phase 1 TOML benchmark suite.
        suite: PathBuf,
        /// External tool contract to invoke.
        #[arg(long, value_enum)]
        tool: Tool,
        /// Explicit regular-file path to the user-provided binary.
        #[arg(long)]
        binary: PathBuf,
        /// New live-run bundle directory.
        #[arg(long)]
        output: PathBuf,
        /// Repository root used to resolve scanner-visible fixture paths.
        #[arg(long, default_value = ".")]
        repository_root: PathBuf,
        /// Stable run identifier.
        #[arg(long, default_value = "secure-engine-baseline")]
        run_id: String,
        /// Public UTF-8 configuration copied outside the scanned tree and fingerprinted.
        #[arg(long)]
        configuration: Option<PathBuf>,
        /// Exact argument template item; repeat for every argument.
        #[arg(long = "argument", allow_hyphen_values = true)]
        arguments: Vec<String>,
    },
    /// Normalize and score a recorded mock report or a live-run bundle.
    Evaluate {
        /// TOML suite in the Phase 1 positional form.
        suite_path: Option<PathBuf>,
        /// Recorded-run file or live-run bundle in the Phase 1 positional form.
        run_path: Option<PathBuf>,
        /// TOML suite in the preserved Phase 0 option form.
        #[arg(long = "suite", conflicts_with = "suite_path")]
        suite_option: Option<PathBuf>,
        /// Recorded-run file in the preserved Phase 0 option form.
        #[arg(long = "run", conflicts_with = "run_path")]
        run_option: Option<PathBuf>,
        /// Optional JSON result path; JSON is printed to standard output when omitted.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Validate Phase 0 suite, run, adapter, and matching contracts.
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
        /// Result in the Phase 1 positional form.
        result_path: Option<PathBuf>,
        /// Result in the preserved Phase 0 option form.
        #[arg(long = "result", conflicts_with = "result_path")]
        result_option: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum TaxonomyCommand {
    /// Validate schema, semantics, content hash, and canonical serialization.
    Validate {
        /// Frozen taxonomy JSON document.
        taxonomy: PathBuf,
    },
    /// Report declared and computed fingerprints without validating the hash.
    Inspect {
        /// Frozen taxonomy JSON document.
        taxonomy: PathBuf,
    },
    /// Emit deterministic canonical JSON after complete validation.
    Canonicalize {
        /// Frozen taxonomy JSON document.
        taxonomy: PathBuf,
        /// Optional output path; canonical JSON is printed when omitted.
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum CorpusCommand {
    /// Validate schemas, semantics, leakage controls, provenance, and fingerprints.
    Validate {
        /// Phase 1 TOML suite.
        suite: PathBuf,
        /// Repository root used to resolve fixture paths.
        #[arg(long, default_value = ".")]
        repository_root: PathBuf,
    },
    /// Compute scanner-visible fingerprints without accepting manifest claims.
    Inspect {
        /// Phase 1 TOML suite.
        suite: PathBuf,
        /// Repository root used to resolve fixture paths.
        #[arg(long, default_value = ".")]
        repository_root: PathBuf,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum Tool {
    SecureEngine,
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
        Command::Corpus { command } => run_corpus_command(command),
        Command::Taxonomy { command } => run_taxonomy_command(command),
        Command::Run {
            suite,
            tool,
            binary,
            output,
            repository_root,
            run_id,
            configuration,
            arguments,
        } => run_external(RunOptions {
            suite,
            tool,
            binary,
            output,
            repository_root,
            run_id,
            configuration,
            arguments,
        }),
        Command::Evaluate {
            suite_path,
            run_path,
            suite_option,
            run_option,
            output,
        } => {
            let suite = select_path(suite_path, suite_option, "suite")?;
            let run = select_path(run_path, run_option, "run")?;
            let result = evaluate_any_files(&suite, &run)?;
            let json = stable_json(&result)?;
            if let Some(path) = output {
                atomic_write(&path, &json)?;
                eprintln!("Wrote deterministic result to {}.", path.display());
                eprintln!("{}", summary_text(&result));
            } else {
                io::stdout()
                    .write_all(&json)
                    .map_err(|error| format!("could not write JSON result: {error}"))?;
                eprintln!("{}", summary_text(&result));
            }
            Ok(())
        }
        Command::Validate { suite, run } => {
            let result = evaluate_recorded_files(&suite, &run)?;
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
        Command::Summary {
            result_path,
            result_option,
        } => {
            let result = select_path(result_path, result_option, "result")?;
            let bytes = read_bounded(&result, MAX_RESULT_BYTES, "result")?;
            let parsed: BenchmarkResult = serde_json::from_slice(&bytes)
                .map_err(|error| format!("result JSON is invalid at line {}", error.line()))?;
            println!("{}", summary_text(&parsed));
            Ok(())
        }
    }
}

fn run_taxonomy_command(command: TaxonomyCommand) -> Result<(), String> {
    match command {
        TaxonomyCommand::Validate { taxonomy } => {
            let bytes = read_bounded(&taxonomy, MAX_MANIFEST_BYTES, "taxonomy")?;
            let parsed = load_taxonomy(&bytes).map_err(|error| error.to_string())?;
            let canonical = canonical_taxonomy_json(&parsed).map_err(|error| error.to_string())?;
            if bytes != canonical {
                return Err("taxonomy is valid but is not stored in canonical JSON form".to_owned());
            }
            println!(
                "Validated neutral taxonomy {} with {} categories and content hash {}.",
                parsed.taxonomy_version,
                parsed.categories.len(),
                parsed.content_hash
            );
            Ok(())
        }
        TaxonomyCommand::Inspect { taxonomy } => {
            let bytes = read_bounded(&taxonomy, MAX_MANIFEST_BYTES, "taxonomy")?;
            let parsed = inspect_taxonomy(&bytes).map_err(|error| error.to_string())?;
            let computed = taxonomy_content_hash(&parsed).map_err(|error| error.to_string())?;
            let canonical = canonical_taxonomy_json(&parsed).map_err(|error| error.to_string())?;
            let output = serde_json::json!({
                "artifact_fingerprint": fingerprint(&bytes),
                "canonical_serialization": bytes == canonical,
                "categories": parsed.categories.len(),
                "computed_content_hash": computed,
                "content_hash_matches": parsed.content_hash == computed,
                "declared_content_hash": parsed.content_hash,
                "publication_date": parsed.publication_date,
                "schema_version": parsed.schema_version,
                "taxonomy_version": parsed.taxonomy_version,
            });
            let mut output = serde_json::to_vec_pretty(&output)
                .map_err(|error| format!("could not serialize taxonomy inspection: {error}"))?;
            output.push(b'\n');
            io::stdout()
                .write_all(&output)
                .map_err(|error| format!("could not write taxonomy inspection: {error}"))
        }
        TaxonomyCommand::Canonicalize { taxonomy, output } => {
            let bytes = read_bounded(&taxonomy, MAX_MANIFEST_BYTES, "taxonomy")?;
            let parsed = load_taxonomy(&bytes).map_err(|error| error.to_string())?;
            let canonical = canonical_taxonomy_json(&parsed).map_err(|error| error.to_string())?;
            if let Some(path) = output {
                atomic_write(&path, &canonical)?;
                eprintln!("Wrote canonical taxonomy to {}.", path.display());
                Ok(())
            } else {
                io::stdout()
                    .write_all(&canonical)
                    .map_err(|error| format!("could not write canonical taxonomy: {error}"))
            }
        }
    }
}

fn run_corpus_command(command: CorpusCommand) -> Result<(), String> {
    match command {
        CorpusCommand::Validate {
            suite,
            repository_root,
        } => {
            let suite_bytes = read_bounded(&suite, MAX_MANIFEST_BYTES, "suite")?;
            let suite = load_suite(&suite_bytes).map_err(|error| error.to_string())?;
            let validation =
                validate_corpus(&suite, &repository_root).map_err(|error| error.to_string())?;
            println!(
                "Validated {} cases: {} vulnerable, {} safe controls; corpus fingerprint {}.",
                validation.cases,
                validation.vulnerable_cases,
                validation.safe_controls,
                validation.corpus_fingerprint
            );
            Ok(())
        }
        CorpusCommand::Inspect {
            suite,
            repository_root,
        } => {
            let suite_bytes = read_bounded(&suite, MAX_MANIFEST_BYTES, "suite")?;
            let suite = load_suite(&suite_bytes).map_err(|error| error.to_string())?;
            let validation =
                inspect_corpus(&suite, &repository_root).map_err(|error| error.to_string())?;
            let output = serde_json::json!({
                "case_fingerprints": validation.case_fingerprints,
                "cases": validation.cases,
                "corpus_fingerprint": validation.corpus_fingerprint,
                "safe_controls": validation.safe_controls,
                "vulnerable_cases": validation.vulnerable_cases,
            });
            let mut bytes = serde_json::to_vec_pretty(&output)
                .map_err(|error| format!("could not serialize corpus inspection: {error}"))?;
            bytes.push(b'\n');
            io::stdout()
                .write_all(&bytes)
                .map_err(|error| format!("could not write corpus inspection: {error}"))
        }
    }
}

struct RunOptions {
    suite: PathBuf,
    tool: Tool,
    binary: PathBuf,
    output: PathBuf,
    repository_root: PathBuf,
    run_id: String,
    configuration: Option<PathBuf>,
    arguments: Vec<String>,
}

fn run_external(options: RunOptions) -> Result<(), String> {
    if options.tool != Tool::SecureEngine {
        return Err("only the public Secure Engine contract is available in Phase 1".to_owned());
    }
    let suite_bytes = read_bounded(&options.suite, MAX_MANIFEST_BYTES, "suite")?;
    let suite = load_suite(&suite_bytes).map_err(|error| error.to_string())?;
    validate_corpus(&suite, &options.repository_root).map_err(|error| error.to_string())?;
    let configuration = options.configuration.as_deref().map_or_else(
        || Ok(Vec::new()),
        |path| read_bounded(path, MAX_MANIFEST_BYTES, "configuration"),
    )?;
    let arguments = if options.arguments.is_empty() {
        DEFAULT_SECURE_ENGINE_ARGUMENTS
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
    } else {
        options.arguments
    };
    let cancellation = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&cancellation);
    ctrlc::set_handler(move || signal.store(true, std::sync::atomic::Ordering::SeqCst))
        .map_err(|error| format!("could not install cancellation handler: {error}"))?;
    let run = run_secure_engine(&RunnerRequest {
        suite: &suite,
        repository_root: &options.repository_root,
        binary: &options.binary,
        output: &options.output,
        run_id: &options.run_id,
        argument_template: &arguments,
        configuration: &configuration,
        cancellation,
    })
    .map_err(|error| error.to_string())?;
    eprintln!(
        "Completed black-box run `{}` with status {:?}; bundle written to {}.",
        run.run_id,
        run.status,
        options.output.display()
    );
    Ok(())
}

fn select_path(
    positional: Option<PathBuf>,
    option: Option<PathBuf>,
    label: &str,
) -> Result<PathBuf, String> {
    positional
        .or(option)
        .ok_or_else(|| format!("a {label} path is required"))
}

fn evaluate_any_files(suite_path: &Path, run_path: &Path) -> Result<BenchmarkResult, String> {
    if fs::symlink_metadata(run_path).is_ok_and(|metadata| metadata.is_dir()) {
        evaluate_live_files(suite_path, run_path)
    } else {
        evaluate_recorded_files(suite_path, run_path)
    }
}

fn evaluate_recorded_files(suite_path: &Path, run_path: &Path) -> Result<BenchmarkResult, String> {
    let suite = read_bounded(suite_path, MAX_MANIFEST_BYTES, "suite")?;
    let run = read_bounded(run_path, MAX_MANIFEST_BYTES, "recorded run")?;
    let recorded = load_run_manifest(&run).map_err(|error| error.to_string())?;
    load_suite(&suite).map_err(|error| error.to_string())?;
    let report_path = resolve_recorded_report_path(run_path, &recorded.report_path)?;
    let report = read_bounded(&report_path, MAX_REPORT_BYTES, "mock report")?;
    evaluate(EvaluationInput {
        suite: &suite,
        run_manifest: &run,
        report: &report,
    })
    .map_err(|error| error.to_string())
}

fn evaluate_live_files(suite_path: &Path, bundle: &Path) -> Result<BenchmarkResult, String> {
    let bundle_metadata = fs::symlink_metadata(bundle)
        .map_err(|error| format!("could not inspect live-run bundle: {error}"))?;
    if !bundle_metadata.is_dir() || bundle_metadata.file_type().is_symlink() {
        return Err("live-run bundle must be a regular directory".to_owned());
    }
    let suite = read_bounded(suite_path, MAX_MANIFEST_BYTES, "suite")?;
    let run_path = bundle.join("run.json");
    let run_manifest = read_bounded(&run_path, MAX_MANIFEST_BYTES, "live run")?;
    let run = load_live_run(&run_manifest).map_err(|error| error.to_string())?;
    let expected = run
        .cases
        .iter()
        .filter_map(|case| case.report_path.clone())
        .collect::<BTreeSet<_>>();
    let actual = collect_bundle_reports(bundle)?;
    if actual != expected {
        return Err("live-run bundle contains missing or unrelated raw reports".to_owned());
    }
    let mut reports = BTreeMap::new();
    for path in expected {
        if !valid_report_path(&path) {
            return Err(format!("live report path `{path}` is unsafe"));
        }
        reports.insert(
            path.clone(),
            read_bounded(
                &safe_bundle_join(bundle, &path)?,
                MAX_REPORT_BYTES,
                "live report",
            )?,
        );
    }
    evaluate_live_run(&LiveEvaluationInput {
        suite: &suite,
        run_manifest: &run_manifest,
        reports: &reports,
    })
    .map_err(|error| error.to_string())
}

fn collect_bundle_reports(bundle: &Path) -> Result<BTreeSet<String>, String> {
    let reports_root = bundle.join("reports");
    let mut result = BTreeSet::new();
    if fs::symlink_metadata(&reports_root).is_err() {
        return Ok(result);
    }
    let mut pending = vec![reports_root];
    while let Some(directory) = pending.pop() {
        let metadata = fs::symlink_metadata(&directory)
            .map_err(|error| format!("could not inspect report directory: {error}"))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("report bundle contains an unsafe directory".to_owned());
        }
        for entry in fs::read_dir(&directory)
            .map_err(|error| format!("could not read report directory: {error}"))?
        {
            let entry = entry.map_err(|error| format!("could not read report entry: {error}"))?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)
                .map_err(|error| format!("could not inspect report entry: {error}"))?;
            if metadata.file_type().is_symlink() {
                return Err("report bundle contains a symlink".to_owned());
            }
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file() {
                let relative = path
                    .strip_prefix(bundle)
                    .map_err(|_| "report path escaped its bundle".to_owned())?;
                result.insert(path_to_slashes(relative)?);
            } else {
                return Err("report bundle contains a non-regular entry".to_owned());
            }
        }
    }
    Ok(result)
}

fn safe_bundle_join(bundle: &Path, relative: &str) -> Result<PathBuf, String> {
    let mut joined = bundle.to_path_buf();
    for component in Path::new(relative).components() {
        match component {
            Component::Normal(segment) => joined.push(segment),
            _ => return Err(format!("live report path `{relative}` is unsafe")),
        }
    }
    Ok(joined)
}

fn path_to_slashes(path: &Path) -> Result<String, String> {
    let mut segments = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(segment) => segments.push(
                segment
                    .to_str()
                    .ok_or_else(|| "report bundle path is not UTF-8".to_owned())?,
            ),
            _ => return Err("report bundle path is unsafe".to_owned()),
        }
    }
    Ok(segments.join("/"))
}

fn resolve_recorded_report_path(run_path: &Path, relative: &str) -> Result<PathBuf, String> {
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
            Component::Normal(segment) => Some(segment.to_os_string()),
            _ => None,
        })
        .collect::<Vec<_>>();
    for component in relative_path.components() {
        match component {
            Component::Normal(segment) => segments.push(segment.to_os_string()),
            Component::CurDir => {}
            Component::ParentDir => {
                if segments.pop().is_none() {
                    return Err("recorded report_path escapes the reports directory".to_owned());
                }
            }
            Component::RootDir | Component::Prefix(_) => {
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

fn summary_text(result: &BenchmarkResult) -> String {
    let score = &result.score;
    let phase = if result.schema_version == RESULT_SCHEMA_V2 {
        "Phase 1 live result"
    } else {
        "Phase 0 mock data"
    };
    format!(
        concat!(
            "Secure Bench {} (neutral evaluation; no ranking)\n",
            "Suite: {} | Run: {} | Normalized findings: {}\n",
            "Vulnerable recall: {}/{} eligible; {}/{} attempted\n",
            "Safe-control false positives: {}/{} attempted; clean coverage: {}/{} eligible\n",
            "Evidence paths: {}/{} | Sources: {}/{} | Sinks: {}/{} | Duplicates: {}/{}\n",
            "Calibration observations: severity {}/{}, confidence {}/{}\n",
            "Failures: crashes {}, timeouts {}, missing {}, parse {}, unsupported {}, invalid {}, execution {}, cancelled {}\n",
            "Performance: duration {} ms/{} samples; peak memory {:?} bytes/{} samples"
        ),
        phase,
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
        score.source_localization_accuracy.numerator,
        score.source_localization_accuracy.denominator,
        score.sink_localization_accuracy.numerator,
        score.sink_localization_accuracy.denominator,
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
        score.failures.invalid_outputs,
        score.failures.execution_failures,
        score.failures.cancellations,
        score.performance.cold_duration.total,
        score.performance.cold_duration.samples,
        score.performance.peak_memory.maximum,
        score.performance.peak_memory.samples,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_path_cannot_escape_manifest_directory() {
        assert!(
            resolve_recorded_report_path(
                Path::new("fixtures/reports/runs/run.json"),
                "../../secret"
            )
            .is_err()
        );
        assert_eq!(
            resolve_recorded_report_path(
                Path::new("fixtures/reports/runs/run.json"),
                "../mock.json"
            ),
            Ok(PathBuf::from("fixtures/reports/mock.json"))
        );
    }

    #[test]
    fn live_report_paths_are_portable_and_confined() {
        assert_eq!(
            safe_bundle_join(Path::new("bundle"), "reports/case.json"),
            Ok(PathBuf::from("bundle/reports/case.json"))
        );
        assert!(safe_bundle_join(Path::new("bundle"), "../case.json").is_err());
        assert!(safe_bundle_join(Path::new("bundle"), "/case.json").is_err());
    }
}
