//! Isolated black-box execution of an explicitly supplied Secure Engine binary.

use crate::adapter::{Adapter, AdapterError, AdapterInput, SecureJsonAdapter, fingerprint};
use crate::corpus::{CorpusError, validate_corpus};
use crate::model::{BenchmarkCase, BenchmarkSuite, HostProvenance};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tempfile::Builder;
use thiserror::Error;

/// Versioned live-run bundle manifest.
pub const LIVE_RUN_SCHEMA_V1: &str = "secure-bench-live-run-v1";
/// Default public Secure Engine argument template.
pub const DEFAULT_SECURE_ENGINE_ARGUMENTS: [&str; 6] = [
    "scan",
    "{fixture}",
    "--format",
    "secure-json-v1",
    "--output",
    "{report}",
];

const STREAM_PREFIX_BYTES: usize = 4096;
const MAX_CONFIGURATION_BYTES: usize = 1024 * 1024;
const VERSION_TIMEOUT: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(5);

/// Immutable request for one black-box corpus run.
pub struct RunnerRequest<'a> {
    /// Valid Phase 1 suite.
    pub suite: &'a BenchmarkSuite,
    /// Repository root used to resolve fixture paths.
    pub repository_root: &'a Path,
    /// Explicit user-provided executable path.
    pub binary: &'a Path,
    /// New output bundle directory.
    pub output: &'a Path,
    /// Stable run identifier.
    pub run_id: &'a str,
    /// Exact argument template. `{fixture}` and `{report}` are required placeholders.
    pub argument_template: &'a [String],
    /// Public configuration bytes fingerprinted for provenance.
    pub configuration: &'a [u8],
    /// Cancellation signal controlled by the caller.
    pub cancellation: Arc<AtomicBool>,
}

/// Reproducible live-run manifest; raw reports live beside it in the bundle.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LiveRun {
    /// Versioned schema identifier.
    pub schema_version: String,
    /// Stable run identifier.
    pub run_id: String,
    /// Evaluated suite identifier.
    pub suite_id: String,
    /// Validated scanner-visible corpus fingerprint.
    pub corpus_fingerprint: String,
    /// External binary and public contract provenance.
    pub tool: LiveToolProvenance,
    /// Sanitized host provenance.
    pub host: HostProvenance,
    /// Start time in Unix milliseconds.
    pub started_unix_ms: u64,
    /// Finish time in Unix milliseconds.
    pub finished_unix_ms: u64,
    /// Aggregate execution outcome.
    pub status: LiveRunStatus,
    /// One outcome for every suite case.
    pub cases: Vec<LiveCaseRun>,
}

/// External tool provenance without an absolute executable path.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LiveToolProvenance {
    /// Fixed adapter-neutral tool identifier.
    pub name: String,
    /// Sanitized output of the public version probe.
    pub reported_version: String,
    /// SHA-256 of the user-provided executable.
    pub binary_fingerprint: String,
    /// Public output schema requested from the process.
    pub report_schema: String,
    /// Exact portable argument template.
    pub argument_template: Vec<String>,
    /// SHA-256 of explicit public configuration bytes.
    pub configuration_fingerprint: String,
    /// Version-probe outcome.
    pub version_probe_status: VersionProbeStatus,
    /// Bounded-memory version-probe stdout metadata.
    pub version_stdout: StreamCapture,
    /// Bounded-memory version-probe stderr metadata.
    pub version_stderr: StreamCapture,
}

/// Aggregate live-run status.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveRunStatus {
    /// Every case completed with a valid report.
    Completed,
    /// At least one case completed and at least one did not.
    PartialFailure,
    /// No case completed with a valid report.
    Failed,
    /// Cancellation affected one or more cases.
    Cancelled,
}

/// Version probe status.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionProbeStatus {
    /// `--version` exited successfully.
    Success,
    /// `--version` exited unsuccessfully.
    Failed,
    /// `--version` timed out.
    Timeout,
    /// `--version` could not be executed.
    ExecutionFailure,
}

/// Per-case black-box outcome.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LiveCaseRun {
    /// Stable case identifier.
    pub case_id: String,
    /// Validated scanner-visible fixture fingerprint.
    pub fixture_fingerprint: String,
    /// Explicit execution outcome.
    pub status: LiveCaseStatus,
    /// Exact argument array passed to the external process.
    pub arguments: Vec<String>,
    /// Bundle-relative raw report path, when retained.
    pub report_path: Option<String>,
    /// Raw report SHA-256, when retained.
    pub report_fingerprint: Option<String>,
    /// Start time in Unix milliseconds.
    pub started_unix_ms: u64,
    /// Finish time in Unix milliseconds.
    pub finished_unix_ms: u64,
    /// Wall-clock duration.
    pub duration_ms: u64,
    /// Scanner process exit code, when it exited normally rather than by forced termination.
    pub process_exit_code: Option<i32>,
    /// Peak resident memory sampled from the child process, when supported.
    pub peak_memory_bytes: Option<u64>,
    /// Raw report size, when observed.
    pub output_bytes: Option<u64>,
    /// Bounded-memory stdout metadata.
    pub stdout: StreamCapture,
    /// Bounded-memory stderr metadata.
    pub stderr: StreamCapture,
    /// Stable failure reason without process output.
    pub error_code: Option<String>,
}

/// Live process and output states that never collapse into an empty clean result.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveCaseStatus {
    /// Valid report with no normalized findings.
    Success,
    /// Valid report with at least one normalized finding.
    Findings,
    /// Process exited unsuccessfully after starting.
    Crash,
    /// Process exceeded the case timeout.
    Timeout,
    /// Report was missing, oversized, malformed, or privacy-unsafe.
    InvalidOutput,
    /// Report declared an unsupported schema version.
    UnsupportedSchema,
    /// Process could not be started or monitored.
    ExecutionFailure,
    /// User cancellation stopped or skipped the case.
    Cancelled,
}

impl LiveCaseStatus {
    /// Whether this status represents a completed, adapter-valid scan.
    #[must_use]
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Success | Self::Findings)
    }
}

/// Fingerprint and size metadata for an unretained process stream.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StreamCapture {
    /// SHA-256 of the complete drained stream.
    pub fingerprint: String,
    /// Total drained bytes.
    pub bytes: u64,
    /// Whether the stream exceeded the in-memory diagnostic prefix.
    pub truncated: bool,
}

/// Runner setup, filesystem, execution, or artifact error.
#[derive(Debug, Error)]
pub enum RunnerError {
    /// Corpus validation failed before execution.
    #[error(transparent)]
    Corpus(#[from] CorpusError),
    /// Runner input is invalid.
    #[error("runner request is invalid: {0}")]
    InvalidRequest(String),
    /// Filesystem operation failed.
    #[error("runner filesystem operation failed for `{path}`: {detail}")]
    Io {
        /// User-requested or repository-relative path.
        path: String,
        /// Sanitized operating-system detail.
        detail: String,
    },
    /// Final bundle serialization failed.
    #[error("could not serialize the live-run manifest: {0}")]
    Serialization(String),
}

/// Runs an explicitly provided binary as a direct, isolated black-box process.
///
/// This function never downloads, installs, builds, discovers, or invokes a shell. Fixture copies
/// contain scanner-visible case files only; matcher-owned expectations remain outside the process
/// working directory and environment.
///
/// # Errors
///
/// Returns [`RunnerError`] for invalid requests, invalid corpora, unsafe binaries, bundle conflicts,
/// or filesystem failures. Per-case process and report failures are retained in a successful bundle.
pub fn run_secure_engine(request: &RunnerRequest<'_>) -> Result<LiveRun, RunnerError> {
    validate_request(request)?;
    let corpus = validate_corpus(request.suite, request.repository_root)?;
    let binary = validate_binary(request.binary)?;
    let binary_fingerprint = fingerprint_file(&binary)?;
    let output_parent = request.output.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(output_parent).map_err(|error| RunnerError::Io {
        path: output_parent.display().to_string(),
        detail: error.to_string(),
    })?;
    if fs::symlink_metadata(request.output).is_ok() {
        return Err(RunnerError::InvalidRequest(format!(
            "output `{}` already exists",
            request.output.display()
        )));
    }

    let staging = Builder::new()
        .prefix(".secure-bench-run-")
        .tempdir_in(output_parent)
        .map_err(|error| RunnerError::Io {
            path: output_parent.display().to_string(),
            detail: error.to_string(),
        })?;
    let reports_directory = staging.path().join("reports");
    fs::create_dir(&reports_directory).map_err(|error| RunnerError::Io {
        path: "reports".to_owned(),
        detail: error.to_string(),
    })?;

    let started_unix_ms = unix_millis();
    let version_probe = probe_version(&binary, &request.cancellation);
    let mut cases = Vec::with_capacity(request.suite.cases.len());
    let mut ordered_cases = request.suite.cases.iter().collect::<Vec<_>>();
    ordered_cases.sort_by(|left, right| left.case_id.cmp(&right.case_id));
    for case in ordered_cases {
        let fingerprint = corpus
            .case_fingerprints
            .get(&case.case_id)
            .cloned()
            .ok_or_else(|| {
                RunnerError::InvalidRequest(format!(
                    "validated corpus omitted case `{}`",
                    case.case_id
                ))
            })?;
        cases.push(run_case(
            request,
            case,
            &fingerprint,
            &binary,
            &reports_directory,
        )?);
    }
    let finished_unix_ms = unix_millis();
    let status = aggregate_status(&cases);
    let run = LiveRun {
        schema_version: LIVE_RUN_SCHEMA_V1.to_owned(),
        run_id: request.run_id.to_owned(),
        suite_id: request.suite.suite_id.clone(),
        corpus_fingerprint: corpus.corpus_fingerprint,
        tool: LiveToolProvenance {
            name: "Secure Engine".to_owned(),
            reported_version: version_probe.reported_version,
            binary_fingerprint,
            report_schema: "secure-json-v1".to_owned(),
            argument_template: request.argument_template.to_vec(),
            configuration_fingerprint: fingerprint(request.configuration),
            version_probe_status: version_probe.status,
            version_stdout: version_probe.stdout,
            version_stderr: version_probe.stderr,
        },
        host: host_provenance(),
        started_unix_ms,
        finished_unix_ms,
        status,
        cases,
    };
    let manifest = stable_json(&run)?;
    atomic_write(&staging.path().join("run.json"), &manifest)?;
    let staged_path = staging.keep();
    if let Err(error) = fs::rename(&staged_path, request.output) {
        let _ = fs::remove_dir_all(&staged_path);
        return Err(RunnerError::Io {
            path: request.output.display().to_string(),
            detail: error.to_string(),
        });
    }
    Ok(run)
}

fn validate_request(request: &RunnerRequest<'_>) -> Result<(), RunnerError> {
    if request.run_id.is_empty()
        || !request
            .run_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(RunnerError::InvalidRequest(
            "run_id must use ASCII letters, digits, dots, dashes, or underscores".to_owned(),
        ));
    }
    validate_argument_template(request.argument_template).map_err(RunnerError::InvalidRequest)?;
    let configuration_placeholders = request
        .argument_template
        .iter()
        .filter(|argument| argument.as_str() == "{configuration}")
        .count();
    if (request.configuration.is_empty() && configuration_placeholders != 0)
        || (!request.configuration.is_empty() && configuration_placeholders != 1)
    {
        return Err(RunnerError::InvalidRequest(
            "non-empty configuration bytes require exactly one {configuration} argument".to_owned(),
        ));
    }
    validate_configuration(request.suite, request.configuration)?;
    Ok(())
}

pub(crate) fn validate_argument_template(template: &[String]) -> Result<(), String> {
    if template.is_empty() {
        return Err("argument template must not be empty".to_owned());
    }
    if template.len() > 128
        || template.iter().any(|argument| {
            argument.is_empty()
                || argument.len() > 4_096
                || argument.chars().any(char::is_control)
                || Path::new(argument).is_absolute()
                || argument.contains("=/")
                || is_windows_absolute(argument)
        })
    {
        return Err(
            "argument template must be bounded, portable, and free of absolute paths".to_owned(),
        );
    }
    let fixture_placeholders = template
        .iter()
        .filter(|argument| argument.as_str() == "{fixture}")
        .count();
    let report_placeholders = template
        .iter()
        .filter(|argument| argument.as_str() == "{report}")
        .count();
    let configuration_placeholders = template
        .iter()
        .filter(|argument| argument.as_str() == "{configuration}")
        .count();
    if fixture_placeholders != 1 || report_placeholders != 1 || configuration_placeholders > 1 {
        return Err(
            "argument template requires one {fixture}, one {report}, and at most one {configuration} placeholder"
                .to_owned(),
        );
    }
    Ok(())
}

fn validate_configuration(suite: &BenchmarkSuite, configuration: &[u8]) -> Result<(), RunnerError> {
    if configuration.len() > MAX_CONFIGURATION_BYTES {
        return Err(RunnerError::InvalidRequest(format!(
            "configuration exceeds its {MAX_CONFIGURATION_BYTES} byte limit"
        )));
    }
    if configuration.is_empty() {
        return Ok(());
    }
    let text = std::str::from_utf8(configuration)
        .map_err(|_| RunnerError::InvalidRequest("configuration must be UTF-8 text".to_owned()))?;
    let lowercase = text.to_ascii_lowercase();
    let contains_matcher_data = suite.cases.iter().any(|case| {
        lowercase.contains(&case.category.to_ascii_lowercase())
            || case
                .invariant
                .as_ref()
                .is_some_and(|invariant| lowercase.contains(&invariant.to_ascii_lowercase()))
            || case.expected_findings.iter().any(|expected| {
                lowercase.contains(&expected.expectation_id.to_ascii_lowercase())
                    || lowercase.contains(&expected.invariant.to_ascii_lowercase())
            })
    });
    if contains_matcher_data {
        return Err(RunnerError::InvalidRequest(
            "configuration contains matcher-owned category, invariant, or expectation data"
                .to_owned(),
        ));
    }
    Ok(())
}

fn is_windows_absolute(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\')
}

pub(crate) fn validate_binary(path: &Path) -> Result<PathBuf, RunnerError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| RunnerError::Io {
        path: path.display().to_string(),
        detail: error.to_string(),
    })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(RunnerError::InvalidRequest(
            "binary must be an explicit regular file, not a symlink".to_owned(),
        ));
    }
    fs::canonicalize(path).map_err(|error| RunnerError::Io {
        path: path.display().to_string(),
        detail: error.to_string(),
    })
}

#[allow(clippy::too_many_lines)]
fn run_case(
    request: &RunnerRequest<'_>,
    case: &BenchmarkCase,
    fixture_fingerprint: &str,
    binary: &Path,
    reports_directory: &Path,
) -> Result<LiveCaseRun, RunnerError> {
    let arguments = render_arguments(request.argument_template);
    if request.cancellation.load(Ordering::SeqCst) {
        return Ok(cancelled_case(case, fixture_fingerprint, arguments));
    }

    let workspace = Builder::new()
        .prefix("secure-bench-case-")
        .tempdir()
        .map_err(|error| RunnerError::Io {
            path: "temporary case workspace".to_owned(),
            detail: error.to_string(),
        })?;
    let scanner_root = workspace.path().join("workspace");
    fs::create_dir(&scanner_root).map_err(|error| RunnerError::Io {
        path: "temporary scanner workspace".to_owned(),
        detail: error.to_string(),
    })?;
    let fixture = request.repository_root.join(&case.fixture_path);
    copy_fixture(&fixture, &scanner_root, &case.fixture_path)?;
    if !request.configuration.is_empty() {
        atomic_write(
            &workspace.path().join(".secure-bench-configuration"),
            request.configuration,
        )?;
    }
    let report_path = workspace.path().join(".secure-bench-report.json");

    let started_unix_ms = unix_millis();
    let started = Instant::now();
    let process = execute_process(
        binary,
        &arguments,
        &scanner_root,
        Duration::from_millis(case.resource_budget.timeout_ms),
        case.resource_budget.memory_bytes,
        &request.cancellation,
    );
    let finished_unix_ms = unix_millis();
    let duration_ms = millis_u64(started.elapsed());
    let relative_report = format!("reports/{}.json", case.case_id);

    match process {
        Err(error_code) => Ok(LiveCaseRun {
            case_id: case.case_id.clone(),
            fixture_fingerprint: fixture_fingerprint.to_owned(),
            status: LiveCaseStatus::ExecutionFailure,
            arguments,
            report_path: None,
            report_fingerprint: None,
            started_unix_ms,
            finished_unix_ms,
            duration_ms,
            process_exit_code: None,
            peak_memory_bytes: None,
            output_bytes: None,
            stdout: empty_capture(),
            stderr: empty_capture(),
            error_code: Some(error_code),
        }),
        Ok(process) => {
            let mut status = process.status;
            let mut error_code = process.error_code;
            let mut retained_report = None;
            let mut report_fingerprint = None;
            let mut output_bytes = None;

            if let Ok(metadata) = fs::symlink_metadata(&report_path) {
                output_bytes = Some(metadata.len());
                if metadata.is_file()
                    && !metadata.file_type().is_symlink()
                    && metadata.len() <= case.resource_budget.output_bytes
                {
                    let bytes = fs::read(&report_path).map_err(|error| RunnerError::Io {
                        path: relative_report.clone(),
                        detail: error.to_string(),
                    })?;
                    let digest = fingerprint(&bytes);
                    atomic_write(
                        &reports_directory.join(format!("{}.json", case.case_id)),
                        &bytes,
                    )?;
                    retained_report = Some(relative_report.clone());
                    report_fingerprint = Some(digest.clone());
                    if process.status.is_success() || report_declares_completed_scan(&bytes) {
                        match SecureJsonAdapter.normalize_scoped(AdapterInput {
                            report: &bytes,
                            report_fingerprint: &digest,
                            case_id: Some(&case.case_id),
                            path_prefix: Some(&case.fixture_path),
                        }) {
                            Ok(findings) => {
                                status = if findings.is_empty() {
                                    LiveCaseStatus::Success
                                } else {
                                    LiveCaseStatus::Findings
                                };
                                error_code = None;
                            }
                            Err(
                                AdapterError::UnsupportedVersion(_)
                                | AdapterError::UnsupportedFormat,
                            ) => {
                                status = LiveCaseStatus::UnsupportedSchema;
                                error_code = Some("runner.unsupported_schema".to_owned());
                            }
                            Err(_) => {
                                status = LiveCaseStatus::InvalidOutput;
                                error_code = Some("runner.invalid_output".to_owned());
                            }
                        }
                    }
                } else if process.status.is_success() {
                    status = LiveCaseStatus::InvalidOutput;
                    error_code = Some("runner.oversized_or_unsafe_report".to_owned());
                }
            } else if process.status.is_success() {
                status = LiveCaseStatus::InvalidOutput;
                error_code = Some("runner.missing_report".to_owned());
            }

            Ok(LiveCaseRun {
                case_id: case.case_id.clone(),
                fixture_fingerprint: fixture_fingerprint.to_owned(),
                status,
                arguments,
                report_path: retained_report,
                report_fingerprint,
                started_unix_ms,
                finished_unix_ms,
                duration_ms,
                process_exit_code: process.exit_code,
                peak_memory_bytes: process.peak_memory_bytes,
                output_bytes,
                stdout: process.stdout,
                stderr: process.stderr,
                error_code,
            })
        }
    }
}

fn cancelled_case(
    case: &BenchmarkCase,
    fixture_fingerprint: &str,
    arguments: Vec<String>,
) -> LiveCaseRun {
    let now = unix_millis();
    LiveCaseRun {
        case_id: case.case_id.clone(),
        fixture_fingerprint: fixture_fingerprint.to_owned(),
        status: LiveCaseStatus::Cancelled,
        arguments,
        report_path: None,
        report_fingerprint: None,
        started_unix_ms: now,
        finished_unix_ms: now,
        duration_ms: 0,
        process_exit_code: None,
        peak_memory_bytes: None,
        output_bytes: None,
        stdout: empty_capture(),
        stderr: empty_capture(),
        error_code: Some("runner.cancelled".to_owned()),
    }
}

pub(crate) fn render_arguments(template: &[String]) -> Vec<String> {
    template
        .iter()
        .map(|argument| {
            argument
                .replace("{fixture}", ".")
                .replace("{report}", "../.secure-bench-report.json")
                .replace("{configuration}", "../.secure-bench-configuration")
        })
        .collect()
}

pub(crate) struct ProcessOutcome {
    pub(crate) status: LiveCaseStatus,
    pub(crate) exit_code: Option<i32>,
    pub(crate) peak_memory_bytes: Option<u64>,
    pub(crate) stdout: StreamCapture,
    pub(crate) stderr: StreamCapture,
    pub(crate) error_code: Option<String>,
}

#[allow(clippy::too_many_lines)]
pub(crate) fn execute_process(
    binary: &Path,
    arguments: &[String],
    current_directory: &Path,
    timeout: Duration,
    memory_limit: u64,
    cancellation: &AtomicBool,
) -> Result<ProcessOutcome, String> {
    let mut command = Command::new(binary);
    command
        .args(arguments)
        .current_dir(current_directory)
        .env_clear()
        .env("LC_ALL", "C")
        .env("TZ", "UTC")
        .env("NO_COLOR", "1")
        .env("TMPDIR", current_directory)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure_process_group(&mut command);
    let mut child = command
        .spawn()
        .map_err(|_| "runner.spawn_failed".to_owned())?;
    let Some(stdout) = child.stdout.take() else {
        terminate_process_group(&mut child);
        wait_after_termination(&mut child);
        return Err("runner.stdout_capture_failed".to_owned());
    };
    let Some(stderr) = child.stderr.take() else {
        terminate_process_group(&mut child);
        wait_after_termination(&mut child);
        return Err("runner.stderr_capture_failed".to_owned());
    };
    let stdout_thread = thread::spawn(move || capture_stream(stdout));
    let stderr_thread = thread::spawn(move || capture_stream(stderr));
    let started = Instant::now();
    let mut peak_memory = None;
    let (forced_status, exit_code, error_code) = loop {
        peak_memory = maximum_option(peak_memory, sample_peak_memory(child.id()));
        if peak_memory.is_some_and(|bytes| bytes > memory_limit) {
            terminate_process_group(&mut child);
            wait_after_termination(&mut child);
            break (
                LiveCaseStatus::ExecutionFailure,
                None,
                Some("runner.memory_limit".to_owned()),
            );
        }
        if cancellation.load(Ordering::SeqCst) {
            terminate_process_group(&mut child);
            wait_after_termination(&mut child);
            break (
                LiveCaseStatus::Cancelled,
                None,
                Some("runner.cancelled".to_owned()),
            );
        }
        if started.elapsed() >= timeout {
            terminate_process_group(&mut child);
            wait_after_termination(&mut child);
            break (
                LiveCaseStatus::Timeout,
                None,
                Some("runner.timeout".to_owned()),
            );
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                let live_status = if status.success() {
                    LiveCaseStatus::Success
                } else {
                    LiveCaseStatus::Crash
                };
                let code = if status.success() {
                    None
                } else {
                    Some("runner.crash".to_owned())
                };
                break (live_status, status.code(), code);
            }
            Ok(None) => thread::sleep(POLL_INTERVAL),
            Err(_) => {
                terminate_process_group(&mut child);
                wait_after_termination(&mut child);
                break (
                    LiveCaseStatus::ExecutionFailure,
                    None,
                    Some("runner.wait_failed".to_owned()),
                );
            }
        }
    };
    let stdout = stdout_thread
        .join()
        .map_err(|_| "runner.stdout_capture_failed".to_owned())?
        .map_err(|_| "runner.stdout_capture_failed".to_owned())?;
    let stderr = stderr_thread
        .join()
        .map_err(|_| "runner.stderr_capture_failed".to_owned())?
        .map_err(|_| "runner.stderr_capture_failed".to_owned())?;
    Ok(ProcessOutcome {
        status: forced_status,
        exit_code,
        peak_memory_bytes: peak_memory,
        stdout: stdout.metadata,
        stderr: stderr.metadata,
        error_code,
    })
}

pub(crate) fn report_declares_completed_scan(report: &[u8]) -> bool {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(report) else {
        return false;
    };
    value
        .get("scan")
        .and_then(|scan| scan.get("complete"))
        .and_then(serde_json::Value::as_bool)
        == Some(true)
        && value
            .get("errors")
            .and_then(serde_json::Value::as_array)
            .is_some_and(Vec::is_empty)
}

fn wait_after_termination(child: &mut Child) {
    let _ = child.wait();
}

#[cfg(unix)]
fn configure_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    command.process_group(0);
}

#[cfg(not(unix))]
fn configure_process_group(_command: &mut Command) {}

#[cfg(unix)]
fn terminate_process_group(child: &mut Child) {
    use nix::sys::signal::{Signal, killpg};
    use nix::unistd::Pid;

    if let Ok(pid) = i32::try_from(child.id()) {
        let _ = killpg(Pid::from_raw(pid), Signal::SIGKILL);
    }
    let _ = child.kill();
}

#[cfg(not(unix))]
fn terminate_process_group(child: &mut Child) {
    let _ = child.kill();
}

struct CapturedStream {
    metadata: StreamCapture,
    prefix: Vec<u8>,
}

struct StreamReadFailure;

fn capture_stream<R: Read>(mut reader: R) -> Result<CapturedStream, StreamReadFailure> {
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut prefix = Vec::with_capacity(STREAM_PREFIX_BYTES);
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader.read(&mut buffer).map_err(|_| StreamReadFailure)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        total = total.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
        let remaining = STREAM_PREFIX_BYTES.saturating_sub(prefix.len());
        prefix.extend_from_slice(&buffer[..read.min(remaining)]);
    }
    Ok(CapturedStream {
        metadata: StreamCapture {
            fingerprint: hex_digest(&hasher.finalize()),
            bytes: total,
            truncated: total > u64::try_from(STREAM_PREFIX_BYTES).unwrap_or(u64::MAX),
        },
        prefix,
    })
}

struct VersionProbe {
    reported_version: String,
    status: VersionProbeStatus,
    stdout: StreamCapture,
    stderr: StreamCapture,
}

fn probe_version(binary: &Path, cancellation: &AtomicBool) -> VersionProbe {
    let temporary = Builder::new().prefix("secure-bench-version-").tempdir();
    let Ok(temporary) = temporary else {
        return failed_version_probe(VersionProbeStatus::ExecutionFailure);
    };
    let mut command = Command::new(binary);
    command
        .arg("--version")
        .current_dir(temporary.path())
        .env_clear()
        .env("LC_ALL", "C")
        .env("TZ", "UTC")
        .env("NO_COLOR", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure_process_group(&mut command);
    let Ok(mut child) = command.spawn() else {
        return failed_version_probe(VersionProbeStatus::ExecutionFailure);
    };
    let Some(stdout) = child.stdout.take() else {
        terminate_process_group(&mut child);
        wait_after_termination(&mut child);
        return failed_version_probe(VersionProbeStatus::ExecutionFailure);
    };
    let Some(stderr) = child.stderr.take() else {
        terminate_process_group(&mut child);
        wait_after_termination(&mut child);
        return failed_version_probe(VersionProbeStatus::ExecutionFailure);
    };
    let stdout_thread = thread::spawn(move || capture_stream(stdout));
    let stderr_thread = thread::spawn(move || capture_stream(stderr));
    let started = Instant::now();
    let (status, exit_success) = loop {
        if cancellation.load(Ordering::SeqCst) {
            terminate_process_group(&mut child);
            let _ = child.wait();
            break (VersionProbeStatus::ExecutionFailure, false);
        }
        if started.elapsed() >= VERSION_TIMEOUT {
            terminate_process_group(&mut child);
            let _ = child.wait();
            break (VersionProbeStatus::Timeout, false);
        }
        match child.try_wait() {
            Ok(Some(exit)) => {
                break (
                    if exit.success() {
                        VersionProbeStatus::Success
                    } else {
                        VersionProbeStatus::Failed
                    },
                    exit.success(),
                );
            }
            Ok(None) => thread::sleep(POLL_INTERVAL),
            Err(_) => {
                terminate_process_group(&mut child);
                let _ = child.wait();
                break (VersionProbeStatus::ExecutionFailure, false);
            }
        }
    };
    let Ok(Ok(stdout)) = stdout_thread.join() else {
        return failed_version_probe(VersionProbeStatus::ExecutionFailure);
    };
    let Ok(Ok(stderr)) = stderr_thread.join() else {
        return failed_version_probe(VersionProbeStatus::ExecutionFailure);
    };
    let reported_version = if exit_success {
        let stdout_version = sanitized_version(&stdout.prefix);
        if stdout_version == "unavailable" {
            sanitized_version(&stderr.prefix)
        } else {
            stdout_version
        }
    } else {
        "unavailable".to_owned()
    };
    VersionProbe {
        reported_version,
        status,
        stdout: stdout.metadata,
        stderr: stderr.metadata,
    }
}

fn failed_version_probe(status: VersionProbeStatus) -> VersionProbe {
    VersionProbe {
        reported_version: "unavailable".to_owned(),
        status,
        stdout: empty_capture(),
        stderr: empty_capture(),
    }
}

fn sanitized_version(prefix: &[u8]) -> String {
    let text = String::from_utf8_lossy(prefix);
    let line = text.lines().next().unwrap_or("unavailable").trim();
    if !line.is_empty()
        && line.len() <= 128
        && !line.contains(['/', '\\'])
        && line
            .chars()
            .all(|character| !character.is_control() || character == '\t')
    {
        line.to_owned()
    } else {
        "unavailable".to_owned()
    }
}

pub(crate) fn copy_fixture(
    source: &Path,
    destination: &Path,
    display: &str,
) -> Result<(), RunnerError> {
    let mut pending = vec![(source.to_path_buf(), destination.to_path_buf())];
    while let Some((source_directory, destination_directory)) = pending.pop() {
        let entries = fs::read_dir(&source_directory).map_err(|error| RunnerError::Io {
            path: display.to_owned(),
            detail: error.to_string(),
        })?;
        let mut ordered =
            entries
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| RunnerError::Io {
                    path: display.to_owned(),
                    detail: error.to_string(),
                })?;
        ordered.sort_by_key(fs::DirEntry::file_name);
        for entry in ordered {
            let source_path = entry.path();
            let destination_path = destination_directory.join(entry.file_name());
            let metadata = fs::symlink_metadata(&source_path).map_err(|error| RunnerError::Io {
                path: display.to_owned(),
                detail: error.to_string(),
            })?;
            if metadata.file_type().is_symlink() {
                return Err(RunnerError::InvalidRequest(format!(
                    "fixture `{display}` contains a symlink"
                )));
            }
            if metadata.is_dir() {
                fs::create_dir(&destination_path).map_err(|error| RunnerError::Io {
                    path: display.to_owned(),
                    detail: error.to_string(),
                })?;
                pending.push((source_path, destination_path));
            } else if metadata.is_file() {
                fs::copy(&source_path, &destination_path).map_err(|error| RunnerError::Io {
                    path: display.to_owned(),
                    detail: error.to_string(),
                })?;
            } else {
                return Err(RunnerError::InvalidRequest(format!(
                    "fixture `{display}` contains a non-regular entry"
                )));
            }
        }
    }
    Ok(())
}

pub(crate) fn fingerprint_file(path: &Path) -> Result<String, RunnerError> {
    let mut file = fs::File::open(path).map_err(|error| RunnerError::Io {
        path: path.display().to_string(),
        detail: error.to_string(),
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let read = file.read(&mut buffer).map_err(|error| RunnerError::Io {
            path: path.display().to_string(),
            detail: error.to_string(),
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex_digest(&hasher.finalize()))
}

pub(crate) fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), RunnerError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|error| RunnerError::Io {
        path: parent.display().to_string(),
        detail: error.to_string(),
    })?;
    let name = path
        .file_name()
        .ok_or_else(|| RunnerError::InvalidRequest("artifact path must name a file".to_owned()))?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        name.to_string_lossy(),
        std::process::id()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| RunnerError::Io {
                path: path.display().to_string(),
                detail: error.to_string(),
            })?;
        file.write_all(bytes).map_err(|error| RunnerError::Io {
            path: path.display().to_string(),
            detail: error.to_string(),
        })?;
        file.sync_all().map_err(|error| RunnerError::Io {
            path: path.display().to_string(),
            detail: error.to_string(),
        })?;
        fs::rename(&temporary, path).map_err(|error| RunnerError::Io {
            path: path.display().to_string(),
            detail: error.to_string(),
        })?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

pub(crate) fn stable_json<T: Serialize>(value: &T) -> Result<Vec<u8>, RunnerError> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| RunnerError::Serialization(error.to_string()))?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub(crate) fn aggregate_status(cases: &[LiveCaseRun]) -> LiveRunStatus {
    if cases
        .iter()
        .any(|case| case.status == LiveCaseStatus::Cancelled)
    {
        return LiveRunStatus::Cancelled;
    }
    let successful = cases.iter().filter(|case| case.status.is_success()).count();
    if successful == cases.len() {
        LiveRunStatus::Completed
    } else if successful == 0 {
        LiveRunStatus::Failed
    } else {
        LiveRunStatus::PartialFailure
    }
}

pub(crate) fn host_provenance() -> HostProvenance {
    HostProvenance {
        os: std::env::consts::OS.to_owned(),
        architecture: std::env::consts::ARCH.to_owned(),
        logical_cpus: std::thread::available_parallelism()
            .ok()
            .and_then(|count| u32::try_from(count.get()).ok()),
        memory_bytes: read_total_memory(),
        kernel_release: fs::read_to_string("/proc/sys/kernel/osrelease")
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty() && value.len() <= 128),
    }
}

fn read_total_memory() -> Option<u64> {
    let content = fs::read_to_string("/proc/meminfo").ok()?;
    let line = content.lines().find(|line| line.starts_with("MemTotal:"))?;
    let kib = line.split_whitespace().nth(1)?.parse::<u64>().ok()?;
    kib.checked_mul(1024)
}

fn sample_peak_memory(pid: u32) -> Option<u64> {
    let content = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let line = content.lines().find(|line| line.starts_with("VmHWM:"))?;
    let kib = line.split_whitespace().nth(1)?.parse::<u64>().ok()?;
    kib.checked_mul(1024)
}

fn maximum_option(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

pub(crate) fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, millis_u64)
}

pub(crate) fn millis_u64(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

pub(crate) fn empty_capture() -> StreamCapture {
    StreamCapture {
        fingerprint: fingerprint(&[]),
        bytes: 0,
        truncated: false,
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

/// Loads a live-run manifest from JSON bytes.
///
/// # Errors
///
/// Returns a sanitized shape error for malformed JSON.
pub fn load_live_run(bytes: &[u8]) -> Result<LiveRun, RunnerError> {
    serde_json::from_slice(bytes).map_err(|error| {
        RunnerError::InvalidRequest(format!(
            "live-run JSON syntax or shape error at line {}",
            error.line()
        ))
    })
}

/// Validates that a report path is bundle-relative and under `reports/`.
#[must_use]
pub fn valid_report_path(path: &str) -> bool {
    let path = Path::new(path);
    if path.is_absolute() {
        return false;
    }
    let mut components = path.components();
    matches!(components.next(), Some(Component::Normal(value)) if value == "reports")
        && components.all(|component| matches!(component, Component::Normal(_)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_arguments_are_portable_and_complete() {
        let template = DEFAULT_SECURE_ENGINE_ARGUMENTS
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        assert_eq!(
            render_arguments(&template),
            [
                "scan",
                ".",
                "--format",
                "secure-json-v1",
                "--output",
                "../.secure-bench-report.json"
            ]
        );
    }

    #[test]
    fn report_paths_cannot_escape_the_bundle() {
        assert!(valid_report_path("reports/case-001.json"));
        assert!(!valid_report_path("../case-001.json"));
        assert!(!valid_report_path("/tmp/case-001.json"));
    }

    #[test]
    fn windows_and_unix_absolute_arguments_are_detected() {
        assert!(is_windows_absolute("C:\\private\\configuration.json"));
        assert!(Path::new("/private/configuration.json").is_absolute());
        assert!(!is_windows_absolute("secure-json-v1"));
    }

    #[test]
    fn matcher_owned_data_is_rejected_from_configuration()
    -> Result<(), crate::pipeline::ContractError> {
        let suite =
            crate::pipeline::load_suite(include_bytes!("../../../fixtures/corpus-v1.toml"))?;
        assert!(validate_configuration(&suite, b"format = 'secure-json-v1'").is_ok());
        assert!(validate_configuration(&suite, b"category = 'command-execution'").is_err());
        Ok(())
    }
}
