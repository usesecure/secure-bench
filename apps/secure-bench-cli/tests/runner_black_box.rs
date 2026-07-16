//! Black-box runner failure, isolation, cancellation, and portability tests.

use secure_bench_core::runner::{
    DEFAULT_SECURE_ENGINE_ARGUMENTS, LiveCaseStatus, RunnerRequest, run_secure_engine,
};
use secure_bench_core::{BenchmarkSuite, load_suite};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;
use tempfile::TempDir;

const SUITE: &[u8] = include_bytes!("../../../fixtures/corpus-v1.toml");

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn suite() -> Result<BenchmarkSuite, secure_bench_core::ContractError> {
    load_suite(SUITE)
}

fn copied_mock_binary(temporary: &TempDir, name: &str) -> io::Result<PathBuf> {
    let directory = temporary.path().join("binary path with space Δ");
    fs::create_dir_all(&directory)?;
    let target = directory.join(name);
    fs::copy(env!("CARGO_BIN_EXE_secure-bench-mock-tool"), &target)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755))?;
    }
    Ok(target)
}

fn arguments(mode: &str) -> Vec<String> {
    DEFAULT_SECURE_ENGINE_ARGUMENTS
        .iter()
        .map(ToString::to_string)
        .chain([
            "--mock-mode".to_owned(),
            mode.to_owned(),
            "--configuration".to_owned(),
            "{configuration}".to_owned(),
        ])
        .collect()
}

fn execute(
    suite: &BenchmarkSuite,
    temporary: &TempDir,
    binary: &Path,
    name: &str,
    mode: &str,
    cancellation: Arc<AtomicBool>,
) -> Result<secure_bench_core::runner::LiveRun, secure_bench_core::runner::RunnerError> {
    let output = temporary.path().join(name);
    let run_id = name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_') {
                character
            } else {
                '-'
            }
        })
        .collect::<String>();
    run_secure_engine(&RunnerRequest {
        suite,
        repository_root: &repository_root(),
        binary,
        output: &output,
        run_id: &run_id,
        argument_template: &arguments(mode),
        configuration: b"TEST_ONLY_SECRET_VALUE",
        cancellation,
    })
}

#[test]
fn direct_runner_handles_spaces_unicode_and_portable_arguments()
-> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let binary = copied_mock_binary(&temporary, "mock executable")?;
    let suite = suite()?;
    let run = execute(
        &suite,
        &temporary,
        &binary,
        "run path with space Ω",
        "empty",
        Arc::new(AtomicBool::new(false)),
    )?;

    assert!(
        run.cases
            .iter()
            .all(|case| case.status == LiveCaseStatus::Success)
    );
    assert!(run.cases.iter().all(|case| {
        case.arguments.contains(&".".to_owned())
            && case
                .arguments
                .contains(&"../.secure-bench-report.json".to_owned())
            && !case.arguments.iter().any(String::is_empty)
    }));
    let manifest = serde_json::to_string(&run)?;
    assert!(!manifest.contains("TEST_ONLY_SECRET_VALUE"));
    assert!(!manifest.contains(temporary.path().to_string_lossy().as_ref()));
    assert_eq!(
        run.corpus_fingerprint,
        suite.corpus_fingerprint.as_deref().unwrap_or_default()
    );

    let findings_exit = execute(
        &suite,
        &temporary,
        &binary,
        "findings-exit",
        "finding-exit",
        Arc::new(AtomicBool::new(false)),
    )?;
    assert!(findings_exit.cases.iter().all(|case| {
        case.status == LiveCaseStatus::Findings && case.process_exit_code == Some(1)
    }));
    Ok(())
}

#[test]
fn runner_accounts_for_each_output_and_process_failure() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let binary = copied_mock_binary(&temporary, "mock-tool")?;
    let base_suite = suite()?;
    let scenarios = [
        ("crash", LiveCaseStatus::Crash),
        ("missing", LiveCaseStatus::InvalidOutput),
        ("malformed", LiveCaseStatus::InvalidOutput),
        ("oversized", LiveCaseStatus::InvalidOutput),
        ("unsupported", LiveCaseStatus::UnsupportedSchema),
    ];
    for (mode, expected) in scenarios {
        let run = execute(
            &base_suite,
            &temporary,
            &binary,
            &format!("failure-{mode}"),
            mode,
            Arc::new(AtomicBool::new(false)),
        )?;
        assert!(run.cases.iter().all(|case| case.status == expected));
        assert!(run.cases.iter().all(|case| case.error_code.is_some()));
    }

    let mut timeout_suite = base_suite.clone();
    for case in &mut timeout_suite.cases {
        case.resource_budget.timeout_ms = 25;
    }
    let timeout = execute(
        &timeout_suite,
        &temporary,
        &binary,
        "failure-timeout",
        "timeout",
        Arc::new(AtomicBool::new(false)),
    )?;
    assert!(
        timeout
            .cases
            .iter()
            .all(|case| case.status == LiveCaseStatus::Timeout)
    );

    let mut memory_suite = base_suite.clone();
    for case in &mut memory_suite.cases {
        case.resource_budget.memory_bytes = 1;
    }
    let memory_limited = execute(
        &memory_suite,
        &temporary,
        &binary,
        "failure-memory",
        "timeout",
        Arc::new(AtomicBool::new(false)),
    )?;
    assert!(memory_limited.cases.iter().all(|case| {
        case.status == LiveCaseStatus::ExecutionFailure
            && case.error_code.as_deref() == Some("runner.memory_limit")
    }));

    let streams = execute(
        &base_suite,
        &temporary,
        &binary,
        "bounded-streams",
        "streams",
        Arc::new(AtomicBool::new(false)),
    )?;
    assert!(streams.cases.iter().all(|case| {
        case.status == LiveCaseStatus::Success
            && case.stdout.bytes > 4_096
            && case.stdout.truncated
            && case.stderr.bytes > 4_096
            && case.stderr.truncated
    }));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let non_executable = copied_mock_binary(&temporary, "non-executable")?;
        fs::set_permissions(&non_executable, fs::Permissions::from_mode(0o644))?;
        let failed = execute(
            &base_suite,
            &temporary,
            &non_executable,
            "failure-execution",
            "empty",
            Arc::new(AtomicBool::new(false)),
        )?;
        assert!(
            failed
                .cases
                .iter()
                .all(|case| case.status == LiveCaseStatus::ExecutionFailure)
        );
    }
    Ok(())
}

#[test]
fn cancellation_stops_a_process_group_and_accounts_for_remaining_cases()
-> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let binary = copied_mock_binary(&temporary, "mock-tool")?;
    let mut suite = suite()?;
    for case in &mut suite.cases {
        case.resource_budget.timeout_ms = 5_000;
    }
    let cancellation = Arc::new(AtomicBool::new(false));
    let trigger = Arc::clone(&cancellation);
    let cancellation_thread = thread::spawn(move || {
        thread::sleep(Duration::from_secs(1));
        trigger.store(true, Ordering::SeqCst);
    });
    let run = execute(
        &suite,
        &temporary,
        &binary,
        "cancelled-run",
        "timeout",
        cancellation,
    )?;
    cancellation_thread
        .join()
        .map_err(|_| io::Error::other("cancellation thread did not finish"))?;
    assert!(
        run.cases
            .iter()
            .all(|case| case.status == LiveCaseStatus::Cancelled)
    );
    assert!(run.cases.iter().any(|case| case.duration_ms > 0));
    Ok(())
}

#[test]
fn existing_output_bundle_is_never_replaced() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let binary = copied_mock_binary(&temporary, "mock-tool")?;
    let suite = suite()?;
    let output = temporary.path().join("existing-output");
    fs::create_dir(&output)?;
    let marker = output.join("owned-by-caller");
    fs::write(&marker, b"preserve")?;
    let result = run_secure_engine(&RunnerRequest {
        suite: &suite,
        repository_root: &repository_root(),
        binary: &binary,
        output: &output,
        run_id: "no-overwrite",
        argument_template: &arguments("empty"),
        configuration: b"TEST_ONLY_SECRET_VALUE",
        cancellation: Arc::new(AtomicBool::new(false)),
    });
    assert!(result.is_err());
    assert_eq!(fs::read(marker)?, b"preserve");
    Ok(())
}

#[test]
fn cli_clears_parent_secrets_before_starting_the_tool() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let binary = copied_mock_binary(&temporary, "mock-tool")?;
    let output_directory = temporary.path().join("environment-run");
    let root = repository_root();
    let suite_path = root.join("fixtures/corpus-v1.toml");
    let output = Command::new(env!("CARGO_BIN_EXE_secure-bench"))
        .current_dir(&root)
        .env("SECURE_BENCH_PARENT_SECRET", "DO_NOT_INHERIT_THIS_VALUE")
        .arg("run")
        .arg(&suite_path)
        .args(["--tool", "secure-engine", "--binary"])
        .arg(&binary)
        .arg("--output")
        .arg(&output_directory)
        .args([
            "--run-id",
            "environment-isolation",
            "--argument",
            "scan",
            "--argument",
            "{fixture}",
            "--argument",
            "--format",
            "--argument",
            "secure-json-v1",
            "--argument",
            "--output",
            "--argument",
            "{report}",
            "--argument",
            "--mock-mode",
            "--argument",
            "environment",
        ])
        .output()?;
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    let manifest = fs::read(output_directory.join("run.json"))?;
    assert!(
        !manifest
            .windows(b"DO_NOT_INHERIT_THIS_VALUE".len())
            .any(|window| window == b"DO_NOT_INHERIT_THIS_VALUE")
    );
    Ok(())
}
