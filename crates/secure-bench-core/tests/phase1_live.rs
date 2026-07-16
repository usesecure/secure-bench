//! Phase 1 live bundle evaluation, matching, determinism, and failure tests.

use secure_bench_core::adapter::{Adapter, AdapterInput, SecureJsonAdapter, fingerprint};
use secure_bench_core::runner::{
    LIVE_RUN_SCHEMA_V1, LiveCaseRun, LiveCaseStatus, LiveRun, LiveRunStatus, LiveToolProvenance,
    StreamCapture, VersionProbeStatus,
};
use secure_bench_core::{
    HostProvenance, LiveEvaluationInput, RESULT_SCHEMA_V2, evaluate_live_run, load_suite,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

const SUITE: &[u8] = include_bytes!("../../../fixtures/corpus-v1.toml");
type Reports = BTreeMap<String, Vec<u8>>;
type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

fn empty_capture() -> StreamCapture {
    StreamCapture {
        fingerprint: fingerprint(&[]),
        bytes: 0,
        truncated: false,
    }
}

fn finding(
    rule_id: &str,
    category: &str,
    invariant: &str,
    path: &str,
    source_line: u32,
    sink_line: u32,
) -> Value {
    json!({
        "rule_id": rule_id,
        "category": category,
        "invariant": invariant,
        "severity": "high",
        "confidence": "high",
        "source": {"path": path, "line": source_line, "column": 1},
        "sink": {"path": path, "line": sink_line, "column": 1},
        "evidence_path": [
            {"kind": "source", "location": {"path": path, "line": source_line, "column": 1}},
            {"kind": "sink", "location": {"path": path, "line": sink_line, "column": 1}}
        ],
        "message": "DO_NOT_EXPORT_/home/test/SECRET_VALUE"
    })
}

fn report(findings: &[Value]) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec_pretty(&json!({
        "schema_version": "secure-json-v1",
        "findings": findings,
    }))
}

fn live_bundle() -> TestResult<(LiveRun, Reports)> {
    let suite = load_suite(SUITE)?;
    let mut reports = BTreeMap::new();
    let mut cases = Vec::new();
    for case in &suite.cases {
        let findings = match case.case_id.as_str() {
            "phase1-001" => vec![
                finding(
                    "mock.alpha",
                    "command-execution",
                    "untrusted values must not reach command execution through a shell",
                    "src/entry.js",
                    4,
                    5,
                ),
                finding(
                    "mock.beta",
                    "command-execution",
                    "untrusted values must not reach command execution through a shell",
                    "src/entry.js",
                    4,
                    5,
                ),
            ],
            "phase1-002" => vec![finding(
                "mock.control",
                "unmatched-observation",
                "an observation that has no matcher expectation",
                "src/entry.ts",
                1,
                1,
            )],
            _ => Vec::new(),
        };
        let has_findings = !findings.is_empty();
        let bytes = report(&findings)?;
        let report_path = format!("reports/{}.json", case.case_id);
        cases.push(LiveCaseRun {
            case_id: case.case_id.clone(),
            fixture_fingerprint: case.content_fingerprint.clone().unwrap_or_default(),
            status: if has_findings {
                LiveCaseStatus::Findings
            } else {
                LiveCaseStatus::Success
            },
            arguments: vec![
                "scan".to_owned(),
                ".".to_owned(),
                "--output".to_owned(),
                "../.secure-bench-report.json".to_owned(),
            ],
            report_path: Some(report_path.clone()),
            report_fingerprint: Some(fingerprint(&bytes)),
            started_unix_ms: 1,
            finished_unix_ms: 2,
            duration_ms: 1,
            process_exit_code: Some(0),
            peak_memory_bytes: Some(1_024),
            output_bytes: Some(u64::try_from(bytes.len())?),
            stdout: empty_capture(),
            stderr: empty_capture(),
            error_code: None,
        });
        reports.insert(report_path, bytes);
    }
    Ok((
        LiveRun {
            schema_version: LIVE_RUN_SCHEMA_V1.to_owned(),
            run_id: "phase1-recorded-live-test".to_owned(),
            suite_id: suite.suite_id,
            corpus_fingerprint: suite.corpus_fingerprint.unwrap_or_default(),
            tool: LiveToolProvenance {
                name: "Secure Engine".to_owned(),
                reported_version: "recorded-test-version".to_owned(),
                binary_fingerprint: fingerprint(b"test binary"),
                report_schema: "secure-json-v1".to_owned(),
                argument_template: vec![
                    "scan".to_owned(),
                    "{fixture}".to_owned(),
                    "--output".to_owned(),
                    "{report}".to_owned(),
                ],
                configuration_fingerprint: fingerprint(&[]),
                version_probe_status: VersionProbeStatus::Success,
                version_stdout: empty_capture(),
                version_stderr: empty_capture(),
            },
            host: HostProvenance {
                os: "test".to_owned(),
                architecture: "test".to_owned(),
                logical_cpus: Some(1),
                memory_bytes: Some(1_024),
                kernel_release: None,
            },
            started_unix_ms: 1,
            finished_unix_ms: 2,
            status: LiveRunStatus::Completed,
            cases,
        },
        reports,
    ))
}

#[test]
fn live_evaluation_is_exact_deterministic_and_keeps_controls_separate() -> TestResult<()> {
    let (run, reports) = live_bundle()?;
    let run_manifest = serde_json::to_vec_pretty(&run)?;
    let input = LiveEvaluationInput {
        suite: SUITE,
        run_manifest: &run_manifest,
        reports: &reports,
    };
    let first = evaluate_live_run(&input)?;
    let second = evaluate_live_run(&input)?;

    assert_eq!(
        serde_json::to_vec_pretty(&first)?,
        serde_json::to_vec_pretty(&second)?
    );
    assert_eq!(first.schema_version, RESULT_SCHEMA_V2);
    assert_eq!(first.score.counts.vulnerable_cases, 7);
    assert_eq!(first.score.counts.safe_control_cases, 7);
    assert_eq!(first.score.counts.detected_expectations, 1);
    assert_eq!(first.score.counts.false_positive_safe_controls, 1);
    assert_eq!(first.score.counts.duplicate_findings, 1);
    assert_eq!(first.score.vulnerable_recall.numerator, 1);
    assert_eq!(first.score.vulnerable_recall.denominator, 7);
    assert_eq!(first.score.safe_control_clean_coverage.numerator, 6);
    assert_eq!(first.score.safe_control_clean_coverage.denominator, 7);
    assert_eq!(first.score.evidence_path_accuracy.numerator, 1);
    assert_eq!(first.score.source_localization_accuracy.numerator, 1);
    assert_eq!(first.score.sink_localization_accuracy.numerator, 1);
    let exported = serde_json::to_string(&first)?;
    assert!(!exported.contains("/home/test"));
    assert!(!exported.contains("SECRET_VALUE"));
    Ok(())
}

#[test]
fn live_failures_never_become_clean_scans() -> TestResult<()> {
    let (mut run, mut reports) = live_bundle()?;
    let statuses = [
        LiveCaseStatus::Crash,
        LiveCaseStatus::Timeout,
        LiveCaseStatus::InvalidOutput,
        LiveCaseStatus::UnsupportedSchema,
        LiveCaseStatus::ExecutionFailure,
        LiveCaseStatus::Cancelled,
    ];
    for (case, status) in run.cases.iter_mut().zip(statuses) {
        if let Some(path) = case.report_path.take() {
            reports.remove(&path);
        }
        case.report_fingerprint = None;
        case.status = status;
        case.error_code = Some("runner.test_failure".to_owned());
    }
    run.status = LiveRunStatus::Cancelled;
    let manifest = serde_json::to_vec_pretty(&run)?;
    let result = evaluate_live_run(&LiveEvaluationInput {
        suite: SUITE,
        run_manifest: &manifest,
        reports: &reports,
    })?;

    assert_eq!(result.score.failures.crashes, 1);
    assert_eq!(result.score.failures.timeouts, 1);
    assert_eq!(result.score.failures.invalid_outputs, 1);
    assert_eq!(result.score.failures.unsupported, 1);
    assert_eq!(result.score.failures.execution_failures, 1);
    assert_eq!(result.score.failures.cancellations, 1);
    assert_eq!(result.score.safe_control_clean_coverage.denominator, 7);
    assert!(result.score.safe_control_clean_coverage.numerator < 7);
    Ok(())
}

#[test]
fn recorded_and_live_adapter_entry_points_are_equivalent() -> TestResult<()> {
    let mut recorded_observation = finding(
        "mock.equivalent",
        "command-execution",
        "untrusted values must not reach command execution through a shell",
        "fixtures/corpus/case-001/src/entry.js",
        4,
        5,
    );
    recorded_observation["case_id"] = Value::String("phase1-001".to_owned());
    let recorded_bytes = report(&[recorded_observation])?;
    let live_bytes = report(&[finding(
        "mock.equivalent",
        "command-execution",
        "untrusted values must not reach command execution through a shell",
        "src/entry.js",
        4,
        5,
    )])?;
    let shared_provenance_fingerprint = fingerprint(b"equivalent adapter input");
    let recorded = SecureJsonAdapter.normalize(&recorded_bytes, &shared_provenance_fingerprint)?;
    let live = SecureJsonAdapter.normalize_scoped(AdapterInput {
        report: &live_bytes,
        report_fingerprint: &shared_provenance_fingerprint,
        case_id: Some("phase1-001"),
        path_prefix: Some("fixtures/corpus/case-001"),
    })?;
    assert_eq!(recorded, live);
    Ok(())
}
