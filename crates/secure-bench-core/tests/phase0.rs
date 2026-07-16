//! End-to-end regression coverage for the committed Phase 0 mock corpus.

use secure_bench_core::model::{FindingDisposition, MatchOutcome};
use secure_bench_core::{
    BenchmarkResult, EvaluationInput, ExecutionStatus, RecordedRun, evaluate, load_run_manifest,
};
use std::fs;
use std::path::{Path, PathBuf};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn repository_root() -> TestResult<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or("core crate must remain inside the workspace")?;
    Ok(root.to_path_buf())
}

fn evaluate_run(name: &str) -> TestResult<BenchmarkResult> {
    let root = repository_root()?;
    let suite = fs::read(root.join("fixtures/suite.toml"))?;
    let run_path = root.join("fixtures/reports/runs").join(name);
    let run = fs::read(&run_path)?;
    let recorded: RecordedRun = load_run_manifest(&run)?;
    let run_parent = run_path.parent().ok_or("run fixture must have a parent")?;
    let report = fs::read(run_parent.join(recorded.report_path))?;
    Ok(evaluate(EvaluationInput {
        suite: &suite,
        run_manifest: &run,
        report: &report,
    })?)
}

#[test]
fn equivalent_native_and_sarif_reports_score_equally() -> TestResult {
    let native = evaluate_run("native-success.json")?;
    let sarif = evaluate_run("sarif-success.json")?;

    assert_eq!(native.score, sarif.score);
    assert_eq!(native.matching, sarif.matching);
    assert_eq!(native.normalized_findings.len(), 1);
    assert_eq!(sarif.normalized_findings.len(), 1);

    let native_finding = &native.normalized_findings[0];
    let sarif_finding = &sarif.normalized_findings[0];
    assert_eq!(native_finding.finding_id, sarif_finding.finding_id);
    assert_eq!(native_finding.category, sarif_finding.category);
    assert_eq!(native_finding.invariant, sarif_finding.invariant);
    assert_eq!(native_finding.source, sarif_finding.source);
    assert_eq!(native_finding.sink, sarif_finding.sink);
    assert_eq!(native_finding.evidence_path, sarif_finding.evidence_path);
    Ok(())
}

#[test]
fn repeated_evaluation_is_byte_stable() -> TestResult {
    let first = evaluate_run("native-success.json")?;
    let second = evaluate_run("native-success.json")?;
    let first_bytes = serde_json::to_vec_pretty(&first)?;
    let second_bytes = serde_json::to_vec_pretty(&second)?;
    assert_eq!(first_bytes, second_bytes);
    Ok(())
}

#[test]
fn safe_control_false_positive_remains_visible() -> TestResult {
    let result = evaluate_run("safe-false-positive.json")?;
    assert_eq!(result.score.safe_control_false_positive_rate.numerator, 1);
    assert_eq!(result.score.safe_control_false_positive_rate.denominator, 1);
    assert_eq!(result.score.safe_control_clean_coverage.numerator, 0);
    assert!(
        result.matching.findings.iter().any(|decision| {
            decision.disposition == FindingDisposition::SafeControlFalsePositive
        })
    );
    Ok(())
}

#[test]
fn duplicates_do_not_increase_detection_credit() -> TestResult {
    let result = evaluate_run("duplicates.json")?;
    assert_eq!(result.score.vulnerable_recall.numerator, 1);
    assert_eq!(result.score.vulnerable_recall.denominator, 1);
    assert_eq!(result.score.counts.duplicate_findings, 1);
    assert_eq!(result.score.duplicate_rate.numerator, 1);
    assert_eq!(result.score.duplicate_rate.denominator, 2);
    Ok(())
}

#[test]
fn multiple_distinct_valid_candidates_are_reported_as_ambiguous() -> TestResult {
    let result = evaluate_run("ambiguous.json")?;
    assert_eq!(result.score.vulnerable_recall.numerator, 1);
    assert_eq!(result.score.counts.ambiguous_expectations, 1);
    assert_eq!(
        result.matching.expectations[0].outcome,
        MatchOutcome::Ambiguous
    );
    assert_eq!(
        result.matching.expectations[0].ambiguous_finding_ids.len(),
        1
    );
    assert!(
        result
            .matching
            .findings
            .iter()
            .any(|decision| { decision.disposition == FindingDisposition::AmbiguousCandidate })
    );
    Ok(())
}

#[test]
fn category_and_location_without_required_evidence_receive_no_credit() -> TestResult {
    let result = evaluate_run("wrong-evidence.json")?;
    assert_eq!(result.score.vulnerable_recall.numerator, 0);
    assert_eq!(result.score.counts.missed_expectations, 1);
    assert_eq!(
        result.matching.expectations[0].outcome,
        MatchOutcome::Missed
    );
    assert!(!result.matching.expectations[0].criteria.evidence_path);
    Ok(())
}

#[test]
fn malformed_and_privacy_unsafe_reports_are_parse_failures() -> TestResult {
    for run in ["malformed.json", "unsafe-path.json"] {
        let result = evaluate_run(run)?;
        assert_eq!(result.score.failures.parse_failures, 2, "run: {run}");
        assert_eq!(result.score.counts.normalized_findings, 0, "run: {run}");
        assert_eq!(result.score.safe_control_clean_coverage.numerator, 0);
        assert_eq!(result.score.safe_control_false_positive_rate.denominator, 0);
        assert_eq!(result.errors.len(), 1);
    }
    Ok(())
}

#[test]
fn unsupported_formats_and_versions_are_not_clean_runs() -> TestResult {
    for run in ["unsupported-format.json", "unsupported-version.json"] {
        let result = evaluate_run(run)?;
        assert_eq!(result.score.failures.unsupported, 2, "run: {run}");
        assert_eq!(result.score.vulnerable_recall.numerator, 0);
        assert_eq!(result.score.safe_control_clean_coverage.numerator, 0);
        assert_eq!(result.score.safe_control_false_positive_rate.denominator, 0);
    }
    Ok(())
}

#[test]
fn operational_failures_have_distinct_accounting() -> TestResult {
    let crash = evaluate_run("crash.json")?;
    assert_eq!(crash.score.failures.crashes, 1);
    assert_eq!(crash.score.attempted_vulnerable_recall.denominator, 0);
    assert_eq!(crash.score.vulnerable_recall.denominator, 1);

    let timeout = evaluate_run("timeout.json")?;
    assert_eq!(timeout.score.failures.timeouts, 1);
    assert_eq!(timeout.score.attempted_vulnerable_recall.denominator, 0);

    let missing = evaluate_run("missing.json")?;
    assert_eq!(missing.score.failures.missing, 1);
    assert_eq!(missing.score.attempted_vulnerable_recall.denominator, 0);

    let unsupported = evaluate_run("unsupported-case.json")?;
    assert_eq!(unsupported.score.failures.unsupported, 1);
    assert_eq!(
        unsupported.matching.expectations[0].outcome,
        MatchOutcome::Unsupported
    );
    Ok(())
}

#[test]
fn exported_results_keep_paths_relative_and_do_not_embed_source_or_messages() -> TestResult {
    let result = evaluate_run("native-success.json")?;
    let json = serde_json::to_string(&result)?;
    assert!(!json.contains("/home/"));
    assert!(!json.contains("Bun.spawn"));
    assert!(!json.contains("Mock evidence used only"));
    assert!(
        result
            .normalized_findings
            .iter()
            .flat_map(|finding| [&finding.source.path, &finding.sink.path])
            .all(|path| !Path::new(path).is_absolute())
    );
    Ok(())
}

#[test]
fn result_provenance_links_all_aggregate_inputs() -> TestResult {
    let result = evaluate_run("native-success.json")?;
    assert_eq!(result.provenance.suite_fingerprint.len(), 64);
    assert_eq!(result.provenance.run_manifest_fingerprint.len(), 64);
    assert_eq!(result.provenance.report_fingerprint.len(), 64);
    assert_eq!(
        result.provenance.schemas.get("suite").map(String::as_str),
        Some("secure-bench-suite-v1")
    );
    assert_eq!(
        result.provenance.schemas.get("result").map(String::as_str),
        Some("secure-bench-result-v1")
    );
    Ok(())
}

#[test]
fn recorded_commands_are_provenance_only() -> TestResult {
    let result = evaluate_run("native-success.json")?;
    assert_eq!(
        result.provenance.tool.command,
        ["mock-native", "--format", "secure-json-v1"]
    );
    assert_eq!(result.score.failures.crashes, 0);
    Ok(())
}

#[test]
fn parse_failure_status_is_distinct_from_declared_execution_statuses() -> TestResult {
    let result = evaluate_run("malformed.json")?;
    assert!(
        result
            .matching
            .expectations
            .iter()
            .all(|decision| { decision.outcome == MatchOutcome::NotAttempted })
    );
    assert_eq!(result.score.failures.parse_failures, 2);
    assert!(!result.errors.is_empty());
    let parsed_status = ExecutionStatus::ParseFailure;
    assert_ne!(parsed_status, ExecutionStatus::Success);
    Ok(())
}
