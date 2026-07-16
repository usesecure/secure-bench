//! Deterministic, non-composite scoring with explicit denominators.

use crate::model::{
    BenchmarkSuite, CaseExecution, CaseKind, ExecutionStatus, FailureCounts, FindingDisposition,
    MatchOutcome, MatchingReport, MeasurementMaximum, MeasurementTotal, NormalizedFinding,
    PerformanceMetrics, RatioMetric, ScoreCard, ScoreCounts,
};
use std::collections::{BTreeMap, BTreeSet};

/// Computes quality, failure, and performance metrics without tool-specific branches.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn score(
    suite: &BenchmarkSuite,
    findings: &[NormalizedFinding],
    matching: &MatchingReport,
    executions: &[CaseExecution],
) -> ScoreCard {
    let execution_by_case: BTreeMap<&str, &CaseExecution> = executions
        .iter()
        .map(|execution| (execution.case_id.as_str(), execution))
        .collect();
    let mut counts = ScoreCounts::default();
    let mut failures = FailureCounts::default();
    let mut performance = PerformanceMetrics::default();

    for case in &suite.cases {
        let status = execution_by_case
            .get(case.case_id.as_str())
            .map_or(ExecutionStatus::Missing, |execution| execution.status);
        match case.kind {
            CaseKind::Vulnerable => {
                counts.vulnerable_cases += 1;
                counts.eligible_expectations +=
                    u64::try_from(case.expected_findings.len()).unwrap_or(u64::MAX);
                if status == ExecutionStatus::Success {
                    counts.attempted_vulnerable_cases += 1;
                    counts.attempted_expectations +=
                        u64::try_from(case.expected_findings.len()).unwrap_or(u64::MAX);
                }
            }
            CaseKind::SafeControl => {
                counts.safe_control_cases += 1;
                if status == ExecutionStatus::Success {
                    counts.attempted_safe_control_cases += 1;
                }
            }
        }
        count_failure(status, &mut failures);
        if let Some(execution) = execution_by_case.get(case.case_id.as_str()) {
            add_performance(execution, &mut performance);
        }
    }

    let mut evidence_correct = 0;
    let mut source_correct = 0;
    let mut sink_correct = 0;
    let mut severity_correct = 0;
    let mut confidence_correct = 0;
    let expected_by_id = suite
        .cases
        .iter()
        .flat_map(|case| &case.expected_findings)
        .map(|expected| (expected.expectation_id.as_str(), expected))
        .collect::<BTreeMap<_, _>>();
    let finding_by_id = findings
        .iter()
        .map(|finding| (finding.finding_id.as_str(), finding))
        .collect::<BTreeMap<_, _>>();
    for decision in &matching.expectations {
        match decision.outcome {
            MatchOutcome::Matched | MatchOutcome::Ambiguous => {
                counts.detected_expectations += 1;
                evidence_correct += u64::from(decision.criteria.evidence_path);
                source_correct += u64::from(decision.criteria.source);
                sink_correct += u64::from(decision.criteria.sink);
                if let (Some(expected), Some(finding)) = (
                    expected_by_id.get(decision.expectation_id.as_str()),
                    decision
                        .selected_finding_id
                        .as_deref()
                        .and_then(|id| finding_by_id.get(id)),
                ) {
                    severity_correct += u64::from(expected.severity == finding.severity);
                    confidence_correct += u64::from(expected.confidence == finding.confidence);
                }
                if decision.outcome == MatchOutcome::Ambiguous {
                    counts.ambiguous_expectations += 1;
                }
            }
            MatchOutcome::Missed => counts.missed_expectations += 1,
            MatchOutcome::NotAttempted | MatchOutcome::Unsupported => {}
        }
    }

    let successful_cases = suite
        .cases
        .iter()
        .filter(|case| {
            execution_by_case
                .get(case.case_id.as_str())
                .is_some_and(|execution| execution.status == ExecutionStatus::Success)
        })
        .map(|case| case.case_id.as_str())
        .collect::<BTreeSet<_>>();
    counts.normalized_findings = matching
        .findings
        .iter()
        .filter(|decision| successful_cases.contains(decision.case_id.as_str()))
        .count()
        .try_into()
        .unwrap_or(u64::MAX);
    counts.duplicate_findings = matching
        .findings
        .iter()
        .filter(|decision| decision.disposition == FindingDisposition::Duplicate)
        .count()
        .try_into()
        .unwrap_or(u64::MAX);
    counts.unmatched_findings = matching
        .findings
        .iter()
        .filter(|decision| {
            matches!(
                decision.disposition,
                FindingDisposition::SafeControlFalsePositive | FindingDisposition::Unmatched
            )
        })
        .count()
        .try_into()
        .unwrap_or(u64::MAX);

    for case in suite
        .cases
        .iter()
        .filter(|case| case.kind == CaseKind::SafeControl)
    {
        let successful = execution_by_case
            .get(case.case_id.as_str())
            .is_some_and(|execution| execution.status == ExecutionStatus::Success);
        if !successful {
            continue;
        }
        let has_false_positive = matching.findings.iter().any(|decision| {
            decision.case_id == case.case_id
                && matches!(
                    decision.disposition,
                    FindingDisposition::SafeControlFalsePositive
                        | FindingDisposition::Duplicate
                        | FindingDisposition::AmbiguousCandidate
                )
        });
        if has_false_positive {
            counts.false_positive_safe_controls += 1;
        } else {
            counts.clean_safe_controls += 1;
        }
    }

    ScoreCard {
        vulnerable_recall: ratio(counts.detected_expectations, counts.eligible_expectations),
        attempted_vulnerable_recall: ratio(
            counts.detected_expectations,
            counts.attempted_expectations,
        ),
        safe_control_false_positive_rate: ratio(
            counts.false_positive_safe_controls,
            counts.attempted_safe_control_cases,
        ),
        safe_control_clean_coverage: ratio(counts.clean_safe_controls, counts.safe_control_cases),
        evidence_path_accuracy: ratio(evidence_correct, counts.detected_expectations),
        source_localization_accuracy: ratio(source_correct, counts.detected_expectations),
        sink_localization_accuracy: ratio(sink_correct, counts.detected_expectations),
        severity_calibration_accuracy: ratio(severity_correct, counts.detected_expectations),
        confidence_calibration_accuracy: ratio(confidence_correct, counts.detected_expectations),
        duplicate_rate: ratio(counts.duplicate_findings, counts.normalized_findings),
        counts,
        failures,
        performance,
    }
}

fn ratio(numerator: u64, denominator: u64) -> RatioMetric {
    RatioMetric {
        numerator,
        denominator,
        basis_points: if denominator == 0 {
            None
        } else {
            let scaled = u128::from(numerator) * 10_000 / u128::from(denominator);
            Some(u32::try_from(scaled).unwrap_or(u32::MAX))
        },
    }
}

fn count_failure(status: ExecutionStatus, failures: &mut FailureCounts) {
    match status {
        ExecutionStatus::Success => {}
        ExecutionStatus::Crash => failures.crashes += 1,
        ExecutionStatus::Timeout => failures.timeouts += 1,
        ExecutionStatus::Unsupported => failures.unsupported += 1,
        ExecutionStatus::Missing => failures.missing += 1,
        ExecutionStatus::ParseFailure => failures.parse_failures += 1,
    }
}

fn add_performance(execution: &CaseExecution, performance: &mut PerformanceMetrics) {
    add_total(execution.cold_duration_ms, &mut performance.cold_duration);
    add_total(execution.warm_duration_ms, &mut performance.warm_duration);
    add_maximum(execution.peak_memory_bytes, &mut performance.peak_memory);
    add_total(execution.output_bytes, &mut performance.output_size);
}

fn add_total(value: Option<u64>, measurement: &mut MeasurementTotal) {
    if let Some(value) = value {
        measurement.total = measurement.total.saturating_add(value);
        measurement.samples += 1;
    }
}

fn add_maximum(value: Option<u64>, measurement: &mut MeasurementMaximum) {
    if let Some(value) = value {
        measurement.maximum = Some(
            measurement
                .maximum
                .map_or(value, |current| current.max(value)),
        );
        measurement.samples += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_denominator_has_no_rate() {
        assert_eq!(
            ratio(0, 0),
            RatioMetric {
                numerator: 0,
                denominator: 0,
                basis_points: None,
            }
        );
    }
}
