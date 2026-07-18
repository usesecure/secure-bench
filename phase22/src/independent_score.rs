//! Independently implemented Phase 22 scoring used only by the scanner-free verifier.
//!
//! This module intentionally does not call the canonical scorer. Keeping the two
//! implementations separate makes scoring drift detectable from sealed evidence.

use crate::Phase22Error;
use crate::model::{
    AttemptState, CaseDecision, CaseSpec, Comparison, Disagreement, HistoricalRow, LaneResult,
    Metrics, Observation, Operations, PairDecision, Ratio, Results,
};
use std::collections::{BTreeMap, BTreeSet};

fn gcd(mut left: u64, mut right: u64) -> u64 {
    while right != 0 {
        (left, right) = (right, left % right);
    }
    left.max(1)
}

fn ratio(numerator: u64, denominator: u64) -> Option<Ratio> {
    if denominator == 0 {
        return None;
    }
    let divisor = gcd(numerator, denominator);
    Some(Ratio {
        numerator: numerator / divisor,
        denominator: denominator / divisor,
        decimal: format!("{:.6}", numerator as f64 / denominator as f64),
    })
}

fn metrics(decisions: &[CaseDecision]) -> Metrics {
    let counts = decisions.iter().fold([0_u64; 4], |mut values, decision| {
        match decision.outcome.as_str() {
            "tp" => values[0] += 1,
            "fp" => values[1] += 1,
            "tn" => values[2] += 1,
            "fn" => values[3] += 1,
            _ => {}
        }
        values
    });
    let [tp, fp, tn, fn_count] = counts;
    Metrics {
        tp,
        fp,
        tn,
        fn_count,
        precision: ratio(tp, tp + fp),
        recall: ratio(tp, tp + fn_count),
        specificity: ratio(tn, tn + fp),
        f1: ratio(2 * tp, 2 * tp + fp + fn_count),
        balanced_accuracy: if tp + fn_count == 0 || tn + fp == 0 {
            None
        } else {
            ratio(
                tp * (tn + fp) + tn * (tp + fn_count),
                2 * (tp + fn_count) * (tn + fp),
            )
        },
    }
}

fn grouped<F>(decisions: &[CaseDecision], key: F) -> BTreeMap<String, Metrics>
where
    F: Fn(&CaseDecision) -> &str,
{
    let mut members = BTreeMap::<String, Vec<CaseDecision>>::new();
    for decision in decisions {
        members
            .entry(key(decision).to_owned())
            .or_default()
            .push(decision.clone());
    }
    members
        .into_iter()
        .map(|(name, decisions)| (name, metrics(&decisions)))
        .collect()
}

fn percentile(values: &[u64], percent: usize) -> Option<u64> {
    if values.is_empty() {
        return None;
    }
    let index = values
        .len()
        .saturating_mul(percent)
        .div_ceil(100)
        .saturating_sub(1)
        .min(values.len() - 1);
    values.get(index).copied()
}

fn operations(observations: &[&Observation]) -> Operations {
    let count = |state: AttemptState| {
        u64::try_from(
            observations
                .iter()
                .filter(|observation| observation.state == state)
                .count(),
        )
        .unwrap_or(u64::MAX)
    };
    let mut durations = observations
        .iter()
        .map(|observation| observation.duration_ms)
        .collect::<Vec<_>>();
    durations.sort_unstable();
    Operations {
        attempts: u64::try_from(observations.len()).unwrap_or(u64::MAX),
        completed: count(AttemptState::Completed),
        failed: count(AttemptState::Failed),
        timeouts: count(AttemptState::Timeout),
        malformed: count(AttemptState::Malformed),
        unsupported: count(AttemptState::Unsupported),
        unavailable: count(AttemptState::Unavailable),
        total_duration_ms: durations.iter().sum(),
        min_duration_ms: durations.first().copied(),
        median_duration_ms: percentile(&durations, 50),
        p95_duration_ms: percentile(&durations, 95),
        max_duration_ms: durations.last().copied(),
    }
}

fn decision(case: &CaseSpec, finding_count: u64) -> CaseDecision {
    let predicted_positive = finding_count != 0;
    let vulnerable = case.classification == "vulnerable";
    let outcome = match (vulnerable, predicted_positive) {
        (true, true) => "tp",
        (true, false) => "fn",
        (false, true) => "fp",
        (false, false) => "tn",
    };
    CaseDecision {
        case_id: case.case_id.clone(),
        pair_id: case.pair_id.clone(),
        expected: case.classification.clone(),
        finding_count,
        predicted_positive,
        outcome: outcome.to_owned(),
        family: case.family.clone(),
        framework: case.framework.clone(),
        source_format: case.source_format.clone(),
        topology: case.topology.clone(),
        adversarial_variant: case
            .adversarial_variant
            .clone()
            .unwrap_or_else(|| "none".to_owned()),
    }
}

fn pair_results(decisions: &[CaseDecision]) -> Result<Vec<PairDecision>, Phase22Error> {
    let mut pairs = BTreeMap::<String, Vec<&CaseDecision>>::new();
    for decision in decisions {
        pairs
            .entry(decision.pair_id.clone())
            .or_default()
            .push(decision);
    }
    let mut output = Vec::new();
    for (pair_id, members) in pairs {
        if members.len() != 2 {
            return Err(Phase22Error::Verification(format!(
                "independent scorer found incomplete pair {pair_id}"
            )));
        }
        let vulnerable = members
            .iter()
            .find(|member| member.expected == "vulnerable")
            .ok_or_else(|| {
                Phase22Error::Verification(format!(
                    "independent scorer found no vulnerable member in {pair_id}"
                ))
            })?;
        let control = members
            .iter()
            .find(|member| member.expected == "control")
            .ok_or_else(|| {
                Phase22Error::Verification(format!(
                    "independent scorer found no control member in {pair_id}"
                ))
            })?;
        output.push(PairDecision {
            pair_id,
            vulnerable_case_id: vulnerable.case_id.clone(),
            control_case_id: control.case_id.clone(),
            vulnerable_flagged: vulnerable.predicted_positive,
            control_flagged: control.predicted_positive,
            pair_exact: vulnerable.predicted_positive && !control.predicted_positive,
        });
    }
    Ok(output)
}

fn lane(
    scanner: &str,
    cases: &BTreeMap<String, CaseSpec>,
    observations: &[Observation],
) -> Result<LaneResult, Phase22Error> {
    let selected = observations
        .iter()
        .filter(|observation| observation.scanner == scanner)
        .collect::<Vec<_>>();
    let operation = operations(&selected);
    let mut decisions = selected
        .iter()
        .filter(|observation| observation.state == AttemptState::Completed)
        .map(|observation| {
            let case = cases.get(&observation.case_id).ok_or_else(|| {
                Phase22Error::Verification(format!(
                    "independent scorer found unknown case {}",
                    observation.case_id
                ))
            })?;
            let findings = observation.finding_count.ok_or_else(|| {
                Phase22Error::Verification(format!(
                    "independent scorer found no count for observation {}",
                    observation.sequence
                ))
            })?;
            Ok(decision(case, findings))
        })
        .collect::<Result<Vec<_>, Phase22Error>>()?;
    decisions.sort_by(|left, right| left.case_id.cmp(&right.case_id));
    let complete = operation.attempts == 112 && operation.completed == 112;
    let state = if complete {
        "completed"
    } else if operation.completed == 0 {
        "failed"
    } else {
        "partial"
    };
    Ok(LaneResult {
        scanner: scanner.to_owned(),
        lane: "capability-normalized".to_owned(),
        state: state.to_owned(),
        operations: operation,
        metrics: complete.then(|| metrics(&decisions)),
        cases: decisions.clone(),
        pairs: if complete {
            pair_results(&decisions)?
        } else {
            Vec::new()
        },
        by_family: complete
            .then(|| grouped(&decisions, |value| &value.family))
            .unwrap_or_default(),
        by_framework: complete
            .then(|| grouped(&decisions, |value| &value.framework))
            .unwrap_or_default(),
        by_source_format: complete
            .then(|| grouped(&decisions, |value| &value.source_format))
            .unwrap_or_default(),
        by_topology: complete
            .then(|| grouped(&decisions, |value| &value.topology))
            .unwrap_or_default(),
        by_adversarial_variant: complete
            .then(|| grouped(&decisions, |value| &value.adversarial_variant))
            .unwrap_or_default(),
        by_classification: complete
            .then(|| grouped(&decisions, |value| &value.expected))
            .unwrap_or_default(),
    })
}

fn absolute(left: &Ratio, right: &Ratio) -> Ratio {
    ratio(
        (left.numerator * right.denominator).abs_diff(right.numerator * left.denominator),
        left.denominator * right.denominator,
    )
    .unwrap_or(Ratio {
        numerator: 0,
        denominator: 1,
        decimal: "0.000000".to_owned(),
    })
}

fn comparison(opengrep: &LaneResult, semgrep: &LaneResult) -> Comparison {
    let (Some(left_metrics), Some(right_metrics)) = (&opengrep.metrics, &semgrep.metrics) else {
        return Comparison {
            state: "unavailable".to_owned(),
            lane: "capability-normalized".to_owned(),
            agreements: None,
            opengrep_only_correct: None,
            semgrep_only_correct: None,
            both_incorrect: None,
            absolute_metric_differences: BTreeMap::new(),
            disagreements: Vec::new(),
            reason: Some("one or both normalized recovery lanes are incomplete".to_owned()),
        };
    };
    let right = semgrep
        .cases
        .iter()
        .map(|decision| (decision.case_id.as_str(), decision))
        .collect::<BTreeMap<_, _>>();
    let mut agreements = 0;
    let mut opengrep_only = 0;
    let mut semgrep_only = 0;
    let mut both_incorrect = 0;
    let mut disagreements = Vec::new();
    for left in &opengrep.cases {
        let Some(right) = right.get(left.case_id.as_str()) else {
            continue;
        };
        let left_correct = matches!(left.outcome.as_str(), "tp" | "tn");
        let right_correct = matches!(right.outcome.as_str(), "tp" | "tn");
        if left.predicted_positive == right.predicted_positive {
            agreements += 1;
        } else {
            disagreements.push(Disagreement {
                case_id: left.case_id.clone(),
                expected: left.expected.clone(),
                opengrep_positive: left.predicted_positive,
                semgrep_positive: right.predicted_positive,
                opengrep_findings: left.finding_count,
                semgrep_findings: right.finding_count,
                opengrep_outcome: left.outcome.clone(),
                semgrep_outcome: right.outcome.clone(),
                family: left.family.clone(),
                framework: left.framework.clone(),
                source_format: left.source_format.clone(),
                topology: left.topology.clone(),
                adversarial_variant: left.adversarial_variant.clone(),
            });
        }
        match (left_correct, right_correct) {
            (true, false) => opengrep_only += 1,
            (false, true) => semgrep_only += 1,
            (false, false) => both_incorrect += 1,
            (true, true) => {}
        }
    }
    let mut differences = BTreeMap::new();
    for (name, left, right) in [
        (
            "precision",
            &left_metrics.precision,
            &right_metrics.precision,
        ),
        ("recall", &left_metrics.recall, &right_metrics.recall),
        (
            "specificity",
            &left_metrics.specificity,
            &right_metrics.specificity,
        ),
        ("f1", &left_metrics.f1, &right_metrics.f1),
        (
            "balanced_accuracy",
            &left_metrics.balanced_accuracy,
            &right_metrics.balanced_accuracy,
        ),
    ] {
        if let (Some(left), Some(right)) = (left, right) {
            differences.insert(name.to_owned(), absolute(left, right));
        }
    }
    Comparison {
        state: "paired-complete".to_owned(),
        lane: "capability-normalized".to_owned(),
        agreements: Some(agreements),
        opengrep_only_correct: Some(opengrep_only),
        semgrep_only_correct: Some(semgrep_only),
        both_incorrect: Some(both_incorrect),
        absolute_metric_differences: differences,
        disagreements,
        reason: None,
    }
}

fn historical(opengrep: &LaneResult, semgrep: &LaneResult) -> Vec<HistoricalRow> {
    vec![
        HistoricalRow {
            phase: "20".to_owned(),
            study: "one-shot multi-scanner comparison".to_owned(),
            scanner: "secure-engine".to_owned(),
            lane: "native".to_owned(),
            state: "completed".to_owned(),
            attempts: 112,
            note: "historical Phase 20 native evidence; not merged with normalized metrics"
                .to_owned(),
        },
        HistoricalRow {
            phase: "20".to_owned(),
            study: "one-shot multi-scanner comparison".to_owned(),
            scanner: "opengrep".to_owned(),
            lane: "capability-normalized".to_owned(),
            state: "failed".to_owned(),
            attempts: 112,
            note: "immutable historical infrastructure failures; not replaced".to_owned(),
        },
        HistoricalRow {
            phase: "20".to_owned(),
            study: "one-shot multi-scanner comparison".to_owned(),
            scanner: "semgrep-ce".to_owned(),
            lane: "capability-normalized".to_owned(),
            state: "failed".to_owned(),
            attempts: 112,
            note: "immutable historical infrastructure failures; not replaced".to_owned(),
        },
        HistoricalRow {
            phase: "22".to_owned(),
            study: "post-open recovery study".to_owned(),
            scanner: "opengrep".to_owned(),
            lane: "capability-normalized".to_owned(),
            state: opengrep.state.clone(),
            attempts: opengrep.operations.attempts,
            note: "Phase 22 recovery evidence; separate denominator".to_owned(),
        },
        HistoricalRow {
            phase: "22".to_owned(),
            study: "post-open recovery study".to_owned(),
            scanner: "semgrep-ce".to_owned(),
            lane: "capability-normalized".to_owned(),
            state: semgrep.state.clone(),
            attempts: semgrep.operations.attempts,
            note: "Phase 22 recovery evidence; separate denominator".to_owned(),
        },
    ]
}

/// Recompute Phase 22 results without invoking the canonical scoring module.
pub(crate) fn compute(
    cases: &BTreeMap<String, CaseSpec>,
    observations: &[Observation],
) -> Result<Results, Phase22Error> {
    let keys = observations
        .iter()
        .map(|observation| (observation.scanner.as_str(), observation.case_id.as_str()))
        .collect::<BTreeSet<_>>();
    let opengrep = lane("opengrep", cases, observations)?;
    let semgrep = lane("semgrep-ce", cases, observations)?;
    Ok(Results {
        schema_version: "secure-bench-phase22-results-v1".to_owned(),
        study: "post-open recovery study".to_owned(),
        phase21_commit: "be1ce9327c5c2acab25abe5af7a4f923d1623c48".to_owned(),
        total_recovery_attempts: u64::try_from(observations.len()).unwrap_or(u64::MAX),
        retries: 0,
        secure_engine_attempts: 0,
        repeated_attempts: keys.len() != observations.len(),
        comparison: comparison(&opengrep, &semgrep),
        historical: historical(&opengrep, &semgrep),
        lanes: vec![opengrep, semgrep],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical_json;

    fn observation(sequence: u64, scanner: &str, case_id: &str, findings: u64) -> Observation {
        Observation {
            sequence,
            scanner: scanner.to_owned(),
            lane: "capability-normalized".to_owned(),
            case_id: case_id.to_owned(),
            state: AttemptState::Completed,
            process_decision: "successful-report".to_owned(),
            exit_code: Some(i32::from(findings != 0)),
            timed_out: false,
            duration_ms: sequence,
            command: Vec::new(),
            command_sha256: String::new(),
            environment: Vec::new(),
            environment_sha256: String::new(),
            stdout_path: String::new(),
            stdout_sha256: String::new(),
            stderr_path: String::new(),
            stderr_sha256: String::new(),
            raw_output_path: None,
            raw_output_sha256: None,
            finding_count: Some(findings),
            failure: None,
        }
    }

    fn population() -> (BTreeMap<String, CaseSpec>, Vec<Observation>) {
        let mut cases = BTreeMap::new();
        for pair in 1..=56 {
            for classification in ["vulnerable", "control"] {
                let case_id = format!("case-{pair:02}-{classification}");
                cases.insert(
                    case_id.clone(),
                    CaseSpec {
                        case_id,
                        pair_id: format!("pair-{pair:02}"),
                        classification: classification.to_owned(),
                        family: format!("SE100{}", pair % 7 + 1),
                        framework: format!("framework-{}", pair % 3),
                        source_format: format!("format-{}", pair % 2),
                        topology: format!("topology-{}", pair % 4),
                        adversarial_variant: (pair % 2 == 0).then(|| "variant".to_owned()),
                        fixture_path: "fixture".to_owned(),
                    },
                );
            }
        }
        let mut observations = Vec::new();
        for scanner in ["opengrep", "semgrep-ce"] {
            for case in cases.values() {
                let findings = if scanner == "opengrep" {
                    u64::from(case.classification == "vulnerable")
                } else {
                    u64::from(case.case_id.len() % 3 != 0)
                };
                observations.push(observation(
                    u64::try_from(observations.len() + 1).unwrap_or(u64::MAX),
                    scanner,
                    &case.case_id,
                    findings,
                ));
            }
        }
        (cases, observations)
    }

    #[test]
    fn independent_scorer_matches_canonical_for_complete_and_partial_lanes()
    -> Result<(), Phase22Error> {
        let (cases, mut observations) = population();
        let canonical = crate::score::compute(&cases, &observations)?;
        let independent = compute(&cases, &observations)?;
        assert_eq!(canonical_json(&canonical)?, canonical_json(&independent)?);

        observations[0].state = AttemptState::Failed;
        observations[0].finding_count = None;
        observations[0].failure = Some("synthetic failure".to_owned());
        let canonical = crate::score::compute(&cases, &observations)?;
        let independent = compute(&cases, &observations)?;
        assert_eq!(canonical_json(&canonical)?, canonical_json(&independent)?);
        Ok(())
    }
}
