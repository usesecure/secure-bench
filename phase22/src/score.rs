use crate::Phase22Error;
use crate::model::{
    AttemptState, CaseDecision, CaseSpec, Comparison, Disagreement, HistoricalRow, LaneResult,
    Metrics, Observation, Operations, PairDecision, Ratio, Results,
};
use std::collections::{BTreeMap, BTreeSet};

fn gcd(mut left: u64, mut right: u64) -> u64 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
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

/// Compute exact requested metrics for case decisions.
pub(crate) fn metrics(decisions: &[CaseDecision]) -> Metrics {
    let mut tp = 0;
    let mut fp = 0;
    let mut tn = 0;
    let mut fn_count = 0;
    for decision in decisions {
        match decision.outcome.as_str() {
            "tp" => tp += 1,
            "fp" => fp += 1,
            "tn" => tn += 1,
            "fn" => fn_count += 1,
            _ => {}
        }
    }
    let precision = ratio(tp, tp + fp);
    let recall = ratio(tp, tp + fn_count);
    let specificity = ratio(tn, tn + fp);
    let f1 = ratio(2 * tp, 2 * tp + fp + fn_count);
    let balanced_accuracy = if tp + fn_count == 0 || tn + fp == 0 {
        None
    } else {
        ratio(
            tp * (tn + fp) + tn * (tp + fn_count),
            2 * (tp + fn_count) * (tn + fp),
        )
    };
    Metrics {
        tp,
        fp,
        tn,
        fn_count,
        precision,
        recall,
        specificity,
        f1,
        balanced_accuracy,
    }
}

fn decisions_by<F>(decisions: &[CaseDecision], key: F) -> BTreeMap<String, Metrics>
where
    F: Fn(&CaseDecision) -> &str,
{
    let mut groups = BTreeMap::<String, Vec<CaseDecision>>::new();
    for decision in decisions {
        groups
            .entry(key(decision).to_owned())
            .or_default()
            .push(decision.clone());
    }
    groups
        .into_iter()
        .map(|(name, members)| (name, metrics(&members)))
        .collect()
}

fn percentile(sorted: &[u64], numerator: usize, denominator: usize) -> Option<u64> {
    if sorted.is_empty() {
        return None;
    }
    let rank = sorted
        .len()
        .saturating_mul(numerator)
        .div_ceil(denominator)
        .saturating_sub(1)
        .min(sorted.len() - 1);
    sorted.get(rank).copied()
}

fn operations(observations: &[&Observation]) -> Operations {
    let mut durations = observations
        .iter()
        .map(|observation| observation.duration_ms)
        .collect::<Vec<_>>();
    durations.sort_unstable();
    Operations {
        attempts: u64::try_from(observations.len()).unwrap_or(u64::MAX),
        completed: u64::try_from(
            observations
                .iter()
                .filter(|observation| observation.state == AttemptState::Completed)
                .count(),
        )
        .unwrap_or(u64::MAX),
        failed: u64::try_from(
            observations
                .iter()
                .filter(|observation| observation.state == AttemptState::Failed)
                .count(),
        )
        .unwrap_or(u64::MAX),
        timeouts: u64::try_from(
            observations
                .iter()
                .filter(|observation| observation.state == AttemptState::Timeout)
                .count(),
        )
        .unwrap_or(u64::MAX),
        malformed: u64::try_from(
            observations
                .iter()
                .filter(|observation| observation.state == AttemptState::Malformed)
                .count(),
        )
        .unwrap_or(u64::MAX),
        unsupported: u64::try_from(
            observations
                .iter()
                .filter(|observation| observation.state == AttemptState::Unsupported)
                .count(),
        )
        .unwrap_or(u64::MAX),
        unavailable: u64::try_from(
            observations
                .iter()
                .filter(|observation| observation.state == AttemptState::Unavailable)
                .count(),
        )
        .unwrap_or(u64::MAX),
        total_duration_ms: durations.iter().sum(),
        min_duration_ms: durations.first().copied(),
        median_duration_ms: percentile(&durations, 50, 100),
        p95_duration_ms: percentile(&durations, 95, 100),
        max_duration_ms: durations.last().copied(),
    }
}

fn case_decision(case: &CaseSpec, finding_count: u64) -> CaseDecision {
    let predicted_positive = finding_count > 0;
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

fn pairs(decisions: &[CaseDecision]) -> Result<Vec<PairDecision>, Phase22Error> {
    let mut grouped = BTreeMap::<String, Vec<&CaseDecision>>::new();
    for decision in decisions {
        grouped
            .entry(decision.pair_id.clone())
            .or_default()
            .push(decision);
    }
    let mut output = Vec::new();
    for (pair_id, members) in grouped {
        if members.len() != 2 {
            return Err(Phase22Error::Execution(format!(
                "pair {pair_id} does not contain two completed decisions"
            )));
        }
        let vulnerable = members
            .iter()
            .find(|decision| decision.expected == "vulnerable")
            .ok_or_else(|| Phase22Error::Execution(format!("pair {pair_id} has no vulnerable")))?;
        let control = members
            .iter()
            .find(|decision| decision.expected == "control")
            .ok_or_else(|| Phase22Error::Execution(format!("pair {pair_id} has no control")))?;
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
    let lane_observations = observations
        .iter()
        .filter(|observation| observation.scanner == scanner)
        .collect::<Vec<_>>();
    let operational = operations(&lane_observations);
    let mut decisions = Vec::new();
    for observation in &lane_observations {
        if observation.state == AttemptState::Completed {
            let case = cases.get(&observation.case_id).ok_or_else(|| {
                Phase22Error::Execution(format!("unknown case {}", observation.case_id))
            })?;
            let count = observation.finding_count.ok_or_else(|| {
                Phase22Error::Execution(format!(
                    "completed observation {} has no finding count",
                    observation.sequence
                ))
            })?;
            decisions.push(case_decision(case, count));
        }
    }
    decisions.sort_by(|left, right| left.case_id.cmp(&right.case_id));
    let complete = operational.attempts == 112 && operational.completed == 112;
    let state = if complete {
        "completed"
    } else if operational.completed > 0 {
        "partial"
    } else {
        "failed"
    };
    Ok(LaneResult {
        scanner: scanner.to_owned(),
        lane: "capability-normalized".to_owned(),
        state: state.to_owned(),
        operations: operational,
        metrics: complete.then(|| metrics(&decisions)),
        pairs: if complete {
            pairs(&decisions)?
        } else {
            Vec::new()
        },
        by_family: complete
            .then(|| decisions_by(&decisions, |decision| &decision.family))
            .unwrap_or_default(),
        by_framework: complete
            .then(|| decisions_by(&decisions, |decision| &decision.framework))
            .unwrap_or_default(),
        by_source_format: complete
            .then(|| decisions_by(&decisions, |decision| &decision.source_format))
            .unwrap_or_default(),
        by_topology: complete
            .then(|| decisions_by(&decisions, |decision| &decision.topology))
            .unwrap_or_default(),
        by_adversarial_variant: complete
            .then(|| decisions_by(&decisions, |decision| &decision.adversarial_variant))
            .unwrap_or_default(),
        by_classification: complete
            .then(|| decisions_by(&decisions, |decision| &decision.expected))
            .unwrap_or_default(),
        cases: decisions,
    })
}

fn absolute(left: &Ratio, right: &Ratio) -> Ratio {
    let left_scaled = left.numerator * right.denominator;
    let right_scaled = right.numerator * left.denominator;
    let numerator = left_scaled.abs_diff(right_scaled);
    let denominator = left.denominator * right.denominator;
    ratio(numerator, denominator).unwrap_or(Ratio {
        numerator: 0,
        denominator: 1,
        decimal: "0.000000".to_owned(),
    })
}

fn comparison(left: &LaneResult, right: &LaneResult) -> Comparison {
    let (Some(left_metrics), Some(right_metrics)) = (&left.metrics, &right.metrics) else {
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
    let right_cases = right
        .cases
        .iter()
        .map(|decision| (decision.case_id.as_str(), decision))
        .collect::<BTreeMap<_, _>>();
    let mut agreements = 0;
    let mut left_only = 0;
    let mut right_only = 0;
    let mut both_incorrect = 0;
    let mut disagreements = Vec::new();
    for left_case in &left.cases {
        let Some(right_case) = right_cases.get(left_case.case_id.as_str()) else {
            continue;
        };
        let left_correct = matches!(left_case.outcome.as_str(), "tp" | "tn");
        let right_correct = matches!(right_case.outcome.as_str(), "tp" | "tn");
        if left_case.predicted_positive == right_case.predicted_positive {
            agreements += 1;
        } else {
            disagreements.push(Disagreement {
                case_id: left_case.case_id.clone(),
                expected: left_case.expected.clone(),
                opengrep_positive: left_case.predicted_positive,
                semgrep_positive: right_case.predicted_positive,
                opengrep_findings: left_case.finding_count,
                semgrep_findings: right_case.finding_count,
                opengrep_outcome: left_case.outcome.clone(),
                semgrep_outcome: right_case.outcome.clone(),
                family: left_case.family.clone(),
                framework: left_case.framework.clone(),
                source_format: left_case.source_format.clone(),
                topology: left_case.topology.clone(),
                adversarial_variant: left_case.adversarial_variant.clone(),
            });
        }
        match (left_correct, right_correct) {
            (true, false) => left_only += 1,
            (false, true) => right_only += 1,
            (false, false) => both_incorrect += 1,
            (true, true) => {}
        }
    }
    let mut differences = BTreeMap::new();
    for (name, left_value, right_value) in [
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
        if let (Some(left_ratio), Some(right_ratio)) = (left_value, right_value) {
            differences.insert(name.to_owned(), absolute(left_ratio, right_ratio));
        }
    }
    Comparison {
        state: "paired-complete".to_owned(),
        lane: "capability-normalized".to_owned(),
        agreements: Some(agreements),
        opengrep_only_correct: Some(left_only),
        semgrep_only_correct: Some(right_only),
        both_incorrect: Some(both_incorrect),
        absolute_metric_differences: differences,
        disagreements,
        reason: None,
    }
}

/// Compute canonical Phase 22 results from observations and post-open metadata.
pub(crate) fn compute(
    cases: &BTreeMap<String, CaseSpec>,
    observations: &[Observation],
) -> Result<Results, Phase22Error> {
    let keys = observations
        .iter()
        .map(|observation| (observation.scanner.as_str(), observation.case_id.as_str()))
        .collect::<BTreeSet<_>>();
    let repeated = keys.len() != observations.len();
    let opengrep = lane("opengrep", cases, observations)?;
    let semgrep = lane("semgrep-ce", cases, observations)?;
    let paired = comparison(&opengrep, &semgrep);
    let historical = vec![
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
    ];
    Ok(Results {
        schema_version: "secure-bench-phase22-results-v1".to_owned(),
        study: "post-open recovery study".to_owned(),
        phase21_commit: "be1ce9327c5c2acab25abe5af7a4f923d1623c48".to_owned(),
        total_recovery_attempts: u64::try_from(observations.len()).unwrap_or(u64::MAX),
        retries: 0,
        secure_engine_attempts: 0,
        repeated_attempts: repeated,
        lanes: vec![opengrep, semgrep],
        comparison: paired,
        historical,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decision(expected: &str, outcome: &str) -> CaseDecision {
        CaseDecision {
            case_id: format!("case-{expected}-{outcome}"),
            pair_id: "pair".to_owned(),
            expected: expected.to_owned(),
            finding_count: u64::from(matches!(outcome, "tp" | "fp")),
            predicted_positive: matches!(outcome, "tp" | "fp"),
            outcome: outcome.to_owned(),
            family: "SE1001".to_owned(),
            framework: "framework".to_owned(),
            source_format: "js".to_owned(),
            topology: "direct".to_owned(),
            adversarial_variant: "none".to_owned(),
        }
    }

    #[test]
    fn requested_metrics_are_exact() {
        let values = vec![
            decision("vulnerable", "tp"),
            decision("vulnerable", "fn"),
            decision("control", "tn"),
            decision("control", "fp"),
        ];
        let result = metrics(&values);
        assert_eq!(
            (result.tp, result.fp, result.tn, result.fn_count),
            (1, 1, 1, 1)
        );
        assert_eq!(
            result
                .balanced_accuracy
                .and_then(|value| value.decimal.parse::<f64>().ok()),
            Some(0.5)
        );
    }
}
