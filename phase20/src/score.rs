use crate::model::{CaseDecision, CaseSpec, Metrics, PairDecision, Ratio};
use std::collections::BTreeMap;

fn ratio(numerator: u64, denominator: u64) -> Option<Ratio> {
    (denominator != 0).then(|| Ratio {
        numerator,
        denominator,
        decimal: format!("{:.6}", numerator as f64 / denominator as f64),
    })
}

/// Computes all required metrics from completed case decisions.
#[must_use]
pub fn metrics(decisions: &[CaseDecision]) -> Metrics {
    let count = |label: &str| {
        u64::try_from(
            decisions
                .iter()
                .filter(|decision| decision.outcome == label)
                .count(),
        )
        .unwrap_or(u64::MAX)
    };
    let tp = count("tp");
    let fp = count("fp");
    let tn = count("tn");
    let fn_count = count("fn");
    let recall_denominator = tp + fn_count;
    let specificity_denominator = tn + fp;
    Metrics {
        tp,
        fp,
        tn,
        fn_count,
        precision: ratio(tp, tp + fp),
        recall: ratio(tp, recall_denominator),
        specificity: ratio(tn, specificity_denominator),
        f1: ratio(2 * tp, 2 * tp + fp + fn_count),
        balanced_accuracy: ratio(
            tp * specificity_denominator + tn * recall_denominator,
            2 * recall_denominator * specificity_denominator,
        ),
    }
}

/// Converts finding counts into case decisions without consulting scanner identity.
#[must_use]
pub fn decide(cases: &[CaseSpec], findings: &BTreeMap<String, u64>) -> Vec<CaseDecision> {
    cases
        .iter()
        .filter_map(|case| {
            findings.get(&case.case_id).map(|count| {
                let predicted_positive = *count > 0;
                let outcome = match (case.classification.as_str(), predicted_positive) {
                    ("vulnerable", true) => "tp",
                    ("vulnerable", false) => "fn",
                    ("control", true) => "fp",
                    ("control", false) => "tn",
                    _ => "invalid",
                };
                CaseDecision {
                    case_id: case.case_id.clone(),
                    pair_id: case.pair_id.clone(),
                    expected: case.classification.clone(),
                    finding_count: *count,
                    predicted_positive,
                    outcome: outcome.to_owned(),
                    family: case.family.clone(),
                    framework: case.framework.clone(),
                    source_format: case.source_format.clone(),
                    topology: case.topology.clone(),
                }
            })
        })
        .collect()
}

/// Computes complete pair-level decisions.
#[must_use]
pub fn pairs(decisions: &[CaseDecision]) -> Vec<PairDecision> {
    let mut grouped = BTreeMap::<String, Vec<&CaseDecision>>::new();
    for decision in decisions {
        grouped
            .entry(decision.pair_id.clone())
            .or_default()
            .push(decision);
    }
    grouped
        .into_iter()
        .filter_map(|(pair_id, members)| {
            let vulnerable = members
                .iter()
                .find(|member| member.expected == "vulnerable")?;
            let control = members.iter().find(|member| member.expected == "control")?;
            Some(PairDecision {
                pair_id,
                vulnerable_case_id: vulnerable.case_id.clone(),
                control_case_id: control.case_id.clone(),
                vulnerable_flagged: vulnerable.predicted_positive,
                control_flagged: control.predicted_positive,
                pair_exact: vulnerable.predicted_positive && !control.predicted_positive,
            })
        })
        .collect()
}

/// Groups decisions and computes one confusion matrix per exact label.
#[must_use]
pub fn grouped<F>(decisions: &[CaseDecision], label: F) -> BTreeMap<String, Metrics>
where
    F: Fn(&CaseDecision) -> &str,
{
    let mut values = BTreeMap::<String, Vec<CaseDecision>>::new();
    for decision in decisions {
        values
            .entry(label(decision).to_owned())
            .or_default()
            .push(decision.clone());
    }
    values
        .into_iter()
        .map(|(key, group)| (key, metrics(&group)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{decide, metrics, pairs};
    use crate::model::CaseSpec;
    use std::collections::BTreeMap;

    fn case(id: &str, pair: &str, classification: &str) -> CaseSpec {
        CaseSpec {
            case_id: id.to_owned(),
            pair_id: pair.to_owned(),
            classification: classification.to_owned(),
            family: "synthetic-family".to_owned(),
            framework: "synthetic-framework".to_owned(),
            source_format: "synthetic-format".to_owned(),
            topology: "synthetic-topology".to_owned(),
            fixture_path: "synthetic-only".to_owned(),
        }
    }

    #[test]
    fn synthetic_metrics_expose_all_denominators() {
        let cases = vec![
            case("s1", "p1", "vulnerable"),
            case("s2", "p1", "control"),
            case("s3", "p2", "vulnerable"),
            case("s4", "p2", "control"),
        ];
        let findings = BTreeMap::from([
            ("s1".to_owned(), 1),
            ("s2".to_owned(), 0),
            ("s3".to_owned(), 0),
            ("s4".to_owned(), 2),
        ]);
        let decisions = decide(&cases, &findings);
        let result = metrics(&decisions);
        assert_eq!(
            (result.tp, result.fp, result.tn, result.fn_count),
            (1, 1, 1, 1)
        );
        assert_eq!(result.precision.map(|value| value.denominator), Some(2));
        assert_eq!(pairs(&decisions).len(), 2);
    }
}
