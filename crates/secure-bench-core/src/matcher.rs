//! Deterministic, one-to-one expectation matching with explicit ambiguity.

use crate::model::{
    BenchmarkCase, BenchmarkSuite, CaseExecution, CaseKind, EvidenceConstraint, ExecutionStatus,
    ExpectationDecision, ExpectedFinding, FindingDecision, FindingDisposition, LocationConstraint,
    MatchCriteria, MatchOutcome, MatchingReport, NormalizedFinding, SourceLocation,
};
use std::collections::{BTreeMap, BTreeSet};

/// Matches normalized findings without access to adapter or tool identity.
#[must_use]
pub fn match_findings(
    suite: &BenchmarkSuite,
    findings: &[NormalizedFinding],
    executions: &[CaseExecution],
) -> MatchingReport {
    let execution_by_case: BTreeMap<&str, ExecutionStatus> = executions
        .iter()
        .map(|execution| (execution.case_id.as_str(), execution.status))
        .collect();
    let case_by_id: BTreeMap<&str, &BenchmarkCase> = suite
        .cases
        .iter()
        .map(|case| (case.case_id.as_str(), case))
        .collect();

    let mut ordered_findings = findings.iter().collect::<Vec<_>>();
    ordered_findings.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));

    let duplicate_of = duplicate_map(&ordered_findings);
    let mut finding_decisions = BTreeMap::<String, FindingDecision>::new();
    for finding in &ordered_findings {
        let decision = if let Some(canonical_id) = duplicate_of.get(&finding.finding_id) {
            FindingDecision {
                finding_id: finding.finding_id.clone(),
                case_id: finding.case_id.clone(),
                disposition: FindingDisposition::Duplicate,
                related_id: Some(canonical_id.clone()),
            }
        } else {
            let status = execution_by_case
                .get(finding.case_id.as_str())
                .copied()
                .unwrap_or(ExecutionStatus::Missing);
            let kind = case_by_id
                .get(finding.case_id.as_str())
                .map(|case| case.kind);
            let disposition = if status != ExecutionStatus::Success || kind.is_none() {
                FindingDisposition::IneligibleRunOutput
            } else if kind == Some(CaseKind::SafeControl) {
                FindingDisposition::SafeControlFalsePositive
            } else {
                FindingDisposition::Unmatched
            };
            FindingDecision {
                finding_id: finding.finding_id.clone(),
                case_id: finding.case_id.clone(),
                disposition,
                related_id: None,
            }
        };
        finding_decisions.insert(finding.finding_id.clone(), decision);
    }

    let mut expectation_decisions = Vec::new();
    let mut vulnerable_cases = suite
        .cases
        .iter()
        .filter(|case| case.kind == CaseKind::Vulnerable)
        .collect::<Vec<_>>();
    vulnerable_cases.sort_by(|left, right| left.case_id.cmp(&right.case_id));

    for case in vulnerable_cases {
        let status = execution_by_case
            .get(case.case_id.as_str())
            .copied()
            .unwrap_or(ExecutionStatus::Missing);
        if status != ExecutionStatus::Success {
            let outcome = if status == ExecutionStatus::Unsupported {
                MatchOutcome::Unsupported
            } else {
                MatchOutcome::NotAttempted
            };
            for expected in sorted_expectations(&case.expected_findings) {
                expectation_decisions.push(ExpectationDecision {
                    case_id: case.case_id.clone(),
                    expectation_id: expected.expectation_id.clone(),
                    outcome,
                    selected_finding_id: None,
                    ambiguous_finding_ids: Vec::new(),
                    criteria: MatchCriteria::default(),
                });
            }
            continue;
        }

        let candidates = ordered_findings
            .iter()
            .copied()
            .filter(|finding| {
                finding.case_id == case.case_id && !duplicate_of.contains_key(&finding.finding_id)
            })
            .collect::<Vec<_>>();
        match_case(
            case,
            &candidates,
            &mut expectation_decisions,
            &mut finding_decisions,
        );
    }

    expectation_decisions.sort_by(|left, right| {
        (&left.case_id, &left.expectation_id).cmp(&(&right.case_id, &right.expectation_id))
    });
    let mut findings = finding_decisions.into_values().collect::<Vec<_>>();
    findings.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
    MatchingReport {
        expectations: expectation_decisions,
        findings,
    }
}

fn match_case(
    case: &BenchmarkCase,
    findings: &[&NormalizedFinding],
    decisions: &mut Vec<ExpectationDecision>,
    finding_decisions: &mut BTreeMap<String, FindingDecision>,
) {
    let mut work = case
        .expected_findings
        .iter()
        .map(|expected| {
            let mut full_candidates = findings
                .iter()
                .copied()
                .filter(|finding| criteria(expected, finding) == full_criteria())
                .collect::<Vec<_>>();
            full_candidates.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
            (expected, full_candidates)
        })
        .collect::<Vec<_>>();
    work.sort_by(
        |(left_expected, left_candidates), (right_expected, right_candidates)| {
            (left_candidates.len(), &left_expected.expectation_id)
                .cmp(&(right_candidates.len(), &right_expected.expectation_id))
        },
    );

    let mut used = BTreeSet::<String>::new();
    for (expected, full_candidates) in work {
        let available = full_candidates
            .iter()
            .copied()
            .filter(|candidate| !used.contains(&candidate.finding_id))
            .collect::<Vec<_>>();
        if let Some(selected) = available.first().copied() {
            used.insert(selected.finding_id.clone());
            let alternatives = available
                .iter()
                .skip(1)
                .map(|finding| finding.finding_id.clone())
                .collect::<Vec<_>>();
            let outcome = if alternatives.is_empty() {
                MatchOutcome::Matched
            } else {
                MatchOutcome::Ambiguous
            };
            if let Some(decision) = finding_decisions.get_mut(&selected.finding_id) {
                decision.disposition = FindingDisposition::Matched;
                decision.related_id = Some(expected.expectation_id.clone());
            }
            for alternative in &alternatives {
                if let Some(decision) = finding_decisions.get_mut(alternative) {
                    decision.disposition = FindingDisposition::AmbiguousCandidate;
                    decision.related_id = Some(expected.expectation_id.clone());
                }
            }
            decisions.push(ExpectationDecision {
                case_id: case.case_id.clone(),
                expectation_id: expected.expectation_id.clone(),
                outcome,
                selected_finding_id: Some(selected.finding_id.clone()),
                ambiguous_finding_ids: alternatives,
                criteria: full_criteria(),
            });
        } else {
            let best = findings
                .iter()
                .map(|finding| criteria(expected, finding))
                .max_by_key(criteria_count)
                .unwrap_or_default();
            decisions.push(ExpectationDecision {
                case_id: case.case_id.clone(),
                expectation_id: expected.expectation_id.clone(),
                outcome: MatchOutcome::Missed,
                selected_finding_id: None,
                ambiguous_finding_ids: Vec::new(),
                criteria: best,
            });
        }
    }
}

fn sorted_expectations(expectations: &[ExpectedFinding]) -> Vec<&ExpectedFinding> {
    let mut ordered = expectations.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| left.expectation_id.cmp(&right.expectation_id));
    ordered
}

fn criteria(expected: &ExpectedFinding, finding: &NormalizedFinding) -> MatchCriteria {
    MatchCriteria {
        category: canonical(&expected.category) == finding.category,
        invariant: canonical(&expected.invariant) == finding.invariant,
        source: location_matches(&expected.source, &finding.source),
        sink: location_matches(&expected.sink, &finding.sink),
        evidence_path: evidence_matches(&expected.evidence, finding),
    }
}

fn full_criteria() -> MatchCriteria {
    MatchCriteria {
        category: true,
        invariant: true,
        source: true,
        sink: true,
        evidence_path: true,
    }
}

fn criteria_count(criteria: &MatchCriteria) -> u8 {
    u8::from(criteria.category)
        + u8::from(criteria.invariant)
        + u8::from(criteria.source)
        + u8::from(criteria.sink)
        + u8::from(criteria.evidence_path)
}

fn location_matches(expected: &LocationConstraint, actual: &SourceLocation) -> bool {
    location_variant_matches(&expected.path, expected.line, actual)
        || expected
            .alternatives
            .iter()
            .any(|variant| location_variant_matches(&variant.path, variant.line, actual))
}

fn location_variant_matches(path: &str, line: Option<u32>, actual: &SourceLocation) -> bool {
    path == actual.path && line.is_none_or(|expected_line| expected_line == actual.line)
}

fn evidence_matches(expected: &EvidenceConstraint, finding: &NormalizedFinding) -> bool {
    let Ok(actual_hops) = u32::try_from(finding.evidence_path.len()) else {
        return false;
    };
    if actual_hops < expected.minimum_hops {
        return false;
    }
    let actual_kinds = finding
        .evidence_path
        .iter()
        .map(|hop| hop.kind.as_str())
        .collect::<Vec<_>>();
    let mut next = 0;
    for required in &expected.required_kinds {
        let normalized_required = canonical(required);
        let Some(relative_index) = actual_kinds[next..]
            .iter()
            .position(|actual| *actual == normalized_required)
        else {
            return false;
        };
        next += relative_index + 1;
    }
    true
}

fn canonical(value: &str) -> String {
    value
        .trim()
        .to_ascii_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn duplicate_map(findings: &[&NormalizedFinding]) -> BTreeMap<String, String> {
    let mut canonical_findings = Vec::<&NormalizedFinding>::new();
    let mut duplicate_of = BTreeMap::new();
    for finding in findings {
        if let Some(existing) = canonical_findings
            .iter()
            .find(|existing| same_semantics(existing, finding))
        {
            duplicate_of.insert(finding.finding_id.clone(), existing.finding_id.clone());
        } else {
            canonical_findings.push(finding);
        }
    }
    duplicate_of
}

fn same_semantics(left: &NormalizedFinding, right: &NormalizedFinding) -> bool {
    left.case_id == right.case_id
        && left.category == right.category
        && left.invariant == right.invariant
        && left.source == right.source
        && left.sink == right.sink
        && left.evidence_path == right.evidence_path
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_evidence_does_not_match_required_hops() {
        let constraint = EvidenceConstraint {
            minimum_hops: 2,
            required_kinds: vec!["source".to_owned(), "sink".to_owned()],
        };
        let finding = NormalizedFinding {
            finding_id: "finding-1".to_owned(),
            case_id: "case-1".to_owned(),
            native_rule_id: "rule".to_owned(),
            category: "injection".to_owned(),
            invariant: "untrusted input must not reach command execution".to_owned(),
            severity: crate::model::Severity::High,
            confidence: crate::model::Confidence::High,
            source: SourceLocation {
                path: "app.ts".to_owned(),
                line: 1,
                column: None,
            },
            sink: SourceLocation {
                path: "app.ts".to_owned(),
                line: 2,
                column: None,
            },
            evidence_path: Vec::new(),
            provenance: crate::model::FindingProvenance {
                adapter: "test".to_owned(),
                report_fingerprint: "0".repeat(64),
                raw_index: 0,
            },
        };
        assert!(!evidence_matches(&constraint, &finding));
    }
}
