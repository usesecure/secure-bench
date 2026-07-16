//! Frozen taxonomy, adapter-boundary, prospective matching, and baseline-preservation tests.

use secure_bench_core::adapter::{Adapter, SarifAdapter, SecureJsonAdapter, fingerprint};
use secure_bench_core::model::{
    Confidence, EvidenceConstraint, EvidenceHop, ExpectedFinding, FindingProvenance,
    LocationConstraint, NormalizedFinding, ReportedTaxonomyMetadata, Severity, SourceLocation,
    TaxonomyCoordinates,
};
use secure_bench_core::runner::LiveRun;
use secure_bench_core::taxonomy::{
    TaxonomyError, TaxonomyMatchOutcome, TaxonomyResolution, UnmappedReason,
    canonical_taxonomy_json, inspect_taxonomy, load_taxonomy, match_taxonomy_finding,
    resolve_reported_taxonomy, taxonomy_content_hash,
};
use secure_bench_core::{LiveEvaluationInput, evaluate_live_run};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

const TAXONOMY: &[u8] = include_bytes!("../../../taxonomy/secure-bench-taxonomy-v1.json");
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn repository_root() -> TestResult<PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| "core crate must remain inside the workspace".into())
}

fn command_coordinates() -> TaxonomyCoordinates {
    TaxonomyCoordinates {
        taxonomy_version: "1.0.0".to_owned(),
        category_id: "secure-bench.category.command-execution".to_owned(),
        invariant_id: "secure-bench.invariant.command-control-data-separation".to_owned(),
    }
}

fn reported(
    version: Option<&str>,
    category_id: Option<&str>,
    invariant_id: Option<&str>,
) -> ReportedTaxonomyMetadata {
    ReportedTaxonomyMetadata {
        taxonomy_version: version.map(str::to_owned),
        category_id: category_id.map(str::to_owned),
        invariant_id: invariant_id.map(str::to_owned),
    }
}

fn expected() -> ExpectedFinding {
    ExpectedFinding {
        expectation_id: "future-command-expectation".to_owned(),
        taxonomy: Some(command_coordinates()),
        invariant: "display prose selected before a report exists".to_owned(),
        category: "display-only expectation prose".to_owned(),
        severity: Severity::High,
        confidence: Confidence::High,
        source: LocationConstraint {
            path: "src/app.js".to_owned(),
            line: Some(1),
            alternatives: Vec::new(),
        },
        sink: LocationConstraint {
            path: "src/app.js".to_owned(),
            line: Some(2),
            alternatives: Vec::new(),
        },
        evidence: EvidenceConstraint {
            minimum_hops: 2,
            required_kinds: vec!["source".to_owned(), "sink".to_owned()],
        },
    }
}

fn finding() -> NormalizedFinding {
    let source = SourceLocation {
        path: "src/app.js".to_owned(),
        line: 1,
        column: Some(1),
    };
    let sink = SourceLocation {
        path: "src/app.js".to_owned(),
        line: 2,
        column: Some(1),
    };
    NormalizedFinding {
        finding_id: "finding-prospective".to_owned(),
        case_id: "future-case".to_owned(),
        native_rule_id: "scanner-specific-rule".to_owned(),
        taxonomy: Some(reported(
            Some("1.0.0"),
            Some("secure-bench.category.command-execution"),
            Some("secure-bench.invariant.command-control-data-separation"),
        )),
        category: "scanner-controlled category prose".to_owned(),
        invariant: "scanner-controlled invariant prose".to_owned(),
        severity: Severity::Low,
        confidence: Confidence::Low,
        source: source.clone(),
        sink: sink.clone(),
        evidence_path: vec![
            EvidenceHop {
                kind: "source".to_owned(),
                location: source,
            },
            EvidenceHop {
                kind: "sink".to_owned(),
                location: sink,
            },
        ],
        provenance: FindingProvenance {
            adapter: "prospective-test".to_owned(),
            report_fingerprint: fingerprint(b"prospective-test"),
            raw_index: 0,
        },
    }
}

#[test]
fn frozen_taxonomy_is_valid_hashed_canonical_and_byte_stable() -> TestResult {
    let taxonomy = load_taxonomy(TAXONOMY)?;
    let first = canonical_taxonomy_json(&taxonomy)?;
    let second = canonical_taxonomy_json(&taxonomy)?;
    assert_eq!(first, TAXONOMY);
    assert_eq!(first, second);
    assert_eq!(
        taxonomy_content_hash(&taxonomy)?,
        "22852bd7401020b315af11dfa2b60c0b46f78eb19f95079e6400d7b3bea3272c"
    );
    assert_eq!(taxonomy.categories.len(), 7);
    Ok(())
}

#[test]
fn taxonomy_rejects_schema_semantic_and_content_hash_changes() -> TestResult {
    let mut invalid_id: Value = serde_json::from_slice(TAXONOMY)?;
    invalid_id["categories"][0]["category_id"] = json!("scanner.authorization");
    let invalid_id = serde_json::to_vec(&invalid_id)?;
    assert!(matches!(
        inspect_taxonomy(&invalid_id),
        Err(TaxonomyError::InvalidSchema(_))
    ));

    let mut wrong_url: Value = serde_json::from_slice(TAXONOMY)?;
    wrong_url["categories"][0]["primary_cwe"]["url"] =
        json!("https://cwe.mitre.org/data/definitions/78.html");
    let wrong_url = serde_json::to_vec(&wrong_url)?;
    assert!(matches!(
        inspect_taxonomy(&wrong_url),
        Err(TaxonomyError::InvalidSemantics(_))
    ));

    let mut wrong_hash: Value = serde_json::from_slice(TAXONOMY)?;
    wrong_hash["content_hash"] =
        json!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let wrong_hash = serde_json::to_vec(&wrong_hash)?;
    assert_eq!(
        load_taxonomy(&wrong_hash),
        Err(TaxonomyError::ContentHashMismatch)
    );
    Ok(())
}

#[test]
fn resolution_is_explicit_for_every_non_mapping_state() -> TestResult {
    let taxonomy = load_taxonomy(TAXONOMY)?;
    let cases = [
        (None, UnmappedReason::MissingMetadata),
        (
            Some(reported(Some("1.0.0"), None, None)),
            UnmappedReason::MissingFields,
        ),
        (
            Some(reported(
                Some("2.0.0"),
                Some("secure-bench.category.command-execution"),
                Some("secure-bench.invariant.command-control-data-separation"),
            )),
            UnmappedReason::VersionMismatch,
        ),
        (
            Some(reported(
                Some("1.0.0"),
                Some("secure-bench.category.scanner-alias"),
                Some("secure-bench.invariant.command-control-data-separation"),
            )),
            UnmappedReason::UnknownCategory,
        ),
        (
            Some(reported(
                Some("1.0.0"),
                Some("secure-bench.category.command-execution"),
                Some("secure-bench.invariant.scanner-alias"),
            )),
            UnmappedReason::UnknownInvariant,
        ),
        (
            Some(reported(
                Some("1.0.0"),
                Some("secure-bench.category.command-execution"),
                Some("secure-bench.invariant.sql-control-data-separation"),
            )),
            UnmappedReason::ConflictingIdentifiers,
        ),
    ];
    for (metadata, reason) in cases {
        assert_eq!(
            resolve_reported_taxonomy(&taxonomy, metadata.as_ref()),
            TaxonomyResolution::Unmapped { reason }
        );
    }
    Ok(())
}

#[test]
fn native_and_sarif_adapters_preserve_identical_taxonomy_metadata() -> TestResult {
    let taxonomy = json!({
        "taxonomy_version": "1.0.0",
        "category_id": "secure-bench.category.command-execution",
        "invariant_id": "secure-bench.invariant.command-control-data-separation"
    });
    let native = serde_json::to_vec(&json!({
        "schema_version": "secure-json-v1",
        "findings": [{
            "case_id": "future-case",
            "rule_id": "native.command",
            "taxonomy": taxonomy,
            "category": "display category",
            "invariant": "display invariant",
            "severity": "high",
            "confidence": "high",
            "source": {"path": "src/app.js", "line": 1, "column": 1},
            "sink": {"path": "src/app.js", "line": 2, "column": 1},
            "evidence_path": [
                {"kind": "source", "location": {"path": "src/app.js", "line": 1, "column": 1}},
                {"kind": "sink", "location": {"path": "src/app.js", "line": 2, "column": 1}}
            ]
        }]
    }))?;
    let sarif = serde_json::to_vec(&json!({
        "version": "2.1.0",
        "runs": [{"results": [{
            "ruleId": "sarif.command",
            "properties": {
                "case_id": "future-case",
                "taxonomy": taxonomy,
                "category": "display category",
                "invariant": "display invariant",
                "severity": "high",
                "confidence": "high"
            },
            "locations": [],
            "codeFlows": [{"threadFlows": [{"locations": [
                {"location": {"physicalLocation": {"artifactLocation": {"uri": "src/app.js"}, "region": {"startLine": 1, "startColumn": 1}}, "properties": {"kind": "source"}}},
                {"location": {"physicalLocation": {"artifactLocation": {"uri": "src/app.js"}, "region": {"startLine": 2, "startColumn": 1}}, "properties": {"kind": "sink"}}}
            ]}]}]
        }]}]
    }))?;
    let provenance = fingerprint(b"equivalent taxonomy reports");
    let native = SecureJsonAdapter.normalize(&native, &provenance)?;
    let sarif = SarifAdapter.normalize(&sarif, &provenance)?;
    assert_eq!(native[0].taxonomy, sarif[0].taxonomy);
    assert_eq!(native[0].finding_id, sarif[0].finding_id);
    assert_eq!(native[0].source, sarif[0].source);
    assert_eq!(native[0].sink, sarif[0].sink);
    assert_eq!(native[0].evidence_path, sarif[0].evidence_path);
    Ok(())
}

#[test]
fn adapters_reject_scanner_specific_taxonomy_alias_fields() -> TestResult {
    let report = serde_json::to_vec(&json!({
        "schema_version": "secure-json-v1",
        "findings": [{
            "case_id": "future-case",
            "rule_id": "native.command",
            "taxonomy": {
                "taxonomy_version": "1.0.0",
                "category_id": "secure-bench.category.command-execution",
                "invariant_id": "secure-bench.invariant.command-control-data-separation",
                "scanner_rule_alias": "native.command"
            },
            "category": "display category",
            "invariant": "display invariant",
            "severity": "high",
            "confidence": "high",
            "source": {"path": "src/app.js", "line": 1},
            "sink": {"path": "src/app.js", "line": 2},
            "evidence_path": []
        }]
    }))?;
    assert!(
        SecureJsonAdapter
            .normalize(&report, &fingerprint(&report))
            .is_err()
    );
    Ok(())
}

#[test]
fn prospective_matching_uses_only_canonical_coordinates_and_evidence() -> TestResult {
    let taxonomy = load_taxonomy(TAXONOMY)?;
    let mut expectation = expected();
    let mut observation = finding();
    let first = match_taxonomy_finding(&taxonomy, &expectation, &observation)?;
    assert_eq!(first.outcome, TaxonomyMatchOutcome::Matched);

    expectation.category = "entirely different expectation prose".to_owned();
    expectation.invariant = "another human explanation".to_owned();
    observation.category = "scanner prose changed".to_owned();
    observation.invariant = "scanner explanation changed".to_owned();
    observation.native_rule_id = "another.scanner.rule".to_owned();
    let second = match_taxonomy_finding(&taxonomy, &expectation, &observation)?;
    assert_eq!(first, second);

    observation.taxonomy = Some(reported(
        Some("1.0.0"),
        Some("secure-bench.category.scanner-alias"),
        Some("secure-bench.invariant.command-control-data-separation"),
    ));
    assert_eq!(
        match_taxonomy_finding(&taxonomy, &expectation, &observation)?.outcome,
        TaxonomyMatchOutcome::Unmapped
    );
    Ok(())
}

#[test]
fn committed_phase1_result_remains_exactly_byte_identical() -> TestResult {
    let root = repository_root()?;
    let suite = fs::read(root.join("fixtures/corpus-v1.toml"))?;
    let baseline = root.join("baselines/phase-1-secure-engine-phase6");
    let run_bytes = fs::read(baseline.join("run.json"))?;
    let run: LiveRun = serde_json::from_slice(&run_bytes)?;
    let mut reports = BTreeMap::new();
    for case in &run.cases {
        if let Some(path) = &case.report_path {
            reports.insert(path.clone(), fs::read(baseline.join(path))?);
        }
    }
    let result = evaluate_live_run(&LiveEvaluationInput {
        suite: &suite,
        run_manifest: &run_bytes,
        reports: &reports,
    })?;
    let mut generated = serde_json::to_vec_pretty(&result)?;
    generated.push(b'\n');
    assert_eq!(generated, fs::read(baseline.join("result.json"))?);
    Ok(())
}
