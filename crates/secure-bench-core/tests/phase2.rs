//! Prospective Phase 2 profile, evaluator, stability, and historical-boundary tests.

use secure_bench_core::adapter::fingerprint;
use secure_bench_core::phase2::{
    NetworkIsolationAttestation, Phase2Error, Phase2EvaluationInput, canonical_phase2_json,
    evaluate_phase2, load_network_attestation, load_taxonomy_profile,
};
use secure_bench_core::runner::{LiveRun, load_live_run};
use secure_bench_core::taxonomy::load_taxonomy;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

const SUITE: &[u8] = include_bytes!("../../../fixtures/corpus-v1.toml");
const TAXONOMY: &[u8] = include_bytes!("../../../taxonomy/secure-bench-taxonomy-v1.json");
const PROFILE: &[u8] = include_bytes!("../../../taxonomy/phase-1-corpus-taxonomy-profile-v1.json");
const BINARY_SHA256: &str = "d154c427723f1a259f168d17f4974ced006ecc093d5b9150e8ef7186442aa8e2";
const RPM_SHA256: &str = "a06c21fc0484d2b91ccacce8c49abfce2be9f985b58f79f83f8623a04523c795";

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type SyntheticBundle = (
    Vec<u8>,
    Vec<u8>,
    BTreeMap<String, Vec<u8>>,
    BTreeMap<String, Vec<u8>>,
);

fn repository_root() -> TestResult<PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| "core crate must remain inside the workspace".into())
}

fn attestation() -> TestResult<Vec<u8>> {
    Ok(serde_json::to_vec_pretty(&NetworkIsolationAttestation {
        schema_version: "secure-bench-network-isolation-v1".to_owned(),
        mechanism: "bwrap-unshare-net".to_owned(),
        scope: "version-probe-and-all-scanner-processes".to_owned(),
        interfaces: vec!["lo".to_owned()],
        outbound_connectivity: "blocked".to_owned(),
        probe_target: "1.1.1.1:53".to_owned(),
    })?)
}

fn baseline_bundle(raw_reports_equal: bool) -> TestResult<SyntheticBundle> {
    let root = repository_root()?;
    let baseline = root.join("baselines/phase-1-secure-engine-phase6");
    let source_run = fs::read(baseline.join("run.json"))?;
    let mut primary: LiveRun = load_live_run(&source_run)?;
    "phase-2-contract-primary".clone_into(&mut primary.run_id);
    "secure 0.1.1".clone_into(&mut primary.tool.reported_version);
    BINARY_SHA256.clone_into(&mut primary.tool.binary_fingerprint);
    let mut reports = BTreeMap::new();
    for case in &primary.cases {
        if let Some(path) = &case.report_path {
            reports.insert(path.clone(), fs::read(baseline.join(path))?);
        }
    }
    let mut repeat = primary.clone();
    "phase-2-contract-repeat".clone_into(&mut repeat.run_id);
    let repeat_reports = if raw_reports_equal {
        reports.clone()
    } else {
        let mut changed = reports.clone();
        let path = "reports/phase1-001.json";
        let mut report: serde_json::Value = serde_json::from_slice(
            changed
                .get(path)
                .ok_or("synthetic bundle omitted phase1-001")?,
        )?;
        report["scan"]["started_at"] = serde_json::json!("volatile-repeat-timestamp");
        let bytes = serde_json::to_vec_pretty(&report)?;
        changed.insert(path.to_owned(), bytes.clone());
        let case = repeat
            .cases
            .iter_mut()
            .find(|case| case.case_id == "phase1-001")
            .ok_or("synthetic run omitted phase1-001")?;
        case.report_fingerprint = Some(fingerprint(&bytes));
        case.output_bytes = Some(bytes.len().try_into()?);
        changed
    };
    Ok((
        serde_json::to_vec_pretty(&primary)?,
        serde_json::to_vec_pretty(&repeat)?,
        reports,
        repeat_reports,
    ))
}

#[test]
fn frozen_profile_validates_and_covers_every_vulnerable_expectation() -> TestResult {
    let taxonomy = load_taxonomy(TAXONOMY)?;
    let profile = load_taxonomy_profile(PROFILE, SUITE, &taxonomy)?;
    assert_eq!(profile.assignments.len(), 7);
    assert_eq!(profile.taxonomy_version, "1.0.0");
    assert_eq!(
        profile.suite_fingerprint,
        "57d91da3dff7393b1ee8844072d3999161371403027a6d9c78df56907d61e97b"
    );
    Ok(())
}

#[test]
fn profile_and_isolation_attestation_fail_closed() -> TestResult {
    let taxonomy = load_taxonomy(TAXONOMY)?;
    let mut altered: serde_json::Value = serde_json::from_slice(PROFILE)?;
    altered["assignments"][0]["category_id"] =
        serde_json::json!("secure-bench.category.unknown-scanner-alias");
    assert!(load_taxonomy_profile(&serde_json::to_vec(&altered)?, SUITE, &taxonomy).is_err());

    let mut unsafe_attestation: serde_json::Value = serde_json::from_slice(&attestation()?)?;
    unsafe_attestation["interfaces"] = serde_json::json!(["lo", "eth0"]);
    assert!(matches!(
        load_network_attestation(&serde_json::to_vec(&unsafe_attestation)?),
        Err(Phase2Error::InvalidContract(_))
    ));
    Ok(())
}

#[test]
fn phase2_evaluation_is_deterministic_and_does_not_relabel_phase1() -> TestResult {
    let root = repository_root()?;
    let phase1_result = fs::read(root.join("baselines/phase-1-secure-engine-phase6/result.json"))?;
    assert_eq!(
        fingerprint(&phase1_result),
        "b16c374c21e5738967c82eb836992dc41a8ea0bd10627f34b4dda304b58f7099"
    );
    let (primary, repeat, primary_reports, repeat_reports) = baseline_bundle(true)?;
    let network = attestation()?;
    let input = Phase2EvaluationInput {
        suite: SUITE,
        taxonomy: TAXONOMY,
        profile: PROFILE,
        network_attestation: &network,
        phase1_result: &phase1_result,
        primary_run: &primary,
        primary_reports: &primary_reports,
        repeat_run: &repeat,
        repeat_reports: &repeat_reports,
        binary_fingerprint: BINARY_SHA256,
        source_rpm_fingerprint: RPM_SHA256,
    };
    let first = evaluate_phase2(&input)?;
    let second = evaluate_phase2(&input)?;
    assert_eq!(
        canonical_phase2_json(&first)?,
        canonical_phase2_json(&second)?
    );
    assert_eq!(first.metrics.counts.exact_detections, 0);
    assert_eq!(first.metrics.counts.partial_matches, 5);
    assert_eq!(first.metrics.counts.misses, 2);
    assert_eq!(first.metrics.counts.safe_controls_flagged, 3);
    assert_eq!(first.metrics.counts.clean_safe_controls, 4);
    assert!(first.stability.deterministic_evaluation_equal);
    assert!(first.stability.raw_reports_equal);
    assert_eq!(first.comparison.phase1_exact_detections, 0);
    assert_eq!(first.comparison.remaining_misses.len(), 7);
    Ok(())
}

#[test]
fn volatile_raw_report_metadata_does_not_change_semantic_equality() -> TestResult {
    let root = repository_root()?;
    let phase1_result = fs::read(root.join("baselines/phase-1-secure-engine-phase6/result.json"))?;
    let (primary, repeat, primary_reports, repeat_reports) = baseline_bundle(false)?;
    let network = attestation()?;
    let result = evaluate_phase2(&Phase2EvaluationInput {
        suite: SUITE,
        taxonomy: TAXONOMY,
        profile: PROFILE,
        network_attestation: &network,
        phase1_result: &phase1_result,
        primary_run: &primary,
        primary_reports: &primary_reports,
        repeat_run: &repeat,
        repeat_reports: &repeat_reports,
        binary_fingerprint: BINARY_SHA256,
        source_rpm_fingerprint: RPM_SHA256,
    })?;
    assert!(!result.stability.raw_reports_equal);
    assert!(result.stability.semantic_findings_equal);
    assert!(result.stability.deterministic_evaluation_equal);
    assert_eq!(
        result.stability.primary_semantic_fingerprint,
        result.stability.repeat_semantic_fingerprint
    );
    Ok(())
}
