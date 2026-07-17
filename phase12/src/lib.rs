//! Secure Bench 0.2.1 prospective methodology and stable historical verification foundation.
//!
//! This workspace is scanner-free. It repairs adapter precedence prospectively, generates a
//! disclosed public regression corpus, publishes the authoring contract for a later unseen
//! holdout, and verifies the immutable Phase 0–11 history without executing external processes.

pub mod adapter;
mod conformance;
mod historical;
pub mod methodology;
pub mod regression;

use crate::conformance::validate_public_vectors;
use crate::methodology::{
    Phase12Provenance, Phase13Audit, ProcessAudit, adapter_policy, holdout_authoring_policy,
};
use crate::regression::{
    RegressionManifest, build_regression, manifest_bytes, validate_regression,
};
use secure_bench_core::phase5::EvidenceContractV2;
use secure_bench_core::taxonomy::{FrozenTaxonomy, load_taxonomy};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

/// Secure Bench prospective behavior version.
pub const BENCHMARK_VERSION: &str = "0.2.1";
const PUBLISHED_PHASE12_VERSION: &str = "0.2.0";
/// Required unchanged starting commit.
pub const BASE_COMMIT: &str = "1f3373e6f763876fba3af136648651e6235ede61";
/// Required Phase 12 branch.
pub const BRANCH: &str = "codex/phase-12-prospective-methodology-repair";

const PHASE11_DIAGNOSTIC_SHA256: &str =
    "b38ad8efef6dc440f3fe60202008e5a64ebcff9372fe6cb8be5dd4c5b748a165";
const PHASE11_REGRESSION_SHA256: &str =
    "220652398cf37c2d10d17461229cd1f62cc530faa22d4572091767df840152e2";
const PHASE11_LEDGER_SHA256: &str =
    "46d53fd230c19c97beecd166c4dd27c44169edd16a33aca173a92ff8e1ea98cb";
const PHASE11_VECTORS_SHA256: &str =
    "e2f0ad23d3bb0b8c291fcefb318796ac3143e6fcb846cf5376e29bcf1759e115";
const PHASE11_CAUSAL_SHA256: &str =
    "2a9b497398e506be9b3bfaed1a71acb30122e6f4978d26167213dc40f09d9eae";
const PHASE10_RESULT_SHA256: &str =
    "bfb74fbc89345bcb6c8584fc8774b2347f31816bdbf1efc9628e96cab8904a7c";

const TAXONOMY_PATH: &str = "taxonomy/secure-bench-taxonomy-v1.json";
const EVIDENCE_CONTRACT_PATH: &str = "holdout/phase-5/evidence-contract-v2.json";
const PROCESS_POLICY_PATH: &str = "policies/process-status-v1.json";
const VECTORS_PATH: &str = "diagnostics/phase-11/evidence-contract-v2-conformance-v1.json";
const MANIFEST_PATH: &str = "phase12/public-regression/manifest.json";
const ADAPTER_POLICY_PATH: &str = "phase12/policies/adapter-precedence-v1.json";
const HOLDOUT_POLICY_PATH: &str = "phase12/methodology/holdout-authoring-v1.json";
const PROVENANCE_PATH: &str = "phase12/provenance.json";
const CHECKSUMS_PATH: &str = "phase12/SHA256SUMS";

const PUBLISHED_HISTORICAL_ROOTS: [&str; 24] = [
    ".github",
    "Cargo.lock",
    "Cargo.toml",
    "CONTRIBUTING.md",
    "GOAL.md",
    "LICENSE",
    "PLAN.md",
    "README.md",
    "SECURITY.md",
    "apps",
    "artifacts",
    "baselines",
    "crates",
    "deny.toml",
    "docs",
    "fixtures",
    "holdout",
    "phase8",
    "phase9",
    "phase10",
    "phase11",
    "policies",
    "schemas",
    "taxonomy",
];

/// Phase 12 request, contract, or integrity failure.
#[derive(Debug, Error)]
pub enum Phase12Error {
    /// Invalid command-line or public API request.
    #[error("invalid Phase 12 request: {0}")]
    InvalidRequest(String),
    /// Prospective adapter rejected a report projection.
    #[error("Phase 12 adapter rejected evidence: {0}")]
    Adapter(String),
    /// Public conformance vector differed.
    #[error("Phase 12 conformance validation failed: {0}")]
    InvalidConformance(String),
    /// Public regression corpus differed.
    #[error("Phase 12 public regression validation failed: {0}")]
    InvalidRegression(String),
    /// Methodology or provenance contract differed.
    #[error("Phase 12 methodology validation failed: {0}")]
    InvalidMethodology(String),
    /// Historical evidence differed.
    #[error("Phase 12 historical integrity failed: {0}")]
    HistoricalIntegrity(String),
    /// Filesystem operation failed.
    #[error("Phase 12 filesystem operation failed for `{path}`: {detail}")]
    Io {
        /// Portable path context.
        path: String,
        /// Operating-system error detail.
        detail: String,
    },
    /// JSON serialization failed.
    #[error("Phase 12 serialization failed: {0}")]
    Serialization(String),
}

/// Scanner-free verification summary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Phase12Summary {
    /// Prospective benchmark version.
    pub benchmark_version: &'static str,
    /// Public regression pair count.
    pub pairs: u64,
    /// Public regression case count.
    pub cases: u64,
    /// Public conformance vector count.
    pub conformance_vectors: u64,
    /// Generated artifact count, excluding the checksum index.
    pub artifacts: u64,
    /// Historical payload aggregate.
    pub historical_payload_sha256: String,
}

fn io(path: &Path, error: &std::io::Error) -> Phase12Error {
    Phase12Error::Io {
        path: path.to_string_lossy().into_owned(),
        detail: error.to_string(),
    }
}

fn safe_relative(relative: &str) -> Result<PathBuf, Phase12Error> {
    let path = Path::new(relative);
    if relative.is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(Phase12Error::InvalidRequest(format!(
            "path `{relative}` is not a portable relative path"
        )));
    }
    Ok(path.to_path_buf())
}

fn read(root: &Path, relative: &str) -> Result<Vec<u8>, Phase12Error> {
    let path = root.join(safe_relative(relative)?);
    fs::read(&path).map_err(|error| io(&path, &error))
}

pub(crate) fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

pub(crate) fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, Phase12Error> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| Phase12Error::Serialization(error.to_string()))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn parse<T: for<'de> Deserialize<'de>>(bytes: &[u8], label: &str) -> Result<T, Phase12Error> {
    serde_json::from_slice(bytes)
        .map_err(|error| Phase12Error::InvalidMethodology(format!("{label}: {error}")))
}

fn expected_inputs() -> [(&'static str, &'static str); 6] {
    [
        (
            "diagnostics/phase-11/retired-diagnostic-v1.json",
            PHASE11_DIAGNOSTIC_SHA256,
        ),
        (
            "diagnostics/phase-11/regression-manifest-v1.json",
            PHASE11_REGRESSION_SHA256,
        ),
        (
            "diagnostics/phase-11/benchmark-defect-ledger-v1.jsonl",
            PHASE11_LEDGER_SHA256,
        ),
        (VECTORS_PATH, PHASE11_VECTORS_SHA256),
        ("docs/phase-11-postmortem.md", PHASE11_CAUSAL_SHA256),
        (
            "phase10/output/secure-engine-0-1-4-phase9-holdout/result.json",
            PHASE10_RESULT_SHA256,
        ),
    ]
}

fn verify_historical_inputs(root: &Path) -> Result<BTreeMap<String, String>, Phase12Error> {
    let mut inputs = BTreeMap::new();
    for (path, expected) in expected_inputs() {
        let actual = sha256(&read(root, path)?);
        if actual != expected {
            return Err(Phase12Error::HistoricalIntegrity(format!(
                "`{path}` is {actual}, expected {expected}"
            )));
        }
        if path.starts_with("diagnostics/phase-11") || path == "docs/phase-11-postmortem.md" {
            inputs.insert(path.to_owned(), actual);
        }
    }
    secure_bench_phase11::verify_repository(root)
        .map_err(|error| Phase12Error::HistoricalIntegrity(error.to_string()))?;
    Ok(inputs)
}

fn load_contracts(root: &Path) -> Result<(FrozenTaxonomy, EvidenceContractV2), Phase12Error> {
    let taxonomy_bytes = read(root, TAXONOMY_PATH)?;
    let taxonomy = load_taxonomy(&taxonomy_bytes)
        .map_err(|error| Phase12Error::InvalidMethodology(error.to_string()))?;
    let contract: EvidenceContractV2 =
        parse(&read(root, EVIDENCE_CONTRACT_PATH)?, "Evidence Contract v2")?;
    if contract.contract_version != "2.0.0"
        || contract.taxonomy.taxonomy_version != taxonomy.taxonomy_version
        || contract.taxonomy.content_hash != taxonomy.content_hash
    {
        return Err(Phase12Error::InvalidMethodology(
            "Evidence Contract v2 and frozen taxonomy binding differ".to_owned(),
        ));
    }
    secure_bench_core::schema::validate_evidence_contract_v2(&contract)
        .map_err(|error| Phase12Error::InvalidMethodology(error.to_string()))?;
    Ok((taxonomy, contract))
}

fn provenance(
    root: &Path,
    phase11_inputs: BTreeMap<String, String>,
    historical_payload_sha256: String,
) -> Result<Phase12Provenance, Phase12Error> {
    Ok(Phase12Provenance {
        schema_version: methodology::PROVENANCE_SCHEMA.to_owned(),
        benchmark_version: PUBLISHED_PHASE12_VERSION.to_owned(),
        base_commit: BASE_COMMIT.to_owned(),
        phase11_inputs,
        taxonomy_sha256: sha256(&read(root, TAXONOMY_PATH)?),
        evidence_contract_sha256: sha256(&read(root, EVIDENCE_CONTRACT_PATH)?),
        process_status_policy_sha256: sha256(&read(root, PROCESS_POLICY_PATH)?),
        historical_payload_sha256,
        historical_roots: PUBLISHED_HISTORICAL_ROOTS
            .iter()
            .map(ToString::to_string)
            .collect(),
        official_phase10_result_sha256: PHASE10_RESULT_SHA256.to_owned(),
        process_audit: ProcessAudit {
            scanner_processes_started: 0,
            external_processes_started: 0,
            secure_engine_executed: false,
            secure_engine_source_inspected: false,
            phase10_rescored: false,
        },
        phase13_audit: Phase13Audit {
            fixtures_created: false,
            answers_created: false,
            manifest_created: false,
            ledger_created: false,
        },
        limitations: vec![
            "The public regression corpus is disclosed development material, not an unseen holdout or production benchmark.".to_owned(),
            "Phase 12 validates contracts and fixture semantics; it does not measure scanner detection.".to_owned(),
            "No result supports a ranking, superiority, production-readiness, or complete-coverage claim.".to_owned(),
        ],
    })
}

fn build_artifacts(
    root: &Path,
) -> Result<(BTreeMap<String, Vec<u8>>, Phase12Summary), Phase12Error> {
    let phase11_inputs = verify_historical_inputs(root)?;
    let historical = historical::verify_committed_baseline(root)?;
    let (taxonomy, contract) = load_contracts(root)?;
    let taxonomy_sha = sha256(&read(root, TAXONOMY_PATH)?);
    let contract_sha = sha256(&read(root, EVIDENCE_CONTRACT_PATH)?);
    let (manifest, fixtures) = build_regression(&taxonomy, taxonomy_sha, contract_sha)?;
    let vectors = validate_public_vectors(&read(root, VECTORS_PATH)?, &contract, &taxonomy)?;

    let mut artifacts = BTreeMap::new();
    for (path, bytes) in fixtures {
        artifacts.insert(format!("phase12/public-regression/{path}"), bytes);
    }
    artifacts.insert(MANIFEST_PATH.to_owned(), manifest_bytes(&manifest)?);
    artifacts.insert(
        ADAPTER_POLICY_PATH.to_owned(),
        canonical_json(&adapter_policy())?,
    );
    artifacts.insert(
        HOLDOUT_POLICY_PATH.to_owned(),
        canonical_json(&holdout_authoring_policy())?,
    );
    artifacts.insert(
        PROVENANCE_PATH.to_owned(),
        canonical_json(&provenance(
            root,
            phase11_inputs,
            "c21efa9e73b47b6d8e04986f576b6c835860c2b5b15a58bbab053fee2dcca0f5".to_owned(),
        )?)?,
    );
    let artifact_count = u64::try_from(artifacts.len())
        .map_err(|_| Phase12Error::InvalidMethodology("artifact count overflow".to_owned()))?;
    let mut checksums = Vec::new();
    for (path, bytes) in &artifacts {
        checksums.extend_from_slice(format!("{}  {path}\n", sha256(bytes)).as_bytes());
    }
    artifacts.insert(CHECKSUMS_PATH.to_owned(), checksums);
    Ok((
        artifacts,
        Phase12Summary {
            benchmark_version: BENCHMARK_VERSION,
            pairs: u64::try_from(manifest.pairs.len())
                .map_err(|_| Phase12Error::InvalidRegression("pair count overflow".to_owned()))?,
            cases: u64::try_from(manifest.pairs.len() * 2)
                .map_err(|_| Phase12Error::InvalidRegression("case count overflow".to_owned()))?,
            conformance_vectors: vectors,
            artifacts: artifact_count,
            historical_payload_sha256: historical,
        },
    ))
}

fn validate_schema(root: &Path, schema: &str, bytes: &[u8]) -> Result<(), Phase12Error> {
    let schema_value: Value = parse(&read(root, schema)?, schema)?;
    let instance: Value = parse(bytes, "Phase 12 artifact")?;
    let validator = jsonschema::validator_for(&schema_value)
        .map_err(|error| Phase12Error::InvalidMethodology(error.to_string()))?;
    validator.validate(&instance).map_err(|error| {
        Phase12Error::InvalidMethodology(format!("schema `{schema}` rejected an artifact: {error}"))
    })
}

fn validate_artifact_contracts(
    root: &Path,
    artifacts: &BTreeMap<String, Vec<u8>>,
) -> Result<(), Phase12Error> {
    let schemas = [
        (
            MANIFEST_PATH,
            "phase12/schemas/phase12-public-regression-v1.schema.json",
        ),
        (
            ADAPTER_POLICY_PATH,
            "phase12/schemas/phase12-adapter-policy-v1.schema.json",
        ),
        (
            HOLDOUT_POLICY_PATH,
            "phase12/schemas/phase12-holdout-authoring-v1.schema.json",
        ),
        (
            PROVENANCE_PATH,
            "phase12/schemas/phase12-provenance-v1.schema.json",
        ),
    ];
    for (artifact, schema) in schemas {
        validate_schema(
            root,
            schema,
            artifacts.get(artifact).ok_or_else(|| {
                Phase12Error::InvalidMethodology(format!(
                    "generated artifact `{artifact}` is missing"
                ))
            })?,
        )?;
    }
    Ok(())
}

fn phase13_absent(root: &Path) -> Result<(), Phase12Error> {
    for relative in [
        "phase13",
        "holdout/phase-13",
        "fixtures/phase-13",
        "artifacts/phase-13",
        "phase12/phase13-fixtures",
        "phase12/phase13-answers.json",
        "phase12/phase13-manifest.json",
        "phase12/phase13-ledger.jsonl",
    ] {
        if root.join(relative).exists() {
            return Err(Phase12Error::InvalidMethodology(format!(
                "prohibited future holdout artifact `{relative}` exists"
            )));
        }
    }
    Ok(())
}

/// Generates the deterministic Phase 12 public artifacts and fixtures.
///
/// This function writes only under `phase12/` and does not launch a process.
///
/// # Errors
///
/// Returns an error for historical drift, invalid contracts, unsafe paths, or filesystem failure.
pub fn generate_repository(root: &Path) -> Result<Phase12Summary, Phase12Error> {
    phase13_absent(root)?;
    let (artifacts, summary) = build_artifacts(root)?;
    validate_artifact_contracts(root, &artifacts)?;
    for (relative, bytes) in artifacts {
        let path = root.join(safe_relative(&relative)?);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| io(parent, &error))?;
        }
        fs::write(&path, bytes).map_err(|error| io(&path, &error))?;
    }
    Ok(summary)
}

/// Verifies every Phase 12 artifact by deterministic reconstruction.
///
/// # Errors
///
/// Returns an error for any schema, taxonomy, provenance, privacy, corpus, conformance, Phase 13,
/// historical, or byte-reconstruction mismatch.
pub fn verify_repository(root: &Path) -> Result<Phase12Summary, Phase12Error> {
    phase13_absent(root)?;
    let (artifacts, summary) = build_artifacts(root)?;
    validate_artifact_contracts(root, &artifacts)?;
    for (relative, expected) in &artifacts {
        let actual = read(root, relative)?;
        if &actual != expected {
            return Err(Phase12Error::InvalidMethodology(format!(
                "committed artifact `{relative}` differs from deterministic reconstruction"
            )));
        }
        let text = String::from_utf8_lossy(&actual).to_ascii_lowercase();
        if text.contains("/home/")
            || text.contains("danielcastrillon")
            || text.contains("proyectos/")
            || text.contains("\"api_key\"")
            || text.contains("\"access_token\"")
        {
            return Err(Phase12Error::InvalidMethodology(format!(
                "committed artifact `{relative}` failed privacy validation"
            )));
        }
    }
    let manifest: RegressionManifest = parse(
        artifacts
            .get(MANIFEST_PATH)
            .ok_or_else(|| Phase12Error::InvalidRegression("manifest is missing".to_owned()))?,
        "public regression manifest",
    )?;
    let fixture_prefix = "phase12/public-regression/";
    let files = artifacts
        .iter()
        .filter_map(|(path, bytes)| {
            path.strip_prefix(fixture_prefix)
                .filter(|path| *path != "manifest.json")
                .map(|path| (path.to_owned(), bytes.clone()))
        })
        .collect::<BTreeMap<_, _>>();
    let taxonomy = load_taxonomy(&read(root, TAXONOMY_PATH)?)
        .map_err(|error| Phase12Error::InvalidRegression(error.to_string()))?;
    validate_regression(&manifest, &files, &taxonomy)?;
    Ok(summary)
}

/// Produces a concise neutral public summary without fixture answers.
///
/// # Errors
///
/// Returns an error if repository verification fails.
pub fn summarize_repository(root: &Path) -> Result<String, Phase12Error> {
    let summary = verify_repository(root)?;
    Ok(format!(
        "benchmark_version={} public_regression_pairs={} public_regression_cases={} conformance_vectors={} disclosed_development_material=true unseen_holdout=false phase10_rescored=false scanner_processes_started=0 phase13_holdout_created=false",
        summary.benchmark_version, summary.pairs, summary.cases, summary.conformance_vectors
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::{AdapterRoute, ProjectionSource, adapt_finding};
    use crate::regression::{mutate_control_barrier_value, mutate_taxonomy};
    use secure_bench_core::phase5::{
        CanonicalFindingV2, EvidenceExpectationV2, EvidenceMatchV2, match_evidence_v2,
    };
    use secure_bench_phase8::{
        ProcessStatusDecision, ProcessTermination, ReportAssessment, adjudicate_status,
    };
    use serde_json::json;

    fn root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_default()
    }

    fn exact_vector_report() -> Result<(Value, EvidenceExpectationV2), Phase12Error> {
        let suite: Value = parse(&read(&root(), VECTORS_PATH)?, "vectors")?;
        let vector = &suite["vectors"][0];
        let finding: CanonicalFindingV2 = serde_json::from_value(vector["finding"].clone())
            .map_err(|error| Phase12Error::InvalidConformance(error.to_string()))?;
        let expectation: EvidenceExpectationV2 =
            serde_json::from_value(vector["expectation"].clone())
                .map_err(|error| Phase12Error::InvalidConformance(error.to_string()))?;
        Ok((
            json!({
                "taxonomy": {
                    "taxonomy_version": finding.taxonomy_version,
                    "category_id": finding.category_id,
                    "invariant_id": finding.invariant_id,
                },
                "primary_cwe": expectation.primary_cwe,
                "evidence_contract_v2": {
                    "contract_version": "2.0.0",
                    "semantics_version": "secure-evidence-semantics-v2",
                    "path": finding.path,
                    "connected_edges": finding.connected_edges,
                    "effective_barriers": finding.effective_barriers,
                    "unresolved_call": finding.unresolved_call,
                    "uncertain": finding.uncertain,
                    "fingerprint": sha256(b"exact-vector"),
                    "duplicate_fingerprint": sha256(b"exact-vector-duplicate"),
                },
                "evidence_path": [{"semantic": {"identity": "generic-unmapped-value"}}],
            }),
            expectation,
        ))
    }

    #[test]
    fn authoritative_v2_repairs_phase10_precedence_defect() -> Result<(), Phase12Error> {
        let repository = root();
        let (taxonomy, contract) = load_contracts(&repository)?;
        let (report, expectation) = exact_vector_report()?;
        let finding = adapt_finding(
            &report,
            AdapterRoute::EvidenceContractV2,
            &contract,
            &taxonomy,
        )?;
        assert_eq!(
            finding.provenance.projection_source,
            ProjectionSource::AuthoritativeEvidenceContractV2
        );
        assert_eq!(
            match_evidence_v2(&contract, &expectation, &finding.canonical),
            EvidenceMatchV2::Exact
        );
        Ok(())
    }

    #[test]
    fn authoritative_projection_fails_closed_without_legacy_fallback() -> Result<(), Phase12Error> {
        let repository = root();
        let (taxonomy, contract) = load_contracts(&repository)?;
        let (mut report, _) = exact_vector_report()?;
        report["evidence_contract_v2"]["contract_version"] = json!("1.0.0");
        report["declared_legacy_projection"] = json!({
            "projection_version": "legacy-compat-v1",
            "taxonomy": report["taxonomy"],
            "primary_cwe": report["primary_cwe"],
            "canonical": report["evidence_contract_v2"],
            "fingerprint": sha256(b"legacy"),
            "duplicate_fingerprint": sha256(b"legacy-duplicate"),
        });
        assert!(
            adapt_finding(
                &report,
                AdapterRoute::ExplicitLegacyCompatibility,
                &contract,
                &taxonomy
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn legacy_route_is_explicit_and_conflicts_fail_closed() -> Result<(), Phase12Error> {
        let repository = root();
        let (taxonomy, contract) = load_contracts(&repository)?;
        let (mut report, _) = exact_vector_report()?;
        let authoritative = adapt_finding(
            &report,
            AdapterRoute::EvidenceContractV2,
            &contract,
            &taxonomy,
        )?;
        let v2 = report["evidence_contract_v2"].clone();
        report
            .as_object_mut()
            .ok_or_else(|| Phase12Error::InvalidConformance("report is not an object".to_owned()))?
            .remove("evidence_contract_v2");
        report["declared_legacy_projection"] = json!({
            "projection_version": "legacy-compat-v1",
            "taxonomy": report["taxonomy"],
            "primary_cwe": report["primary_cwe"],
            "canonical": authoritative.canonical,
            "fingerprint": authoritative.declared_fingerprint,
            "duplicate_fingerprint": authoritative.duplicate_fingerprint,
        });
        assert!(
            adapt_finding(
                &report,
                AdapterRoute::EvidenceContractV2,
                &contract,
                &taxonomy
            )
            .is_err()
        );
        let legacy = adapt_finding(
            &report,
            AdapterRoute::ExplicitLegacyCompatibility,
            &contract,
            &taxonomy,
        )?;
        assert_eq!(
            legacy.provenance.projection_source,
            ProjectionSource::LegacyCompatibilityV1
        );
        report["evidence_contract_v2"] = v2;
        report["declared_legacy_projection"]["canonical"]["uncertain"] = json!(true);
        assert!(
            adapt_finding(
                &report,
                AdapterRoute::EvidenceContractV2,
                &contract,
                &taxonomy
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn taxonomy_drift_and_other_value_barrier_are_rejected() -> Result<(), Phase12Error> {
        let repository = root();
        let taxonomy = load_taxonomy(&read(&repository, TAXONOMY_PATH)?)
            .map_err(|error| Phase12Error::InvalidRegression(error.to_string()))?;
        let (manifest, files) = build_regression(
            &taxonomy,
            sha256(&read(&repository, TAXONOMY_PATH)?),
            sha256(&read(&repository, EVIDENCE_CONTRACT_PATH)?),
        )?;
        let mut drift = manifest.clone();
        mutate_taxonomy(&mut drift);
        assert!(validate_regression(&drift, &files, &taxonomy).is_err());
        let mut wrong_value = manifest;
        mutate_control_barrier_value(&mut wrong_value);
        assert!(validate_regression(&wrong_value, &files, &taxonomy).is_err());
        Ok(())
    }

    fn refresh_case_hash(case: &mut regression::RegressionCase, files: &BTreeMap<String, Vec<u8>>) {
        let mut aggregate = Vec::new();
        for file in &mut case.files {
            if let Some(bytes) = files.get(&file.path) {
                file.sha256 = sha256(bytes);
            }
            aggregate.extend_from_slice(file.path.as_bytes());
            aggregate.push(0);
            aggregate.extend_from_slice(file.sha256.as_bytes());
            aggregate.push(b'\n');
        }
        case.case_sha256 = sha256(&aggregate);
    }

    #[test]
    fn disconnected_direct_flow_duplicate_and_leakage_are_rejected() -> Result<(), Phase12Error> {
        let repository = root();
        let taxonomy = load_taxonomy(&read(&repository, TAXONOMY_PATH)?)
            .map_err(|error| Phase12Error::InvalidRegression(error.to_string()))?;
        let (manifest, files) = build_regression(
            &taxonomy,
            sha256(&read(&repository, TAXONOMY_PATH)?),
            sha256(&read(&repository, EVIDENCE_CONTRACT_PATH)?),
        )?;

        let mut disconnected_manifest = manifest.clone();
        let mut disconnected_files = files.clone();
        let sink_file = disconnected_manifest.pairs[0]
            .vulnerable
            .path
            .last()
            .map(|node| node.span.file.clone())
            .ok_or_else(|| Phase12Error::InvalidRegression("sink is missing".to_owned()))?;
        let source = disconnected_files
            .get(&sink_file)
            .cloned()
            .ok_or_else(|| Phase12Error::InvalidRegression("sink file is missing".to_owned()))?;
        let text = String::from_utf8(source)
            .map_err(|error| Phase12Error::InvalidRegression(error.to_string()))?;
        disconnected_files.insert(
            sink_file,
            text.replace("records.update(candidate)", "records.update(value)")
                .into_bytes(),
        );
        refresh_case_hash(
            &mut disconnected_manifest.pairs[0].vulnerable,
            &disconnected_files,
        );
        assert!(
            validate_regression(&disconnected_manifest, &disconnected_files, &taxonomy).is_err()
        );

        let mut duplicate = manifest.clone();
        let duplicate_id = duplicate.pairs[0].pair_id.clone();
        duplicate.pairs[1].pair_id = duplicate_id;
        assert!(validate_regression(&duplicate, &files, &taxonomy).is_err());

        let mut leaked_manifest = manifest;
        let mut leaked_files = files;
        let leaked_path = leaked_manifest.pairs[0].vulnerable.files[0].path.clone();
        leaked_files
            .get_mut(&leaked_path)
            .ok_or_else(|| Phase12Error::InvalidRegression("leakage file is missing".to_owned()))?
            .extend_from_slice(b"// secure-bench expectation\n");
        refresh_case_hash(&mut leaked_manifest.pairs[0].vulnerable, &leaked_files);
        assert!(validate_regression(&leaked_manifest, &leaked_files, &taxonomy).is_err());
        Ok(())
    }

    #[test]
    fn process_status_remains_separate_from_report_matching() {
        assert_eq!(
            adjudicate_status(
                ProcessTermination::Exited(1),
                ReportAssessment::AdapterValid { findings: 1 }
            ),
            ProcessStatusDecision::PolicyExitWithValidFindingsReport
        );
        assert_eq!(
            adjudicate_status(
                ProcessTermination::Exited(0),
                ReportAssessment::AdapterValid { findings: 0 }
            ),
            ProcessStatusDecision::CleanSuccessfulReport
        );
        assert_eq!(
            adjudicate_status(ProcessTermination::Signaled, ReportAssessment::Missing),
            ProcessStatusDecision::GenuineCrash
        );
        assert_eq!(
            adjudicate_status(ProcessTermination::Timeout, ReportAssessment::Missing),
            ProcessStatusDecision::Timeout
        );
        assert_eq!(
            adjudicate_status(ProcessTermination::Exited(0), ReportAssessment::Malformed),
            ProcessStatusDecision::MalformedReport
        );
        assert_eq!(
            adjudicate_status(
                ProcessTermination::Exited(0),
                ReportAssessment::InternallyErrored
            ),
            ProcessStatusDecision::InternallyErroredReport
        );
    }

    #[test]
    fn deterministic_reconstruction_and_public_vectors_validate() -> Result<(), Phase12Error> {
        let repository = root();
        let first = build_artifacts(&repository)?;
        let second = build_artifacts(&repository)?;
        assert_eq!(first.0, second.0);
        assert_eq!(first.1.pairs, 28);
        assert_eq!(first.1.cases, 56);
        assert_eq!(first.1.conformance_vectors, 19);
        Ok(())
    }

    #[test]
    fn committed_repository_validates_end_to_end() -> Result<(), Phase12Error> {
        let summary = verify_repository(&root())?;
        assert_eq!(summary.benchmark_version, "0.2.1");
        assert_eq!(summary.pairs, 28);
        assert_eq!(summary.cases, 56);
        assert_eq!(summary.conformance_vectors, 19);
        Ok(())
    }

    #[test]
    fn published_phase12_artifacts_remain_byte_identical() -> Result<(), Phase12Error> {
        let repository = root();
        for (path, expected) in [
            (
                MANIFEST_PATH,
                "e4e2d0a4b36d798af3f6add084eb8dcc44958cd11d5a89eda89c52960a9a63ab",
            ),
            (
                ADAPTER_POLICY_PATH,
                "0255000731a6f63ecd1383f3aa9b219627e337a18600d20ff28ef968e4c1826f",
            ),
            (
                HOLDOUT_POLICY_PATH,
                "a13e317a9e515d5389a7ff7d8da99b67da6d588e69284041c8df8eebad8778c5",
            ),
            (
                PROVENANCE_PATH,
                "801929c79381c1f9862effc8f6db2c1fdb5dea35841f0afbd6fe6c1fd3fcf0da",
            ),
            (
                CHECKSUMS_PATH,
                "330724e1b956a19fb2d1e47d10958be28dc00334be35a7ddcaf5027c375b914a",
            ),
            (
                "docs/phase-12-methodology.md",
                "d221251ff0b92f35c43f09e60453331e24e4e92f00cf620267054b4d0974511d",
            ),
        ] {
            assert_eq!(sha256(&read(&repository, path)?), expected, "{path}");
        }
        Ok(())
    }

    #[test]
    fn library_has_no_process_or_network_launch_api() {
        let sources = [
            include_str!("lib.rs"),
            include_str!("adapter.rs"),
            include_str!("conformance.rs"),
            include_str!("methodology.rs"),
            include_str!("regression.rs"),
            include_str!("historical.rs"),
        ]
        .concat();
        let process_api = ["std::process", "::Command"].concat();
        let constructor = ["Command", "::new"].concat();
        let network_api = ["Tcp", "Stream"].concat();
        assert!(!sources.contains(&process_api));
        assert!(!sources.contains(&constructor));
        assert!(!sources.contains(&network_api));
    }
}
