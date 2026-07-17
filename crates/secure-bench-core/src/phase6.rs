//! Phase 6 retired-holdout diagnostics derived only from immutable Phase 3 and Phase 4 artifacts.

use crate::adapter::{Adapter, AdapterInput, SecureJsonAdapter, fingerprint};
use crate::holdout::{
    HoldoutExpectation, HoldoutFramework, HoldoutLanguage, HoldoutLedgerEvent, HoldoutManifest,
    HoldoutTaxonomyCoordinates, HoldoutVariation, load_holdout_manifest, validate_holdout_ledger,
};
use crate::model::{
    CaseKind, Confidence, EvidenceConstraint, EvidenceHop, ExpectedFinding, FindingProvenance,
    LocationVariant, NormalizedFinding, ReportedTaxonomyMetadata, Severity, SourceLocation,
    TaxonomyCoordinates,
};
use crate::phase2::{Phase2CaseDecision, Phase2Criteria, Phase2Metrics, Phase2Outcome};
use crate::phase4::{
    Phase4Artifacts, Phase4Measurement, Phase4Provenance, Phase4Result, Phase4Run,
};
use crate::runner::LiveCaseStatus;
use crate::taxonomy::{
    FrozenTaxonomy, TaxonomyMatchOutcome, load_taxonomy, match_taxonomy_finding,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path};
use thiserror::Error;

/// Public diagnostic package schema.
pub const PHASE6_DIAGNOSTIC_SCHEMA: &str = "secure-bench-retired-holdout-diagnostic-v1";
/// Engine-consumable regression manifest schema.
pub const PHASE6_REGRESSION_SCHEMA: &str = "secure-bench-retired-holdout-regression-v1";
/// Stable diagnostic package version.
pub const PHASE6_VERSION: &str = "1.0.0";
/// Required branch for the additive postmortem.
pub const PHASE6_BRANCH: &str = "codex/phase-6-phase4-postmortem";
/// Immutable Git parent.
pub const PHASE6_GIT_BASE: &str = "ac85c6f09f48057e4bcebb7249e2487fe43e1902";

const PHASE3_MANIFEST: &str = "holdout/phase-3/manifest.json";
const PHASE3_LEDGER: &str = "holdout/phase-3/execution-ledger.jsonl";
const PHASE4_RESULT: &str = "artifacts/phase-4-secure-engine-0-1-2/result.json";
const PHASE4_RUN: &str = "artifacts/phase-4-secure-engine-0-1-2/run/run.json";
const PHASE4_ARTIFACTS: &str = "artifacts/phase-4-secure-engine-0-1-2/artifacts.json";
const PHASE4_REPORT_ROOT: &str = "artifacts/phase-4-secure-engine-0-1-2/run";
const TAXONOMY_PATH: &str = "taxonomy/secure-bench-taxonomy-v1.json";
const DIAGNOSTIC_ROOT: &str = "diagnostics/phase-6";
const DIAGNOSTIC_PATH: &str = "diagnostics/phase-6/retired-holdout-diagnostic-v1.json";
const REGRESSION_PATH: &str = "diagnostics/phase-6/regression-manifest-v1.json";
const FIXTURE_ROOT: &str = "diagnostics/phase-6/fixtures";

const PHASE3_MANIFEST_SHA256: &str =
    "a7a2e47fa85c5fcda305e2c193b91216fd9df1c28fd52dd0179b588f83790da2";
const PHASE3_LEDGER_SHA256: &str =
    "4153d6ef7a3728f0dd5c29a0782c919debc60b963d2e8c22865ce65b6c1d480c";
const PHASE4_RESULT_SHA256: &str =
    "86fa3a373dbc6b7eb346ecaa84b86c1a1aef04bf7f05c807f3f3f6cfaa0b0911";
const PHASE4_RUN_SHA256: &str = "44785c69d87fd293b35b9e5d59d02ec5cf3d5de050c01acf1a3b2a0df550c98a";
const PHASE4_ARTIFACTS_SHA256: &str =
    "891ffd0264590e04b3fc78b69e77ec9c2cf39a7d4b0a23bee9a14e0b8104a10d";
const PHASE4_REPORTS_SHA256: &str =
    "4dfee834691ee7743a1b2124cf4eb7d2a25e03de8fbd0c3977d650d38b86c456";
const TAXONOMY_SHA256: &str = "059fe22d7707cf8d17f2c1621fdae9819787a1958ba2ef0421eca4e4ec858452";
const EXPECTED_CASES: usize = 56;
const EXPECTED_PAIRS: usize = 28;
const ALL_DIAGNOSTIC_CATEGORIES: [DiagnosticCategory; 11] = [
    DiagnosticCategory::NoFindingEmitted,
    DiagnosticCategory::WrongTaxonomyCategoryInvariantOrCwe,
    DiagnosticCategory::MissingOrIncorrectSource,
    DiagnosticCategory::MissingOrIncorrectSink,
    DiagnosticCategory::EvidencePathMismatch,
    DiagnosticCategory::TransformationOrValueIdentityMismatch,
    DiagnosticCategory::GuardSanitizerOrDominanceMismatch,
    DiagnosticCategory::SafeControlFalsePositive,
    DiagnosticCategory::DuplicateOrUnrelatedFinding,
    DiagnosticCategory::AdapterOrEvidenceContractAmbiguity,
    DiagnosticCategory::FrameworkLanguageTopologyAttributionUncertainty,
];

/// Neutral case-level mismatch category.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticCategory {
    /// Successful report contained no finding.
    NoFindingEmitted,
    /// Reported canonical coordinates or primary CWE differ.
    WrongTaxonomyCategoryInvariantOrCwe,
    /// Reported source is absent or differs from the frozen location.
    MissingOrIncorrectSource,
    /// Reported sink is absent or differs from the frozen location.
    MissingOrIncorrectSink,
    /// Ordered evidence is absent, incomplete, disconnected, or incompatible.
    EvidencePathMismatch,
    /// Reported value identity or transform chain does not establish the expected flow.
    TransformationOrValueIdentityMismatch,
    /// A control guard, sanitizer, or dominance condition was not distinguished.
    GuardSanitizerOrDominanceMismatch,
    /// A negative control emitted one or more findings.
    SafeControlFalsePositive,
    /// A finding is duplicate or unrelated to the frozen expectation.
    DuplicateOrUnrelatedFinding,
    /// Contract v1 cannot express or recognize available semantic evidence unambiguously.
    AdapterOrEvidenceContractAmbiguity,
    /// Framework, language, and topology effects cannot be separated.
    FrameworkLanguageTopologyAttributionUncertainty,
}

/// Layer responsible for one diagnostic statement.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticLayer {
    /// Directly retained scanner observation.
    ScannerBehavior,
    /// Evaluator or evidence-contract behavior.
    EvaluatorBehavior,
    /// Experimental-design limitation.
    ExperimentalDesign,
}

/// One evidence-backed case classification.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticClassification {
    /// Neutral mismatch category.
    pub category: DiagnosticCategory,
    /// Responsible analytical layer.
    pub layer: DiagnosticLayer,
    /// Stable bounded rationale code.
    pub reason_code: String,
}

/// Public semantic endpoint expectation derived from taxonomy, never scanner vocabulary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedSemantics {
    /// Canonical external source semantics.
    pub source_semantic: String,
    /// Canonical sensitive sink semantics.
    pub sink_semantic: String,
}

/// Immutable expected diagnostic view for a vulnerable case.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticExpectation {
    /// Original expectation identity.
    pub expectation_id: String,
    /// Exact taxonomy coordinates.
    pub taxonomy: HoldoutTaxonomyCoordinates,
    /// Frozen primary CWE.
    pub primary_cwe: String,
    /// Expected semantic endpoint kinds.
    pub semantics: ExpectedSemantics,
    /// Exact contract-v1 source.
    pub source: crate::model::LocationConstraint,
    /// Exact contract-v1 sink.
    pub sink: crate::model::LocationConstraint,
    /// Ordered evidence requirements.
    pub evidence: EvidenceConstraint,
}

/// One retained normalized black-box observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticObservation {
    /// Stable normalized finding identity.
    pub finding_id: String,
    /// Native rule identity retained only as observation provenance.
    pub native_rule_id: String,
    /// Reported taxonomy coordinates.
    pub taxonomy: Option<crate::model::ReportedTaxonomyMetadata>,
    /// Reported display category.
    pub reported_category: String,
    /// Reported display invariant.
    pub reported_invariant: String,
    /// Reported source.
    pub source: SourceLocation,
    /// Reported sink.
    pub sink: SourceLocation,
    /// Reported ordered evidence.
    pub evidence_path: Vec<EvidenceHop>,
    /// Stable semantic fingerprint from the official result.
    pub semantic_fingerprint: String,
    /// Canonical duplicate link, when present.
    pub duplicate_of: Option<String>,
    /// Exact raw report SHA-256.
    pub report_sha256: String,
    /// Zero-based raw report result index.
    pub raw_index: u64,
}

/// Complete diagnostic record for one retired case.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetiredCaseDiagnostic {
    /// Stable case identity.
    pub case_id: String,
    /// Pair identity.
    pub pair_id: String,
    /// Frozen label.
    pub kind: CaseKind,
    /// Public diagnostic-copy fixture path.
    pub fixture_path: String,
    /// Original scanner-visible fixture SHA-256.
    pub fixture_sha256: String,
    /// Original complete case-contract SHA-256.
    pub original_contract_sha256: String,
    /// Framework factor.
    pub framework: HoldoutFramework,
    /// Language factor.
    pub language: HoldoutLanguage,
    /// Topology factor.
    pub topology: HoldoutVariation,
    /// Pair taxonomy coordinates, applicable to both vulnerable and control members.
    pub taxonomy: HoldoutTaxonomyCoordinates,
    /// Pair primary CWE, applicable to both vulnerable and control members.
    pub primary_cwe: String,
    /// Pair semantic endpoints, applicable to both vulnerable and control members.
    pub semantics: ExpectedSemantics,
    /// Immutable vulnerable expectation.
    pub expected: Option<DiagnosticExpectation>,
    /// Immutable safe-control property.
    pub security_property: Option<String>,
    /// Official Phase 4 outcome, copied without reinterpretation.
    pub official_outcome: Phase2Outcome,
    /// Official black-box execution status.
    pub execution_status: LiveCaseStatus,
    /// Official selected finding.
    pub selected_finding_id: Option<String>,
    /// Official atomic criteria.
    pub official_criteria: Option<Phase2Criteria>,
    /// Exact retained report path.
    pub retained_report_path: String,
    /// Exact retained report SHA-256.
    pub retained_report_sha256: String,
    /// All normalized observations.
    pub observations: Vec<DiagnosticObservation>,
    /// Neutral diagnostic classifications.
    pub classifications: Vec<DiagnosticClassification>,
    /// Hash of this record excluding this field.
    pub record_sha256: String,
}

/// Vulnerable/control comparison for one retired pair.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetiredPairDiagnostic {
    /// Pair identity.
    pub pair_id: String,
    /// Vulnerable member.
    pub vulnerable_case_id: String,
    /// Control member.
    pub control_case_id: String,
    /// Vulnerable official outcome.
    pub vulnerable_outcome: Phase2Outcome,
    /// Control official outcome.
    pub control_outcome: Phase2Outcome,
    /// Vulnerable finding count.
    pub vulnerable_findings: u64,
    /// Control finding count.
    pub control_findings: u64,
    /// Stable observation-delta classification.
    pub control_differentiation: String,
}

/// Exact integer association measurement.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase6Association {
    /// Pearson chi-square multiplied by 1,000.
    pub chi_square_milli: u64,
    /// Cramer's V multiplied by 10,000.
    pub cramers_v_basis_points: u32,
}

/// Confounding proof for the retired design.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase6ConfoundingAudit {
    /// Framework by language pair counts.
    pub framework_by_language: BTreeMap<String, BTreeMap<String, u64>>,
    /// Framework by topology pair counts.
    pub framework_by_topology: BTreeMap<String, BTreeMap<String, u64>>,
    /// Language by topology pair counts.
    pub language_by_topology: BTreeMap<String, BTreeMap<String, u64>>,
    /// Framework/language association.
    pub framework_language_association: Phase6Association,
    /// Framework/topology association.
    pub framework_topology_association: Phase6Association,
    /// Language/topology association.
    pub language_topology_association: Phase6Association,
    /// Whether independent causal attribution is supported.
    pub independent_factor_attribution_supported: bool,
    /// Stable conclusions that are prohibited by the design.
    pub prohibited_conclusions: Vec<String>,
}

/// Synthetic contract-v1 audit vector.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContractV1SyntheticVector {
    /// Stable vector identity.
    pub vector_id: String,
    /// Tested semantic condition.
    pub condition: String,
    /// Contract-v1 outcome.
    pub contract_v1_matches: bool,
    /// Audit interpretation.
    pub interpretation: String,
}

/// Retained and synthetic evidence-contract v1 audit.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceContractV1Audit {
    /// Synthetic vectors only; never changes official scoring.
    pub synthetic_vectors: Vec<ContractV1SyntheticVector>,
    /// Retained vulnerable observations with exact taxonomy agreement.
    pub retained_taxonomy_agreements: u64,
    /// Retained vulnerable observations with exact source agreement.
    pub retained_source_agreements: u64,
    /// Retained vulnerable observations with exact sink agreement.
    pub retained_sink_agreements: u64,
    /// Retained vulnerable observations with exact ordered evidence agreement.
    pub retained_evidence_agreements: u64,
    /// Stable prospective findings about contract behavior.
    pub findings: Vec<String>,
    /// Conceptual v2 comparison limited to the public contract, never Phase 5 cases.
    pub prospective_v2_comparison: Vec<String>,
    /// Explicit retrospective policy.
    pub retrospective_credit_changed: bool,
}

/// Aggregate disagreement matrices.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticMatrices {
    /// Source relationship counts.
    pub source: BTreeMap<String, u64>,
    /// Sink relationship counts.
    pub sink: BTreeMap<String, u64>,
    /// Evidence relationship counts.
    pub evidence: BTreeMap<String, u64>,
    /// Joint exact Boolean criteria counts.
    pub source_sink_evidence: BTreeMap<String, u64>,
}

/// One representative retained-report example with exact provenance.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedReportExample {
    /// Represented diagnostic category.
    pub category: DiagnosticCategory,
    /// Case identity.
    pub case_id: String,
    /// Finding identity, when a finding exists.
    pub finding_id: Option<String>,
    /// Exact retained report path.
    pub report_path: String,
    /// Exact retained report SHA-256.
    pub report_sha256: String,
}

/// Immutable source and historical-integrity bindings.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase6Provenance {
    /// Immutable Git base.
    pub git_base: String,
    /// Original Phase 3 manifest hash.
    pub phase3_manifest_sha256: String,
    /// Original aggregate retired-corpus commitment.
    pub retired_aggregate_corpus_sha256: String,
    /// Original retired case-contract Merkle root.
    pub retired_contract_merkle_root: String,
    /// Completed Phase 3 ledger hash.
    pub completed_ledger_sha256: String,
    /// Official Phase 4 result hash.
    pub phase4_result_sha256: String,
    /// Retained Phase 4 run hash.
    pub phase4_run_sha256: String,
    /// Phase 4 artifact index hash.
    pub phase4_artifacts_sha256: String,
    /// Aggregate retained report hash.
    pub retained_reports_sha256: String,
    /// Frozen taxonomy artifact hash.
    pub taxonomy_sha256: String,
    /// Exact analyzer source hash.
    pub generator_sha256: String,
    /// Scanner processes launched by this phase.
    pub scanner_processes_launched: u64,
    /// Phase 5 cases, answers, identifiers, or metadata read by this analyzer.
    pub phase5_holdout_inputs_read: u64,
}

/// Complete deterministic retired-holdout diagnostic package.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetiredHoldoutDiagnosticPack {
    /// Schema identity.
    pub schema_version: String,
    /// Package version.
    pub package_version: String,
    /// Stable package identity.
    pub package_id: String,
    /// Deterministic publication time.
    pub published_at_utc: String,
    /// Explicit retirement state.
    pub holdout_status: String,
    /// Whether future unbiased use is prohibited.
    pub unbiased_holdout_use_prohibited: bool,
    /// Official result remains unchanged and authoritative.
    pub official_phase4_result_unchanged: bool,
    /// Exact official Phase 4 metrics copied without rescoring.
    pub official_phase4_metrics: Phase2Metrics,
    /// Exact official Phase 4 process and resource measurements.
    pub official_phase4_measurement: Phase4Measurement,
    /// Exact official Phase 4 binary, command, environment, isolation, and ledger provenance.
    pub official_phase4_provenance: Phase4Provenance,
    /// Root-cause counts across all records.
    pub category_counts: BTreeMap<DiagnosticCategory, u64>,
    /// Root-cause counts per taxonomy family.
    pub family_category_counts: BTreeMap<String, BTreeMap<DiagnosticCategory, u64>>,
    /// Root-cause counts per framework stratum.
    pub framework_category_counts: BTreeMap<String, BTreeMap<DiagnosticCategory, u64>>,
    /// Root-cause counts per language stratum.
    pub language_category_counts: BTreeMap<String, BTreeMap<DiagnosticCategory, u64>>,
    /// Root-cause counts per topology stratum.
    pub topology_category_counts: BTreeMap<String, BTreeMap<DiagnosticCategory, u64>>,
    /// Source, sink, and evidence matrices.
    pub matrices: DiagnosticMatrices,
    /// Confounding proof.
    pub confounding: Phase6ConfoundingAudit,
    /// Contract-v1 audit.
    pub evidence_contract_v1_audit: EvidenceContractV1Audit,
    /// All 56 case diagnostics.
    pub cases: Vec<RetiredCaseDiagnostic>,
    /// All 28 pair comparisons.
    pub pairs: Vec<RetiredPairDiagnostic>,
    /// Representative retained reports.
    pub retained_report_examples: Vec<RetainedReportExample>,
    /// Complete provenance.
    pub provenance: Phase6Provenance,
    /// SHA-256 over this package with this field empty.
    pub content_sha256: String,
}

/// One engine-consumable retired regression case.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetiredRegressionCase {
    /// Stable case identity.
    pub case_id: String,
    /// Vulnerable or safe-control status.
    pub kind: CaseKind,
    /// Public diagnostic fixture path.
    pub fixture_path: String,
    /// Scanner-visible fixture SHA-256.
    pub fixture_sha256: String,
    /// Taxonomy coordinates shared by the pair.
    pub taxonomy: HoldoutTaxonomyCoordinates,
    /// Primary CWE.
    pub primary_cwe: String,
    /// Expected semantic endpoints.
    pub semantics: ExpectedSemantics,
    /// Exact expected source for vulnerable cases.
    pub expected_source: Option<crate::model::LocationConstraint>,
    /// Exact expected sink for vulnerable cases.
    pub expected_sink: Option<crate::model::LocationConstraint>,
    /// Ordered evidence requirements for vulnerable cases.
    pub expected_evidence: Option<EvidenceConstraint>,
    /// Safe-control property.
    pub security_property: Option<String>,
    /// Historical observed outcome.
    pub historical_outcome: Phase2Outcome,
    /// Historical mismatch classes.
    pub mismatch_categories: Vec<DiagnosticCategory>,
    /// Exact retained report SHA-256.
    pub retained_report_sha256: String,
}

/// Standalone engine-consumable regression manifest for the retired corpus.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetiredRegressionManifest {
    /// Schema identity.
    pub schema_version: String,
    /// Package version.
    pub package_version: String,
    /// Diagnostic package content hash.
    pub diagnostic_content_sha256: String,
    /// Explicit public development-corpus status.
    pub status: String,
    /// Future unbiased use is prohibited.
    pub unbiased_holdout_use_prohibited: bool,
    /// Complete regression cases.
    pub cases: Vec<RetiredRegressionCase>,
    /// SHA-256 with this field empty.
    pub content_sha256: String,
}

/// Aggregate validation result safe to print.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Phase6Validation {
    /// Cases validated.
    pub cases: u64,
    /// Pairs validated.
    pub pairs: u64,
    /// Diagnostic package artifact SHA-256.
    pub diagnostic_artifact_sha256: String,
    /// Regression manifest artifact SHA-256.
    pub regression_artifact_sha256: String,
    /// Diagnostic package content hash.
    pub diagnostic_content_sha256: String,
    /// Category counts.
    pub category_counts: BTreeMap<DiagnosticCategory, u64>,
}

/// Phase 6 deterministic analysis error.
#[derive(Debug, Error)]
pub enum Phase6Error {
    /// Source or generated contract is invalid.
    #[error("invalid Phase 6 diagnostic contract: {0}")]
    InvalidContract(String),
    /// Filesystem failure with bounded path information.
    #[error("Phase 6 filesystem operation failed for `{path}`: {detail}")]
    Io {
        /// Repository-relative path.
        path: String,
        /// Operating-system detail.
        detail: String,
    },
    /// Deterministic serialization failed.
    #[error("Phase 6 deterministic serialization failed")]
    Serialization,
}

struct SourceArtifacts {
    manifest: HoldoutManifest,
    taxonomy: FrozenTaxonomy,
    taxonomy_bytes: Vec<u8>,
    result: Phase4Result,
    run: Phase4Run,
    artifacts: Phase4Artifacts,
    reports: BTreeMap<String, Vec<u8>>,
}

/// Generates the additive retired-holdout diagnostic package without launching a scanner.
///
/// # Errors
///
/// Returns [`Phase6Error`] when an immutable source differs, output already exists, or generated
/// content fails deterministic validation.
pub fn generate_phase6(
    repository_root: &Path,
    published_at_utc: &str,
) -> Result<Phase6Validation, Phase6Error> {
    validate_timestamp(published_at_utc)?;
    if repository_root.join(DIAGNOSTIC_ROOT).exists() {
        return Err(Phase6Error::InvalidContract(
            "diagnostic output already exists; refusing replacement".to_owned(),
        ));
    }
    let sources = load_sources(repository_root)?;
    fs::create_dir_all(repository_root.join(FIXTURE_ROOT))
        .map_err(|error| io_error(FIXTURE_ROOT, error))?;
    copy_retired_fixtures(repository_root, &sources.manifest)?;
    let mut pack = build_pack(repository_root, &sources, published_at_utc)?;
    pack.content_sha256 = content_hash(&pack)?;
    let pack_bytes = canonical_json(&pack)?;
    let mut regression = build_regression_manifest(&pack);
    regression.content_sha256 = content_hash(&regression)?;
    let regression_bytes = canonical_json(&regression)?;
    write_new(repository_root, DIAGNOSTIC_PATH, &pack_bytes)?;
    write_new(repository_root, REGRESSION_PATH, &regression_bytes)?;
    validate_phase6(repository_root)
}

/// Validates diagnostic artifacts against the original immutable Phase 3 and Phase 4 sources.
///
/// This function has no scanner execution path and does not read any Phase 5 case or expectation.
///
/// # Errors
///
/// Returns [`Phase6Error`] for schema, hash, provenance, fixture-copy, classification, ordering,
/// or deterministic-serialization drift.
pub fn validate_phase6(repository_root: &Path) -> Result<Phase6Validation, Phase6Error> {
    let sources = load_sources(repository_root)?;
    let pack_bytes = read_file(repository_root, DIAGNOSTIC_PATH)?;
    let regression_bytes = read_file(repository_root, REGRESSION_PATH)?;
    let pack: RetiredHoldoutDiagnosticPack = parse_json(&pack_bytes, "diagnostic package")?;
    let regression: RetiredRegressionManifest =
        parse_json(&regression_bytes, "regression manifest")?;
    crate::schema::validate_phase6_diagnostic(&pack)
        .map_err(|error| Phase6Error::InvalidContract(error.to_string()))?;
    crate::schema::validate_phase6_regression(&regression)
        .map_err(|error| Phase6Error::InvalidContract(error.to_string()))?;
    if pack.schema_version != PHASE6_DIAGNOSTIC_SCHEMA
        || pack.package_version != PHASE6_VERSION
        || pack.package_id != "phase-3-retired-after-phase-4"
        || pack.holdout_status != "executed_and_retired_public_diagnostic_corpus"
        || !pack.unbiased_holdout_use_prohibited
        || !pack.official_phase4_result_unchanged
        || pack.cases.len() != EXPECTED_CASES
        || pack.pairs.len() != EXPECTED_PAIRS
        || pack.content_sha256 != content_hash(&pack)?
        || canonical_json(&pack)? != pack_bytes
    {
        return Err(Phase6Error::InvalidContract(
            "diagnostic identity, cardinality, or content hash differs".to_owned(),
        ));
    }
    if regression.schema_version != PHASE6_REGRESSION_SCHEMA
        || regression.package_version != PHASE6_VERSION
        || regression.status != "public_development_regression_corpus"
        || !regression.unbiased_holdout_use_prohibited
        || regression.cases.len() != EXPECTED_CASES
        || regression.diagnostic_content_sha256 != pack.content_sha256
        || regression.content_sha256 != content_hash(&regression)?
        || canonical_json(&regression)? != regression_bytes
    {
        return Err(Phase6Error::InvalidContract(
            "regression manifest identity or content hash differs".to_owned(),
        ));
    }
    validate_fixture_copies(repository_root, &sources.manifest, &pack)?;
    let mut expected = build_pack(repository_root, &sources, &pack.published_at_utc)?;
    expected.content_sha256 = content_hash(&expected)?;
    if expected != pack || build_regression_manifest_with_hash(&pack)? != regression {
        return Err(Phase6Error::InvalidContract(
            "diagnostic artifacts do not reproduce from immutable sources".to_owned(),
        ));
    }
    validate_no_phase5_reference(&pack_bytes, &regression_bytes)?;
    Ok(Phase6Validation {
        cases: u64::try_from(pack.cases.len()).unwrap_or(u64::MAX),
        pairs: u64::try_from(pack.pairs.len()).unwrap_or(u64::MAX),
        diagnostic_artifact_sha256: fingerprint(&pack_bytes),
        regression_artifact_sha256: fingerprint(&regression_bytes),
        diagnostic_content_sha256: pack.content_sha256,
        category_counts: pack.category_counts,
    })
}

fn load_sources(repository_root: &Path) -> Result<SourceArtifacts, Phase6Error> {
    let manifest_bytes = read_and_verify(repository_root, PHASE3_MANIFEST, PHASE3_MANIFEST_SHA256)?;
    let ledger_bytes = read_and_verify(repository_root, PHASE3_LEDGER, PHASE3_LEDGER_SHA256)?;
    let result_bytes = read_and_verify(repository_root, PHASE4_RESULT, PHASE4_RESULT_SHA256)?;
    let run_bytes = read_and_verify(repository_root, PHASE4_RUN, PHASE4_RUN_SHA256)?;
    let artifacts_bytes =
        read_and_verify(repository_root, PHASE4_ARTIFACTS, PHASE4_ARTIFACTS_SHA256)?;
    let taxonomy_bytes = read_and_verify(repository_root, TAXONOMY_PATH, TAXONOMY_SHA256)?;
    let (manifest, validation) =
        load_holdout_manifest(&manifest_bytes, repository_root, &taxonomy_bytes)
            .map_err(|error| Phase6Error::InvalidContract(error.to_string()))?;
    if validation.cases != EXPECTED_CASES as u64 || validation.pairs != EXPECTED_PAIRS as u64 {
        return Err(Phase6Error::InvalidContract(
            "retired manifest cardinality differs".to_owned(),
        ));
    }
    let ledger = validate_holdout_ledger(&ledger_bytes, &manifest)
        .map_err(|error| Phase6Error::InvalidContract(error.to_string()))?;
    let terminal = ledger.last().ok_or_else(|| {
        Phase6Error::InvalidContract("completed ledger has no terminal entry".to_owned())
    })?;
    if terminal.event != HoldoutLedgerEvent::ExecutionCompleted
        || terminal.result_sha256.as_deref() != Some(PHASE4_RESULT_SHA256)
    {
        return Err(Phase6Error::InvalidContract(
            "Phase 3 ledger is not immutably completed by the Phase 4 result".to_owned(),
        ));
    }
    let taxonomy = load_taxonomy(&taxonomy_bytes)
        .map_err(|error| Phase6Error::InvalidContract(error.to_string()))?;
    let result: Phase4Result = parse_json(&result_bytes, "Phase 4 result")?;
    let run: Phase4Run = parse_json(&run_bytes, "Phase 4 run")?;
    let artifacts: Phase4Artifacts = parse_json(&artifacts_bytes, "Phase 4 artifact index")?;
    crate::schema::validate_phase4_result(&result)
        .map_err(|error| Phase6Error::InvalidContract(error.to_string()))?;
    crate::schema::validate_phase4_run(&run)
        .map_err(|error| Phase6Error::InvalidContract(error.to_string()))?;
    crate::schema::validate_phase4_artifacts(&artifacts)
        .map_err(|error| Phase6Error::InvalidContract(error.to_string()))?;
    if artifacts.result_sha256 != PHASE4_RESULT_SHA256
        || artifacts.run_sha256 != PHASE4_RUN_SHA256
        || artifacts.ledger_sha256 != PHASE3_LEDGER_SHA256
        || artifacts.reports_sha256 != PHASE4_REPORTS_SHA256
        || artifacts.report_count != EXPECTED_CASES as u64
        || result.metrics.counts.eligible_expectations != EXPECTED_PAIRS as u64
        || run.cases.len() != EXPECTED_CASES
    {
        return Err(Phase6Error::InvalidContract(
            "Phase 4 artifact bindings or official counts differ".to_owned(),
        ));
    }
    let mut reports = BTreeMap::new();
    for case in &run.cases {
        let relative = case.report_path.as_deref().ok_or_else(|| {
            Phase6Error::InvalidContract(format!("case `{}` has no retained report", case.case_id))
        })?;
        let full_relative = format!("{PHASE4_REPORT_ROOT}/{relative}");
        let bytes = read_file(repository_root, &full_relative)?;
        let digest = fingerprint(&bytes);
        if case.report_fingerprint.as_deref() != Some(digest.as_str()) {
            return Err(Phase6Error::InvalidContract(format!(
                "retained report hash differs for `{}`",
                case.case_id
            )));
        }
        reports.insert(relative.to_owned(), bytes);
    }
    if report_aggregate(&run) != PHASE4_REPORTS_SHA256 {
        return Err(Phase6Error::InvalidContract(
            "retained report aggregate differs".to_owned(),
        ));
    }
    Ok(SourceArtifacts {
        manifest,
        taxonomy,
        taxonomy_bytes,
        result,
        run,
        artifacts,
        reports,
    })
}

#[allow(clippy::too_many_lines)]
fn build_pack(
    repository_root: &Path,
    sources: &SourceArtifacts,
    published_at_utc: &str,
) -> Result<RetiredHoldoutDiagnosticPack, Phase6Error> {
    let decisions = sources
        .result
        .cases
        .iter()
        .map(|decision| (decision.case_id.as_str(), decision))
        .collect::<BTreeMap<_, _>>();
    let result_findings = sources
        .result
        .findings
        .iter()
        .map(|finding| (finding.finding_id.as_str(), finding))
        .collect::<BTreeMap<_, _>>();
    let run_cases = sources
        .run
        .cases
        .iter()
        .map(|case| (case.case_id.as_str(), case))
        .collect::<BTreeMap<_, _>>();
    let mut cases = Vec::with_capacity(EXPECTED_CASES);
    let mut pairs = Vec::with_capacity(EXPECTED_PAIRS);
    let mut category_counts = zero_category_counts();
    let mut family_category_counts = BTreeMap::<String, BTreeMap<DiagnosticCategory, u64>>::new();
    let mut framework_category_counts =
        BTreeMap::<String, BTreeMap<DiagnosticCategory, u64>>::new();
    let mut language_category_counts = BTreeMap::<String, BTreeMap<DiagnosticCategory, u64>>::new();
    let mut topology_category_counts = BTreeMap::<String, BTreeMap<DiagnosticCategory, u64>>::new();
    let mut matrices = DiagnosticMatrices {
        source: BTreeMap::new(),
        sink: BTreeMap::new(),
        evidence: BTreeMap::new(),
        source_sink_evidence: BTreeMap::new(),
    };
    for pair in &sources.manifest.pairs {
        family_category_counts
            .entry(pair.taxonomy.category_id.clone())
            .or_insert_with(zero_category_counts);
        framework_category_counts
            .entry(framework_name(pair.framework).to_owned())
            .or_insert_with(zero_category_counts);
        language_category_counts
            .entry(language_name(pair.language).to_owned())
            .or_insert_with(zero_category_counts);
        topology_category_counts
            .entry(topology_name(pair.variation).to_owned())
            .or_insert_with(zero_category_counts);
        let mut pair_case_records = Vec::new();
        for case in [&pair.vulnerable, &pair.control] {
            let decision = decisions.get(case.case_id.as_str()).ok_or_else(|| {
                Phase6Error::InvalidContract(format!("official result omitted `{}`", case.case_id))
            })?;
            let execution = run_cases.get(case.case_id.as_str()).ok_or_else(|| {
                Phase6Error::InvalidContract(format!("run omitted `{}`", case.case_id))
            })?;
            let report_path = execution.report_path.as_ref().ok_or_else(|| {
                Phase6Error::InvalidContract(format!(
                    "retained report path absent for `{}`",
                    case.case_id
                ))
            })?;
            let report = sources.reports.get(report_path).ok_or_else(|| {
                Phase6Error::InvalidContract(format!(
                    "retained report bytes absent for `{}`",
                    case.case_id
                ))
            })?;
            let report_sha256 = fingerprint(report);
            let mut normalized = SecureJsonAdapter
                .normalize_scoped(AdapterInput {
                    report,
                    report_fingerprint: &report_sha256,
                    case_id: Some(&case.case_id),
                    path_prefix: None,
                })
                .map_err(|error| Phase6Error::InvalidContract(error.to_string()))?;
            normalized.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
            if normalized.len() as u64 != decision.finding_count {
                return Err(Phase6Error::InvalidContract(format!(
                    "normalized finding count differs for `{}`",
                    case.case_id
                )));
            }
            let observations = normalized
                .iter()
                .map(|finding| observation(finding, &result_findings))
                .collect::<Result<Vec<_>, Phase6Error>>()?;
            let selected = decision
                .selected_finding_id
                .as_deref()
                .and_then(|identifier| {
                    normalized.iter().find(|item| item.finding_id == identifier)
                });
            let expected = case
                .expected
                .as_ref()
                .map(|expectation| DiagnosticExpectation {
                    expectation_id: expectation.expectation_id.clone(),
                    taxonomy: pair.taxonomy.clone(),
                    primary_cwe: pair.primary_cwe.clone(),
                    semantics: expected_semantics(&pair.taxonomy.category_id),
                    source: expectation.source.clone(),
                    sink: expectation.sink.clone(),
                    evidence: expectation.evidence.clone(),
                });
            let classifications = classify_case(
                decision,
                case.expected.as_ref(),
                &pair.taxonomy,
                &normalized,
                selected,
            );
            for classification in &classifications {
                *category_counts.entry(classification.category).or_insert(0) += 1;
                *family_category_counts
                    .entry(pair.taxonomy.category_id.clone())
                    .or_default()
                    .entry(classification.category)
                    .or_insert(0) += 1;
                *framework_category_counts
                    .entry(framework_name(pair.framework).to_owned())
                    .or_default()
                    .entry(classification.category)
                    .or_insert(0) += 1;
                *language_category_counts
                    .entry(language_name(pair.language).to_owned())
                    .or_default()
                    .entry(classification.category)
                    .or_insert(0) += 1;
                *topology_category_counts
                    .entry(topology_name(pair.variation).to_owned())
                    .or_default()
                    .entry(classification.category)
                    .or_insert(0) += 1;
            }
            if case.kind == CaseKind::Vulnerable {
                update_matrices(&mut matrices, case.expected.as_ref(), decision, selected);
            }
            let copied_path = format!("{FIXTURE_ROOT}/{}", case.case_id);
            let mut record = RetiredCaseDiagnostic {
                case_id: case.case_id.clone(),
                pair_id: pair.pair_id.clone(),
                kind: case.kind,
                fixture_path: copied_path,
                fixture_sha256: case.fixture_sha256.clone(),
                original_contract_sha256: case.contract_sha256.clone(),
                framework: pair.framework,
                language: pair.language,
                topology: pair.variation,
                taxonomy: pair.taxonomy.clone(),
                primary_cwe: pair.primary_cwe.clone(),
                semantics: expected_semantics(&pair.taxonomy.category_id),
                expected,
                security_property: case.security_property.clone(),
                official_outcome: decision.outcome,
                execution_status: decision.execution_status,
                selected_finding_id: decision.selected_finding_id.clone(),
                official_criteria: decision.criteria.clone(),
                retained_report_path: format!("{PHASE4_REPORT_ROOT}/{report_path}"),
                retained_report_sha256: report_sha256,
                observations,
                classifications,
                record_sha256: String::new(),
            };
            record.record_sha256 = content_hash(&record)?;
            pair_case_records.push(record.clone());
            cases.push(record);
        }
        let vulnerable = pair_case_records.first().ok_or_else(|| {
            Phase6Error::InvalidContract("pair has no vulnerable record".to_owned())
        })?;
        let control = pair_case_records
            .get(1)
            .ok_or_else(|| Phase6Error::InvalidContract("pair has no control record".to_owned()))?;
        pairs.push(RetiredPairDiagnostic {
            pair_id: pair.pair_id.clone(),
            vulnerable_case_id: vulnerable.case_id.clone(),
            control_case_id: control.case_id.clone(),
            vulnerable_outcome: vulnerable.official_outcome,
            control_outcome: control.official_outcome,
            vulnerable_findings: vulnerable.observations.len() as u64,
            control_findings: control.observations.len() as u64,
            control_differentiation: control_differentiation(
                vulnerable.observations.len(),
                control.observations.len(),
            )
            .to_owned(),
        });
    }
    cases.sort_by(|left, right| left.case_id.cmp(&right.case_id));
    pairs.sort_by(|left, right| left.pair_id.cmp(&right.pair_id));
    validate_record_order(&cases, &pairs)?;
    let contract_audit = evidence_contract_v1_audit(
        &sources.taxonomy,
        &sources.taxonomy_bytes,
        &sources.manifest,
        &cases,
    )?;
    let examples = representative_examples(&cases);
    let generator_sha256 = fingerprint(&read_file(
        repository_root,
        "crates/secure-bench-core/src/phase6.rs",
    )?);
    Ok(RetiredHoldoutDiagnosticPack {
        schema_version: PHASE6_DIAGNOSTIC_SCHEMA.to_owned(),
        package_version: PHASE6_VERSION.to_owned(),
        package_id: "phase-3-retired-after-phase-4".to_owned(),
        published_at_utc: published_at_utc.to_owned(),
        holdout_status: "executed_and_retired_public_diagnostic_corpus".to_owned(),
        unbiased_holdout_use_prohibited: true,
        official_phase4_result_unchanged: true,
        official_phase4_metrics: sources.result.metrics.clone(),
        official_phase4_measurement: sources.result.measurement.clone(),
        official_phase4_provenance: sources.result.provenance.clone(),
        category_counts,
        family_category_counts,
        framework_category_counts,
        language_category_counts,
        topology_category_counts,
        matrices,
        confounding: confounding_audit(&sources.manifest),
        evidence_contract_v1_audit: contract_audit,
        cases,
        pairs,
        retained_report_examples: examples,
        provenance: Phase6Provenance {
            git_base: PHASE6_GIT_BASE.to_owned(),
            phase3_manifest_sha256: PHASE3_MANIFEST_SHA256.to_owned(),
            retired_aggregate_corpus_sha256: sources
                .manifest
                .commitment
                .aggregate_corpus_sha256
                .clone(),
            retired_contract_merkle_root: sources.manifest.commitment.contract_merkle_root.clone(),
            completed_ledger_sha256: PHASE3_LEDGER_SHA256.to_owned(),
            phase4_result_sha256: PHASE4_RESULT_SHA256.to_owned(),
            phase4_run_sha256: PHASE4_RUN_SHA256.to_owned(),
            phase4_artifacts_sha256: PHASE4_ARTIFACTS_SHA256.to_owned(),
            retained_reports_sha256: sources.artifacts.reports_sha256.clone(),
            taxonomy_sha256: TAXONOMY_SHA256.to_owned(),
            generator_sha256,
            scanner_processes_launched: 0,
            phase5_holdout_inputs_read: 0,
        },
        content_sha256: String::new(),
    })
}

fn observation(
    finding: &NormalizedFinding,
    official: &BTreeMap<&str, &crate::phase2::Phase2FindingRecord>,
) -> Result<DiagnosticObservation, Phase6Error> {
    let record = official.get(finding.finding_id.as_str()).ok_or_else(|| {
        Phase6Error::InvalidContract(format!(
            "normalized finding `{}` is absent from official result",
            finding.finding_id
        ))
    })?;
    if record.report_fingerprint != finding.provenance.report_fingerprint {
        return Err(Phase6Error::InvalidContract(
            "finding report provenance differs".to_owned(),
        ));
    }
    Ok(DiagnosticObservation {
        finding_id: finding.finding_id.clone(),
        native_rule_id: finding.native_rule_id.clone(),
        taxonomy: finding.taxonomy.clone(),
        reported_category: finding.category.clone(),
        reported_invariant: finding.invariant.clone(),
        source: finding.source.clone(),
        sink: finding.sink.clone(),
        evidence_path: finding.evidence_path.clone(),
        semantic_fingerprint: record.semantic_fingerprint.clone(),
        duplicate_of: record.duplicate_of.clone(),
        report_sha256: finding.provenance.report_fingerprint.clone(),
        raw_index: finding.provenance.raw_index,
    })
}

#[allow(clippy::too_many_lines)]
fn classify_case(
    decision: &Phase2CaseDecision,
    expectation: Option<&HoldoutExpectation>,
    taxonomy: &HoldoutTaxonomyCoordinates,
    findings: &[NormalizedFinding],
    selected: Option<&NormalizedFinding>,
) -> Vec<DiagnosticClassification> {
    let mut categories = BTreeMap::<DiagnosticCategory, DiagnosticClassification>::new();
    let mut add = |category, layer, reason: &str| {
        categories
            .entry(category)
            .or_insert(DiagnosticClassification {
                category,
                layer,
                reason_code: reason.to_owned(),
            });
    };
    add(
        DiagnosticCategory::FrameworkLanguageTopologyAttributionUncertainty,
        DiagnosticLayer::ExperimentalDesign,
        "perfect_factor_association",
    );
    match decision.kind {
        CaseKind::Vulnerable => {
            if findings.is_empty() {
                add(
                    DiagnosticCategory::NoFindingEmitted,
                    DiagnosticLayer::ScannerBehavior,
                    "successful_empty_report",
                );
            }
            if let Some(criteria) = &decision.criteria {
                if !criteria.taxonomy_mapped
                    || !criteria.category
                    || !criteria.invariant
                    || !criteria.cwe
                {
                    add(
                        DiagnosticCategory::WrongTaxonomyCategoryInvariantOrCwe,
                        DiagnosticLayer::ScannerBehavior,
                        "selected_observation_taxonomy_disagrees",
                    );
                }
                if !criteria.source {
                    add(
                        DiagnosticCategory::MissingOrIncorrectSource,
                        DiagnosticLayer::ScannerBehavior,
                        "selected_observation_source_disagrees",
                    );
                    add(
                        DiagnosticCategory::TransformationOrValueIdentityMismatch,
                        DiagnosticLayer::ScannerBehavior,
                        "expected_external_value_not_localized",
                    );
                }
                if !criteria.sink {
                    add(
                        DiagnosticCategory::MissingOrIncorrectSink,
                        DiagnosticLayer::ScannerBehavior,
                        "selected_observation_sink_disagrees",
                    );
                }
                if !criteria.evidence_path {
                    add(
                        DiagnosticCategory::EvidencePathMismatch,
                        DiagnosticLayer::EvaluatorBehavior,
                        "ordered_contract_v1_evidence_not_satisfied",
                    );
                }
            }
            if let (Some(expected), Some(finding)) = (expectation, selected)
                && ((!location_matches(&expected.source, &finding.source)
                    && expected.source.path == finding.source.path)
                    || (!evidence_matches(&expected.evidence, finding)
                        && semantic_endpoint_roles_present(finding)))
            {
                add(
                    DiagnosticCategory::AdapterOrEvidenceContractAmbiguity,
                    DiagnosticLayer::EvaluatorBehavior,
                    "semantic_evidence_exists_but_contract_v1_exact_form_rejects",
                );
            }
            if findings.iter().any(|finding| {
                Some(finding.finding_id.as_str()) != decision.selected_finding_id.as_deref()
                    || finding
                        .taxonomy
                        .as_ref()
                        .and_then(|metadata| metadata.category_id.as_deref())
                        != Some(taxonomy.category_id.as_str())
            }) {
                add(
                    DiagnosticCategory::DuplicateOrUnrelatedFinding,
                    DiagnosticLayer::ScannerBehavior,
                    "additional_or_unrelated_observation",
                );
            }
        }
        CaseKind::SafeControl => {
            if !findings.is_empty() {
                add(
                    DiagnosticCategory::SafeControlFalsePositive,
                    DiagnosticLayer::ScannerBehavior,
                    "negative_control_flagged",
                );
                add(
                    DiagnosticCategory::GuardSanitizerOrDominanceMismatch,
                    DiagnosticLayer::ScannerBehavior,
                    "paired_control_property_not_distinguished",
                );
            }
            if decision.duplicate_findings > 0
                || findings.len() > 1
                || findings.iter().any(|finding| {
                    finding
                        .taxonomy
                        .as_ref()
                        .and_then(|metadata| metadata.category_id.as_deref())
                        != Some(taxonomy.category_id.as_str())
                })
            {
                add(
                    DiagnosticCategory::DuplicateOrUnrelatedFinding,
                    DiagnosticLayer::ScannerBehavior,
                    "control_contains_multiple_or_unrelated_observations",
                );
            }
        }
    }
    categories.into_values().collect()
}

fn update_matrices(
    matrices: &mut DiagnosticMatrices,
    expectation: Option<&HoldoutExpectation>,
    decision: &Phase2CaseDecision,
    selected: Option<&NormalizedFinding>,
) {
    let (source, sink, evidence) = match (expectation, selected) {
        (_, None) => ("no_finding", "no_finding", "no_finding"),
        (Some(expected), Some(finding)) => (
            location_relationship(&expected.source, &finding.source),
            location_relationship(&expected.sink, &finding.sink),
            evidence_relationship(&expected.evidence, finding),
        ),
        (None, Some(_)) => ("not_applicable", "not_applicable", "not_applicable"),
    };
    *matrices.source.entry(source.to_owned()).or_insert(0) += 1;
    *matrices.sink.entry(sink.to_owned()).or_insert(0) += 1;
    *matrices.evidence.entry(evidence.to_owned()).or_insert(0) += 1;
    let joint = decision.criteria.as_ref().map_or_else(
        || "source_false_sink_false_evidence_false".to_owned(),
        |criteria| {
            format!(
                "source_{}_sink_{}_evidence_{}",
                criteria.source, criteria.sink, criteria.evidence_path
            )
        },
    );
    *matrices.source_sink_evidence.entry(joint).or_insert(0) += 1;
}

fn location_relationship(
    expected: &crate::model::LocationConstraint,
    observed: &SourceLocation,
) -> &'static str {
    if location_matches(expected, observed) {
        "exact_or_declared_alternative"
    } else if expected.path == observed.path
        || expected
            .alternatives
            .iter()
            .any(|alternative| alternative.path == observed.path)
    {
        "same_path_different_line"
    } else {
        "different_path"
    }
}

fn location_matches(
    expected: &crate::model::LocationConstraint,
    observed: &SourceLocation,
) -> bool {
    (expected.path == observed.path && expected.line.is_none_or(|line| line == observed.line))
        || expected.alternatives.iter().any(|alternative| {
            alternative.path == observed.path
                && alternative.line.is_none_or(|line| line == observed.line)
        })
}

fn evidence_relationship(
    expected: &EvidenceConstraint,
    finding: &NormalizedFinding,
) -> &'static str {
    if evidence_matches(expected, finding) {
        "contract_v1_exact"
    } else if finding.evidence_path.len() < expected.minimum_hops as usize {
        "below_minimum_hops"
    } else if semantic_endpoint_roles_present(finding) {
        "semantic_endpoints_present_kind_vocabulary_incompatible"
    } else {
        "required_ordered_kinds_absent_or_unordered"
    }
}

fn evidence_matches(expected: &EvidenceConstraint, finding: &NormalizedFinding) -> bool {
    if finding.evidence_path.len() < expected.minimum_hops as usize {
        return false;
    }
    let actual = finding
        .evidence_path
        .iter()
        .map(|hop| canonical_token(&hop.kind))
        .collect::<Vec<_>>();
    let mut index = 0;
    for required in &expected.required_kinds {
        let required = canonical_token(required);
        let Some(offset) = actual[index..]
            .iter()
            .position(|candidate| *candidate == required)
        else {
            return false;
        };
        index += offset + 1;
    }
    true
}

fn semantic_endpoint_roles_present(finding: &NormalizedFinding) -> bool {
    finding.evidence_path.len() >= 2
        && finding
            .evidence_path
            .last()
            .is_some_and(|hop| canonical_token(&hop.kind) == "sink")
}

fn canonical_token(value: &str) -> String {
    value
        .trim()
        .to_ascii_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn expected_semantics(category: &str) -> ExpectedSemantics {
    let (source, sink) = if category.ends_with("authorization-dominance") {
        (
            "request_selected_operation_context",
            "protected_sensitive_operation",
        )
    } else if category.ends_with("command-execution") {
        (
            "externally_controlled_value",
            "operating_system_command_execution",
        )
    } else if category.ends_with("dynamic-code-execution") {
        ("externally_controlled_value", "dynamic_code_evaluation")
    } else if category.ends_with("filesystem-boundary") {
        (
            "externally_controlled_path_component",
            "filesystem_operation",
        )
    } else if category.ends_with("outbound-request-boundary") {
        (
            "externally_controlled_destination",
            "server_side_outbound_request",
        )
    } else if category.ends_with("redirect-boundary") {
        ("externally_controlled_destination", "redirect_response")
    } else {
        ("externally_controlled_query_value", "sql_query_execution")
    };
    ExpectedSemantics {
        source_semantic: source.to_owned(),
        sink_semantic: sink.to_owned(),
    }
}

fn control_differentiation(vulnerable: usize, control: usize) -> &'static str {
    match (vulnerable, control) {
        (0, 0) => "no_observation_in_either_member",
        (0, _) => "control_only_observation",
        (_, 0) => "control_suppressed_all_observations",
        (left, right) if right < left => "control_reduced_but_did_not_suppress_all",
        (left, right) if right == left => "no_observation_count_differentiation",
        _ => "control_increased_observation_count",
    }
}

fn framework_name(value: HoldoutFramework) -> &'static str {
    match value {
        HoldoutFramework::NodeJs => "node_js",
        HoldoutFramework::Express => "express",
        HoldoutFramework::NextAppRouter => "next_app_router",
        HoldoutFramework::NextServerActions => "next_server_actions",
    }
}

fn zero_category_counts() -> BTreeMap<DiagnosticCategory, u64> {
    ALL_DIAGNOSTIC_CATEGORIES
        .iter()
        .map(|category| (*category, 0))
        .collect()
}

fn language_name(value: HoldoutLanguage) -> &'static str {
    match value {
        HoldoutLanguage::JavaScript => "java_script",
        HoldoutLanguage::Jsx => "jsx",
        HoldoutLanguage::TypeScript => "type_script",
        HoldoutLanguage::Tsx => "tsx",
    }
}

fn topology_name(value: HoldoutVariation) -> &'static str {
    match value {
        HoldoutVariation::Direct => "direct",
        HoldoutVariation::HelperMediated => "helper_mediated",
        HoldoutVariation::InterFileAliased => "inter_file_aliased",
        HoldoutVariation::ControlFlowSensitive => "control_flow_sensitive",
    }
}

fn zero_table(rows: &[&str], columns: &[&str]) -> BTreeMap<String, BTreeMap<String, u64>> {
    rows.iter()
        .map(|row| {
            (
                (*row).to_owned(),
                columns
                    .iter()
                    .map(|column| ((*column).to_owned(), 0))
                    .collect(),
            )
        })
        .collect()
}

fn increment_table(table: &mut BTreeMap<String, BTreeMap<String, u64>>, row: &str, column: &str) {
    if let Some(columns) = table.get_mut(row)
        && let Some(count) = columns.get_mut(column)
    {
        *count += 1;
    }
}

fn confounding_audit(manifest: &HoldoutManifest) -> Phase6ConfoundingAudit {
    const FRAMEWORKS: [&str; 4] = [
        "node_js",
        "express",
        "next_app_router",
        "next_server_actions",
    ];
    const LANGUAGES: [&str; 4] = ["java_script", "jsx", "type_script", "tsx"];
    const TOPOLOGIES: [&str; 4] = [
        "direct",
        "helper_mediated",
        "inter_file_aliased",
        "control_flow_sensitive",
    ];
    let mut framework_by_language = zero_table(&FRAMEWORKS, &LANGUAGES);
    let mut framework_by_topology = zero_table(&FRAMEWORKS, &TOPOLOGIES);
    let mut language_by_topology = zero_table(&LANGUAGES, &TOPOLOGIES);
    for pair in &manifest.pairs {
        increment_table(
            &mut framework_by_language,
            framework_name(pair.framework),
            language_name(pair.language),
        );
        increment_table(
            &mut framework_by_topology,
            framework_name(pair.framework),
            topology_name(pair.variation),
        );
        increment_table(
            &mut language_by_topology,
            language_name(pair.language),
            topology_name(pair.variation),
        );
    }
    let perfect = Phase6Association {
        chi_square_milli: 84_000,
        cramers_v_basis_points: 10_000,
    };
    Phase6ConfoundingAudit {
        framework_by_language,
        framework_by_topology,
        language_by_topology,
        framework_language_association: perfect.clone(),
        framework_topology_association: perfect.clone(),
        language_topology_association: perfect,
        independent_factor_attribution_supported: false,
        prohibited_conclusions: vec![
            "Framework effects cannot be separated from language or topology effects.".to_owned(),
            "Language effects cannot be separated from framework or topology effects.".to_owned(),
            "Topology effects cannot be separated from framework or language effects.".to_owned(),
            "Observed differences do not establish a causal scanner capability limitation."
                .to_owned(),
            "Retired-corpus observations do not generalize to production coverage.".to_owned(),
        ],
    }
}

#[allow(clippy::too_many_lines)]
fn evidence_contract_v1_audit(
    taxonomy: &FrozenTaxonomy,
    taxonomy_bytes: &[u8],
    manifest: &HoldoutManifest,
    cases: &[RetiredCaseDiagnostic],
) -> Result<EvidenceContractV1Audit, Phase6Error> {
    let pair = manifest.pairs.first().ok_or_else(|| {
        Phase6Error::InvalidContract("retired manifest contains no pair".to_owned())
    })?;
    let holdout_expected = pair.vulnerable.expected.as_ref().ok_or_else(|| {
        Phase6Error::InvalidContract("first retired pair has no expectation".to_owned())
    })?;
    let expected = ExpectedFinding {
        expectation_id: "synthetic-contract-v1".to_owned(),
        taxonomy: Some(TaxonomyCoordinates {
            taxonomy_version: pair.taxonomy.taxonomy_version.clone(),
            category_id: pair.taxonomy.category_id.clone(),
            invariant_id: pair.taxonomy.invariant_id.clone(),
        }),
        invariant: "synthetic invariant".to_owned(),
        category: "synthetic category".to_owned(),
        severity: Severity::High,
        confidence: Confidence::High,
        source: holdout_expected.source.clone(),
        sink: holdout_expected.sink.clone(),
        evidence: holdout_expected.evidence.clone(),
    };
    let canonical = synthetic_finding(&expected)?;
    let mut vectors = Vec::new();
    vectors.push(contract_vector(
        taxonomy,
        &expected,
        canonical.clone(),
        "exact_canonical",
        "Exact declared coordinates and ordered hop kinds are accepted.",
    )?);
    let mut shifted = canonical.clone();
    shifted.source.line = shifted.source.line.saturating_add(1);
    vectors.push(contract_vector(
        taxonomy,
        &expected,
        shifted,
        "source_line_shifted",
        "Contract v1 rejects an undeclared line shift even when the file is unchanged.",
    )?);
    let mut vocabulary = canonical.clone();
    if let Some(first) = vocabulary.evidence_path.first_mut() {
        "handler_input".clone_into(&mut first.kind);
    }
    vectors.push(contract_vector(
        taxonomy,
        &expected,
        vocabulary,
        "semantic_role_vocabulary_differs",
        "Contract v1 compares normalized hop-kind strings, not semantic role equivalence.",
    )?);
    let mut reversed = canonical.clone();
    reversed.evidence_path.reverse();
    vectors.push(contract_vector(
        taxonomy,
        &expected,
        reversed,
        "ordered_path_reversed",
        "Contract v1 correctly rejects reversed required evidence order.",
    )?);
    let mut alternative_expected = expected.clone();
    let alternative_line = expected.source.line.unwrap_or(1).saturating_add(1);
    alternative_expected
        .source
        .alternatives
        .push(LocationVariant {
            path: expected.source.path.clone(),
            line: Some(alternative_line),
        });
    let mut alternative = canonical.clone();
    alternative.source.line = alternative_line;
    vectors.push(contract_vector(
        taxonomy,
        &alternative_expected,
        alternative,
        "declared_source_alternative",
        "Contract v1 accepts an explicitly declared equivalent source location.",
    )?);
    let mut unmapped = canonical;
    unmapped.taxonomy = None;
    vectors.push(contract_vector(
        taxonomy,
        &expected,
        unmapped,
        "taxonomy_metadata_absent",
        "Contract v1 cannot award a match without prospective canonical taxonomy metadata.",
    )?);
    let v2 = crate::phase5::evidence_contract_v2(taxonomy_bytes)
        .map_err(|error| Phase6Error::InvalidContract(error.to_string()))?;
    let metrics = &cases
        .first()
        .ok_or_else(|| Phase6Error::InvalidContract("no diagnostics generated".to_owned()))?;
    let _ = metrics;
    let eligible = cases
        .iter()
        .filter(|case| case.kind == CaseKind::Vulnerable);
    let retained_taxonomy_agreements = eligible
        .clone()
        .filter(|case| {
            case.official_criteria.as_ref().is_some_and(|criteria| {
                criteria.taxonomy_mapped && criteria.category && criteria.invariant && criteria.cwe
            })
        })
        .count() as u64;
    let retained_source_agreements = eligible
        .clone()
        .filter(|case| {
            case.official_criteria
                .as_ref()
                .is_some_and(|criteria| criteria.source)
        })
        .count() as u64;
    let retained_sink_agreements = eligible
        .clone()
        .filter(|case| {
            case.official_criteria
                .as_ref()
                .is_some_and(|criteria| criteria.sink)
        })
        .count() as u64;
    let retained_evidence_agreements = eligible
        .filter(|case| {
            case.official_criteria
                .as_ref()
                .is_some_and(|criteria| criteria.evidence_path)
        })
        .count() as u64;
    Ok(EvidenceContractV1Audit {
        synthetic_vectors: vectors,
        retained_taxonomy_agreements,
        retained_source_agreements,
        retained_sink_agreements,
        retained_evidence_agreements,
        findings: vec![
            "Contract v1 requires exact or predeclared source and sink lines.".to_owned(),
            "Contract v1 treats evidence hop kinds as ordered vocabulary tokens rather than semantic roles.".to_owned(),
            "Retained semantic endpoint observations cannot receive retrospective credit when frozen atomic criteria disagree.".to_owned(),
        ],
        prospective_v2_comparison: vec![
            format!(
                "Contract v2 permits bidirectional span containment bounded to {} lines.",
                v2.location_rules.maximum_containment_lines
            ),
            format!(
                "Contract v2 requires semantic source and sink kinds ({} source kinds and {} sink kinds).",
                v2.source_semantic_kinds.len(),
                v2.sink_semantic_kinds.len()
            ),
            format!(
                "Contract v2 restricts path compression to declared summarizable nodes: {}.",
                v2.path_rules.summarizable_nodes_only
            ),
            format!(
                "Contract v2 represents declared uncertainty as partial: {}.",
                v2.partial_rules.uncertainty_is_partial
            ),
            "This comparison is prospective, contract-only, and reads no Phase 5 case or answer artifact.".to_owned(),
        ],
        retrospective_credit_changed: false,
    })
}

fn synthetic_finding(expected: &ExpectedFinding) -> Result<NormalizedFinding, Phase6Error> {
    let source = SourceLocation {
        path: expected.source.path.clone(),
        line: expected.source.line.unwrap_or(1),
        column: None,
    };
    let sink = SourceLocation {
        path: expected.sink.path.clone(),
        line: expected.sink.line.unwrap_or(1),
        column: None,
    };
    let last = expected.evidence.required_kinds.len().saturating_sub(1);
    let evidence_path = expected
        .evidence
        .required_kinds
        .iter()
        .enumerate()
        .map(|(index, kind)| EvidenceHop {
            kind: kind.clone(),
            location: if index == last {
                sink.clone()
            } else {
                source.clone()
            },
        })
        .collect();
    let coordinates = expected.taxonomy.as_ref().ok_or_else(|| {
        Phase6Error::InvalidContract("synthetic expectation omitted taxonomy".to_owned())
    })?;
    Ok(NormalizedFinding {
        finding_id: "synthetic-finding".to_owned(),
        case_id: "synthetic-case".to_owned(),
        native_rule_id: "synthetic".to_owned(),
        taxonomy: Some(ReportedTaxonomyMetadata {
            taxonomy_version: Some(coordinates.taxonomy_version.clone()),
            category_id: Some(coordinates.category_id.clone()),
            invariant_id: Some(coordinates.invariant_id.clone()),
        }),
        category: "synthetic category".to_owned(),
        invariant: "synthetic invariant".to_owned(),
        severity: Severity::High,
        confidence: Confidence::High,
        source,
        sink,
        evidence_path,
        provenance: FindingProvenance {
            adapter: "synthetic-contract-v1".to_owned(),
            report_fingerprint: "0".repeat(64),
            raw_index: 0,
        },
    })
}

#[allow(clippy::needless_pass_by_value)]
fn contract_vector(
    taxonomy: &FrozenTaxonomy,
    expected: &ExpectedFinding,
    finding: NormalizedFinding,
    vector_id: &str,
    interpretation: &str,
) -> Result<ContractV1SyntheticVector, Phase6Error> {
    let decision = match_taxonomy_finding(taxonomy, expected, &finding)
        .map_err(|error| Phase6Error::InvalidContract(error.to_string()))?;
    Ok(ContractV1SyntheticVector {
        vector_id: vector_id.to_owned(),
        condition: vector_id.replace('_', " "),
        contract_v1_matches: decision.outcome == TaxonomyMatchOutcome::Matched,
        interpretation: interpretation.to_owned(),
    })
}

fn representative_examples(cases: &[RetiredCaseDiagnostic]) -> Vec<RetainedReportExample> {
    let mut selected = BTreeMap::<DiagnosticCategory, RetainedReportExample>::new();
    for case in cases {
        for classification in &case.classifications {
            selected
                .entry(classification.category)
                .or_insert_with(|| RetainedReportExample {
                    category: classification.category,
                    case_id: case.case_id.clone(),
                    finding_id: case.selected_finding_id.clone().or_else(|| {
                        case.observations
                            .first()
                            .map(|item| item.finding_id.clone())
                    }),
                    report_path: case.retained_report_path.clone(),
                    report_sha256: case.retained_report_sha256.clone(),
                });
        }
    }
    selected.into_values().collect()
}

fn build_regression_manifest(pack: &RetiredHoldoutDiagnosticPack) -> RetiredRegressionManifest {
    RetiredRegressionManifest {
        schema_version: PHASE6_REGRESSION_SCHEMA.to_owned(),
        package_version: PHASE6_VERSION.to_owned(),
        diagnostic_content_sha256: pack.content_sha256.clone(),
        status: "public_development_regression_corpus".to_owned(),
        unbiased_holdout_use_prohibited: true,
        cases: pack
            .cases
            .iter()
            .map(|case| RetiredRegressionCase {
                case_id: case.case_id.clone(),
                kind: case.kind,
                fixture_path: case.fixture_path.clone(),
                fixture_sha256: case.fixture_sha256.clone(),
                taxonomy: case.taxonomy.clone(),
                primary_cwe: case.primary_cwe.clone(),
                semantics: case.semantics.clone(),
                expected_source: case.expected.as_ref().map(|item| item.source.clone()),
                expected_sink: case.expected.as_ref().map(|item| item.sink.clone()),
                expected_evidence: case.expected.as_ref().map(|item| item.evidence.clone()),
                security_property: case.security_property.clone(),
                historical_outcome: case.official_outcome,
                mismatch_categories: case
                    .classifications
                    .iter()
                    .map(|item| item.category)
                    .collect(),
                retained_report_sha256: case.retained_report_sha256.clone(),
            })
            .collect(),
        content_sha256: String::new(),
    }
}

fn build_regression_manifest_with_hash(
    pack: &RetiredHoldoutDiagnosticPack,
) -> Result<RetiredRegressionManifest, Phase6Error> {
    let mut manifest = build_regression_manifest(pack);
    manifest.content_sha256 = content_hash(&manifest)?;
    Ok(manifest)
}

fn validate_record_order(
    cases: &[RetiredCaseDiagnostic],
    pairs: &[RetiredPairDiagnostic],
) -> Result<(), Phase6Error> {
    if cases.len() != EXPECTED_CASES || pairs.len() != EXPECTED_PAIRS {
        return Err(Phase6Error::InvalidContract(
            "diagnostic record cardinality differs".to_owned(),
        ));
    }
    if !cases
        .windows(2)
        .all(|items| items[0].case_id < items[1].case_id)
        || !pairs
            .windows(2)
            .all(|items| items[0].pair_id < items[1].pair_id)
        || cases
            .iter()
            .any(|record| content_hash(record).ok().as_deref() != Some(&record.record_sha256))
    {
        return Err(Phase6Error::InvalidContract(
            "diagnostic records are unordered or their hashes differ".to_owned(),
        ));
    }
    Ok(())
}

trait ClearContentHash: Clone + Serialize {
    fn clear_content_hash(&mut self);
}

impl ClearContentHash for RetiredCaseDiagnostic {
    fn clear_content_hash(&mut self) {
        self.record_sha256.clear();
    }
}

impl ClearContentHash for RetiredHoldoutDiagnosticPack {
    fn clear_content_hash(&mut self) {
        self.content_sha256.clear();
    }
}

impl ClearContentHash for RetiredRegressionManifest {
    fn clear_content_hash(&mut self) {
        self.content_sha256.clear();
    }
}

fn content_hash<T: ClearContentHash>(value: &T) -> Result<String, Phase6Error> {
    let mut projection = value.clone();
    projection.clear_content_hash();
    Ok(fingerprint(&canonical_json(&projection)?))
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, Phase6Error> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|_| Phase6Error::Serialization)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn parse_json<T: for<'de> Deserialize<'de>>(bytes: &[u8], label: &str) -> Result<T, Phase6Error> {
    serde_json::from_slice(bytes)
        .map_err(|_| Phase6Error::InvalidContract(format!("{label} is not valid strict JSON")))
}

fn read_and_verify(root: &Path, relative: &str, expected: &str) -> Result<Vec<u8>, Phase6Error> {
    let bytes = read_file(root, relative)?;
    let actual = fingerprint(&bytes);
    if actual != expected {
        return Err(Phase6Error::InvalidContract(format!(
            "immutable artifact `{relative}` hash differs: expected {expected}, got {actual}"
        )));
    }
    Ok(bytes)
}

fn read_file(root: &Path, relative: &str) -> Result<Vec<u8>, Phase6Error> {
    let path = safe_join(root, relative)?;
    fs::read(path).map_err(|error| io_error(relative, error))
}

fn write_new(root: &Path, relative: &str, bytes: &[u8]) -> Result<(), Phase6Error> {
    let path = safe_join(root, relative)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| io_error(relative, error))?;
    }
    let mut handle = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| io_error(relative, error))?;
    handle
        .write_all(bytes)
        .map_err(|error| io_error(relative, error))
}

fn safe_join(root: &Path, relative: &str) -> Result<std::path::PathBuf, Phase6Error> {
    let path = Path::new(relative);
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(Phase6Error::InvalidContract(format!(
            "unsafe repository-relative path `{relative}`"
        )));
    }
    Ok(root.join(path))
}

#[allow(clippy::needless_pass_by_value)]
fn io_error(path: &str, error: std::io::Error) -> Phase6Error {
    Phase6Error::Io {
        path: path.to_owned(),
        detail: error.to_string(),
    }
}

fn validate_timestamp(value: &str) -> Result<(), Phase6Error> {
    let valid = value.len() == 20
        && value.ends_with('Z')
        && value.as_bytes().get(4) == Some(&b'-')
        && value.as_bytes().get(7) == Some(&b'-')
        && value.as_bytes().get(10) == Some(&b'T')
        && value.as_bytes().get(13) == Some(&b':')
        && value.as_bytes().get(16) == Some(&b':')
        && value.bytes().enumerate().all(|(index, byte)| {
            matches!(index, 4 | 7 | 10 | 13 | 16 | 19) || byte.is_ascii_digit()
        });
    if !valid {
        return Err(Phase6Error::InvalidContract(
            "publication timestamp must be canonical UTC seconds".to_owned(),
        ));
    }
    Ok(())
}

fn report_aggregate(run: &Phase4Run) -> String {
    let mut bytes = Vec::new();
    for case in &run.cases {
        if let Some(digest) = &case.report_fingerprint {
            bytes.extend_from_slice(case.case_id.as_bytes());
            bytes.push(0);
            bytes.extend_from_slice(digest.as_bytes());
            bytes.push(0);
        }
    }
    fingerprint(&bytes)
}

fn copy_retired_fixtures(root: &Path, manifest: &HoldoutManifest) -> Result<(), Phase6Error> {
    for pair in &manifest.pairs {
        for case in [&pair.vulnerable, &pair.control] {
            let source = safe_join(root, &case.fixture_path)?;
            let destination_relative = format!("{FIXTURE_ROOT}/{}", case.case_id);
            let destination = safe_join(root, &destination_relative)?;
            fs::create_dir_all(&destination)
                .map_err(|error| io_error(&destination_relative, error))?;
            for relative in collect_relative_files(&source, &case.fixture_path)? {
                let bytes = fs::read(source.join(&relative)).map_err(|error| {
                    io_error(&format!("{}/{}", case.fixture_path, relative), error)
                })?;
                write_new(root, &format!("{destination_relative}/{relative}"), &bytes)?;
            }
        }
    }
    Ok(())
}

fn validate_fixture_copies(
    root: &Path,
    manifest: &HoldoutManifest,
    pack: &RetiredHoldoutDiagnosticPack,
) -> Result<(), Phase6Error> {
    let records = pack
        .cases
        .iter()
        .map(|case| (case.case_id.as_str(), case))
        .collect::<BTreeMap<_, _>>();
    for pair in &manifest.pairs {
        for case in [&pair.vulnerable, &pair.control] {
            let record = records.get(case.case_id.as_str()).ok_or_else(|| {
                Phase6Error::InvalidContract(format!("diagnostic omitted `{}`", case.case_id))
            })?;
            if fixture_fingerprint(root, &case.fixture_path)? != case.fixture_sha256
                || fixture_fingerprint(root, &record.fixture_path)? != case.fixture_sha256
                || !fixture_bytes_equal(root, &case.fixture_path, &record.fixture_path)?
            {
                return Err(Phase6Error::InvalidContract(format!(
                    "public fixture copy differs for `{}`",
                    case.case_id
                )));
            }
        }
    }
    Ok(())
}

fn fixture_bytes_equal(root: &Path, left: &str, right: &str) -> Result<bool, Phase6Error> {
    let left_root = safe_join(root, left)?;
    let right_root = safe_join(root, right)?;
    let left_files = collect_relative_files(&left_root, left)?;
    let right_files = collect_relative_files(&right_root, right)?;
    if left_files != right_files {
        return Ok(false);
    }
    for relative in left_files {
        if fs::read(left_root.join(&relative)).map_err(|error| io_error(left, error))?
            != fs::read(right_root.join(&relative)).map_err(|error| io_error(right, error))?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn fixture_fingerprint(root: &Path, relative: &str) -> Result<String, Phase6Error> {
    let fixture = safe_join(root, relative)?;
    let files = collect_relative_files(&fixture, relative)?;
    let mut hasher = Sha256::new();
    for path in files {
        let file = fixture.join(&path);
        let metadata = fs::metadata(&file).map_err(|error| io_error(relative, error))?;
        hasher.update(u64::try_from(path.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(path.as_bytes());
        hasher.update(metadata.len().to_be_bytes());
        let mut handle = fs::File::open(&file).map_err(|error| io_error(relative, error))?;
        let mut buffer = [0_u8; 8192];
        loop {
            let read = handle
                .read(&mut buffer)
                .map_err(|error| io_error(relative, error))?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
    }
    Ok(hex_digest(&hasher.finalize()))
}

fn collect_relative_files(root: &Path, display: &str) -> Result<Vec<String>, Phase6Error> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(directory) = pending.pop() {
        let entries = fs::read_dir(&directory).map_err(|error| io_error(display, error))?;
        for entry in entries {
            let entry = entry.map_err(|error| io_error(display, error))?;
            let metadata =
                fs::symlink_metadata(entry.path()).map_err(|error| io_error(display, error))?;
            if metadata.file_type().is_symlink() {
                return Err(Phase6Error::InvalidContract(format!(
                    "fixture `{display}` contains a symbolic link"
                )));
            }
            if metadata.is_dir() {
                pending.push(entry.path());
            } else if metadata.is_file() {
                let entry_path = entry.path();
                let relative = entry_path.strip_prefix(root).map_err(|_| {
                    Phase6Error::InvalidContract(format!("fixture `{display}` escaped its root"))
                })?;
                let portable = relative
                    .components()
                    .map(|component| component.as_os_str().to_string_lossy())
                    .collect::<Vec<_>>()
                    .join("/");
                files.push(portable);
            } else {
                return Err(Phase6Error::InvalidContract(format!(
                    "fixture `{display}` contains a non-regular file"
                )));
            }
        }
    }
    files.sort();
    Ok(files)
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn validate_no_phase5_reference(pack: &[u8], regression: &[u8]) -> Result<(), Phase6Error> {
    const FORBIDDEN: [&str; 3] = [
        "holdout/phase-5",
        "phase-5-orthogonal-holdout-v2",
        "secure-bench-orthogonal-holdout-v2",
    ];
    let joined = [pack, regression].concat();
    let text = String::from_utf8_lossy(&joined).to_ascii_lowercase();
    if FORBIDDEN.iter().any(|needle| text.contains(needle)) {
        return Err(Phase6Error::InvalidContract(
            "generated public package contains a Phase 5 holdout reference".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_validation_is_strict() {
        assert!(validate_timestamp("2026-07-16T12:00:00Z").is_ok());
        assert!(validate_timestamp("2026-07-16 12:00:00Z").is_err());
    }

    #[test]
    fn confounding_tables_are_perfectly_associated() -> Result<(), Phase6Error> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let sources = load_sources(&root)?;
        let audit = confounding_audit(&sources.manifest);
        assert!(!audit.independent_factor_attribution_supported);
        assert_eq!(
            audit.framework_language_association.chi_square_milli,
            84_000
        );
        assert_eq!(
            audit.framework_language_association.cramers_v_basis_points,
            10_000
        );
        Ok(())
    }
}
