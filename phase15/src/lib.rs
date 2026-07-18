//! Deterministic, scanner-free Phase 15 causal diagnostics for the retired Phase 13 holdout.
//!
//! Phase 15 is additive. It preserves Phase 14 byte-for-byte and reconstructs all conclusions
//! from the frozen Phase 13 contracts, committed fixture bytes, retained Phase 14 reports, and
//! recorded evaluator decisions. It has no scanner, AI, network, or subprocess execution path.

#![allow(
    clippy::module_name_repetitions,
    clippy::struct_excessive_bools,
    clippy::struct_field_names,
    clippy::too_many_lines
)]

use secure_bench_core::adapter::fingerprint;
use secure_bench_core::phase5::{
    CanonicalFindingV2, EvidenceContractV2, EvidenceEffectV2, EvidenceExpectationV2,
    EvidenceMatchV2, EvidenceNodeV2, EvidenceRoleV2, EvidenceSpanV2, SinkSemanticKind,
    SourceSemanticKind, match_evidence_v2,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

/// Phase 15 diagnostic-package schema identifier.
pub const DIAGNOSTIC_SCHEMA: &str = "secure-bench-phase15-retired-phase13-diagnostic-v1";
/// Phase 15 finding-package schema identifier.
pub const FINDING_SCHEMA: &str = "secure-bench-phase15-finding-diagnostic-v1";
/// Phase 15 generalized regression-manifest schema identifier.
pub const REGRESSION_SCHEMA: &str = "secure-bench-phase15-regression-manifest-v1";
/// Phase 15 benchmark-defect ledger-entry schema identifier.
pub const LEDGER_SCHEMA: &str = "secure-bench-phase15-benchmark-defect-ledger-entry-v1";
/// Phase 15 conformance-suite schema identifier.
pub const CONFORMANCE_SCHEMA: &str = "secure-bench-phase15-evidence-contract-v2-conformance-v2";
/// Phase 15 provenance schema identifier.
pub const PROVENANCE_SCHEMA: &str = "secure-bench-phase15-provenance-v1";
/// Phase 15 process-audit schema identifier.
pub const PROCESS_AUDIT_SCHEMA: &str = "secure-bench-phase15-process-audit-v1";
/// Required immutable starting commit.
pub const GIT_BASE: &str = "ec9232186b343af28fd85313a7b9f41573fd4c5f";
/// Required Phase 15 branch.
pub const BRANCH: &str = "codex/phase-15-phase14-offline-postmortem";

const MANIFEST: &str = "prospective/phase-13-holdout-v4/manifest.json";
const EXPECTATIONS: &str =
    "prospective/phase-13-holdout-v4/contracts/evidence-expectations-v2.json";
const EVIDENCE_CONTRACT: &str = "holdout/phase-5/evidence-contract-v2.json";
const RUN: &str = "phase14/output/secure-engine-0-1-4-phase13-holdout-v4/run/run.json";
const RESULT: &str = "phase14/output/secure-engine-0-1-4-phase13-holdout-v4/result.json";
const COMPLETED_LEDGER: &str =
    "phase14/output/secure-engine-0-1-4-phase13-holdout-v4/completed-ledger.jsonl";
const ARTIFACTS: &str = "phase14/output/secure-engine-0-1-4-phase13-holdout-v4/artifacts.json";
const PRE_EXECUTION: &str =
    "phase14/output/secure-engine-0-1-4-phase13-holdout-v4/pre-execution-contract.json";
const PHASE14_PROCESS_AUDIT: &str =
    "phase14/output/secure-engine-0-1-4-phase13-holdout-v4/process-audit.json";
const DIAGNOSTIC_PATH: &str = "diagnostics/phase-15/retired-phase13-diagnostic-v1.json";
const FINDING_PATH: &str = "diagnostics/phase-15/finding-diagnostic-v1.json";
const REGRESSION_PATH: &str = "diagnostics/phase-15/regression-manifest-v1.json";
const LEDGER_PATH: &str = "diagnostics/phase-15/benchmark-defect-ledger-v1.jsonl";
const CONFORMANCE_PATH: &str = "diagnostics/phase-15/evidence-contract-v2-conformance-v2.json";
const PROVENANCE_PATH: &str = "diagnostics/phase-15/provenance-v1.json";
const PROCESS_AUDIT_PATH: &str = "diagnostics/phase-15/process-audit-v1.json";
const HASH_INDEX_PATH: &str = "diagnostics/phase-15/SHA256SUMS";
const DOCUMENT_PATH: &str = "docs/phase-15-postmortem.md";

const IMMUTABLE_HASHES: [(&str, &str); 5] = [
    (
        RESULT,
        "6782bf22740f57aa31345065356986a8d91f9aef012c0c4d65ce39d124830a4d",
    ),
    (
        COMPLETED_LEDGER,
        "e0b66144ccfaf571307339282d918169d3738e8de64289e9de4975d8517c5629",
    ),
    (
        ARTIFACTS,
        "4ffc4b52f6421a4c5d230f3425e6dec538a3592b8acb02c899d6781ddfe2ceae",
    ),
    (
        PRE_EXECUTION,
        "40ac463147310ff84d408f751812be423b92b5bb7ec4167ffecfc09389a0d81a",
    ),
    (
        PHASE14_PROCESS_AUDIT,
        "11f9761ca4b2add7a6acf0a15e7290ae7a452407ebb82615acf355750d17e255",
    ),
];
const REPORT_SET_SHA256: &str = "34e20e8970da844317115b8f1d9cf05b673cf338b09b06e9307567ac9c4ed082";
const PHASE14_SEMANTIC_FINGERPRINT: &str =
    "a88216b7f1b6a3231afdbff3444a581153b56f28048252f344f5e143390926a2";

/// Phase 15 input, reconstruction, or artifact error.
#[derive(Debug, Error)]
pub enum Phase15Error {
    /// Invalid command-line request.
    #[error("invalid Phase 15 request: {0}")]
    InvalidRequest(String),
    /// Immutable evidence or a diagnostic invariant differs.
    #[error("invalid Phase 15 evidence: {0}")]
    InvalidEvidence(String),
    /// Filesystem operation failed.
    #[error("Phase 15 filesystem operation failed for `{path}`: {detail}")]
    Io {
        /// Portable path context.
        path: String,
        /// Operating-system detail.
        detail: String,
    },
    /// JSON serialization failed.
    #[error("Phase 15 serialization failed: {0}")]
    Serialization(String),
}

/// Concise verified Phase 15 summary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DiagnosticSummary {
    /// Retired cases accounted for.
    pub cases: u64,
    /// Retained findings accounted for.
    pub findings: u64,
    /// Findings affected by authoritative-projection loss.
    pub adapter_affected_findings: u64,
    /// Findings for which projection loss changed the Phase 14 matcher outcome.
    pub adapter_outcome_causal_findings: u64,
    /// Safe controls flagged by retained findings.
    pub flagged_controls: u64,
    /// Vulnerable findings whose authoritative projection matches exactly.
    pub authoritative_exact: u64,
    /// Vulnerable findings whose authoritative projection matches partially.
    pub authoritative_partial: u64,
    /// Vulnerable findings whose authoritative projection does not match.
    pub authoritative_no_match: u64,
}

#[derive(Clone, Debug, Deserialize)]
struct Manifest {
    benchmark_version: String,
    holdout_id: String,
    aggregate_corpus_sha256: String,
    contract_merkle_root: String,
    pairs: Vec<Pair>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Pair {
    pair_id: String,
    family_id: String,
    framework: String,
    source_format: String,
    language_group: String,
    topology: String,
    adversarial_features: Vec<String>,
    mutation: Mutation,
    vulnerable: CaseReference,
    control: CaseReference,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Mutation {
    file: String,
    security_invariant: String,
    bidirectional_exact: bool,
    metamorphic_rename_stable: bool,
    metamorphic_insertion_stable: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct CaseReference {
    case_id: String,
    fixture_path: String,
    fixture_sha256: String,
    contract_sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
struct ExpectationsDocument {
    schema_version: String,
    holdout_id: String,
    records: Vec<FrozenExpectation>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct FrozenExpectation {
    case_id: String,
    kind: String,
    evidence_contract_version: String,
    authoritative_projection: String,
    value_id: String,
    taxonomy_version: String,
    category_id: String,
    invariant_id: String,
    primary_cwe: String,
    source_kind: String,
    sink_kind: String,
    path: Vec<ExpectedNode>,
    connected_edges: Vec<bool>,
    effective_barriers: Vec<Barrier>,
    vulnerability_expectation: Option<ExpectedVulnerability>,
    legacy_override_permitted: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ExpectedVulnerability {
    expectation_id: String,
    taxonomy_version: String,
    category_id: String,
    invariant_id: String,
    primary_cwe: String,
    path: Vec<ExpectedNode>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ExpectedNode {
    role: String,
    effect: String,
    source_kind: Option<String>,
    sink_kind: Option<String>,
    span: ExpectedSpan,
    summarizable: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ExpectedSpan {
    file: String,
    start_line: u32,
    start_column: u32,
    end_line: u32,
    end_column: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Barrier {
    role: String,
    effect: String,
    value_id: String,
    terminating: bool,
    dominates_sink: bool,
    span: ExpectedSpan,
}

#[derive(Clone, Debug, Deserialize)]
struct RunDocument {
    cases: Vec<RunCase>,
    scanner_launch_attempts: u64,
}

#[derive(Clone, Debug, Deserialize)]
struct RunCase {
    execution: Execution,
    scanner_launch_attempts: u64,
}

#[derive(Clone, Debug, Deserialize)]
struct Execution {
    case_id: String,
    status: String,
    report_path: Option<String>,
    report_fingerprint: Option<String>,
    process_exit_code: Option<i32>,
}

#[derive(Clone, Debug, Deserialize)]
struct OfficialResult {
    metrics: Value,
    cases: Vec<OfficialCase>,
    findings: Vec<OfficialFinding>,
    semantic_fingerprint: String,
}

#[derive(Clone, Debug, Deserialize)]
struct OfficialCase {
    case_id: String,
    kind: String,
    outcome: String,
    execution_status: String,
    selected_finding_id: Option<String>,
    evidence_match: Option<String>,
    criteria: Option<Value>,
    distinct_findings: u64,
    duplicate_findings: u64,
    unrelated_findings: u64,
}

#[derive(Clone, Debug, Deserialize)]
struct OfficialFinding {
    finding_id: String,
    case_id: String,
    semantic_fingerprint: String,
    adapter_state: String,
    report_sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
struct RawReport {
    schema_version: String,
    findings: Vec<RawFinding>,
    scan: RawScan,
    #[serde(default)]
    errors: Vec<Value>,
}

#[derive(Clone, Debug, Deserialize)]
struct RawScan {
    complete: bool,
}

#[derive(Clone, Debug, Deserialize)]
struct RawFinding {
    finding_id: String,
    rule_id: String,
    taxonomy: RawTaxonomy,
    primary_cwe: Value,
    verification_state: String,
    #[serde(default)]
    guards: Vec<Value>,
    evidence_path: Vec<LegacyNode>,
    evidence_contract_v2: DeclaredContract,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct RawTaxonomy {
    taxonomy_version: String,
    category_id: String,
    invariant_id: String,
}

#[derive(Clone, Debug, Deserialize)]
struct LegacyNode {
    kind: String,
    #[serde(default)]
    edge_id_from_previous: Option<String>,
    #[serde(default)]
    semantic: Option<LegacySemantic>,
    location: DeclaredLocation,
}

#[derive(Clone, Debug, Deserialize)]
struct LegacySemantic {
    role: String,
    identity: String,
    certainty: String,
}

#[derive(Clone, Debug, Deserialize)]
struct DeclaredContract {
    contract_version: String,
    semantics_version: String,
    path: Vec<DeclaredNode>,
    connected_edges: Vec<bool>,
    #[serde(default)]
    effective_barriers: Vec<String>,
    unresolved_call: bool,
    uncertain: bool,
    fingerprint: String,
    duplicate_fingerprint: String,
}

#[derive(Clone, Debug, Deserialize)]
struct DeclaredNode {
    role: String,
    effect: String,
    source_kind: Option<String>,
    sink_kind: Option<String>,
    span: DeclaredLocation,
    summarizable: bool,
}

#[derive(Clone, Debug, Deserialize)]
struct DeclaredLocation {
    path: String,
    span: DeclaredSpan,
}

#[derive(Clone, Debug, Deserialize)]
struct DeclaredSpan {
    start_byte: Option<u64>,
    end_byte: Option<u64>,
    start_line: u32,
    start_column: u32,
    end_line: u32,
    end_column: u32,
}

#[derive(Clone, Debug, Deserialize)]
struct HistoricalBaseline {
    schema_version: String,
    snapshot_version: String,
    cutoff_commit: String,
    excluded_mutable_surfaces: Vec<String>,
    closed_roots: Vec<HistoricalRoot>,
    protected_files: Vec<HistoricalFile>,
    aggregate_sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
struct HistoricalRoot {
    path: String,
    file_count: u64,
    content_sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
struct HistoricalFile {
    path: String,
    byte_length: u64,
    sha256: String,
}

#[derive(Clone, Debug)]
struct HistoricalRecord {
    byte_length: u64,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
struct Phase13Commitments {
    manifest_sha256: String,
    expectations_sha256: String,
    aggregate_corpus_sha256: String,
    contract_merkle_root: String,
    genesis_ledger_sha256: String,
}

fn portable(root: &Path, relative: &str) -> Result<PathBuf, Phase15Error> {
    let candidate = Path::new(relative);
    if candidate.is_absolute()
        || candidate.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(Phase15Error::InvalidEvidence(format!(
            "non-portable path `{relative}`"
        )));
    }
    Ok(root.join(candidate))
}

fn read(root: &Path, relative: &str) -> Result<Vec<u8>, Phase15Error> {
    let absolute = portable(root, relative)?;
    let metadata = fs::symlink_metadata(&absolute).map_err(|error| Phase15Error::Io {
        path: relative.to_owned(),
        detail: error.to_string(),
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(Phase15Error::InvalidEvidence(format!(
            "`{relative}` is not a regular file"
        )));
    }
    fs::read(&absolute).map_err(|error| Phase15Error::Io {
        path: relative.to_owned(),
        detail: error.to_string(),
    })
}

fn parse<T: for<'de> Deserialize<'de>>(bytes: &[u8], label: &str) -> Result<T, Phase15Error> {
    serde_json::from_slice(bytes)
        .map_err(|error| Phase15Error::InvalidEvidence(format!("{label}: {error}")))
}

fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, Phase15Error> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| Phase15Error::Serialization(error.to_string()))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn compact_line<T: Serialize>(value: &T) -> Result<Vec<u8>, Phase15Error> {
    let mut bytes = serde_json::to_vec(value)
        .map_err(|error| Phase15Error::Serialization(error.to_string()))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn hash(bytes: &[u8]) -> String {
    fingerprint(bytes)
}

fn hash_file(root: &Path, relative: &str) -> Result<String, Phase15Error> {
    Ok(hash(&read(root, relative)?))
}

fn write_new(root: &Path, relative: &str, bytes: &[u8]) -> Result<(), Phase15Error> {
    let absolute = portable(root, relative)?;
    if absolute.exists() {
        return Err(Phase15Error::InvalidEvidence(format!(
            "additive output `{relative}` already exists"
        )));
    }
    let parent = absolute.parent().ok_or_else(|| {
        Phase15Error::InvalidEvidence(format!("output `{relative}` has no parent"))
    })?;
    fs::create_dir_all(parent).map_err(|error| Phase15Error::Io {
        path: parent.display().to_string(),
        detail: error.to_string(),
    })?;
    fs::write(&absolute, bytes).map_err(|error| Phase15Error::Io {
        path: relative.to_owned(),
        detail: error.to_string(),
    })
}

fn role(value: &str) -> Result<EvidenceRoleV2, Phase15Error> {
    match value {
        "source" => Ok(EvidenceRoleV2::Source),
        "propagation" | "intermediate" => Ok(EvidenceRoleV2::Propagation),
        "transformation" => Ok(EvidenceRoleV2::Transformation),
        "guard" => Ok(EvidenceRoleV2::Guard),
        "sanitizer" => Ok(EvidenceRoleV2::Sanitizer),
        "authorization" => Ok(EvidenceRoleV2::Authorization),
        "sink" => Ok(EvidenceRoleV2::Sink),
        _ => Err(Phase15Error::InvalidEvidence(format!(
            "unknown evidence role `{value}`"
        ))),
    }
}

fn effect(value: &str) -> Result<EvidenceEffectV2, Phase15Error> {
    match value {
        "preserves_influence" => Ok(EvidenceEffectV2::PreservesInfluence),
        "separates_control_and_data" => Ok(EvidenceEffectV2::SeparatesControlAndData),
        "constrains_to_policy" => Ok(EvidenceEffectV2::ConstrainsToPolicy),
        "rejects_and_terminates" => Ok(EvidenceEffectV2::RejectsAndTerminates),
        "authorizes_operation" => Ok(EvidenceEffectV2::AuthorizesOperation),
        _ => Err(Phase15Error::InvalidEvidence(format!(
            "unknown evidence effect `{value}`"
        ))),
    }
}

fn source_kind(value: Option<&str>) -> Result<Option<SourceSemanticKind>, Phase15Error> {
    value
        .map(|value| match value {
            "http_query_value" => Ok(SourceSemanticKind::HttpQueryValue),
            "http_body_field" => Ok(SourceSemanticKind::HttpBodyField),
            "form_data_value" => Ok(SourceSemanticKind::FormDataValue),
            "protected_resource_id" => Ok(SourceSemanticKind::ProtectedResourceId),
            _ => Err(Phase15Error::InvalidEvidence(format!(
                "unknown source kind `{value}`"
            ))),
        })
        .transpose()
}

fn sink_kind(value: Option<&str>) -> Result<Option<SinkSemanticKind>, Phase15Error> {
    value
        .map(|value| match value {
            "protected_record_mutation" => Ok(SinkSemanticKind::ProtectedRecordMutation),
            "os_command_execution" => Ok(SinkSemanticKind::OsCommandExecution),
            "dynamic_code_evaluation" => Ok(SinkSemanticKind::DynamicCodeEvaluation),
            "filesystem_read" => Ok(SinkSemanticKind::FilesystemRead),
            "outbound_request" => Ok(SinkSemanticKind::OutboundRequest),
            "redirect_response" => Ok(SinkSemanticKind::RedirectResponse),
            "sql_query_execution" => Ok(SinkSemanticKind::SqlQueryExecution),
            _ => Err(Phase15Error::InvalidEvidence(format!(
                "unknown sink kind `{value}`"
            ))),
        })
        .transpose()
}

fn expected_node(node: &ExpectedNode) -> Result<EvidenceNodeV2, Phase15Error> {
    Ok(EvidenceNodeV2 {
        role: role(&node.role)?,
        effect: effect(&node.effect)?,
        source_kind: source_kind(node.source_kind.as_deref())?,
        sink_kind: sink_kind(node.sink_kind.as_deref())?,
        span: EvidenceSpanV2 {
            file: node.span.file.clone(),
            start_line: node.span.start_line,
            start_column: node.span.start_column,
            end_line: node.span.end_line,
            end_column: node.span.end_column,
        },
        summarizable: node.summarizable,
    })
}

fn expectation(value: &ExpectedVulnerability) -> Result<EvidenceExpectationV2, Phase15Error> {
    Ok(EvidenceExpectationV2 {
        expectation_id: value.expectation_id.clone(),
        taxonomy_version: value.taxonomy_version.clone(),
        category_id: value.category_id.clone(),
        invariant_id: value.invariant_id.clone(),
        primary_cwe: value.primary_cwe.clone(),
        path: value
            .path
            .iter()
            .map(expected_node)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn declared_node(node: &DeclaredNode) -> Result<EvidenceNodeV2, Phase15Error> {
    Ok(EvidenceNodeV2 {
        role: role(&node.role)?,
        effect: effect(&node.effect)?,
        source_kind: source_kind(node.source_kind.as_deref())?,
        sink_kind: sink_kind(node.sink_kind.as_deref())?,
        span: EvidenceSpanV2 {
            file: node.span.path.clone(),
            start_line: node.span.span.start_line,
            start_column: node.span.span.start_column,
            end_line: node.span.span.end_line,
            end_column: node.span.span.end_column,
        },
        summarizable: node.summarizable,
    })
}

fn canonical_finding(finding: &RawFinding) -> Result<CanonicalFindingV2, Phase15Error> {
    if finding.evidence_contract_v2.contract_version != "2.0.0"
        || finding.evidence_contract_v2.semantics_version != "secure-evidence-semantics-v2"
    {
        return Err(Phase15Error::InvalidEvidence(
            "retained authoritative evidence contract version differs".to_owned(),
        ));
    }
    Ok(CanonicalFindingV2 {
        taxonomy_version: finding.taxonomy.taxonomy_version.clone(),
        category_id: finding.taxonomy.category_id.clone(),
        invariant_id: finding.taxonomy.invariant_id.clone(),
        path: finding
            .evidence_contract_v2
            .path
            .iter()
            .map(declared_node)
            .collect::<Result<Vec<_>, _>>()?,
        connected_edges: finding.evidence_contract_v2.connected_edges.clone(),
        effective_barriers: finding
            .evidence_contract_v2
            .effective_barriers
            .iter()
            .map(|value| effect(value))
            .collect::<Result<Vec<_>, _>>()?,
        unresolved_call: finding.evidence_contract_v2.unresolved_call,
        uncertain: finding.evidence_contract_v2.uncertain,
        rule_id: Some(hash(finding.rule_id.as_bytes())),
        tool_identity: None,
        prose: None,
    })
}

fn cwe(value: &Value) -> Option<&str> {
    value
        .as_str()
        .or_else(|| value.get("id").and_then(Value::as_str))
}

fn span_hash(root: &Path, fixture: &str, span: &ExpectedSpan) -> Result<String, Phase15Error> {
    let relative = format!("{fixture}/{}", span.file);
    let bytes = read(root, &relative)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| Phase15Error::InvalidEvidence(format!("fixture `{relative}` is not UTF-8")))?;
    let lines = text.lines().collect::<Vec<_>>();
    let start_line = usize::try_from(span.start_line.saturating_sub(1))
        .map_err(|_| Phase15Error::InvalidEvidence("span line overflow".to_owned()))?;
    let end_line = usize::try_from(span.end_line.saturating_sub(1))
        .map_err(|_| Phase15Error::InvalidEvidence("span line overflow".to_owned()))?;
    if start_line >= lines.len() || end_line >= lines.len() || start_line > end_line {
        return Err(Phase15Error::InvalidEvidence(format!(
            "span is outside `{relative}`"
        )));
    }
    let excerpt = if start_line == end_line {
        let start = usize::try_from(span.start_column.saturating_sub(1))
            .map_err(|_| Phase15Error::InvalidEvidence("span column overflow".to_owned()))?;
        let end = usize::try_from(span.end_column.saturating_sub(1))
            .map_err(|_| Phase15Error::InvalidEvidence("span column overflow".to_owned()))?;
        lines[start_line].get(start..end).ok_or_else(|| {
            Phase15Error::InvalidEvidence(format!("span columns are outside `{relative}`"))
        })?
    } else {
        text
    };
    if excerpt.trim().is_empty() {
        return Err(Phase15Error::InvalidEvidence(format!(
            "span in `{relative}` is empty"
        )));
    }
    Ok(hash(excerpt.as_bytes()))
}

fn aggregate_named_hashes(rows: &BTreeMap<String, String>) -> String {
    hash(
        rows.iter()
            .map(|(name, digest)| format!("{name}\0{digest}"))
            .collect::<Vec<_>>()
            .join("\n")
            .as_bytes(),
    )
}

fn prospective_diagnostic_namespace(relative: &Path) -> bool {
    let portable = relative.to_string_lossy().replace('\\', "/");
    portable
        .strip_prefix("diagnostics/phase-")
        .and_then(|tail| tail.split('/').next())
        .and_then(|phase| phase.parse::<u64>().ok())
        .is_some_and(|phase| phase >= 12)
}

fn collect_historical(
    root: &Path,
    absolute: &Path,
    relative: &Path,
    records: &mut BTreeMap<String, HistoricalRecord>,
) -> Result<(), Phase15Error> {
    if prospective_diagnostic_namespace(relative) {
        return Ok(());
    }
    let metadata = fs::symlink_metadata(absolute).map_err(|error| Phase15Error::Io {
        path: relative.display().to_string(),
        detail: error.to_string(),
    })?;
    if metadata.file_type().is_symlink() {
        return Err(Phase15Error::InvalidEvidence(format!(
            "historical path `{}` is a symlink",
            relative.display()
        )));
    }
    if metadata.is_file() {
        let bytes = fs::read(absolute).map_err(|error| Phase15Error::Io {
            path: relative.display().to_string(),
            detail: error.to_string(),
        })?;
        let portable = relative.to_string_lossy().replace('\\', "/");
        let record = HistoricalRecord {
            byte_length: u64::try_from(bytes.len()).map_err(|_| {
                Phase15Error::InvalidEvidence(format!("historical file `{portable}` is too large"))
            })?,
            sha256: hash(&bytes),
        };
        if records.insert(portable.clone(), record).is_some() {
            return Err(Phase15Error::InvalidEvidence(format!(
                "historical path `{portable}` appears more than once"
            )));
        }
        return Ok(());
    }
    if !metadata.is_dir() {
        return Err(Phase15Error::InvalidEvidence(format!(
            "historical path `{}` has an unsupported type",
            relative.display()
        )));
    }
    let mut entries = fs::read_dir(absolute)
        .map_err(|error| Phase15Error::Io {
            path: relative.display().to_string(),
            detail: error.to_string(),
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| Phase15Error::Io {
            path: relative.display().to_string(),
            detail: error.to_string(),
        })?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let child = entry.path();
        let child_metadata = fs::symlink_metadata(&child).map_err(|error| Phase15Error::Io {
            path: child.display().to_string(),
            detail: error.to_string(),
        })?;
        if entry.file_name() == "target" && child_metadata.is_dir() {
            continue;
        }
        collect_historical(root, &child, &relative.join(entry.file_name()), records)?;
    }
    let _ = root;
    Ok(())
}

fn historical_digest(records: &BTreeMap<String, HistoricalRecord>) -> String {
    let mut bytes = Vec::new();
    for (path, record) in records {
        bytes.extend_from_slice(path.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(record.sha256.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(record.byte_length.to_string().as_bytes());
        bytes.push(b'\n');
    }
    hash(&bytes)
}

fn verify_phase0_11_baseline(root: &Path) -> Result<String, Phase15Error> {
    let baseline_path = "phase12/historical/phase0-11-baseline-v1.json";
    let schema_path = "phase12/schemas/phase12-historical-baseline-v1.schema.json";
    let baseline_bytes = read(root, baseline_path)?;
    let schema_bytes = read(root, schema_path)?;
    if hash(&baseline_bytes) != "375ce87c5fce9be3caff282c821c796a9b56e3a1132404d92d40db7d89a7d52f"
        || hash(&schema_bytes) != "30a8709febdf11d500f071c212dfad5ba51395a3fc16fdf863b4a64df6be2d82"
    {
        return Err(Phase15Error::InvalidEvidence(
            "Phase 12 historical baseline or schema differs".to_owned(),
        ));
    }
    let baseline: HistoricalBaseline = parse(&baseline_bytes, baseline_path)?;
    if baseline.schema_version != "secure-bench-historical-baseline-v1"
        || baseline.snapshot_version != "1.0.0"
        || baseline.cutoff_commit != "86aa6f439c14eaa7e2fd7122687aca35f5aadc18"
        || !baseline
            .excluded_mutable_surfaces
            .iter()
            .any(|value| value == "phase12 and later prospective phase namespaces")
    {
        return Err(Phase15Error::InvalidEvidence(
            "Phase 12 historical boundary declaration differs".to_owned(),
        ));
    }
    let mut aggregate = BTreeMap::new();
    for expected in &baseline.closed_roots {
        let relative = Path::new(&expected.path);
        let mut records = BTreeMap::new();
        collect_historical(root, &root.join(relative), relative, &mut records)?;
        if u64::try_from(records.len()).ok() != Some(expected.file_count)
            || historical_digest(&records) != expected.content_sha256
        {
            return Err(Phase15Error::InvalidEvidence(format!(
                "frozen historical root `{}` differs",
                expected.path
            )));
        }
        for (path, record) in records {
            if aggregate.insert(path.clone(), record).is_some() {
                return Err(Phase15Error::InvalidEvidence(format!(
                    "historical path `{path}` has conflicting coverage"
                )));
            }
        }
    }
    for expected in &baseline.protected_files {
        let bytes = read(root, &expected.path)?;
        if u64::try_from(bytes.len()).ok() != Some(expected.byte_length)
            || hash(&bytes) != expected.sha256
        {
            return Err(Phase15Error::InvalidEvidence(format!(
                "protected historical file `{}` differs",
                expected.path
            )));
        }
        aggregate.insert(
            expected.path.clone(),
            HistoricalRecord {
                byte_length: expected.byte_length,
                sha256: expected.sha256.clone(),
            },
        );
    }
    if historical_digest(&aggregate) != baseline.aggregate_sha256 {
        return Err(Phase15Error::InvalidEvidence(
            "Phase 0-11 historical aggregate differs".to_owned(),
        ));
    }
    Ok(baseline.aggregate_sha256)
}

fn verify_checksum_manifest(root: &Path) -> Result<u64, Phase15Error> {
    let relative = "prospective/phase-13-holdout-v4/SHA256SUMS";
    let bytes = read(root, relative)?;
    if hash(&bytes) != "2531fa014c30aec73d082133d598baf8e707c48ee840277413c725efd6c953ce" {
        return Err(Phase15Error::InvalidEvidence(
            "Phase 13 SHA256SUMS differs".to_owned(),
        ));
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        Phase15Error::InvalidEvidence("Phase 13 SHA256SUMS is not UTF-8".to_owned())
    })?;
    let mut paths = BTreeSet::new();
    for line in text.lines() {
        let (expected, path) = line.split_once("  ").ok_or_else(|| {
            Phase15Error::InvalidEvidence("Phase 13 checksum line is malformed".to_owned())
        })?;
        if expected.len() != 64
            || !expected
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || !paths.insert(path.to_owned())
            || hash_file(root, path)? != expected
        {
            return Err(Phase15Error::InvalidEvidence(format!(
                "Phase 13 checksum entry `{path}` differs"
            )));
        }
    }
    u64::try_from(paths.len())
        .map_err(|_| Phase15Error::InvalidEvidence("Phase 13 checksum count overflow".to_owned()))
}

fn verify_immutable(root: &Path) -> Result<Value, Phase15Error> {
    for (relative, expected) in IMMUTABLE_HASHES {
        let observed = hash_file(root, relative)?;
        if observed != expected {
            return Err(Phase15Error::InvalidEvidence(format!(
                "immutable `{relative}` differs: expected {expected}, observed {observed}"
            )));
        }
    }
    let historical_aggregate = verify_phase0_11_baseline(root)?;
    let phase13_files = verify_checksum_manifest(root)?;
    let commitments: Phase13Commitments = parse(
        &read(root, "prospective/phase-13-holdout-v4/commitments.json")?,
        "Phase 13 commitments",
    )?;
    if phase13_files != 155
        || commitments.manifest_sha256 != hash_file(root, MANIFEST)?
        || commitments.expectations_sha256 != hash_file(root, EXPECTATIONS)?
        || commitments.aggregate_corpus_sha256
            != "03545f0f6ff5a1796815d076542770aa3334fce276cdb2906e4cc5b76f6c75a9"
        || commitments.contract_merkle_root
            != "853dbd66de362d9da8ecbe3d6eb262aadafd34fba2dee99d0bc5b2e284db76a6"
        || commitments.genesis_ledger_sha256
            != "fadb09649e2dba60b566096cf33aad0675e5eeb806d4501ea13a232c7af0a1ee"
    {
        return Err(Phase15Error::InvalidEvidence(
            "Phase 13 frozen commitments differ".to_owned(),
        ));
    }
    let result: OfficialResult = parse(&read(root, RESULT)?, "Phase 14 result")?;
    if result.semantic_fingerprint != PHASE14_SEMANTIC_FINGERPRINT {
        return Err(Phase15Error::InvalidEvidence(
            "Phase 14 semantic fingerprint differs".to_owned(),
        ));
    }
    Ok(json!({
        "phase14_result_sha256": IMMUTABLE_HASHES[0].1,
        "phase14_completed_ledger_sha256": IMMUTABLE_HASHES[1].1,
        "phase14_artifact_index_sha256": IMMUTABLE_HASHES[2].1,
        "phase14_pre_execution_contract_sha256": IMMUTABLE_HASHES[3].1,
        "phase14_process_audit_sha256": IMMUTABLE_HASHES[4].1,
        "phase14_report_set_sha256": REPORT_SET_SHA256,
        "phase14_semantic_fingerprint": PHASE14_SEMANTIC_FINGERPRINT,
        "phase13_checksum_entries_verified": phase13_files,
        "phase13_aggregate_corpus_sha256": commitments.aggregate_corpus_sha256,
        "phase13_contract_merkle_root": commitments.contract_merkle_root,
        "phase13_genesis_ledger_sha256": commitments.genesis_ledger_sha256,
        "phase0_11_historical_aggregate_sha256": historical_aggregate,
        "phase12_stable_boundary_interpretation": "prospective diagnostics/phase-N namespaces at N >= 12 are excluded while every baseline-enumerated historical byte remains fail-closed",
    }))
}

type ReportMap = BTreeMap<String, RawReport>;
type DigestMap = BTreeMap<String, String>;

fn report_maps(root: &Path, run: &RunDocument) -> Result<(ReportMap, DigestMap), Phase15Error> {
    if run.cases.len() != 112 || run.scanner_launch_attempts != 112 {
        return Err(Phase15Error::InvalidEvidence(
            "Phase 14 run population or launch count differs".to_owned(),
        ));
    }
    let mut reports = BTreeMap::new();
    let mut hashes = BTreeMap::new();
    for case in &run.cases {
        if case.scanner_launch_attempts != 1 {
            return Err(Phase15Error::InvalidEvidence(format!(
                "{} does not retain exactly one historical launch",
                case.execution.case_id
            )));
        }
        let report_path = case.execution.report_path.as_deref().ok_or_else(|| {
            Phase15Error::InvalidEvidence(format!(
                "{} lacks a retained report",
                case.execution.case_id
            ))
        })?;
        let relative =
            format!("phase14/output/secure-engine-0-1-4-phase13-holdout-v4/run/{report_path}");
        let bytes = read(root, &relative)?;
        let observed = hash(&bytes);
        if case.execution.report_fingerprint.as_deref() != Some(observed.as_str()) {
            return Err(Phase15Error::InvalidEvidence(format!(
                "{} retained report hash differs",
                case.execution.case_id
            )));
        }
        let report: RawReport = parse(&bytes, &relative)?;
        if report.schema_version != "secure-json-v1"
            || !report.scan.complete
            || !report.errors.is_empty()
        {
            return Err(Phase15Error::InvalidEvidence(format!(
                "{} report is not complete and authoritative",
                case.execution.case_id
            )));
        }
        if report.findings.len() > 1 {
            return Err(Phase15Error::InvalidEvidence(format!(
                "{} unexpectedly contains multiple findings",
                case.execution.case_id
            )));
        }
        hashes.insert(case.execution.case_id.clone(), observed);
        reports.insert(case.execution.case_id.clone(), report);
    }
    if reports.len() != 112 || aggregate_named_hashes(&hashes) != REPORT_SET_SHA256 {
        return Err(Phase15Error::InvalidEvidence(
            "Phase 14 retained report-set digest differs".to_owned(),
        ));
    }
    Ok((reports, hashes))
}

fn official_counts_valid(result: &OfficialResult) -> bool {
    let counts = &result.metrics["counts"];
    counts["vulnerable_expectations"] == 56
        && counts["exact_detections"] == 0
        && counts["partial_matches"] == 0
        && counts["misses"] == 56
        && counts["safe_controls"] == 56
        && counts["safe_controls_flagged"] == 40
        && counts["clean_safe_controls"] == 16
        && counts["findings"] == 96
        && counts["distinct_findings"] == 96
        && counts["duplicate_findings"] == 0
        && counts["unrelated_findings"] == 96
}

fn source_node(path: &[EvidenceNodeV2]) -> Option<&EvidenceNodeV2> {
    path.iter().find(|node| node.role == EvidenceRoleV2::Source)
}

fn sink_node(path: &[EvidenceNodeV2]) -> Option<&EvidenceNodeV2> {
    path.iter()
        .rev()
        .find(|node| node.role == EvidenceRoleV2::Sink)
}

fn span_exact(expected: &EvidenceSpanV2, actual: &EvidenceSpanV2) -> bool {
    expected == actual
}

fn span_contains(left: &EvidenceSpanV2, right: &EvidenceSpanV2) -> bool {
    left.file == right.file
        && (left.start_line, left.start_column) <= (right.start_line, right.start_column)
        && (left.end_line, left.end_column) >= (right.end_line, right.end_column)
}

fn span_compatible(expected: &EvidenceSpanV2, actual: &EvidenceSpanV2) -> bool {
    span_exact(expected, actual)
        || ((span_contains(expected, actual) || span_contains(actual, expected))
            && expected.start_line.abs_diff(actual.start_line)
                + expected.end_line.abs_diff(actual.end_line)
                <= 3)
}

fn agreement(
    frozen: &FrozenExpectation,
    expected: Option<&EvidenceExpectationV2>,
    finding: &CanonicalFindingV2,
    reported_cwe: Option<&str>,
    contract: &EvidenceContractV2,
) -> Value {
    let expected_source = frozen
        .path
        .first()
        .and_then(|node| expected_node(node).ok());
    let expected_sink = frozen.path.last().and_then(|node| expected_node(node).ok());
    let actual_source = source_node(&finding.path);
    let actual_sink = sink_node(&finding.path);
    let source_identity = expected_source.as_ref().and_then(|node| node.source_kind)
        == actual_source.and_then(|node| node.source_kind);
    let sink_identity = expected_sink.as_ref().and_then(|node| node.sink_kind)
        == actual_sink.and_then(|node| node.sink_kind);
    let source_span_exact = expected_source
        .as_ref()
        .zip(actual_source)
        .is_some_and(|(left, right)| span_exact(&left.span, &right.span));
    let source_span_compatible = expected_source
        .as_ref()
        .zip(actual_source)
        .is_some_and(|(left, right)| span_compatible(&left.span, &right.span));
    let sink_span_exact = expected_sink
        .as_ref()
        .zip(actual_sink)
        .is_some_and(|(left, right)| span_exact(&left.span, &right.span));
    let sink_span_compatible = expected_sink
        .as_ref()
        .zip(actual_sink)
        .is_some_and(|(left, right)| span_compatible(&left.span, &right.span));
    let connected = finding.connected_edges.len().saturating_add(1) == finding.path.len()
        && finding.connected_edges.iter().all(|edge| *edge);
    let expected_barriers = frozen.effective_barriers.len();
    let actual_barriers = finding.effective_barriers.len();
    let contract_match = expected.map_or("not_applicable", |expectation| {
        match match_evidence_v2(contract, expectation, finding) {
            EvidenceMatchV2::Exact => "exact",
            EvidenceMatchV2::Partial => "partial",
            EvidenceMatchV2::NoMatch => "no_match",
        }
    });
    json!({
        "taxonomy_version": finding.taxonomy_version == frozen.taxonomy_version,
        "category": finding.category_id == frozen.category_id,
        "invariant": finding.invariant_id == frozen.invariant_id,
        "cwe": reported_cwe == Some(frozen.primary_cwe.as_str()),
        "source_identity": source_identity,
        "source_span_exact": source_span_exact,
        "source_span_contract_compatible": source_span_compatible,
        "sink_identity": sink_identity,
        "sink_span_exact": sink_span_exact,
        "sink_span_contract_compatible": sink_span_compatible,
        "connected_edges": connected,
        "connected_value_identity": connected,
        "expected_effective_barriers": expected_barriers,
        "actual_effective_barriers": actual_barriers,
        "barrier_agreement": expected_barriers == actual_barriers,
        "guard_dominance_agreement": frozen.effective_barriers.iter().all(|barrier| barrier.terminating && barrier.dominates_sink) && expected_barriers == actual_barriers,
        "evidence_contract_v2_match": contract_match,
    })
}

fn false_dimensions(agreement: &Value) -> Vec<String> {
    agreement
        .as_object()
        .into_iter()
        .flat_map(|object| object.iter())
        .filter(|(_, value)| value == &&Value::Bool(false))
        .map(|(name, _)| name.clone())
        .collect()
}

fn scanner_causes(agreement: &Value, control: bool, barriers: &[Barrier]) -> Vec<String> {
    let mut causes = Vec::new();
    let is_false = |name: &str| agreement.get(name) == Some(&Value::Bool(false));
    if control {
        causes.push("scanner.false_positive.overbroad".to_owned());
        if is_false("barrier_agreement") {
            for role in barriers.iter().map(|barrier| barrier.role.as_str()) {
                match role {
                    "guard" => causes.push("scanner.guard_recognition".to_owned()),
                    "sanitizer" => causes.push("scanner.sanitizer_recognition".to_owned()),
                    "authorization" => {
                        causes.push("scanner.authorization_recognition".to_owned());
                    }
                    _ => causes.push("scanner.barrier_recognition".to_owned()),
                }
            }
        }
        if is_false("guard_dominance_agreement") {
            causes.push("scanner.dominance_reasoning".to_owned());
        }
    }
    if is_false("taxonomy_version") || is_false("category") || is_false("invariant") {
        causes.push("scanner.taxonomy_classification".to_owned());
    }
    if is_false("cwe") {
        causes.push("scanner.cwe_classification".to_owned());
    }
    if is_false("source_identity") {
        causes.push("scanner.source_identification".to_owned());
    }
    if is_false("source_span_contract_compatible") {
        causes.push("scanner.source_span".to_owned());
    }
    if is_false("sink_identity") {
        causes.push("scanner.sink_identification".to_owned());
    }
    if is_false("sink_span_contract_compatible") {
        causes.push("scanner.sink_span".to_owned());
    }
    if is_false("connected_edges") {
        causes.push("scanner.path_connectivity".to_owned());
    }
    if is_false("connected_value_identity") {
        causes.push("scanner.value_identity".to_owned());
    }
    causes.sort_unstable();
    causes.dedup();
    causes
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
struct GroupCounts {
    cases: u64,
    vulnerable: u64,
    safe_controls: u64,
    retained_findings: u64,
    flagged_controls: u64,
    authoritative_exact: u64,
    authoritative_partial: u64,
    authoritative_no_match: u64,
    adapter_projection_loss_observed: u64,
    adapter_outcome_causal: u64,
    scanner_affected: u64,
}

#[derive(Clone, Copy)]
struct CaseFlags {
    vulnerable: bool,
    has_finding: bool,
    contract_match: &'static str,
    adapter_projection_loss_observed: bool,
    adapter_outcome_causal: bool,
    scanner_affected: bool,
}

impl GroupCounts {
    fn add(&mut self, flags: CaseFlags) {
        self.cases += 1;
        self.vulnerable += u64::from(flags.vulnerable);
        self.safe_controls += u64::from(!flags.vulnerable);
        self.retained_findings += u64::from(flags.has_finding);
        self.flagged_controls += u64::from(!flags.vulnerable && flags.has_finding);
        self.authoritative_exact += u64::from(flags.contract_match == "exact");
        self.authoritative_partial += u64::from(flags.contract_match == "partial");
        self.authoritative_no_match += u64::from(flags.contract_match == "no_match");
        self.adapter_projection_loss_observed += u64::from(flags.adapter_projection_loss_observed);
        self.adapter_outcome_causal += u64::from(flags.adapter_outcome_causal);
        self.scanner_affected += u64::from(flags.scanner_affected);
    }
}

fn update_breakdowns(
    maps: &mut BTreeMap<String, BTreeMap<String, GroupCounts>>,
    pair: &Pair,
    flags: CaseFlags,
) {
    let dimensions = [
        ("taxonomy_family", pair.family_id.clone()),
        ("framework", pair.framework.clone()),
        ("language", pair.language_group.clone()),
        ("source_format", pair.source_format.clone()),
        ("topology", pair.topology.clone()),
        (
            "taxonomy_family_framework",
            format!("{}|{}", pair.family_id, pair.framework),
        ),
        (
            "taxonomy_family_language",
            format!("{}|{}", pair.family_id, pair.language_group),
        ),
        (
            "taxonomy_family_source_format",
            format!("{}|{}", pair.family_id, pair.source_format),
        ),
        (
            "taxonomy_family_topology",
            format!("{}|{}", pair.family_id, pair.topology),
        ),
        (
            "framework_language",
            format!("{}|{}", pair.framework, pair.language_group),
        ),
        (
            "framework_source_format",
            format!("{}|{}", pair.framework, pair.source_format),
        ),
        (
            "framework_topology",
            format!("{}|{}", pair.framework, pair.topology),
        ),
        (
            "language_source_format",
            format!("{}|{}", pair.language_group, pair.source_format),
        ),
        (
            "language_topology",
            format!("{}|{}", pair.language_group, pair.topology),
        ),
        (
            "source_format_topology",
            format!("{}|{}", pair.source_format, pair.topology),
        ),
    ];
    for (dimension, key) in dimensions {
        maps.entry(dimension.to_owned())
            .or_default()
            .entry(key)
            .or_default()
            .add(flags);
    }
}

fn fixture_validation(
    root: &Path,
    case: &CaseReference,
    frozen: &FrozenExpectation,
    pair: &Pair,
) -> Result<Value, Phase15Error> {
    let span_hashes = frozen
        .path
        .iter()
        .enumerate()
        .map(|(index, node)| {
            Ok((
                format!("path_node_{index}"),
                span_hash(root, &case.fixture_path, &node.span)?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>, Phase15Error>>()?;
    let barrier_hashes = frozen
        .effective_barriers
        .iter()
        .enumerate()
        .map(|(index, barrier)| {
            Ok((
                format!("barrier_{index}"),
                span_hash(root, &case.fixture_path, &barrier.span)?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>, Phase15Error>>()?;
    let path_connected = frozen.connected_edges.len().saturating_add(1) == frozen.path.len()
        && frozen.connected_edges.iter().all(|edge| *edge);
    let attacker_controlled_source = frozen.path.first().is_some_and(|node| {
        node.role == "source" && node.source_kind.as_deref() == Some(frozen.source_kind.as_str())
    });
    let correct_sink = frozen.path.last().is_some_and(|node| {
        node.role == "sink" && node.sink_kind.as_deref() == Some(frozen.sink_kind.as_str())
    });
    let vulnerable_has_no_effective_barrier =
        frozen.kind != "vulnerable" || frozen.effective_barriers.is_empty();
    let control_barriers_valid = frozen.kind != "safe_control"
        || (!frozen.effective_barriers.is_empty()
            && frozen.effective_barriers.iter().all(|barrier| {
                barrier.terminating && barrier.dominates_sink && barrier.value_id == frozen.value_id
            }));
    if !path_connected
        || !attacker_controlled_source
        || !correct_sink
        || !vulnerable_has_no_effective_barrier
        || !control_barriers_valid
        || frozen.invariant_id != pair.mutation.security_invariant
        || !pair.mutation.bidirectional_exact
        || !pair.mutation.metamorphic_rename_stable
        || !pair.mutation.metamorphic_insertion_stable
    {
        return Err(Phase15Error::InvalidEvidence(format!(
            "{} frozen fixture contract is internally inconsistent",
            frozen.case_id
        )));
    }
    Ok(json!({
        "phase13_validator": "passed",
        "fixture_sha256": case.fixture_sha256,
        "contract_sha256": case.contract_sha256,
        "source_sink_and_path_spans_resolve": true,
        "concrete_attacker_controlled_source": attacker_controlled_source,
        "source_kind_matches_frozen_contract": attacker_controlled_source,
        "sink_kind_and_exact_span_match_frozen_contract": correct_sink,
        "ordered_path_is_realizable_under_phase13_validation": path_connected,
        "taxonomy_category_invariant_and_cwe_validated": true,
        "vulnerable_case_lacks_effective_dominating_barrier": vulnerable_has_no_effective_barrier,
        "span_content_sha256": span_hashes,
        "barrier_content_sha256": barrier_hashes,
        "connected_value_path_declared": path_connected,
        "control_barrier_terminates_and_dominates": control_barriers_valid,
        "control_barrier_protects_same_value_identity": control_barriers_valid,
        "pair_mutation_bidirectional_exact": pair.mutation.bidirectional_exact,
        "metamorphic_rename_stable": pair.mutation.metamorphic_rename_stable,
        "metamorphic_insertion_stable": pair.mutation.metamorphic_insertion_stable,
        "source_code_exported": false,
    }))
}

fn adapter_source_audit(root: &Path) -> Result<Value, Phase15Error> {
    let bytes = read(root, "phase14/src/lib.rs")?;
    let source = std::str::from_utf8(&bytes)
        .map_err(|_| Phase15Error::InvalidEvidence("Phase 14 source is not UTF-8".to_owned()))?;
    let raw_start = source.find("struct RawSecureFinding {").ok_or_else(|| {
        Phase15Error::InvalidEvidence("Phase 14 raw finding declaration is absent".to_owned())
    })?;
    let raw_end = source[raw_start..]
        .find("struct RawEvidenceNode {")
        .map(|offset| raw_start + offset)
        .ok_or_else(|| {
            Phase15Error::InvalidEvidence("Phase 14 raw finding boundary is absent".to_owned())
        })?;
    let adapter_start = source.find("fn adapt_report(").ok_or_else(|| {
        Phase15Error::InvalidEvidence("Phase 14 adapter function is absent".to_owned())
    })?;
    let adapter_end = source[adapter_start..]
        .find("fn assess_report(")
        .map(|offset| adapter_start + offset)
        .ok_or_else(|| {
            Phase15Error::InvalidEvidence("Phase 14 adapter boundary is absent".to_owned())
        })?;
    let declaration = &source[raw_start..raw_end];
    let adapter = &source[adapter_start..adapter_end];
    if declaration.contains("evidence_contract_v2") || adapter.contains("evidence_contract_v2") {
        return Err(Phase15Error::InvalidEvidence(
            "Phase 14 adapter source no longer demonstrates authoritative-projection loss"
                .to_owned(),
        ));
    }
    Ok(json!({
        "phase14_source_sha256": hash(&bytes),
        "raw_finding_declaration_sha256": hash(declaration.as_bytes()),
        "adapter_function_sha256": hash(adapter.as_bytes()),
        "evidence_contract_v2_deserialized": false,
        "evidence_contract_v2_used_by_adapter": false,
        "legacy_evidence_path_reconstructed_before_matching": true,
        "finding_id_derived_from_reconstructed_projection": true,
    }))
}

fn legacy_projection(finding: &RawFinding) -> Value {
    let path = finding
        .evidence_path
        .iter()
        .enumerate()
        .map(|(index, node)| {
            json!({
                "index": index,
                "kind": node.kind,
                "role": node.semantic.as_ref().map(|value| value.role.as_str()),
                "identity": node.semantic.as_ref().map(|value| value.identity.as_str()),
                "certainty": node.semantic.as_ref().map(|value| value.certainty.as_str()),
                "edge_present": node.edge_id_from_previous.as_ref().is_some_and(|value| !value.is_empty()),
                "path": node.location.path,
                "span": {
                    "start_line": node.location.span.start_line,
                    "start_column": node.location.span.start_column,
                    "end_line": node.location.span.end_line,
                    "end_column": node.location.span.end_column,
                    "byte_offsets_present": node.location.span.start_byte.is_some() && node.location.span.end_byte.is_some(),
                },
            })
        })
        .collect::<Vec<_>>();
    json!({
        "verification_state": finding.verification_state,
        "guards_count": finding.guards.len(),
        "path": path,
    })
}

fn authoritative_projection(finding: &RawFinding) -> Value {
    let path = finding
        .evidence_contract_v2
        .path
        .iter()
        .enumerate()
        .map(|(index, node)| {
            json!({
                "index": index,
                "role": node.role,
                "effect": node.effect,
                "source_kind": node.source_kind,
                "sink_kind": node.sink_kind,
                "path": node.span.path,
                "span": {
                    "start_line": node.span.span.start_line,
                    "start_column": node.span.span.start_column,
                    "end_line": node.span.span.end_line,
                    "end_column": node.span.span.end_column,
                    "byte_offsets_present": node.span.span.start_byte.is_some() && node.span.span.end_byte.is_some(),
                },
                "summarizable": node.summarizable,
            })
        })
        .collect::<Vec<_>>();
    json!({
        "contract_version": finding.evidence_contract_v2.contract_version,
        "semantics_version": finding.evidence_contract_v2.semantics_version,
        "path": path,
        "connected_edges": finding.evidence_contract_v2.connected_edges,
        "effective_barriers": finding.evidence_contract_v2.effective_barriers,
        "unresolved_call": finding.evidence_contract_v2.unresolved_call,
        "uncertain": finding.evidence_contract_v2.uncertain,
        "fingerprint": finding.evidence_contract_v2.fingerprint,
        "duplicate_fingerprint": finding.evidence_contract_v2.duplicate_fingerprint,
    })
}

fn official_agreement_pattern(result: &OfficialResult) -> Value {
    let metrics = &result.metrics;
    json!({
        "taxonomy": metrics["taxonomy_agreement"],
        "category": metrics["category_agreement"],
        "invariant": metrics["invariant_agreement"],
        "cwe": metrics["cwe_agreement"],
        "source_identity": metrics["source_identity_agreement"],
        "source_span": metrics["source_span_agreement"],
        "sink_identity": metrics["sink_identity_agreement"],
        "sink_span": metrics["sink_span_agreement"],
        "connected_value_identity": metrics["connected_value_identity_agreement"],
        "evidence_path": metrics["evidence_path_agreement"],
    })
}

fn add_cause(
    case_sets: &mut BTreeMap<String, BTreeSet<String>>,
    finding_sets: &mut BTreeMap<String, BTreeSet<String>>,
    cause: &str,
    case_id: &str,
    finding_id: Option<&str>,
) {
    case_sets
        .entry(cause.to_owned())
        .or_default()
        .insert(case_id.to_owned());
    if let Some(finding_id) = finding_id {
        finding_sets
            .entry(cause.to_owned())
            .or_default()
            .insert(finding_id.to_owned());
    }
}

fn cause_counts(
    primary_case_sets: &BTreeMap<String, BTreeSet<String>>,
    primary_finding_sets: &BTreeMap<String, BTreeSet<String>>,
    contributing_case_sets: &BTreeMap<String, BTreeSet<String>>,
    contributing_finding_sets: &BTreeMap<String, BTreeSet<String>>,
) -> Value {
    let classes = [
        "scanner.false_negative",
        "scanner.false_positive.overbroad",
        "scanner.source_identification",
        "scanner.sink_identification",
        "scanner.source_span",
        "scanner.sink_span",
        "scanner.path_connectivity",
        "scanner.value_identity",
        "scanner.guard_recognition",
        "scanner.sanitizer_recognition",
        "scanner.authorization_recognition",
        "scanner.barrier_recognition",
        "scanner.dominance_reasoning",
        "adapter.authoritative_projection_loss",
        "matcher.defect",
        "fixture_expectation.defect",
        "taxonomy.drift",
        "contract.ambiguity",
        "operational.failure",
        "unresolved",
    ];
    let mut output = serde_json::Map::new();
    for class in classes {
        let primary_cases = primary_case_sets.get(class).cloned().unwrap_or_default();
        let primary_findings = primary_finding_sets.get(class).cloned().unwrap_or_default();
        let contributing_cases = contributing_case_sets
            .get(class)
            .cloned()
            .unwrap_or_default();
        let contributing_findings = contributing_finding_sets
            .get(class)
            .cloned()
            .unwrap_or_default();
        let affected_cases = primary_cases
            .union(&contributing_cases)
            .cloned()
            .collect::<BTreeSet<_>>();
        let affected_findings = primary_findings
            .union(&contributing_findings)
            .cloned()
            .collect::<BTreeSet<_>>();
        output.insert(
            class.to_owned(),
            json!({
                "primary_cases": primary_cases.len(),
                "primary_findings": primary_findings.len(),
                "contributing_cases": contributing_cases.len(),
                "contributing_findings": contributing_findings.len(),
                "affected_cases": affected_cases.len(),
                "affected_findings": affected_findings.len(),
            }),
        );
    }
    Value::Object(output)
}

struct CoreBundle {
    diagnostic: Value,
    findings: Value,
    regression: Value,
    summary: DiagnosticSummary,
    primary_cause_cases: BTreeMap<String, BTreeSet<String>>,
    primary_cause_findings: BTreeMap<String, BTreeSet<String>>,
    adapter_observed_cases: BTreeSet<String>,
    adapter_observed_findings: BTreeSet<String>,
    report_hashes: BTreeMap<String, String>,
    immutable: Value,
}

fn reconstruct_core(root: &Path) -> Result<CoreBundle, Phase15Error> {
    let immutable = verify_immutable(root)?;
    let manifest: Manifest = parse(&read(root, MANIFEST)?, "Phase 13 manifest")?;
    let expectations: ExpectationsDocument =
        parse(&read(root, EXPECTATIONS)?, "Phase 13 expectations")?;
    let contract: EvidenceContractV2 =
        parse(&read(root, EVIDENCE_CONTRACT)?, "Evidence Contract v2")?;
    let run: RunDocument = parse(&read(root, RUN)?, "Phase 14 run")?;
    let official: OfficialResult = parse(&read(root, RESULT)?, "Phase 14 result")?;
    if manifest.benchmark_version != "0.2.1"
        || manifest.holdout_id != expectations.holdout_id
        || expectations.schema_version != "secure-bench-phase13-expectations-v1"
        || contract.contract_version != "2.0.0"
        || manifest.pairs.len() != 56
        || expectations.records.len() != 112
        || official.cases.len() != 112
        || official.findings.len() != 96
        || !official_counts_valid(&official)
    {
        return Err(Phase15Error::InvalidEvidence(
            "frozen population, contract, or official metrics differ".to_owned(),
        ));
    }
    let (reports, report_hashes) = report_maps(root, &run)?;
    let adapter_audit = adapter_source_audit(root)?;
    let expectation_map = expectations
        .records
        .iter()
        .map(|value| (value.case_id.clone(), value))
        .collect::<BTreeMap<_, _>>();
    let official_case_map = official
        .cases
        .iter()
        .map(|value| (value.case_id.clone(), value))
        .collect::<BTreeMap<_, _>>();
    let official_finding_map = official
        .findings
        .iter()
        .map(|value| (value.case_id.clone(), value))
        .collect::<BTreeMap<_, _>>();
    let run_map = run
        .cases
        .iter()
        .map(|value| (value.execution.case_id.clone(), value))
        .collect::<BTreeMap<_, _>>();

    let mut cases = Vec::with_capacity(112);
    let mut finding_rows = Vec::with_capacity(96);
    let mut regression_rows = Vec::with_capacity(112);
    let mut breakdowns = BTreeMap::new();
    let mut primary_cause_cases = BTreeMap::<String, BTreeSet<String>>::new();
    let mut primary_cause_findings = BTreeMap::<String, BTreeSet<String>>::new();
    let mut contributing_cause_cases = BTreeMap::<String, BTreeSet<String>>::new();
    let mut contributing_cause_findings = BTreeMap::<String, BTreeSet<String>>::new();
    let mut adapter_observed_cases = BTreeSet::new();
    let mut adapter_observed_findings = BTreeSet::new();
    let mut authoritative_exact = 0_u64;
    let mut authoritative_partial = 0_u64;
    let mut authoritative_no_match = 0_u64;
    let mut flagged_controls = 0_u64;
    let mut adapter_affected = 0_u64;
    let mut adapter_outcome_causal = 0_u64;
    let mut findings_seen = 0_u64;

    let mut pairs = manifest.pairs.iter().collect::<Vec<_>>();
    pairs.sort_by(|left, right| left.pair_id.cmp(&right.pair_id));
    for pair in pairs {
        for (case_ref, declared_kind) in [
            (&pair.vulnerable, "vulnerable"),
            (&pair.control, "safe_control"),
        ] {
            let case_id = &case_ref.case_id;
            let frozen = expectation_map.get(case_id).ok_or_else(|| {
                Phase15Error::InvalidEvidence(format!("{case_id} expectation is absent"))
            })?;
            if frozen.kind != declared_kind
                || frozen.evidence_contract_version != "2.0.0"
                || frozen.authoritative_projection != "evidence_contract_v2"
                || frozen.legacy_override_permitted
            {
                return Err(Phase15Error::InvalidEvidence(format!(
                    "{case_id} authoritative expectation differs"
                )));
            }
            let fixture = fixture_validation(root, case_ref, frozen, pair)?;
            let official_case = official_case_map.get(case_id).ok_or_else(|| {
                Phase15Error::InvalidEvidence(format!("{case_id} official decision is absent"))
            })?;
            let run_case = run_map.get(case_id).ok_or_else(|| {
                Phase15Error::InvalidEvidence(format!("{case_id} run metadata is absent"))
            })?;
            let report = reports.get(case_id).ok_or_else(|| {
                Phase15Error::InvalidEvidence(format!("{case_id} retained report is absent"))
            })?;
            let has_finding = report.findings.len() == 1;
            let vulnerable = declared_kind == "vulnerable";
            if vulnerable != (official_case.kind == "vulnerable")
                || run_case.execution.status != official_case.execution_status
                || (vulnerable && !has_finding)
            {
                return Err(Phase15Error::InvalidEvidence(format!(
                    "{case_id} case/run/report correlation differs"
                )));
            }
            let mut primary_causes = Vec::new();
            let mut contributing_causes = Vec::new();
            let mut mismatch_links = Vec::new();
            let mut contract_match = "not_applicable";
            let mut authoritative_agreement = Value::Null;
            let mut finding_reference = Value::Null;
            let mut scanner_affected = false;
            if let Some(finding) = report.findings.first() {
                findings_seen += 1;
                adapter_affected += 1;
                let official_finding = official_finding_map.get(case_id).ok_or_else(|| {
                    Phase15Error::InvalidEvidence(format!("{case_id} official finding is absent"))
                })?;
                if official_finding.adapter_state != "unmapped_semantics"
                    || official_finding.report_sha256 != report_hashes[case_id]
                    || finding.evidence_contract_v2.fingerprint.len() != 64
                    || finding.evidence_contract_v2.duplicate_fingerprint.len() != 64
                {
                    return Err(Phase15Error::InvalidEvidence(format!(
                        "{case_id} finding correlation differs"
                    )));
                }
                adapter_observed_cases.insert(case_id.clone());
                adapter_observed_findings.insert(official_finding.finding_id.clone());
                let canonical = canonical_finding(finding)?;
                let vulnerable_expectation = frozen
                    .vulnerability_expectation
                    .as_ref()
                    .map(expectation)
                    .transpose()?;
                authoritative_agreement = agreement(
                    frozen,
                    vulnerable_expectation.as_ref(),
                    &canonical,
                    cwe(&finding.primary_cwe),
                    &contract,
                );
                contract_match = authoritative_agreement["evidence_contract_v2_match"]
                    .as_str()
                    .unwrap_or("not_applicable");
                if vulnerable {
                    match contract_match {
                        "exact" => authoritative_exact += 1,
                        "partial" => authoritative_partial += 1,
                        "no_match" => authoritative_no_match += 1,
                        _ => {
                            return Err(Phase15Error::InvalidEvidence(format!(
                                "{case_id} has no vulnerable matcher decision"
                            )));
                        }
                    }
                } else {
                    flagged_controls += 1;
                }
                let scanner = scanner_causes(
                    &authoritative_agreement,
                    !vulnerable,
                    &frozen.effective_barriers,
                );
                scanner_affected = !scanner.is_empty();
                if vulnerable && scanner.is_empty() {
                    primary_causes.push("adapter.authoritative_projection_loss".to_owned());
                    adapter_outcome_causal += 1;
                } else if let Some(first) = scanner.first() {
                    primary_causes.push(first.clone());
                    contributing_causes.extend(scanner.iter().skip(1).cloned());
                }
                if !vulnerable {
                    primary_causes.clear();
                    primary_causes.push("scanner.false_positive.overbroad".to_owned());
                    contributing_causes = scanner
                        .into_iter()
                        .filter(|cause| cause != "scanner.false_positive.overbroad")
                        .collect();
                }
                for cause in &primary_causes {
                    add_cause(
                        &mut primary_cause_cases,
                        &mut primary_cause_findings,
                        cause,
                        case_id,
                        Some(&official_finding.finding_id),
                    );
                }
                for cause in &contributing_causes {
                    add_cause(
                        &mut contributing_cause_cases,
                        &mut contributing_cause_findings,
                        cause,
                        case_id,
                        Some(&official_finding.finding_id),
                    );
                }
                mismatch_links.extend(false_dimensions(&authoritative_agreement));
                if vulnerable {
                    mismatch_links.extend(
                        official_case
                            .criteria
                            .as_ref()
                            .map(false_dimensions)
                            .unwrap_or_default()
                            .into_iter()
                            .map(|name| format!("phase14_adapter.{name}")),
                    );
                }
                mismatch_links.sort_unstable();
                mismatch_links.dedup();
                finding_reference = json!({
                    "raw_finding_id": finding.finding_id,
                    "official_phase14_finding_id": official_finding.finding_id,
                    "official_phase14_semantic_fingerprint": official_finding.semantic_fingerprint,
                    "retained_report_sha256": report_hashes[case_id],
                    "declared_v2_fingerprint": finding.evidence_contract_v2.fingerprint,
                });
                finding_rows.push(json!({
                    "case_id": case_id,
                    "pair_id": pair.pair_id,
                    "raw_finding_id": finding.finding_id,
                    "official_phase14_finding_id": official_finding.finding_id,
                    "rule_id_sha256": hash(finding.rule_id.as_bytes()),
                    "reported_taxonomy": finding.taxonomy,
                    "reported_primary_cwe": cwe(&finding.primary_cwe),
                    "report_sha256": report_hashes[case_id],
                    "raw_legacy_projection": legacy_projection(finding),
                    "authoritative_evidence_contract_v2": authoritative_projection(finding),
                    "phase14_adapter_decision": {
                        "adapter_state": official_finding.adapter_state,
                        "semantic_fingerprint": official_finding.semantic_fingerprint,
                        "selected": official_case.selected_finding_id.as_deref() == Some(official_finding.finding_id.as_str()),
                        "evidence_match": official_case.evidence_match,
                        "criteria": official_case.criteria,
                    },
                    "offline_authoritative_comparison": authoritative_agreement,
                    "projection_pipeline": {
                        "authoritative_v2_declared": true,
                        "authoritative_v2_ignored_by_phase14_adapter": true,
                        "projection_loss_observed": true,
                        "projection_loss_outcome_causal": vulnerable && contract_match == "exact",
                        "noncausal_reason": if vulnerable && contract_match == "exact" {Value::Null} else if vulnerable {Value::String("authoritative_v2_already_failed_the_frozen_matcher".to_owned())} else {Value::String("authoritative_v2_already_reported_the_safe_control_as_unsafe".to_owned())},
                    },
                    "attribution": {
                        "primary": primary_causes,
                        "contributing": contributing_causes,
                        "direct_evidence": [
                            "retained_report.authoritative_evidence_contract_v2",
                            "phase14_adapter_decision.adapter_state",
                            "phase14_adapter_source_audit",
                            "frozen_phase13_expectation",
                        ],
                        "no_retrospective_credit": true,
                        "internal_scanner_mechanism": if vulnerable {"not_inferred_beyond_retained_evidence"} else {"not_identifiable_from_black_box_evidence"},
                        "unsupported_internal_alternatives": if vulnerable {Vec::<&str>::new()} else {vec!["barrier_ignored", "barrier_misclassified", "barrier_bypassed", "barrier_not_associated_with_the_evaluated_value"]},
                    },
                }));
            } else if official_finding_map.contains_key(case_id) {
                return Err(Phase15Error::InvalidEvidence(format!(
                    "{case_id} has an official finding without a retained finding"
                )));
            }
            contributing_causes.sort_unstable();
            contributing_causes.dedup();
            let flags = CaseFlags {
                vulnerable,
                has_finding,
                contract_match: match contract_match {
                    "exact" => "exact",
                    "partial" => "partial",
                    "no_match" => "no_match",
                    _ => "not_applicable",
                },
                adapter_projection_loss_observed: has_finding,
                adapter_outcome_causal: vulnerable && contract_match == "exact",
                scanner_affected,
            };
            update_breakdowns(&mut breakdowns, pair, flags);
            cases.push(json!({
                "case_id": case_id,
                "pair_id": pair.pair_id,
                "kind": declared_kind,
                "factors": {
                    "taxonomy_family": pair.family_id,
                    "framework": pair.framework,
                    "language": pair.language_group,
                    "source_format": pair.source_format,
                    "topology": pair.topology,
                    "adversarial_features": pair.adversarial_features,
                },
                "frozen_contract": {
                    "fixture_path": case_ref.fixture_path,
                    "fixture_sha256": case_ref.fixture_sha256,
                    "contract_sha256": case_ref.contract_sha256,
                    "value_id_sha256": hash(frozen.value_id.as_bytes()),
                    "taxonomy_version": frozen.taxonomy_version,
                    "category_id": frozen.category_id,
                    "invariant_id": frozen.invariant_id,
                    "primary_cwe": frozen.primary_cwe,
                    "source_kind": frozen.source_kind,
                    "sink_kind": frozen.sink_kind,
                    "effective_barriers": frozen.effective_barriers,
                },
                "fixture_validation": fixture,
                "phase14_immutable_decision": {
                    "outcome": official_case.outcome,
                    "execution_status": official_case.execution_status,
                    "process_exit_code": run_case.execution.process_exit_code,
                    "distinct_findings": official_case.distinct_findings,
                    "duplicate_findings": official_case.duplicate_findings,
                    "unrelated_findings": official_case.unrelated_findings,
                    "selected_finding_id": official_case.selected_finding_id,
                    "evidence_match": official_case.evidence_match,
                    "criteria": official_case.criteria,
                    "report_sha256": report_hashes[case_id],
                },
                "retained_finding": finding_reference,
                "authoritative_projection_comparison": authoritative_agreement,
                "projection_pipeline": {
                    "projection_loss_observed": has_finding,
                    "projection_loss_outcome_causal": vulnerable && contract_match == "exact",
                },
                "causal_attribution": {
                    "primary": primary_causes,
                    "contributing": contributing_causes,
                    "mismatch_links": mismatch_links,
                    "matcher_defect": false,
                    "fixture_expectation_defect": false,
                    "taxonomy_drift": false,
                    "contract_ambiguity": false,
                    "operational_failure": false,
                    "unresolved": false,
                    "internal_scanner_mechanism_resolved": !has_finding,
                    "internal_scanner_mechanism_boundary": if !vulnerable && has_finding {"The retained report proves omission of the required effective barrier but cannot distinguish ignoring, misclassification, bypass, or value-association failure without prohibited engine introspection."} else {"Attribution is limited to the semantics retained in the authoritative report."},
                },
            }));
            regression_rows.push(json!({
                "case_id": case_id,
                "pair_id": pair.pair_id,
                "retired_disclosed_material": true,
                "fixture_path": case_ref.fixture_path,
                "fixture_sha256": case_ref.fixture_sha256,
                "contract_sha256": case_ref.contract_sha256,
                "kind": declared_kind,
                "taxonomy_family": pair.family_id,
                "framework": pair.framework,
                "language": pair.language_group,
                "source_format": pair.source_format,
                "topology": pair.topology,
                "expected_semantics": {
                    "taxonomy_version": frozen.taxonomy_version,
                    "category_id": frozen.category_id,
                    "invariant_id": frozen.invariant_id,
                    "primary_cwe": frozen.primary_cwe,
                    "source_kind": frozen.source_kind,
                    "sink_kind": frozen.sink_kind,
                    "effective_barriers": frozen.effective_barriers,
                },
                "historical_phase14_score_immutable": true,
            }));
        }
    }
    cases.sort_by(|left, right| left["case_id"].as_str().cmp(&right["case_id"].as_str()));
    finding_rows.sort_by(|left, right| left["case_id"].as_str().cmp(&right["case_id"].as_str()));
    regression_rows.sort_by(|left, right| left["case_id"].as_str().cmp(&right["case_id"].as_str()));
    if cases.len() != 112
        || finding_rows.len() != 96
        || findings_seen != 96
        || adapter_affected != 96
        || adapter_outcome_causal != 10
        || flagged_controls != 40
        || authoritative_exact + authoritative_partial + authoritative_no_match != 56
    {
        return Err(Phase15Error::InvalidEvidence(format!(
            "diagnostic accounting differs: cases={} findings={} adapter_observed={adapter_affected} adapter_causal={adapter_outcome_causal} controls={flagged_controls} exact={authoritative_exact} partial={authoritative_partial} no_match={authoritative_no_match}",
            cases.len(),
            finding_rows.len()
        )));
    }
    let summary = DiagnosticSummary {
        cases: 112,
        findings: 96,
        adapter_affected_findings: adapter_affected,
        adapter_outcome_causal_findings: adapter_outcome_causal,
        flagged_controls,
        authoritative_exact,
        authoritative_partial,
        authoritative_no_match,
    };
    let counts = cause_counts(
        &primary_cause_cases,
        &primary_cause_findings,
        &contributing_cause_cases,
        &contributing_cause_findings,
    );
    let expected_primary = BTreeMap::from([
        ("adapter.authoritative_projection_loss", 10_usize),
        ("scanner.false_positive.overbroad", 40),
        ("scanner.source_identification", 30),
        ("scanner.source_span", 16),
    ]);
    let expected_contributing = BTreeMap::from([
        ("scanner.dominance_reasoning", 40_usize),
        ("scanner.guard_recognition", 32),
        ("scanner.sanitizer_recognition", 8),
        ("scanner.source_identification", 21),
        ("scanner.source_span", 32),
    ]);
    let observed_primary = primary_cause_findings
        .iter()
        .map(|(cause, findings)| (cause.as_str(), findings.len()))
        .collect::<BTreeMap<_, _>>();
    let observed_contributing = contributing_cause_findings
        .iter()
        .map(|(cause, findings)| (cause.as_str(), findings.len()))
        .collect::<BTreeMap<_, _>>();
    if observed_primary != expected_primary || observed_contributing != expected_contributing {
        return Err(Phase15Error::InvalidEvidence(format!(
            "causal attribution differs: primary={observed_primary:?} contributing={observed_contributing:?}"
        )));
    }
    let diagnostic = json!({
        "schema_version": DIAGNOSTIC_SCHEMA,
        "phase": 15,
        "method": "retrospective-causal-offline-reconstruction-from-immutable-retained-evidence",
        "retired_corpus": {
            "holdout_id": manifest.holdout_id,
            "cases": 112,
            "vulnerable": 56,
            "safe_controls": 56,
            "disclosed": true,
            "aggregate_corpus_sha256": manifest.aggregate_corpus_sha256,
            "contract_merkle_root": manifest.contract_merkle_root,
        },
        "root_cause": {
            "confirmed": "Phase 14 declared evidence_contract_v2 authoritative but its adapter neither deserialized nor used that field; it reconstructed a non-authoritative legacy evidence_path projection before finding-ID derivation and matching.",
            "mechanism": adapter_audit,
            "projection_loss_observed_findings": adapter_affected,
            "projection_loss_outcome_causal_findings": adapter_outcome_causal,
            "projection_loss_outcome_noncausal_findings": adapter_affected - adapter_outcome_causal,
            "causal_boundary": "Scanner defects are attributed only to semantics present in the retained authoritative v2 projection; correct v2 evidence lost by the adapter is not attributed to the scanner.",
        },
        "historical_phase14_score_unchanged": {
            "metrics": official.metrics,
            "semantic_fingerprint": official.semantic_fingerprint,
            "rescored": false,
            "retrospective_credit_awarded": false,
        },
        "agreement_explanation": {
            "official_phase14_legacy_projection": official_agreement_pattern(&official),
            "interpretation": "Taxonomy metadata and sink locations survived the legacy projection, while semantic source and sink identities were remapped from non-canonical legacy labels and edge connectivity was reduced to presence-only booleans. The authoritative v2 field was ignored, producing the characteristic 56/56 taxonomy and 0/56 source-identity pattern.",
        },
        "offline_authoritative_projection_only": {
            "vulnerable_exact": authoritative_exact,
            "vulnerable_partial": authoritative_partial,
            "vulnerable_no_match": authoritative_no_match,
            "flagged_controls": flagged_controls,
            "clean_controls": 16,
            "interpretation": "Diagnostic comparison only; these counts do not replace, revise, or receive credit in Phase 14.",
        },
        "cause_counts": counts,
        "confounding_and_unsupported_claims": {
            "cooccurrence": "Projection loss was observed on all 96 findings, but it changed the frozen matcher outcome only for the 10 vulnerable findings whose authoritative v2 projection matched exactly.",
            "noncausal_adapter_observations": 86,
            "barrier_internal_mechanism": "For 40 flagged controls, the authoritative report omitted the required effective barrier. Black-box evidence cannot distinguish ignoring, misclassification, bypass, or value-association failure.",
            "unsupported_claims": [
                "No independent effect size is estimated for the adapter and scanner because their defects co-occur in retained reports.",
                "The diagnostic exact comparison is not scanner detection credit and does not predict a prospective score.",
                "The synthetic corpus does not establish production prevalence, exploitability, readiness, superiority, or complete coverage."
            ],
        },
        "breakdowns": breakdowns,
        "cases": cases,
        "provenance": {
            "immutable_inputs": immutable,
            "report_hashes": report_hashes,
            "scanner_processes_started_by_phase15": 0,
            "ai_processes_started_by_phase15": 0,
            "network_required": false,
            "secure_engine_source_consulted": false,
            "host_paths_exported": false,
        },
        "limitations": [
            "Phase 15 is an offline postmortem, not a scanner execution or rescore.",
            "The retained synthetic evidence does not establish production prevalence, exploitability, readiness, superiority, or complete coverage.",
            "Attribution is limited to deterministic evidence in the retired disclosed corpus and retained reports.",
            "No finding receives retrospective Phase 14 credit.",
        ],
    });
    let findings = json!({
        "schema_version": FINDING_SCHEMA,
        "phase": 15,
        "population": {"retained_findings": 96, "exactly_once_accounting": true},
        "phase14_adapter_source_audit": adapter_audit,
        "findings": finding_rows,
        "no_retrospective_credit": true,
    });
    let regression = json!({
        "schema_version": REGRESSION_SCHEMA,
        "source": "retired-disclosed-phase13-development-material",
        "purpose": "generalized-engine-phase6-9-regression-handoff-using-retired-disclosed-material-not-hidden-evaluation-or-phase14-rescoring",
        "cases": regression_rows,
        "constraints": [
            "Do not introduce fixture identifiers or scanner-specific aliases as exceptions.",
            "Exercise authoritative evidence_contract_v2 precedence before any legacy fallback.",
            "Preserve Evidence Contract v2, taxonomy 1.0.0, public regression semantics, and the immutable Phase 14 score.",
            "This material must not be represented as a ranking, superiority, production-readiness, or complete-coverage result."
        ],
    });
    Ok(CoreBundle {
        diagnostic,
        findings,
        regression,
        summary,
        primary_cause_cases,
        primary_cause_findings,
        adapter_observed_cases,
        adapter_observed_findings,
        report_hashes,
        immutable,
    })
}

fn synthetic_span(line: u32) -> EvidenceSpanV2 {
    EvidenceSpanV2 {
        file: "src/example.ts".to_owned(),
        start_line: line,
        start_column: 1,
        end_line: line,
        end_column: 12,
    }
}

fn synthetic_pair() -> (EvidenceExpectationV2, CanonicalFindingV2) {
    let source = EvidenceNodeV2 {
        role: EvidenceRoleV2::Source,
        effect: EvidenceEffectV2::PreservesInfluence,
        source_kind: Some(SourceSemanticKind::HttpBodyField),
        sink_kind: None,
        span: synthetic_span(2),
        summarizable: false,
    };
    let propagation = EvidenceNodeV2 {
        role: EvidenceRoleV2::Propagation,
        effect: EvidenceEffectV2::PreservesInfluence,
        source_kind: None,
        sink_kind: None,
        span: synthetic_span(3),
        summarizable: true,
    };
    let sink = EvidenceNodeV2 {
        role: EvidenceRoleV2::Sink,
        effect: EvidenceEffectV2::PreservesInfluence,
        source_kind: None,
        sink_kind: Some(SinkSemanticKind::OsCommandExecution),
        span: synthetic_span(4),
        summarizable: false,
    };
    (
        EvidenceExpectationV2 {
            expectation_id: "phase15-synthetic-expectation".to_owned(),
            taxonomy_version: "1.0.0".to_owned(),
            category_id: "secure-bench.category.command-execution".to_owned(),
            invariant_id: "secure-bench.invariant.command-control-data-separation".to_owned(),
            primary_cwe: "CWE-78".to_owned(),
            path: vec![source.clone(), propagation.clone(), sink.clone()],
        },
        CanonicalFindingV2 {
            taxonomy_version: "1.0.0".to_owned(),
            category_id: "secure-bench.category.command-execution".to_owned(),
            invariant_id: "secure-bench.invariant.command-control-data-separation".to_owned(),
            path: vec![source, propagation, sink],
            connected_edges: vec![true, true],
            effective_barriers: Vec::new(),
            unresolved_call: false,
            uncertain: false,
            rule_id: None,
            tool_identity: None,
            prose: None,
        },
    )
}

fn projection_policy(
    authoritative: &str,
    legacy: &str,
    equivalent: bool,
    explicit_legacy: bool,
) -> &'static str {
    match (authoritative, legacy, equivalent, explicit_legacy) {
        ("valid", "absent", _, _) | ("valid", "valid", true, _) => "authoritative_v2",
        ("valid", "valid", false, _) => "fail_closed_conflict",
        ("malformed" | "version_mismatch", _, _, _) => "fail_closed_authoritative_invalid",
        ("absent", "valid", _, true) => "versioned_legacy",
        ("absent", "valid", _, false) => "fail_closed_legacy_not_selected",
        ("absent", "absent" | "malformed", _, _) => "fail_closed_no_canonical_projection",
        _ => "fail_closed_unsupported_state",
    }
}

fn conformance_vectors(root: &Path) -> Result<Value, Phase15Error> {
    let contract: EvidenceContractV2 =
        parse(&read(root, EVIDENCE_CONTRACT)?, "Evidence Contract v2")?;
    let precedence_specs = [
        (
            "v2_only",
            "valid",
            "absent",
            true,
            false,
            "authoritative_v2",
        ),
        (
            "equivalent_v2_and_legacy",
            "valid",
            "valid",
            true,
            false,
            "authoritative_v2",
        ),
        (
            "conflicting_v2_and_legacy",
            "valid",
            "valid",
            false,
            false,
            "fail_closed_conflict",
        ),
        (
            "malformed_v2_cannot_fallback",
            "malformed",
            "valid",
            false,
            true,
            "fail_closed_authoritative_invalid",
        ),
        (
            "version_mismatched_v2_cannot_fallback",
            "version_mismatch",
            "valid",
            false,
            true,
            "fail_closed_authoritative_invalid",
        ),
        (
            "explicit_versioned_legacy_when_v2_absent",
            "absent",
            "valid",
            false,
            true,
            "versioned_legacy",
        ),
        (
            "implicit_legacy_rejected",
            "absent",
            "valid",
            false,
            false,
            "fail_closed_legacy_not_selected",
        ),
        (
            "missing_projections",
            "absent",
            "absent",
            false,
            false,
            "fail_closed_no_canonical_projection",
        ),
    ];
    let mut precedence = Vec::new();
    for (index, (name, v2, legacy, equivalent, explicit, expected)) in
        precedence_specs.into_iter().enumerate()
    {
        let observed = projection_policy(v2, legacy, equivalent, explicit);
        if observed != expected {
            return Err(Phase15Error::InvalidEvidence(format!(
                "precedence vector `{name}` differs"
            )));
        }
        precedence.push(json!({
            "vector_id": format!("phase15-precedence-{:02}", index + 1),
            "condition": name,
            "authoritative_v2": v2,
            "legacy_projection": legacy,
            "byte_semantically_equivalent": equivalent,
            "explicit_versioned_legacy_route": explicit,
            "expected": expected,
            "observed": observed,
            "passed": true,
        }));
    }
    let dimensions = [
        "exact",
        "taxonomy_version_mismatch",
        "category_mismatch",
        "invariant_mismatch",
        "cwe_mismatch",
        "source_identity_mismatch",
        "source_span_mismatch",
        "sink_identity_mismatch",
        "sink_span_mismatch",
        "disconnected_path",
        "incorrect_path_order",
        "effective_guard_barrier",
        "effective_sanitizer_barrier",
        "authorization_dominance_barrier",
        "unresolved_call_partial",
        "uncertain_partial",
    ];
    let mut matching = Vec::new();
    for (index, dimension) in dimensions.into_iter().enumerate() {
        let (expected, mut finding) = synthetic_pair();
        let mut reported_cwe = "CWE-78";
        match dimension {
            "taxonomy_version_mismatch" => "2.0.0".clone_into(&mut finding.taxonomy_version),
            "category_mismatch" => {
                "secure-bench.category.filesystem-boundary".clone_into(&mut finding.category_id);
            }
            "invariant_mismatch" => "different-invariant".clone_into(&mut finding.invariant_id),
            "cwe_mismatch" => reported_cwe = "CWE-22",
            "source_identity_mismatch" => {
                finding.path[0].source_kind = Some(SourceSemanticKind::FormDataValue);
            }
            "source_span_mismatch" => finding.path[0].span.start_line = 20,
            "sink_identity_mismatch" => {
                finding.path[2].sink_kind = Some(SinkSemanticKind::FilesystemRead);
            }
            "sink_span_mismatch" => finding.path[2].span.start_line = 20,
            "disconnected_path" => finding.connected_edges[0] = false,
            "incorrect_path_order" => finding.path.swap(0, 2),
            "effective_guard_barrier" => {
                finding.effective_barriers = vec![EvidenceEffectV2::RejectsAndTerminates];
            }
            "effective_sanitizer_barrier" => {
                finding.effective_barriers = vec![EvidenceEffectV2::SeparatesControlAndData];
            }
            "authorization_dominance_barrier" => {
                finding.effective_barriers = vec![EvidenceEffectV2::AuthorizesOperation];
            }
            "unresolved_call_partial" => finding.unresolved_call = true,
            "uncertain_partial" => finding.uncertain = true,
            _ => {}
        }
        let contract_match = if reported_cwe == expected.primary_cwe {
            match_evidence_v2(&contract, &expected, &finding)
        } else {
            EvidenceMatchV2::NoMatch
        };
        let observed = match contract_match {
            EvidenceMatchV2::Exact => "exact",
            EvidenceMatchV2::Partial => "partial",
            EvidenceMatchV2::NoMatch => "no_match",
        };
        let expected_outcome = match dimension {
            "exact" => "exact",
            "unresolved_call_partial" | "uncertain_partial" => "partial",
            _ => "no_match",
        };
        if observed != expected_outcome {
            return Err(Phase15Error::InvalidEvidence(format!(
                "matching vector `{dimension}` produced {observed}, expected {expected_outcome}"
            )));
        }
        matching.push(json!({
            "vector_id": format!("phase15-match-{:02}", index + 1),
            "dimension": dimension,
            "expectation": expected,
            "authoritative_finding": finding,
            "reported_primary_cwe": reported_cwe,
            "expected": expected_outcome,
            "observed": observed,
            "inverse": "restore_only_the_named_mutation_to_the_exact_base_vector",
            "passed": true,
        }));
    }
    Ok(json!({
        "schema_version": CONFORMANCE_SCHEMA,
        "evidence_contract_version": "2.0.0",
        "adapter_precedence_policy_sha256": hash_file(root, "phase12/policies/adapter-precedence-v1.json")?,
        "synthetic_only": true,
        "scanner_reports_used": false,
        "precedence_vectors": precedence,
        "matching_vectors": matching,
        "canonical_interpretation": "A complete v2 projection is authoritative. Conflicts or invalid v2 fail closed. Legacy is eligible only when v2 is absent and an explicit versioned route is selected.",
    }))
}

struct LedgerAffected<'a> {
    observed_cases: &'a BTreeSet<String>,
    observed_findings: &'a BTreeSet<String>,
    outcome_causal_cases: &'a BTreeSet<String>,
    outcome_causal_findings: &'a BTreeSet<String>,
}

fn ledger_entry(
    sequence: u64,
    defect_id: &str,
    class: &str,
    status: &str,
    affected: &LedgerAffected<'_>,
    previous: &str,
) -> Result<(Value, String), Phase15Error> {
    let LedgerAffected {
        observed_cases,
        observed_findings,
        outcome_causal_cases,
        outcome_causal_findings,
    } = affected;
    let mut entry = json!({
        "schema_version": LEDGER_SCHEMA,
        "sequence": sequence,
        "defect_id": defect_id,
        "class": class,
        "status": status,
        "affected_case_ids": observed_cases,
        "affected_finding_ids": observed_findings,
        "affected_cases": observed_cases.len(),
        "affected_findings": observed_findings.len(),
        "outcome_causal_case_ids": outcome_causal_cases,
        "outcome_causal_finding_ids": outcome_causal_findings,
        "outcome_causal_cases": outcome_causal_cases.len(),
        "outcome_causal_findings": outcome_causal_findings.len(),
        "phase14_result_sha256": IMMUTABLE_HASHES[0].1,
        "phase14_completed_ledger_sha256": IMMUTABLE_HASHES[1].1,
        "phase14_report_set_sha256": REPORT_SET_SHA256,
        "historical_phase14_score_changed": false,
        "previous_entry_hash": previous,
        "entry_hash": "",
    });
    let mut unhashed = entry.clone();
    if let Some(object) = unhashed.as_object_mut() {
        object.remove("entry_hash");
    }
    let digest = hash(&canonical(&unhashed)?);
    entry["entry_hash"] = Value::String(digest.clone());
    Ok((entry, digest))
}

fn defect_ledger(core: &CoreBundle) -> Result<Vec<u8>, Phase15Error> {
    let empty = BTreeSet::new();
    let adapter_causal_cases = core
        .primary_cause_cases
        .get("adapter.authoritative_projection_loss")
        .unwrap_or(&empty);
    let adapter_causal_findings = core
        .primary_cause_findings
        .get("adapter.authoritative_projection_loss")
        .unwrap_or(&empty);
    let entries = [
        (
            "phase15-ledger-genesis",
            "evidence_lifecycle",
            "linked_to_immutable_phase14",
            &empty,
            &empty,
            &empty,
            &empty,
        ),
        (
            "phase15-adapter-authoritative-projection-loss",
            "adapter_defect",
            "confirmed",
            &core.adapter_observed_cases,
            &core.adapter_observed_findings,
            adapter_causal_cases,
            adapter_causal_findings,
        ),
        (
            "phase15-benchmark-integrity-closure",
            "benchmark_integrity",
            "no_fixture_matcher_taxonomy_operational_or_unresolved_defect_confirmed",
            &empty,
            &empty,
            &empty,
            &empty,
        ),
    ];
    let mut previous = "0".repeat(64);
    let mut output = Vec::new();
    for (index, (id, class, status, cases, findings, causal_cases, causal_findings)) in
        entries.into_iter().enumerate()
    {
        let sequence = u64::try_from(index + 1)
            .map_err(|_| Phase15Error::InvalidEvidence("ledger overflow".to_owned()))?;
        let (entry, digest) = ledger_entry(
            sequence,
            id,
            class,
            status,
            &LedgerAffected {
                observed_cases: cases,
                observed_findings: findings,
                outcome_causal_cases: causal_cases,
                outcome_causal_findings: causal_findings,
            },
            &previous,
        )?;
        output.extend(compact_line(&entry)?);
        previous = digest;
    }
    Ok(output)
}

const DIAGNOSTIC_SCHEMA_PATH: &str =
    "phase15/schemas/phase15-retired-phase13-diagnostic-v1.schema.json";
const FINDING_SCHEMA_PATH: &str = "phase15/schemas/phase15-finding-diagnostic-v1.schema.json";
const REGRESSION_SCHEMA_PATH: &str = "phase15/schemas/phase15-regression-manifest-v1.schema.json";
const LEDGER_SCHEMA_PATH: &str =
    "phase15/schemas/phase15-benchmark-defect-ledger-entry-v1.schema.json";
const CONFORMANCE_SCHEMA_PATH: &str =
    "phase15/schemas/phase15-evidence-contract-v2-conformance-v2.schema.json";
const PROVENANCE_SCHEMA_PATH: &str = "phase15/schemas/phase15-provenance-v1.schema.json";
const PROCESS_AUDIT_SCHEMA_PATH: &str = "phase15/schemas/phase15-process-audit-v1.schema.json";

fn object_schema(
    schema_version: &str,
    required: &[&str],
    typed_properties: &[(&str, Value)],
) -> Value {
    let mut properties = serde_json::Map::new();
    properties.insert(
        "schema_version".to_owned(),
        json!({"const": schema_version}),
    );
    for name in required {
        properties.entry((*name).to_owned()).or_insert(json!({}));
    }
    for (name, schema) in typed_properties {
        properties.insert((*name).to_owned(), schema.clone());
    }
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": required,
        "properties": properties,
        "additionalProperties": false,
    })
}

fn schemas() -> BTreeMap<&'static str, Value> {
    let sha256 = json!({"type":"string","pattern":"^[0-9a-f]{64}$"});
    let case_record = json!({
        "type":"object",
        "required":["case_id","pair_id","kind","frozen_contract","fixture_validation","phase14_immutable_decision","projection_pipeline","causal_attribution"],
        "properties":{
            "case_id":{"type":"string","pattern":"^v4-case-[0-9]{3}$"},
            "pair_id":{"type":"string","pattern":"^v4-pair-[0-9]{3}$"},
            "kind":{"enum":["vulnerable","safe_control"]},
            "frozen_contract":{"type":"object"},
            "fixture_validation":{"type":"object"},
            "phase14_immutable_decision":{"type":"object"},
            "retained_finding":{},
            "authoritative_projection_comparison":{},
            "projection_pipeline":{"type":"object","required":["projection_loss_observed","projection_loss_outcome_causal"],"properties":{"projection_loss_observed":{"type":"boolean"},"projection_loss_outcome_causal":{"type":"boolean"}},"additionalProperties":false},
            "causal_attribution":{"type":"object","required":["primary","contributing","matcher_defect","fixture_expectation_defect","taxonomy_drift","contract_ambiguity","operational_failure","unresolved"],"properties":{"primary":{"type":"array","minItems":0,"maxItems":1,"uniqueItems":true,"items":{"type":"string"}},"contributing":{"type":"array","uniqueItems":true,"items":{"type":"string"}},"mismatch_links":{"type":"array","uniqueItems":true,"items":{"type":"string"}},"matcher_defect":{"const":false},"fixture_expectation_defect":{"const":false},"taxonomy_drift":{"const":false},"contract_ambiguity":{"const":false},"operational_failure":{"const":false},"unresolved":{"const":false},"internal_scanner_mechanism_resolved":{"type":"boolean"},"internal_scanner_mechanism_boundary":{"type":"string","minLength":1}},"additionalProperties":false},
            "factors":{"type":"object"}
        },
        "additionalProperties":false
    });
    let finding_record = json!({
        "type":"object",
        "required":["case_id","pair_id","raw_finding_id","official_phase14_finding_id","report_sha256","raw_legacy_projection","authoritative_evidence_contract_v2","phase14_adapter_decision","offline_authoritative_comparison","projection_pipeline","attribution"],
        "properties":{
            "case_id":{"type":"string","pattern":"^v4-case-[0-9]{3}$"},
            "pair_id":{"type":"string","pattern":"^v4-pair-[0-9]{3}$"},
            "raw_finding_id":{"type":"string","minLength":1},
            "official_phase14_finding_id":sha256,
            "rule_id_sha256":sha256,
            "reported_taxonomy":{"type":"object"},
            "reported_primary_cwe":{"type":"string","pattern":"^CWE-[0-9]+$"},
            "report_sha256":sha256,
            "raw_legacy_projection":{"type":"object"},
            "authoritative_evidence_contract_v2":{"type":"object"},
            "phase14_adapter_decision":{"type":"object"},
            "offline_authoritative_comparison":{"type":"object"},
            "projection_pipeline":{"type":"object","required":["authoritative_v2_declared","authoritative_v2_ignored_by_phase14_adapter","projection_loss_observed","projection_loss_outcome_causal","noncausal_reason"],"properties":{"authoritative_v2_declared":{"const":true},"authoritative_v2_ignored_by_phase14_adapter":{"const":true},"projection_loss_observed":{"const":true},"projection_loss_outcome_causal":{"type":"boolean"},"noncausal_reason":{}},"additionalProperties":false},
            "attribution":{"type":"object","required":["primary","contributing","direct_evidence","no_retrospective_credit","internal_scanner_mechanism","unsupported_internal_alternatives"],"properties":{"primary":{"type":"array","minItems":1,"maxItems":1,"uniqueItems":true,"items":{"type":"string"}},"contributing":{"type":"array","uniqueItems":true,"items":{"type":"string"}},"direct_evidence":{"type":"array","minItems":4,"maxItems":4,"uniqueItems":true,"items":{"type":"string"}},"no_retrospective_credit":{"const":true},"internal_scanner_mechanism":{"type":"string","minLength":1},"unsupported_internal_alternatives":{"type":"array","uniqueItems":true,"items":{"type":"string"}}},"additionalProperties":false}
        },
        "additionalProperties":false
    });
    BTreeMap::from([
        (
            DIAGNOSTIC_SCHEMA_PATH,
            object_schema(
                DIAGNOSTIC_SCHEMA,
                &[
                    "schema_version",
                    "phase",
                    "method",
                    "retired_corpus",
                    "root_cause",
                    "historical_phase14_score_unchanged",
                    "agreement_explanation",
                    "offline_authoritative_projection_only",
                    "cause_counts",
                    "confounding_and_unsupported_claims",
                    "breakdowns",
                    "cases",
                    "provenance",
                    "limitations",
                ],
                &[
                    ("phase", json!({"const":15})),
                    ("method", json!({"type":"string","minLength":1})),
                    (
                        "retired_corpus",
                        json!({"type":"object","required":["holdout_id","cases","vulnerable","safe_controls","disclosed","aggregate_corpus_sha256","contract_merkle_root"],"properties":{"holdout_id":{"type":"string","minLength":1},"cases":{"const":112},"vulnerable":{"const":56},"safe_controls":{"const":56},"disclosed":{"const":true},"aggregate_corpus_sha256":sha256,"contract_merkle_root":sha256},"additionalProperties":false}),
                    ),
                    (
                        "root_cause",
                        json!({"type":"object","required":["confirmed","mechanism","projection_loss_observed_findings","projection_loss_outcome_causal_findings","projection_loss_outcome_noncausal_findings","causal_boundary"],"properties":{"confirmed":{"type":"string","minLength":1},"mechanism":{"type":"object"},"projection_loss_observed_findings":{"const":96},"projection_loss_outcome_causal_findings":{"const":10},"projection_loss_outcome_noncausal_findings":{"const":86},"causal_boundary":{"type":"string","minLength":1}},"additionalProperties":false}),
                    ),
                    (
                        "historical_phase14_score_unchanged",
                        json!({"type":"object"}),
                    ),
                    ("agreement_explanation", json!({"type":"object"})),
                    (
                        "offline_authoritative_projection_only",
                        json!({"type":"object","required":["vulnerable_exact","vulnerable_partial","vulnerable_no_match","flagged_controls","clean_controls","interpretation"],"properties":{"vulnerable_exact":{"const":10},"vulnerable_partial":{"type":"integer","minimum":0,"maximum":56},"vulnerable_no_match":{"type":"integer","minimum":0,"maximum":56},"flagged_controls":{"const":40},"clean_controls":{"const":16},"interpretation":{"type":"string","minLength":1}},"additionalProperties":false}),
                    ),
                    (
                        "cause_counts",
                        json!({"type":"object","minProperties":20,"maxProperties":20,"additionalProperties":{"type":"object","required":["primary_cases","primary_findings","contributing_cases","contributing_findings","affected_cases","affected_findings"],"properties":{"primary_cases":{"type":"integer","minimum":0,"maximum":112},"primary_findings":{"type":"integer","minimum":0,"maximum":96},"contributing_cases":{"type":"integer","minimum":0,"maximum":112},"contributing_findings":{"type":"integer","minimum":0,"maximum":96},"affected_cases":{"type":"integer","minimum":0,"maximum":112},"affected_findings":{"type":"integer","minimum":0,"maximum":96}},"additionalProperties":false}}),
                    ),
                    (
                        "confounding_and_unsupported_claims",
                        json!({"type":"object"}),
                    ),
                    ("breakdowns", json!({"type":"object","minProperties":15})),
                    (
                        "cases",
                        json!({"type":"array","minItems":112,"maxItems":112,"uniqueItems":true,"items":case_record}),
                    ),
                    ("provenance", json!({"type":"object"})),
                    (
                        "limitations",
                        json!({"type":"array","minItems":4,"items":{"type":"string"}}),
                    ),
                ],
            ),
        ),
        (
            FINDING_SCHEMA_PATH,
            object_schema(
                FINDING_SCHEMA,
                &[
                    "schema_version",
                    "phase",
                    "population",
                    "phase14_adapter_source_audit",
                    "findings",
                    "no_retrospective_credit",
                ],
                &[
                    ("phase", json!({"const":15})),
                    (
                        "population",
                        json!({"type":"object","required":["retained_findings","exactly_once_accounting"],"properties":{"retained_findings":{"const":96},"exactly_once_accounting":{"const":true}},"additionalProperties":false}),
                    ),
                    ("phase14_adapter_source_audit", json!({"type":"object"})),
                    (
                        "findings",
                        json!({"type":"array","minItems":96,"maxItems":96,"uniqueItems":true,"items":finding_record}),
                    ),
                    ("no_retrospective_credit", json!({"const":true})),
                ],
            ),
        ),
        (
            REGRESSION_SCHEMA_PATH,
            object_schema(
                REGRESSION_SCHEMA,
                &[
                    "schema_version",
                    "source",
                    "purpose",
                    "cases",
                    "constraints",
                ],
                &[
                    (
                        "source",
                        json!({"const":"retired-disclosed-phase13-development-material"}),
                    ),
                    ("purpose", json!({"type":"string","minLength":1})),
                    (
                        "cases",
                        json!({"type":"array","minItems":112,"maxItems":112,"uniqueItems":true,"items":{"type":"object","required":["case_id","pair_id","retired_disclosed_material","historical_phase14_score_immutable"],"properties":{"case_id":{"type":"string","pattern":"^v4-case-[0-9]{3}$"},"pair_id":{"type":"string","pattern":"^v4-pair-[0-9]{3}$"},"retired_disclosed_material":{"const":true},"historical_phase14_score_immutable":{"const":true}},"additionalProperties":true}}),
                    ),
                    (
                        "constraints",
                        json!({"type":"array","minItems":4,"items":{"type":"string"}}),
                    ),
                ],
            ),
        ),
        (
            LEDGER_SCHEMA_PATH,
            object_schema(
                LEDGER_SCHEMA,
                &[
                    "schema_version",
                    "sequence",
                    "defect_id",
                    "class",
                    "status",
                    "affected_case_ids",
                    "affected_finding_ids",
                    "affected_cases",
                    "affected_findings",
                    "outcome_causal_case_ids",
                    "outcome_causal_finding_ids",
                    "outcome_causal_cases",
                    "outcome_causal_findings",
                    "phase14_result_sha256",
                    "phase14_completed_ledger_sha256",
                    "phase14_report_set_sha256",
                    "historical_phase14_score_changed",
                    "previous_entry_hash",
                    "entry_hash",
                ],
                &[
                    (
                        "sequence",
                        json!({"type":"integer","minimum":1,"maximum":3}),
                    ),
                    ("defect_id", json!({"type":"string","minLength":1})),
                    ("class", json!({"type":"string","minLength":1})),
                    ("status", json!({"type":"string","minLength":1})),
                    (
                        "affected_case_ids",
                        json!({"type":"array","uniqueItems":true,"items":{"type":"string"}}),
                    ),
                    (
                        "affected_finding_ids",
                        json!({"type":"array","uniqueItems":true,"items":sha256}),
                    ),
                    (
                        "affected_cases",
                        json!({"type":"integer","minimum":0,"maximum":112}),
                    ),
                    (
                        "affected_findings",
                        json!({"type":"integer","minimum":0,"maximum":96}),
                    ),
                    (
                        "outcome_causal_case_ids",
                        json!({"type":"array","uniqueItems":true,"items":{"type":"string"}}),
                    ),
                    (
                        "outcome_causal_finding_ids",
                        json!({"type":"array","uniqueItems":true,"items":sha256}),
                    ),
                    (
                        "outcome_causal_cases",
                        json!({"type":"integer","minimum":0,"maximum":112}),
                    ),
                    (
                        "outcome_causal_findings",
                        json!({"type":"integer","minimum":0,"maximum":96}),
                    ),
                    ("phase14_result_sha256", sha256.clone()),
                    ("phase14_completed_ledger_sha256", sha256.clone()),
                    ("phase14_report_set_sha256", sha256.clone()),
                    ("historical_phase14_score_changed", json!({"const":false})),
                    ("previous_entry_hash", sha256.clone()),
                    ("entry_hash", sha256.clone()),
                ],
            ),
        ),
        (
            CONFORMANCE_SCHEMA_PATH,
            object_schema(
                CONFORMANCE_SCHEMA,
                &[
                    "schema_version",
                    "evidence_contract_version",
                    "adapter_precedence_policy_sha256",
                    "synthetic_only",
                    "scanner_reports_used",
                    "precedence_vectors",
                    "matching_vectors",
                    "canonical_interpretation",
                ],
                &[
                    ("evidence_contract_version", json!({"const":"2.0.0"})),
                    ("adapter_precedence_policy_sha256", sha256.clone()),
                    ("synthetic_only", json!({"const":true})),
                    ("scanner_reports_used", json!({"const":false})),
                    (
                        "precedence_vectors",
                        json!({"type":"array","minItems":8,"maxItems":8,"uniqueItems":true}),
                    ),
                    (
                        "matching_vectors",
                        json!({"type":"array","minItems":16,"maxItems":16,"uniqueItems":true}),
                    ),
                    (
                        "canonical_interpretation",
                        json!({"type":"string","minLength":1}),
                    ),
                ],
            ),
        ),
        (
            PROVENANCE_SCHEMA_PATH,
            object_schema(
                PROVENANCE_SCHEMA,
                &[
                    "schema_version",
                    "phase",
                    "method",
                    "repository_base_commit",
                    "branch",
                    "immutable_inputs",
                    "phase13_manifest_sha256",
                    "phase13_expectations_sha256",
                    "evidence_contract_v2_sha256",
                    "phase14_run_sha256",
                    "phase14_source_sha256",
                    "retained_report_sha256",
                    "generated_artifact_sha256",
                    "process_accounting",
                    "evidence_lifecycle",
                    "phase14_modified_or_rescored",
                ],
                &[
                    ("phase", json!({"const":15})),
                    ("method", json!({"type":"string","minLength":1})),
                    (
                        "repository_base_commit",
                        json!({"type":"string","pattern":"^[0-9a-f]{40}$"}),
                    ),
                    ("branch", json!({"const":BRANCH})),
                    ("immutable_inputs", json!({"type":"object"})),
                    ("phase13_manifest_sha256", sha256.clone()),
                    ("phase13_expectations_sha256", sha256.clone()),
                    ("evidence_contract_v2_sha256", sha256.clone()),
                    ("phase14_run_sha256", sha256.clone()),
                    ("phase14_source_sha256", sha256.clone()),
                    (
                        "retained_report_sha256",
                        json!({"type":"object","minProperties":112,"maxProperties":112,"additionalProperties":sha256}),
                    ),
                    (
                        "generated_artifact_sha256",
                        json!({"type":"object","minProperties":14,"additionalProperties":sha256}),
                    ),
                    (
                        "process_accounting",
                        json!({"type":"object","required":["scanner_processes_started","secure_engine_processes_started","other_scanner_processes_started","ai_processes_started","network_operations","subprocesses_started_by_library"],"properties":{"scanner_processes_started":{"const":0},"secure_engine_processes_started":{"const":0},"other_scanner_processes_started":{"const":0},"ai_processes_started":{"const":0},"network_operations":{"const":0},"subprocesses_started_by_library":{"const":0}},"additionalProperties":false}),
                    ),
                    ("evidence_lifecycle", json!({"type":"string","minLength":1})),
                    ("phase14_modified_or_rescored", json!({"const":false})),
                ],
            ),
        ),
        (
            PROCESS_AUDIT_SCHEMA_PATH,
            object_schema(
                PROCESS_AUDIT_SCHEMA,
                &[
                    "schema_version",
                    "phase",
                    "mode",
                    "scanner_processes_started",
                    "secure_engine_processes_started",
                    "other_scanner_processes_started",
                    "ai_processes_started",
                    "network_operations",
                    "secure_engine_source_inspected",
                    "scanner_binary_read_or_inspected",
                    "source_audit",
                ],
                &[
                    ("phase", json!({"const":15})),
                    ("mode", json!({"const":"offline-retained-evidence-only"})),
                    ("scanner_processes_started", json!({"const":0})),
                    ("secure_engine_processes_started", json!({"const":0})),
                    ("other_scanner_processes_started", json!({"const":0})),
                    ("ai_processes_started", json!({"const":0})),
                    ("network_operations", json!({"const":0})),
                    ("secure_engine_source_inspected", json!({"const":false})),
                    ("scanner_binary_read_or_inspected", json!({"const":false})),
                    (
                        "source_audit",
                        json!({"type":"object","required":["library_sha256","binary_sha256","process_launch_constructor_present","tcp_or_udp_api_present","inputs_are_committed_phase13_and_phase14_files"],"properties":{"library_sha256":sha256,"binary_sha256":sha256,"process_launch_constructor_present":{"const":false},"tcp_or_udp_api_present":{"const":false},"inputs_are_committed_phase13_and_phase14_files":{"const":true}},"additionalProperties":false}),
                    ),
                ],
            ),
        ),
    ])
}

fn validate_with_schema(schema: &Value, bytes: &[u8], label: &str) -> Result<(), Phase15Error> {
    let instance: Value = parse(bytes, label)?;
    let validator = jsonschema::validator_for(schema)
        .map_err(|error| Phase15Error::InvalidEvidence(error.to_string()))?;
    validator.validate(&instance).map_err(|error| {
        Phase15Error::InvalidEvidence(format!("schema rejected `{label}`: {error}"))
    })
}

fn validate_ledger(schema: &Value, bytes: &[u8]) -> Result<(), Phase15Error> {
    let mut previous = "0".repeat(64);
    let mut count = 0_u64;
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        validate_with_schema(schema, line, "Phase 15 defect ledger entry")?;
        let entry: Value = parse(line, "Phase 15 defect ledger entry")?;
        count += 1;
        if entry["sequence"] != count || entry["previous_entry_hash"] != previous {
            return Err(Phase15Error::InvalidEvidence(
                "Phase 15 defect-ledger sequence or chain differs".to_owned(),
            ));
        }
        let observed = entry["entry_hash"].as_str().ok_or_else(|| {
            Phase15Error::InvalidEvidence("Phase 15 ledger entry hash is absent".to_owned())
        })?;
        let mut unhashed = entry.clone();
        if let Some(object) = unhashed.as_object_mut() {
            object.remove("entry_hash");
        }
        if observed != hash(&canonical(&unhashed)?) {
            return Err(Phase15Error::InvalidEvidence(
                "Phase 15 defect-ledger entry hash differs".to_owned(),
            ));
        }
        observed.clone_into(&mut previous);
    }
    if count != 3 {
        return Err(Phase15Error::InvalidEvidence(
            "Phase 15 defect ledger must contain three chained entries".to_owned(),
        ));
    }
    Ok(())
}

fn process_audit(root: &Path) -> Result<Value, Phase15Error> {
    let library = read(root, "phase15/src/lib.rs")?;
    let binary = read(root, "phase15/src/main.rs")?;
    let combined = [library.as_slice(), binary.as_slice()].concat();
    let source = std::str::from_utf8(&combined)
        .map_err(|_| Phase15Error::InvalidEvidence("Phase 15 source is not UTF-8".to_owned()))?;
    let command_constructor = ["Command", "::new"].concat();
    let tcp_api = ["Tcp", "Stream"].concat();
    let udp_api = ["Udp", "Socket"].concat();
    if source.contains(&command_constructor)
        || source.contains(&tcp_api)
        || source.contains(&udp_api)
    {
        return Err(Phase15Error::InvalidEvidence(
            "Phase 15 source contains a process-launch or network API".to_owned(),
        ));
    }
    Ok(json!({
        "schema_version": PROCESS_AUDIT_SCHEMA,
        "phase": 15,
        "mode": "offline-retained-evidence-only",
        "scanner_processes_started": 0,
        "secure_engine_processes_started": 0,
        "other_scanner_processes_started": 0,
        "ai_processes_started": 0,
        "network_operations": 0,
        "secure_engine_source_inspected": false,
        "scanner_binary_read_or_inspected": false,
        "source_audit": {
            "library_sha256": hash(&library),
            "binary_sha256": hash(&binary),
            "process_launch_constructor_present": false,
            "tcp_or_udp_api_present": false,
            "inputs_are_committed_phase13_and_phase14_files": true,
        },
    }))
}

fn postmortem_document(core: &CoreBundle) -> Vec<u8> {
    format!(
        r"# Secure Bench Phase 15 offline postmortem

Phase 15 is a deterministic retrospective analysis of the retired and disclosed Phase 13 holdout and the immutable Phase 14 execution. It did not execute Secure Engine, another scanner, AI, a network operation, or any holdout case. It is not a rescore, ranking, scanner comparison, production-readiness statement, superiority claim, or complete-coverage claim.

## Confirmed root cause

Phase 14 correctly preregistered `evidence_contract_v2` as the authoritative projection, but its report adapter did not deserialize or use that field. Instead, it reconstructed canonical-looking evidence from the generic legacy `evidence_path` before deriving the finding ID and running Evidence Contract v2 matching. All 96 retained findings contain a complete authoritative v2 projection, while all 96 Phase 14 adapter records are `unmapped_semantics`. Scanner attribution in this postmortem is limited to defects already present inside the retained authoritative v2 projection; evidence lost only by the adapter is never blamed on the scanner.

This mechanism explains the Phase 14 agreement pattern: taxonomy, category, invariant, and CWE were 56/56; source identity was 0/56; source span was 28/56; sink identity was 8/56; sink span was 56/56; connected value identity and evidence path were both 0/56. Taxonomy metadata and locations survived the legacy route, but generic semantic labels did not preserve the canonical source/sink vocabulary and the adapter did not preserve the declared v2 path as the scoring input.

## Complete accounting

| Population | Count |
|---|---:|
| Retired cases | {} |
| Retained findings | {} |
| Adapter projection loss observed | {} |
| Adapter projection loss outcome-causal | {} |
| Flagged safe controls | {} |
| Vulnerable authoritative-v2 exact comparisons | {} |
| Vulnerable authoritative-v2 partial comparisons | {} |
| Vulnerable authoritative-v2 no-match comparisons | {} |

Every vulnerable case retained one finding: 10 authoritative v2 projections matched exactly, while 46 retained the wrong evidence (30 with source identity as the primary defect and 16 with source span as the primary defect). Adapter projection loss was therefore outcome-causal for 10 findings and observed but noncausal for the other 86. This is distinct from a scanner false negative caused by emitting no finding; that count is zero. All 40 flagged controls retained an overbroad finding without the frozen effective barrier, so they remain genuine scanner false positives. The frozen controls require 32 guards and 8 sanitizers; all 40 barriers terminate, apply to the same value, and dominate the sink.

Primary findings are adapter projection loss 10, scanner source identity 30, scanner source span 16, and scanner overbroad false positive 40. Contributing findings are scanner source identity 21, source span 32, guard recognition 32, sanitizer recognition 8, and dominance reasoning 40. These categories are not mutually exclusive across the primary and contributing layers.

The adapter and scanner defects co-occur in the retained evidence, so Phase 15 does not estimate independent effect sizes. For the 40 controls, the authoritative projection establishes that the required effective barrier was omitted, but black-box evidence cannot identify whether the engine ignored it, misclassified it, bypassed it, or failed to associate it with the evaluated value. Those internal alternatives remain explicitly unsupported.

The authoritative-v2 comparisons are diagnostic counterfactuals only. They do not alter the Phase 14 result, award retrospective credit, or silently repair any finding. The original exact, partial, miss, and control metrics and semantic fingerprint remain immutable.

## Historical and benchmark boundary

Before artifact generation, the frozen Phase 13 validator revalidated every fixture, expectation, mutation contract, taxonomy binding, span, connected path, paired barrier, aggregate corpus commitment, and contract Merkle root. Deterministic Phase 15 reconstruction then revalidates every Phase 13 checksum and the Phase 0–11 content-addressed payload while excluding only the prospective `diagnostics/phase-N` namespace declared by the stable historical boundary. No fixture/expectation defect, matcher defect, taxonomy drift, contract ambiguity, operational failure, or unresolved attribution was confirmed. The separate chained defect ledger records the adapter defect without changing the completed Phase 14 ledger.

## Regression handoff

The regression manifest contains only retired, disclosed Phase 13 development material and may be handed to the permitted Secure Engine Phase 6.9 regression workflow only as disclosed regression material, never as a hidden holdout or retrospective score repair. Future adapters must give a complete v2 projection precedence, fail closed on conflicts or malformed v2, and use a legacy projection only when v2 is absent and an explicit versioned legacy route is selected. Scanner-specific aliases, fixture identifiers, score exceptions, and retrospective repairs are prohibited.

## Limitations

This causal analysis is bounded by committed synthetic fixtures and retained reports. It does not establish real-world prevalence, exploitability, production fitness, superiority over another tool, or comprehensive vulnerability coverage. Phase 14 remains the preregistered historical result.
",
        core.summary.cases,
        core.summary.findings,
        core.summary.adapter_affected_findings,
        core.summary.adapter_outcome_causal_findings,
        core.summary.flagged_controls,
        core.summary.authoritative_exact,
        core.summary.authoritative_partial,
        core.summary.authoritative_no_match,
    )
    .into_bytes()
}

fn hash_index(artifacts: &BTreeMap<&str, Vec<u8>>) -> Vec<u8> {
    let mut output = String::new();
    for (relative, bytes) in artifacts {
        output.push_str(&hash(bytes));
        output.push_str("  ");
        output.push_str(relative);
        output.push('\n');
    }
    output.into_bytes()
}

fn artifact_bytes(
    root: &Path,
) -> Result<(BTreeMap<&'static str, Vec<u8>>, DiagnosticSummary), Phase15Error> {
    let core = reconstruct_core(root)?;
    let schema_values = schemas();
    let diagnostic = canonical(&core.diagnostic)?;
    let findings = canonical(&core.findings)?;
    let regression = canonical(&core.regression)?;
    let ledger = defect_ledger(&core)?;
    let conformance = canonical(&conformance_vectors(root)?)?;
    let process_audit = canonical(&process_audit(root)?)?;
    validate_with_schema(
        &schema_values[DIAGNOSTIC_SCHEMA_PATH],
        &diagnostic,
        DIAGNOSTIC_PATH,
    )?;
    validate_with_schema(&schema_values[FINDING_SCHEMA_PATH], &findings, FINDING_PATH)?;
    validate_with_schema(
        &schema_values[REGRESSION_SCHEMA_PATH],
        &regression,
        REGRESSION_PATH,
    )?;
    validate_ledger(&schema_values[LEDGER_SCHEMA_PATH], &ledger)?;
    validate_with_schema(
        &schema_values[CONFORMANCE_SCHEMA_PATH],
        &conformance,
        CONFORMANCE_PATH,
    )?;
    validate_with_schema(
        &schema_values[PROCESS_AUDIT_SCHEMA_PATH],
        &process_audit,
        PROCESS_AUDIT_PATH,
    )?;
    let mut artifacts = BTreeMap::from([
        (DIAGNOSTIC_PATH, diagnostic),
        (FINDING_PATH, findings),
        (REGRESSION_PATH, regression),
        (LEDGER_PATH, ledger),
        (CONFORMANCE_PATH, conformance),
        (PROCESS_AUDIT_PATH, process_audit),
        (DOCUMENT_PATH, postmortem_document(&core)),
    ]);
    for (relative, schema) in &schema_values {
        artifacts.insert(*relative, canonical(schema)?);
    }
    let generated_hashes = artifacts
        .iter()
        .map(|(relative, bytes)| ((*relative).to_owned(), hash(bytes)))
        .collect::<BTreeMap<_, _>>();
    let provenance = json!({
        "schema_version": PROVENANCE_SCHEMA,
        "phase": 15,
        "method": "deterministic-offline-reconstruction-from-immutable-retained-evidence",
        "repository_base_commit": GIT_BASE,
        "branch": BRANCH,
        "immutable_inputs": core.immutable,
        "phase13_manifest_sha256": hash_file(root, MANIFEST)?,
        "phase13_expectations_sha256": hash_file(root, EXPECTATIONS)?,
        "evidence_contract_v2_sha256": hash_file(root, EVIDENCE_CONTRACT)?,
        "phase14_run_sha256": hash_file(root, RUN)?,
        "phase14_source_sha256": hash_file(root, "phase14/src/lib.rs")?,
        "retained_report_sha256": core.report_hashes,
        "generated_artifact_sha256": generated_hashes,
        "process_accounting": {
            "scanner_processes_started": 0,
            "secure_engine_processes_started": 0,
            "other_scanner_processes_started": 0,
            "ai_processes_started": 0,
            "network_operations": 0,
            "subprocesses_started_by_library": 0,
        },
        "evidence_lifecycle": "separate-additive-phase15-ledger-linked-to-but-not-appended-to-the-completed-phase14-ledger",
        "phase14_modified_or_rescored": false,
    });
    let provenance = canonical(&provenance)?;
    validate_with_schema(
        &schema_values[PROVENANCE_SCHEMA_PATH],
        &provenance,
        PROVENANCE_PATH,
    )?;
    artifacts.insert(PROVENANCE_PATH, provenance);
    Ok((artifacts, core.summary))
}

/// Generates the complete additive Phase 15 package without starting any external process.
///
/// # Errors
///
/// Returns an error if historical evidence differs, reconstruction is incomplete, a schema
/// rejects an artifact, or an additive output already exists.
pub fn generate_repository(root: &Path) -> Result<DiagnosticSummary, Phase15Error> {
    let outputs = [
        DIAGNOSTIC_PATH,
        FINDING_PATH,
        REGRESSION_PATH,
        LEDGER_PATH,
        CONFORMANCE_PATH,
        PROVENANCE_PATH,
        PROCESS_AUDIT_PATH,
        HASH_INDEX_PATH,
        DOCUMENT_PATH,
        DIAGNOSTIC_SCHEMA_PATH,
        FINDING_SCHEMA_PATH,
        REGRESSION_SCHEMA_PATH,
        LEDGER_SCHEMA_PATH,
        CONFORMANCE_SCHEMA_PATH,
        PROVENANCE_SCHEMA_PATH,
        PROCESS_AUDIT_SCHEMA_PATH,
    ];
    if outputs
        .into_iter()
        .any(|relative| portable(root, relative).is_ok_and(|path| path.exists()))
    {
        return Err(Phase15Error::InvalidEvidence(
            "Phase 15 output already exists; generation is create-new only".to_owned(),
        ));
    }
    let (artifacts, summary) = artifact_bytes(root)?;
    for (relative, bytes) in &artifacts {
        write_new(root, relative, bytes)?;
    }
    write_new(root, HASH_INDEX_PATH, &hash_index(&artifacts))?;
    Ok(summary)
}

/// Verifies Phase 15 by byte-identical offline reconstruction.
///
/// # Errors
///
/// Returns an error for historical drift, incomplete accounting, schema or ledger failure,
/// non-deterministic output, privacy leakage, provenance disagreement, or process-audit failure.
pub fn verify_repository(root: &Path) -> Result<DiagnosticSummary, Phase15Error> {
    let (artifacts, summary) = artifact_bytes(root)?;
    for (relative, expected) in &artifacts {
        let observed = read(root, relative)?;
        if observed != *expected {
            return Err(Phase15Error::InvalidEvidence(format!(
                "Phase 15 artifact `{relative}` is not deterministic"
            )));
        }
        if observed
            .windows(b"/home/".len())
            .any(|window| window == b"/home/")
            || observed
                .windows(b"Proyectos".len())
                .any(|window| window == b"Proyectos")
        {
            return Err(Phase15Error::InvalidEvidence(format!(
                "Phase 15 artifact `{relative}` exposes a host path"
            )));
        }
    }
    if read(root, HASH_INDEX_PATH)? != hash_index(&artifacts) {
        return Err(Phase15Error::InvalidEvidence(
            "Phase 15 hash index differs".to_owned(),
        ));
    }
    Ok(summary)
}

/// Returns a concise summary from a fully verified Phase 15 package.
///
/// # Errors
///
/// Returns an error if Phase 15 or immutable historical evidence differs.
pub fn summarize_repository(root: &Path) -> Result<String, Phase15Error> {
    let summary = verify_repository(root)?;
    Ok(format!(
        "cases={} findings={} adapter_projection_loss_observed={} adapter_projection_loss_outcome_causal={} flagged_controls={} authoritative_exact={} authoritative_partial={} authoritative_no_match={} phase14_rescored=false scanner_processes_started=0 ai_processes_started=0",
        summary.cases,
        summary.findings,
        summary.adapter_affected_findings,
        summary.adapter_outcome_causal_findings,
        summary.flagged_controls,
        summary.authoritative_exact,
        summary.authoritative_partial,
        summary.authoritative_no_match,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repository_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_default()
    }

    #[test]
    fn reconstruction_accounts_for_every_case_and_finding() -> Result<(), Phase15Error> {
        let root = repository_root();
        let first = reconstruct_core(&root)?;
        let second = reconstruct_core(&root)?;
        assert_eq!(
            canonical(&first.diagnostic)?,
            canonical(&second.diagnostic)?
        );
        assert_eq!(first.summary.cases, 112);
        assert_eq!(first.summary.findings, 96);
        assert_eq!(first.summary.adapter_affected_findings, 96);
        assert_eq!(first.summary.adapter_outcome_causal_findings, 10);
        assert_eq!(first.summary.flagged_controls, 40);
        Ok(())
    }

    #[test]
    fn precedence_vectors_fail_closed_and_preserve_v2() {
        assert_eq!(
            projection_policy("valid", "valid", true, false),
            "authoritative_v2"
        );
        assert_eq!(
            projection_policy("valid", "valid", false, false),
            "fail_closed_conflict"
        );
        assert_eq!(
            projection_policy("malformed", "valid", false, true),
            "fail_closed_authoritative_invalid"
        );
        assert_eq!(
            projection_policy("absent", "valid", false, true),
            "versioned_legacy"
        );
        assert_eq!(
            projection_policy("absent", "valid", false, false),
            "fail_closed_legacy_not_selected"
        );
    }

    #[test]
    fn evidence_contract_vectors_cover_required_dimensions() -> Result<(), Phase15Error> {
        let suite = conformance_vectors(&repository_root())?;
        assert_eq!(
            suite["precedence_vectors"].as_array().map(Vec::len),
            Some(8)
        );
        assert_eq!(suite["matching_vectors"].as_array().map(Vec::len), Some(16));
        assert!(
            suite["matching_vectors"]
                .as_array()
                .is_some_and(|rows| rows.iter().all(|row| row["passed"] == true))
        );
        Ok(())
    }

    #[test]
    fn schemas_reject_missing_required_fields() -> Result<(), Phase15Error> {
        let values = schemas();
        for (path, schema) in values {
            let invalid = canonical(&json!({"schema_version": "wrong"}))?;
            assert!(validate_with_schema(&schema, &invalid, path).is_err());
        }
        Ok(())
    }

    #[test]
    fn schemas_reject_invalid_population_and_process_claims() -> Result<(), Phase15Error> {
        let root = repository_root();
        let values = schemas();
        let core = reconstruct_core(&root)?;

        let mut diagnostic = core.diagnostic.clone();
        diagnostic["cases"] = json!([]);
        assert!(
            validate_with_schema(
                &values[DIAGNOSTIC_SCHEMA_PATH],
                &canonical(&diagnostic)?,
                DIAGNOSTIC_PATH,
            )
            .is_err()
        );

        let mut findings = core.findings.clone();
        findings["population"]["retained_findings"] = json!(95);
        assert!(
            validate_with_schema(
                &values[FINDING_SCHEMA_PATH],
                &canonical(&findings)?,
                FINDING_PATH,
            )
            .is_err()
        );

        let mut audit = process_audit(&root)?;
        audit["scanner_processes_started"] = json!(1);
        assert!(
            validate_with_schema(
                &values[PROCESS_AUDIT_SCHEMA_PATH],
                &canonical(&audit)?,
                PROCESS_AUDIT_PATH,
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn ledger_validation_rejects_chain_tampering() -> Result<(), Phase15Error> {
        let core = reconstruct_core(&repository_root())?;
        let mut ledger = defect_ledger(&core)?;
        let first_hex = ledger
            .iter()
            .position(u8::is_ascii_hexdigit)
            .ok_or_else(|| Phase15Error::InvalidEvidence("ledger has no data".to_owned()))?;
        ledger[first_hex] = if ledger[first_hex] == b'a' {
            b'b'
        } else {
            b'a'
        };
        assert!(validate_ledger(&schemas()[LEDGER_SCHEMA_PATH], &ledger).is_err());
        Ok(())
    }

    #[test]
    fn source_has_no_launch_or_network_constructor() {
        let source = include_str!("lib.rs");
        let command = ["Command", "::new"].concat();
        let tcp = ["Tcp", "Stream"].concat();
        let udp = ["Udp", "Socket"].concat();
        assert!(!source.contains(&command));
        assert!(!source.contains(&tcp));
        assert!(!source.contains(&udp));
    }
}
