//! Prospective authoritative Evidence Contract v2 report projection for Secure Bench 0.2.2.
//!
//! This crate is additive. It has no scanner, network, AI, or subprocess execution path. It
//! validates committed report bytes, projects declared v2 evidence before deriving identifiers,
//! and keeps process-status adjudication outside the projection boundary.

#![allow(
    clippy::module_name_repetitions,
    clippy::struct_excessive_bools,
    clippy::struct_field_names,
    clippy::too_many_lines
)]

use secure_bench_core::adapter::fingerprint;
use secure_bench_core::model::ReportedTaxonomyMetadata;
use secure_bench_core::phase5::{
    CanonicalFindingV2, EvidenceContractV2, EvidenceEffectV2, EvidenceExpectationV2,
    EvidenceMatchV2, EvidenceNodeV2, EvidenceRoleV2, EvidenceSpanV2, SinkSemanticKind,
    SourceSemanticKind, evidence_fingerprint_v2, match_evidence_v2,
};
use secure_bench_core::taxonomy::{FrozenTaxonomy, load_taxonomy};
use secure_bench_phase8::{
    ProcessStatusDecision, ProcessTermination, ReportAssessment, adjudicate_status,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

/// Prospective Secure Bench release containing the adapter repair.
pub const BENCHMARK_VERSION: &str = "0.2.2";
/// Authoritative adapter-precedence policy version.
pub const ADAPTER_POLICY_VERSION: &str = "2.0.0";
/// Evidence Contract v2 version preserved by Phase 16.
pub const EVIDENCE_CONTRACT_VERSION: &str = "2.0.0";
/// Evidence semantics identity required inside declared projections.
pub const EVIDENCE_SEMANTICS_VERSION: &str = "secure-evidence-semantics-v2";
/// Explicit versioned compatibility route for legacy evidence.
pub const LEGACY_ROUTE_VERSION: &str = "secure-json-v1-legacy-canonical-v1";
/// Phase 16 branch identity.
pub const BRANCH: &str = "codex/phase-16-authoritative-v2-adapter";
/// Immutable Phase 15 starting commit.
pub const GIT_BASE: &str = "0b360a159dde5953663ad2a6c2a43a9c431dd4b3";

const MAX_REPORT_BYTES: usize = 10 * 1024 * 1024;
const TAXONOMY_PATH: &str = "taxonomy/secure-bench-taxonomy-v1.json";
const CONTRACT_PATH: &str = "holdout/phase-5/evidence-contract-v2.json";
const EXPECTATIONS_PATH: &str =
    "prospective/phase-13-holdout-v4/contracts/evidence-expectations-v2.json";
const RUN_CASES_PATH: &str =
    "phase14/output/secure-engine-0-1-4-phase13-holdout-v4/run/cases.jsonl";
const RUN_ROOT: &str = "phase14/output/secure-engine-0-1-4-phase13-holdout-v4/run";
const CONFORMANCE_PATH: &str = "diagnostics/phase-15/evidence-contract-v2-conformance-v2.json";
const POLICY_PATH: &str = "phase16/policies/adapter-precedence-v2.json";
const PHASE14_RESULT_PATH: &str =
    "phase14/output/secure-engine-0-1-4-phase13-holdout-v4/result.json";
const PHASE14_RESULT_SHA256: &str =
    "6782bf22740f57aa31345065356986a8d91f9aef012c0c4d65ce39d124830a4d";
const PHASE15_HASHES: [(&str, &str); 7] = [
    (
        "diagnostics/phase-15/retired-phase13-diagnostic-v1.json",
        "25c20a941b1445d1ee38af304acb73f5b00a0062f65a58f9637896a8dad2af6b",
    ),
    (
        "diagnostics/phase-15/finding-diagnostic-v1.json",
        "a7be8347fd2ff2577defc84373cf48505ae89477690b3fa45ca975d37cb08a3f",
    ),
    (
        "diagnostics/phase-15/regression-manifest-v1.json",
        "01ea2a8abd0d532db8f79f280bb203435a135a8e25bcfcf345ab0cefe7a7297c",
    ),
    (
        "diagnostics/phase-15/benchmark-defect-ledger-v1.jsonl",
        "de6e98a949131b72f88f45ef88f8c02b8fc54290bbf9bdb3987be6e2d15fcbb5",
    ),
    (
        CONFORMANCE_PATH,
        "3e6e5808186e0c3187c3a9e8534b30bc8cec37e5859e20448b16f82cc64f72e8",
    ),
    (
        "diagnostics/phase-15/provenance-v1.json",
        "fdd009708838f60fafbacfe095d69b7d142277d91adddf802e0be8bd090fd77a",
    ),
    (
        "diagnostics/phase-15/process-audit-v1.json",
        "5d311b0b8e5e41322846df71c9172856c434a33841fe8c5a87b999f6420d4762",
    ),
];

/// Explicit adapter route. Selection is configuration, never report-name inference.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterRoute {
    /// Require and use declared Evidence Contract v2 for every finding.
    AuthoritativeV2,
    /// Use the explicitly selected versioned legacy compatibility projection.
    LegacyV1,
}

/// Projection source recorded on every adapted finding.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionKind {
    /// Validated declared Evidence Contract v2.
    AuthoritativeV2,
    /// Explicit versioned legacy compatibility route.
    VersionedLegacyV1,
}

/// One validated finding after authoritative projection and identifier derivation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdaptedFinding {
    /// Stable identifier derived after canonical projection.
    pub finding_id: String,
    /// Semantic fingerprint computed from canonical scoring fields.
    pub semantic_fingerprint: String,
    /// Scanner-declared v2 fingerprint, preserved without using it for identity.
    pub declared_fingerprint: Option<String>,
    /// Scanner-declared v2 duplicate fingerprint, preserved without enrichment.
    pub declared_duplicate_fingerprint: Option<String>,
    /// Validated canonical Evidence Contract v2 finding.
    pub canonical: CanonicalFindingV2,
    /// Validated frozen taxonomy metadata.
    pub taxonomy: ReportedTaxonomyMetadata,
    /// Validated primary CWE from the frozen taxonomy pair.
    pub primary_cwe: String,
    /// Exact selected projection route.
    pub projection: ProjectionKind,
    /// Original declared v2 object, retained byte-semantically as parsed JSON.
    pub authoritative_projection: Option<Value>,
}

/// Complete, internally error-free report projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReportProjection {
    /// Report schema identity.
    pub schema_version: String,
    /// SHA-256 of the untouched report bytes.
    pub report_sha256: String,
    /// Validated findings in report order.
    pub findings: Vec<AdaptedFinding>,
}

/// Offline Phase 16 retained-report and conformance summary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationSummary {
    /// Retained reports processed without execution.
    pub reports: u64,
    /// Findings projected from authoritative v2.
    pub authoritative_findings: u64,
    /// Vulnerable diagnostic exact comparisons.
    pub diagnostic_exact: u64,
    /// Vulnerable diagnostic partial comparisons.
    pub diagnostic_partial: u64,
    /// Vulnerable diagnostic no-match comparisons.
    pub diagnostic_no_match: u64,
    /// Flagged safe controls in retained evidence.
    pub flagged_controls: u64,
    /// Clean safe controls in retained evidence.
    pub clean_controls: u64,
    /// Phase 15 precedence vectors executed through the adapter.
    pub precedence_vectors: u64,
    /// Phase 15 matching vectors executed through the matcher.
    pub matching_vectors: u64,
    /// Nonzero exits preserved as authoritative findings reports.
    pub policy_exit_findings_reports: u64,
}

/// Prospective adapter failure with no implicit fallback behavior.
#[derive(Debug, Error)]
pub enum AdapterError {
    /// Invalid caller or CLI request.
    #[error("invalid Phase 16 request: {0}")]
    InvalidRequest(String),
    /// Report is too large for the fixed adapter boundary.
    #[error("report exceeds the 10 MiB adapter input limit")]
    ReportTooLarge,
    /// Report JSON or required envelope fields are malformed.
    #[error("malformed report: {0}")]
    MalformedReport(String),
    /// Declared v2 uses an unsupported contract or semantics version.
    #[error("unsupported authoritative evidence version")]
    UnsupportedEvidenceVersion,
    /// Declared v2 failed its committed schema.
    #[error("authoritative Evidence Contract v2 schema validation failed: {0}")]
    InvalidEvidenceSchema(String),
    /// Declared taxonomy or CWE is absent, drifting, unknown, or conflicting.
    #[error("authoritative taxonomy validation failed: {0}")]
    InvalidTaxonomy(String),
    /// Declared path, span, connectivity, value identity, or barrier semantics are invalid.
    #[error("authoritative evidence semantics are invalid: {0}")]
    InvalidEvidenceSemantics(String),
    /// Fully canonicalizable legacy evidence conflicts with declared v2.
    #[error("authoritative v2 conflicts with a canonical legacy projection")]
    ConflictingProjections,
    /// V2 route was selected for a finding that does not declare v2.
    #[error("authoritative v2 is absent; implicit legacy fallback is prohibited")]
    MissingAuthoritativeProjection,
    /// Legacy route was selected while the report declares v2.
    #[error("versioned legacy route cannot be selected when v2 is declared")]
    LegacyRouteWithAuthoritativeProjection,
    /// Explicit legacy route could not produce a complete canonical projection.
    #[error("versioned legacy projection is invalid: {0}")]
    InvalidLegacyProjection(String),
    /// Repository evidence or an immutable historical invariant differs.
    #[error("Phase 16 offline verification failed: {0}")]
    Verification(String),
    /// Filesystem operation failed.
    #[error("Phase 16 filesystem operation failed for `{path}`: {detail}")]
    Io {
        /// Portable path context.
        path: String,
        /// Sanitized operating-system detail.
        detail: String,
    },
    /// Deterministic serialization failed.
    #[error("Phase 16 deterministic serialization failed")]
    Serialization,
}

#[derive(Debug, Deserialize)]
struct RawReport {
    schema_version: String,
    #[serde(default)]
    findings: Vec<RawFinding>,
    #[serde(default)]
    scan: Option<RawScan>,
    #[serde(default)]
    errors: Vec<Value>,
}

#[derive(Debug, Deserialize)]
struct RawScan {
    complete: bool,
}

#[derive(Debug, Deserialize)]
struct RawFinding {
    #[serde(default)]
    rule_id: Option<String>,
    #[serde(default)]
    taxonomy: Option<RawTaxonomy>,
    #[serde(default)]
    primary_cwe: Option<RawCwe>,
    #[serde(default)]
    evidence_contract_v2: Option<Value>,
    #[serde(default)]
    evidence_path: Vec<LegacyNode>,
    #[serde(default)]
    guards: Vec<Value>,
    #[serde(default)]
    verification_state: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTaxonomy {
    taxonomy_version: String,
    category_id: String,
    invariant_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawCwe {
    Text(String),
    Object { id: String },
}

impl RawCwe {
    fn id(&self) -> &str {
        match self {
            Self::Text(value) | Self::Object { id: value } => value,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeclaredEvidenceV2 {
    contract_version: String,
    semantics_version: String,
    path: Vec<DeclaredNode>,
    connected_edges: Vec<bool>,
    effective_barriers: Vec<EvidenceEffectV2>,
    unresolved_call: bool,
    uncertain: bool,
    fingerprint: String,
    duplicate_fingerprint: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeclaredNode {
    role: EvidenceRoleV2,
    effect: EvidenceEffectV2,
    #[serde(default)]
    source_kind: Option<SourceSemanticKind>,
    #[serde(default)]
    sink_kind: Option<SinkSemanticKind>,
    span: DeclaredLocation,
    summarizable: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeclaredLocation {
    path: String,
    span: DeclaredSpan,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeclaredSpan {
    start_byte: u64,
    end_byte: u64,
    start_line: u32,
    start_column: u32,
    end_line: u32,
    end_column: u32,
}

#[derive(Debug, Deserialize)]
struct LegacyNode {
    #[serde(default)]
    edge_id_from_previous: Option<String>,
    kind: String,
    #[serde(default)]
    semantic: Option<LegacySemantic>,
    location: LegacyLocation,
}

#[derive(Debug, Deserialize)]
struct LegacySemantic {
    role: String,
    identity: String,
    certainty: String,
}

#[derive(Debug, Deserialize)]
struct LegacyLocation {
    path: String,
    span: LegacySpan,
}

#[derive(Debug, Deserialize)]
struct LegacySpan {
    start_line: u32,
    #[serde(default = "one")]
    start_column: u32,
    #[serde(default)]
    end_line: Option<u32>,
    #[serde(default)]
    end_column: Option<u32>,
}

const fn one() -> u32 {
    1
}

fn read(root: &Path, relative: &str) -> Result<Vec<u8>, AdapterError> {
    let path = root.join(relative);
    fs::read(&path).map_err(|error| AdapterError::Io {
        path: relative.to_owned(),
        detail: error.to_string(),
    })
}

fn parse_json<T: for<'de> Deserialize<'de>>(bytes: &[u8], label: &str) -> Result<T, AdapterError> {
    serde_json::from_slice(bytes).map_err(|error| {
        AdapterError::Verification(format!("{label} is invalid JSON at line {}", error.line()))
    })
}

fn safe_relative(value: &str) -> Result<String, AdapterError> {
    if value.is_empty() || value.contains('\\') || value.contains(':') {
        return Err(AdapterError::InvalidEvidenceSemantics(
            "source path is not a portable relative path".to_owned(),
        ));
    }
    let mut normalized = PathBuf::new();
    for component in Path::new(value).components() {
        match component {
            Component::Normal(part) => normalized.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(AdapterError::InvalidEvidenceSemantics(
                    "source path escapes the report scope".to_owned(),
                ));
            }
        }
    }
    if normalized.as_os_str().is_empty() {
        return Err(AdapterError::InvalidEvidenceSemantics(
            "source path is empty after normalization".to_owned(),
        ));
    }
    Ok(normalized.to_string_lossy().replace('\\', "/"))
}

fn canonical_span(location: &DeclaredLocation) -> Result<EvidenceSpanV2, AdapterError> {
    let span = location.span;
    if span.start_byte >= span.end_byte
        || (span.start_line, span.start_column) > (span.end_line, span.end_column)
    {
        return Err(AdapterError::InvalidEvidenceSemantics(
            "declared source span is empty or reversed".to_owned(),
        ));
    }
    Ok(EvidenceSpanV2 {
        file: safe_relative(&location.path)?,
        start_line: span.start_line,
        start_column: span.start_column,
        end_line: span.end_line,
        end_column: span.end_column,
    })
}

fn canonical_legacy_span(location: &LegacyLocation) -> Result<EvidenceSpanV2, AdapterError> {
    let end_line = location.span.end_line.unwrap_or(location.span.start_line);
    let end_column = location
        .span
        .end_column
        .unwrap_or(location.span.start_column);
    if location.span.start_line == 0
        || location.span.start_column == 0
        || end_line == 0
        || end_column == 0
        || (location.span.start_line, location.span.start_column) > (end_line, end_column)
    {
        return Err(AdapterError::InvalidLegacyProjection(
            "legacy span is empty or reversed".to_owned(),
        ));
    }
    Ok(EvidenceSpanV2 {
        file: safe_relative(&location.path).map_err(|_| {
            AdapterError::InvalidLegacyProjection("legacy path is unsafe".to_owned())
        })?,
        start_line: location.span.start_line,
        start_column: location.span.start_column,
        end_line,
        end_column,
    })
}

fn validate_taxonomy(
    frozen: &FrozenTaxonomy,
    reported: Option<&RawTaxonomy>,
    cwe: Option<&RawCwe>,
) -> Result<(ReportedTaxonomyMetadata, String), AdapterError> {
    let reported = reported
        .ok_or_else(|| AdapterError::InvalidTaxonomy("taxonomy metadata is absent".to_owned()))?;
    let cwe = cwe
        .ok_or_else(|| AdapterError::InvalidTaxonomy("primary CWE is absent".to_owned()))?
        .id();
    if reported.taxonomy_version != "1.0.0" || reported.taxonomy_version != frozen.taxonomy_version
    {
        return Err(AdapterError::InvalidTaxonomy(
            "taxonomy version is not frozen 1.0.0".to_owned(),
        ));
    }
    let category = frozen
        .categories
        .iter()
        .find(|candidate| candidate.category_id == reported.category_id)
        .ok_or_else(|| AdapterError::InvalidTaxonomy("category is unknown".to_owned()))?;
    if category.invariant_id != reported.invariant_id {
        return Err(AdapterError::InvalidTaxonomy(
            "category and invariant are not one frozen pair".to_owned(),
        ));
    }
    if category.primary_cwe.id != cwe {
        return Err(AdapterError::InvalidTaxonomy(
            "primary CWE conflicts with the frozen taxonomy pair".to_owned(),
        ));
    }
    Ok((
        ReportedTaxonomyMetadata {
            taxonomy_version: Some(reported.taxonomy_version.clone()),
            category_id: Some(reported.category_id.clone()),
            invariant_id: Some(reported.invariant_id.clone()),
        },
        cwe.to_owned(),
    ))
}

fn validate_declared_schema(value: &Value) -> Result<DeclaredEvidenceV2, AdapterError> {
    let contract_version = value.get("contract_version").and_then(Value::as_str);
    let semantics_version = value.get("semantics_version").and_then(Value::as_str);
    if contract_version.is_some_and(|version| version != EVIDENCE_CONTRACT_VERSION)
        || semantics_version.is_some_and(|version| version != EVIDENCE_SEMANTICS_VERSION)
    {
        return Err(AdapterError::UnsupportedEvidenceVersion);
    }
    let schema: Value = serde_json::from_str(include_str!(
        "../schemas/declared-evidence-contract-v2.schema.json"
    ))
    .map_err(|_| AdapterError::Serialization)?;
    let validator = jsonschema::validator_for(&schema)
        .map_err(|error| AdapterError::InvalidEvidenceSchema(error.to_string()))?;
    validator
        .validate(value)
        .map_err(|error| AdapterError::InvalidEvidenceSchema(error.to_string()))?;
    serde_json::from_value(value.clone())
        .map_err(|error| AdapterError::InvalidEvidenceSchema(error.to_string()))
}

fn validate_node_semantics(
    node: &DeclaredNode,
    index: usize,
    last: usize,
) -> Result<(), AdapterError> {
    if index == 0 && node.role != EvidenceRoleV2::Source {
        return Err(AdapterError::InvalidEvidenceSemantics(
            "ordered path does not begin at a source".to_owned(),
        ));
    }
    if index == last && node.role != EvidenceRoleV2::Sink {
        return Err(AdapterError::InvalidEvidenceSemantics(
            "ordered path does not terminate at a sink".to_owned(),
        ));
    }
    if index > 0 && node.role == EvidenceRoleV2::Source
        || index < last && node.role == EvidenceRoleV2::Sink
    {
        return Err(AdapterError::InvalidEvidenceSemantics(
            "source or sink appears at an interior path position".to_owned(),
        ));
    }
    let source_valid = if node.role == EvidenceRoleV2::Source {
        node.source_kind.is_some() && node.sink_kind.is_none()
    } else {
        node.source_kind.is_none()
    };
    let sink_valid = if node.role == EvidenceRoleV2::Sink {
        node.sink_kind.is_some() && node.source_kind.is_none()
    } else {
        node.sink_kind.is_none()
    };
    if !source_valid || !sink_valid {
        return Err(AdapterError::InvalidEvidenceSemantics(
            "source or sink semantic identity is incomplete or misplaced".to_owned(),
        ));
    }
    if matches!(node.role, EvidenceRoleV2::Source | EvidenceRoleV2::Sink)
        && node.effect != EvidenceEffectV2::PreservesInfluence
    {
        return Err(AdapterError::InvalidEvidenceSemantics(
            "source and sink nodes must preserve influence".to_owned(),
        ));
    }
    if matches!(node.role, EvidenceRoleV2::Source | EvidenceRoleV2::Sink) && node.summarizable {
        return Err(AdapterError::InvalidEvidenceSemantics(
            "source and sink nodes cannot be summarizable".to_owned(),
        ));
    }
    let barrier_valid = match node.role {
        EvidenceRoleV2::Guard => node.effect == EvidenceEffectV2::RejectsAndTerminates,
        EvidenceRoleV2::Sanitizer => matches!(
            node.effect,
            EvidenceEffectV2::SeparatesControlAndData | EvidenceEffectV2::ConstrainsToPolicy
        ),
        EvidenceRoleV2::Authorization => node.effect == EvidenceEffectV2::AuthorizesOperation,
        _ => true,
    };
    if !barrier_valid {
        return Err(AdapterError::InvalidEvidenceSemantics(
            "barrier role and semantic effect conflict".to_owned(),
        ));
    }
    Ok(())
}

fn canonical_authoritative(
    declared: &DeclaredEvidenceV2,
    taxonomy: &RawTaxonomy,
    rule_id: Option<&str>,
) -> Result<CanonicalFindingV2, AdapterError> {
    if declared.contract_version != EVIDENCE_CONTRACT_VERSION
        || declared.semantics_version != EVIDENCE_SEMANTICS_VERSION
    {
        return Err(AdapterError::UnsupportedEvidenceVersion);
    }
    if declared.path.len() < 2
        || declared.connected_edges.len() + 1 != declared.path.len()
        || declared.connected_edges.iter().any(|connected| !connected)
    {
        return Err(AdapterError::InvalidEvidenceSemantics(
            "ordered connected value path is absent or disconnected".to_owned(),
        ));
    }
    let last = declared.path.len() - 1;
    let mut path = Vec::with_capacity(declared.path.len());
    let mut path_barriers = BTreeSet::new();
    for (index, node) in declared.path.iter().enumerate() {
        validate_node_semantics(node, index, last)?;
        if matches!(
            node.role,
            EvidenceRoleV2::Guard | EvidenceRoleV2::Sanitizer | EvidenceRoleV2::Authorization
        ) {
            path_barriers.insert(node.effect);
        }
        path.push(EvidenceNodeV2 {
            role: node.role,
            effect: node.effect,
            source_kind: node.source_kind,
            sink_kind: node.sink_kind,
            span: canonical_span(&node.span)?,
            summarizable: node.summarizable,
        });
    }
    let declared_barriers = declared
        .effective_barriers
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if path_barriers != declared_barriers {
        return Err(AdapterError::InvalidEvidenceSemantics(
            "effective barriers do not exactly match barrier nodes on the connected path"
                .to_owned(),
        ));
    }
    Ok(CanonicalFindingV2 {
        taxonomy_version: taxonomy.taxonomy_version.clone(),
        category_id: taxonomy.category_id.clone(),
        invariant_id: taxonomy.invariant_id.clone(),
        path,
        connected_edges: declared.connected_edges.clone(),
        effective_barriers: declared.effective_barriers.clone(),
        unresolved_call: declared.unresolved_call,
        uncertain: declared.uncertain,
        rule_id: rule_id.map(|value| fingerprint(value.as_bytes())),
        tool_identity: None,
        prose: None,
    })
}

fn legacy_role(value: &str) -> Result<EvidenceRoleV2, AdapterError> {
    match value {
        "source" | "untrusted-source" => Ok(EvidenceRoleV2::Source),
        "propagation" | "transformation" => Ok(EvidenceRoleV2::Propagation),
        "guard" => Ok(EvidenceRoleV2::Guard),
        "sanitizer" => Ok(EvidenceRoleV2::Sanitizer),
        "authorization" => Ok(EvidenceRoleV2::Authorization),
        "sink" | "sensitive-sink" => Ok(EvidenceRoleV2::Sink),
        _ => Err(AdapterError::InvalidLegacyProjection(
            "legacy role is not canonicalizable".to_owned(),
        )),
    }
}

fn legacy_source(identity: &str) -> Result<SourceSemanticKind, AdapterError> {
    match identity {
        "source.http-query-value" | "source.http_query_value" => {
            Ok(SourceSemanticKind::HttpQueryValue)
        }
        "source.http-body-field" | "source.http_body_field" => {
            Ok(SourceSemanticKind::HttpBodyField)
        }
        "source.form-data-value" | "source.form_data_value" => {
            Ok(SourceSemanticKind::FormDataValue)
        }
        "source.protected-resource-id" | "source.protected_resource_id" => {
            Ok(SourceSemanticKind::ProtectedResourceId)
        }
        _ => Err(AdapterError::InvalidLegacyProjection(
            "legacy source identity is not canonicalizable".to_owned(),
        )),
    }
}

fn legacy_sink(identity: &str) -> Result<SinkSemanticKind, AdapterError> {
    match identity {
        "sink.protected-record-mutation" | "sink.protected_record_mutation" => {
            Ok(SinkSemanticKind::ProtectedRecordMutation)
        }
        "sink.os-command-execution" | "sink.os_command_execution" => {
            Ok(SinkSemanticKind::OsCommandExecution)
        }
        "sink.dynamic-code-evaluation" | "sink.dynamic_code_evaluation" => {
            Ok(SinkSemanticKind::DynamicCodeEvaluation)
        }
        "sink.filesystem-read" | "sink.filesystem_read" => Ok(SinkSemanticKind::FilesystemRead),
        "sink.outbound-request" | "sink.outbound_request" => Ok(SinkSemanticKind::OutboundRequest),
        "sink.redirect-response" | "sink.redirect_response" => {
            Ok(SinkSemanticKind::RedirectResponse)
        }
        "sink.sql-query-execution" | "sink.sql_query_execution" => {
            Ok(SinkSemanticKind::SqlQueryExecution)
        }
        _ => Err(AdapterError::InvalidLegacyProjection(
            "legacy sink identity is not canonicalizable".to_owned(),
        )),
    }
}

fn legacy_effect(role: EvidenceRoleV2, identity: &str) -> Result<EvidenceEffectV2, AdapterError> {
    match (role, identity) {
        (EvidenceRoleV2::Source | EvidenceRoleV2::Sink, _)
        | (_, "effect.preserves-influence" | "effect.preserves_influence")
        | (EvidenceRoleV2::Propagation, "transformation.value") => {
            Ok(EvidenceEffectV2::PreservesInfluence)
        }
        (_, "effect.separates-control-and-data" | "effect.separates_control_and_data") => {
            Ok(EvidenceEffectV2::SeparatesControlAndData)
        }
        (_, "effect.constrains-to-policy" | "effect.constrains_to_policy") => {
            Ok(EvidenceEffectV2::ConstrainsToPolicy)
        }
        (_, "effect.rejects-and-terminates" | "effect.rejects_and_terminates") => {
            Ok(EvidenceEffectV2::RejectsAndTerminates)
        }
        (_, "effect.authorizes-operation" | "effect.authorizes_operation") => {
            Ok(EvidenceEffectV2::AuthorizesOperation)
        }
        _ => Err(AdapterError::InvalidLegacyProjection(
            "legacy effect is not canonicalizable".to_owned(),
        )),
    }
}

fn canonical_legacy(
    finding: &RawFinding,
    taxonomy: &RawTaxonomy,
) -> Result<CanonicalFindingV2, AdapterError> {
    if finding.evidence_path.len() < 2 || !finding.guards.is_empty() {
        return Err(AdapterError::InvalidLegacyProjection(
            "legacy path is incomplete or contains unstructured guards".to_owned(),
        ));
    }
    let last = finding.evidence_path.len() - 1;
    let mut path = Vec::with_capacity(finding.evidence_path.len());
    let mut connected_edges = Vec::with_capacity(last);
    let mut barriers = Vec::new();
    for (index, node) in finding.evidence_path.iter().enumerate() {
        if index > 0 {
            let connected = node
                .edge_id_from_previous
                .as_deref()
                .is_some_and(|value| !value.is_empty());
            if !connected {
                return Err(AdapterError::InvalidLegacyProjection(
                    "legacy path is disconnected".to_owned(),
                ));
            }
            connected_edges.push(true);
        }
        let semantic = node.semantic.as_ref().ok_or_else(|| {
            AdapterError::InvalidLegacyProjection("legacy semantic node is absent".to_owned())
        })?;
        if semantic.certainty != "proven" {
            return Err(AdapterError::InvalidLegacyProjection(
                "legacy semantic certainty is not proven".to_owned(),
            ));
        }
        let role = legacy_role(&semantic.role)?;
        if index == 0 && role != EvidenceRoleV2::Source
            || index == last && role != EvidenceRoleV2::Sink
            || index > 0 && role == EvidenceRoleV2::Source
            || index < last && role == EvidenceRoleV2::Sink
        {
            return Err(AdapterError::InvalidLegacyProjection(
                "legacy source and sink ordering is invalid".to_owned(),
            ));
        }
        let source_kind = (role == EvidenceRoleV2::Source)
            .then(|| legacy_source(&semantic.identity))
            .transpose()?;
        let sink_kind = (role == EvidenceRoleV2::Sink)
            .then(|| legacy_sink(&semantic.identity))
            .transpose()?;
        let effect = legacy_effect(role, &semantic.identity)?;
        if matches!(
            role,
            EvidenceRoleV2::Guard | EvidenceRoleV2::Sanitizer | EvidenceRoleV2::Authorization
        ) {
            barriers.push(effect);
        }
        path.push(EvidenceNodeV2 {
            role,
            effect,
            source_kind,
            sink_kind,
            span: canonical_legacy_span(&node.location)?,
            summarizable: false,
        });
    }
    Ok(CanonicalFindingV2 {
        taxonomy_version: taxonomy.taxonomy_version.clone(),
        category_id: taxonomy.category_id.clone(),
        invariant_id: taxonomy.invariant_id.clone(),
        path,
        connected_edges,
        effective_barriers: barriers,
        unresolved_call: finding
            .evidence_path
            .iter()
            .any(|node| node.kind == "unresolved-call"),
        uncertain: finding.verification_state.as_deref() != Some("verified-deterministic-path"),
        rule_id: finding
            .rule_id
            .as_deref()
            .map(|value| fingerprint(value.as_bytes())),
        tool_identity: None,
        prose: None,
    })
}

fn stable_finding_id(case_id: &str, semantic: &str, occurrence: u64) -> String {
    fingerprint(
        format!(
            "secure-bench-finding-id-v2\0{ADAPTER_POLICY_VERSION}\0{case_id}\0{semantic}\0{occurrence}"
        )
        .as_bytes(),
    )
}

/// Projects one complete report through an explicitly selected adapter route.
///
/// # Errors
///
/// Fails closed for malformed envelopes, invalid v2, taxonomy drift, path defects, conflicts,
/// implicit legacy fallback, or selecting legacy while v2 is declared.
pub fn project_report(
    case_id: &str,
    report: &[u8],
    route: AdapterRoute,
    frozen_taxonomy: &FrozenTaxonomy,
) -> Result<ReportProjection, AdapterError> {
    if report.len() > MAX_REPORT_BYTES {
        return Err(AdapterError::ReportTooLarge);
    }
    if case_id.is_empty()
        || !case_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(AdapterError::InvalidRequest(
            "case identity is not portable".to_owned(),
        ));
    }
    let raw: RawReport = serde_json::from_slice(report).map_err(|error| {
        AdapterError::MalformedReport(format!(
            "JSON syntax or shape error at line {}",
            error.line()
        ))
    })?;
    if raw.schema_version != "secure-json-v1" {
        return Err(AdapterError::MalformedReport(
            "report schema is not secure-json-v1".to_owned(),
        ));
    }
    if raw.scan.as_ref().is_none_or(|scan| !scan.complete) || !raw.errors.is_empty() {
        return Err(AdapterError::MalformedReport(
            "report is incomplete or declares scanner errors".to_owned(),
        ));
    }
    let report_sha256 = fingerprint(report);
    let mut occurrences = BTreeMap::<String, u64>::new();
    let mut findings = Vec::with_capacity(raw.findings.len());
    for finding in raw.findings {
        let (taxonomy, primary_cwe) = validate_taxonomy(
            frozen_taxonomy,
            finding.taxonomy.as_ref(),
            finding.primary_cwe.as_ref(),
        )?;
        let raw_taxonomy = finding.taxonomy.as_ref().ok_or_else(|| {
            AdapterError::InvalidTaxonomy("taxonomy metadata is absent".to_owned())
        })?;
        let (
            canonical,
            projection,
            declared_fingerprint,
            declared_duplicate_fingerprint,
            authoritative_projection,
        ) = match route {
            AdapterRoute::AuthoritativeV2 => {
                let value = finding
                    .evidence_contract_v2
                    .as_ref()
                    .ok_or(AdapterError::MissingAuthoritativeProjection)?;
                let declared = validate_declared_schema(value)?;
                let canonical =
                    canonical_authoritative(&declared, raw_taxonomy, finding.rule_id.as_deref())?;
                if !finding.evidence_path.is_empty()
                    && let Ok(legacy) = canonical_legacy(&finding, raw_taxonomy)
                    && legacy != canonical
                {
                    return Err(AdapterError::ConflictingProjections);
                }
                (
                    canonical,
                    ProjectionKind::AuthoritativeV2,
                    Some(declared.fingerprint),
                    Some(declared.duplicate_fingerprint),
                    Some(value.clone()),
                )
            }
            AdapterRoute::LegacyV1 => {
                if finding.evidence_contract_v2.is_some() {
                    return Err(AdapterError::LegacyRouteWithAuthoritativeProjection);
                }
                (
                    canonical_legacy(&finding, raw_taxonomy)?,
                    ProjectionKind::VersionedLegacyV1,
                    None,
                    None,
                    None,
                )
            }
        };
        let semantic_fingerprint =
            evidence_fingerprint_v2(&canonical).map_err(|_| AdapterError::Serialization)?;
        let occurrence = occurrences.entry(semantic_fingerprint.clone()).or_insert(0);
        let finding_id = stable_finding_id(case_id, &semantic_fingerprint, *occurrence);
        *occurrence += 1;
        findings.push(AdaptedFinding {
            finding_id,
            semantic_fingerprint,
            declared_fingerprint,
            declared_duplicate_fingerprint,
            canonical,
            taxonomy,
            primary_cwe,
            projection,
            authoritative_projection,
        });
    }
    Ok(ReportProjection {
        schema_version: raw.schema_version,
        report_sha256,
        findings,
    })
}

/// Converts projection success or failure into report evidence for the separate process policy.
#[must_use]
pub fn report_assessment(projection: &Result<ReportProjection, AdapterError>) -> ReportAssessment {
    match projection {
        Ok(report) => ReportAssessment::AdapterValid {
            findings: u64::try_from(report.findings.len()).unwrap_or(u64::MAX),
        },
        Err(_) => ReportAssessment::Malformed,
    }
}

#[derive(Debug, Deserialize)]
struct ExpectationsDocument {
    records: Vec<ExpectationRecord>,
}

#[derive(Debug, Deserialize)]
struct ExpectationRecord {
    case_id: String,
    kind: String,
    value_id: String,
    evidence_contract_version: String,
    authoritative_projection: String,
    legacy_override_permitted: bool,
    vulnerability_expectation: Option<EvidenceExpectationV2>,
}

#[derive(Debug, Deserialize)]
struct RunCase {
    execution: RunExecution,
    process_status: String,
}

#[derive(Debug, Deserialize)]
struct RunExecution {
    case_id: String,
    report_path: String,
    report_fingerprint: String,
    process_exit_code: Option<i32>,
}

#[derive(Debug, Deserialize)]
struct ConformanceSuite {
    precedence_vectors: Vec<PrecedenceVector>,
    matching_vectors: Vec<MatchingVector>,
}

#[derive(Debug, Deserialize)]
struct AdapterPolicy {
    schema_version: String,
    policy_version: String,
    benchmark_version: String,
    authoritative_route: String,
    legacy_route: String,
    precedence: Vec<String>,
    fail_closed: Vec<String>,
    non_enrichment: String,
    process_separation: String,
    historical_boundary: String,
}

#[derive(Debug, Deserialize)]
struct PrecedenceVector {
    vector_id: String,
    condition: String,
    expected: String,
}

#[derive(Debug, Deserialize)]
struct MatchingVector {
    vector_id: String,
    expectation: EvidenceExpectationV2,
    authoritative_finding: CanonicalFindingV2,
    reported_primary_cwe: String,
    expected: String,
}

fn synthetic_report() -> Value {
    json!({
        "schema_version": "secure-json-v1",
        "scan": {"complete": true},
        "errors": [],
        "findings": [{
            "rule_id": "synthetic-rule",
            "taxonomy": {
                "taxonomy_version": "1.0.0",
                "category_id": "secure-bench.category.command-execution",
                "invariant_id": "secure-bench.invariant.command-control-data-separation"
            },
            "primary_cwe": {"id": "CWE-78"},
            "verification_state": "verified-deterministic-path",
            "guards": [],
            "evidence_contract_v2": {
                "contract_version": "2.0.0",
                "semantics_version": "secure-evidence-semantics-v2",
                "path": [
                    {
                        "role": "source",
                        "effect": "preserves_influence",
                        "source_kind": "http_body_field",
                        "span": {"path": "src/example.ts", "span": {"start_byte": 1, "end_byte": 12, "start_line": 2, "start_column": 1, "end_line": 2, "end_column": 12}},
                        "summarizable": false
                    },
                    {
                        "role": "propagation",
                        "effect": "preserves_influence",
                        "span": {"path": "src/example.ts", "span": {"start_byte": 13, "end_byte": 24, "start_line": 3, "start_column": 1, "end_line": 3, "end_column": 12}},
                        "summarizable": false
                    },
                    {
                        "role": "sink",
                        "effect": "preserves_influence",
                        "sink_kind": "os_command_execution",
                        "span": {"path": "src/example.ts", "span": {"start_byte": 25, "end_byte": 36, "start_line": 4, "start_column": 1, "end_line": 4, "end_column": 12}},
                        "summarizable": false
                    }
                ],
                "connected_edges": [true, true],
                "effective_barriers": [],
                "unresolved_call": false,
                "uncertain": false,
                "fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "duplicate_fingerprint": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            },
            "evidence_path": [
                {
                    "kind": "source",
                    "edge_id_from_previous": null,
                    "semantic": {"role": "source", "identity": "source.http_body_field", "certainty": "proven"},
                    "location": {"path": "src/example.ts", "span": {"start_line": 2, "start_column": 1, "end_line": 2, "end_column": 12}}
                },
                {
                    "kind": "transformation",
                    "edge_id_from_previous": "edge-1",
                    "semantic": {"role": "propagation", "identity": "effect.preserves_influence", "certainty": "proven"},
                    "location": {"path": "src/example.ts", "span": {"start_line": 3, "start_column": 1, "end_line": 3, "end_column": 12}}
                },
                {
                    "kind": "sink",
                    "edge_id_from_previous": "edge-2",
                    "semantic": {"role": "sink", "identity": "sink.os_command_execution", "certainty": "proven"},
                    "location": {"path": "src/example.ts", "span": {"start_line": 4, "start_column": 1, "end_line": 4, "end_column": 12}}
                }
            ]
        }]
    })
}

fn precedence_observation(
    condition: &str,
    taxonomy: &FrozenTaxonomy,
) -> Result<String, AdapterError> {
    let mut report = synthetic_report();
    let route = {
        let finding = &mut report["findings"][0];
        match condition {
            "v2_only" => {
                finding
                    .as_object_mut()
                    .and_then(|object| object.remove("evidence_path"));
                AdapterRoute::AuthoritativeV2
            }
            "equivalent_v2_and_legacy" => AdapterRoute::AuthoritativeV2,
            "conflicting_v2_and_legacy" => {
                finding["evidence_path"][0]["semantic"]["identity"] =
                    Value::String("source.http_query_value".to_owned());
                AdapterRoute::AuthoritativeV2
            }
            "malformed_v2_cannot_fallback" => {
                finding["evidence_contract_v2"]
                    .as_object_mut()
                    .and_then(|object| object.remove("path"));
                AdapterRoute::AuthoritativeV2
            }
            "version_mismatched_v2_cannot_fallback" => {
                finding["evidence_contract_v2"]["contract_version"] =
                    Value::String("2.1.0".to_owned());
                AdapterRoute::AuthoritativeV2
            }
            "explicit_versioned_legacy_when_v2_absent" => {
                finding
                    .as_object_mut()
                    .and_then(|object| object.remove("evidence_contract_v2"));
                AdapterRoute::LegacyV1
            }
            "implicit_legacy_rejected" => {
                finding
                    .as_object_mut()
                    .and_then(|object| object.remove("evidence_contract_v2"));
                AdapterRoute::AuthoritativeV2
            }
            "missing_projections" => {
                if let Some(object) = finding.as_object_mut() {
                    object.remove("evidence_contract_v2");
                    object.remove("evidence_path");
                }
                AdapterRoute::AuthoritativeV2
            }
            _ => {
                return Err(AdapterError::Verification(format!(
                    "unknown precedence condition `{condition}`"
                )));
            }
        }
    };
    let legacy_present = report["findings"][0].get("evidence_path").is_some();
    let bytes = serde_json::to_vec(&report).map_err(|_| AdapterError::Serialization)?;
    match project_report("phase16-synthetic", &bytes, route, taxonomy) {
        Ok(projected) => Ok(
            match projected.findings.first().map(|finding| finding.projection) {
                Some(ProjectionKind::AuthoritativeV2) => "authoritative_v2",
                Some(ProjectionKind::VersionedLegacyV1) => "versioned_legacy",
                None => "fail_closed_no_canonical_projection",
            }
            .to_owned(),
        ),
        Err(AdapterError::ConflictingProjections) => Ok("fail_closed_conflict".to_owned()),
        Err(
            AdapterError::UnsupportedEvidenceVersion
            | AdapterError::InvalidEvidenceSchema(_)
            | AdapterError::InvalidEvidenceSemantics(_),
        ) => Ok("fail_closed_authoritative_invalid".to_owned()),
        Err(AdapterError::MissingAuthoritativeProjection) => {
            if legacy_present {
                Ok("fail_closed_legacy_not_selected".to_owned())
            } else {
                Ok("fail_closed_no_canonical_projection".to_owned())
            }
        }
        Err(error) => Err(error),
    }
}

fn process_status_name(status: ProcessStatusDecision) -> Result<String, AdapterError> {
    let value = serde_json::to_value(status).map_err(|_| AdapterError::Serialization)?;
    value
        .as_str()
        .map(str::to_owned)
        .ok_or(AdapterError::Serialization)
}

fn verify_conformance(
    root: &Path,
    taxonomy: &FrozenTaxonomy,
    contract: &EvidenceContractV2,
) -> Result<(u64, u64), AdapterError> {
    let suite: ConformanceSuite = parse_json(&read(root, CONFORMANCE_PATH)?, "conformance suite")?;
    for vector in &suite.precedence_vectors {
        let observed = precedence_observation(&vector.condition, taxonomy)?;
        if observed != vector.expected {
            return Err(AdapterError::Verification(format!(
                "{} expected {} but observed {observed}",
                vector.vector_id, vector.expected
            )));
        }
    }
    for vector in &suite.matching_vectors {
        let observed = if vector.reported_primary_cwe == vector.expectation.primary_cwe {
            match_evidence_v2(contract, &vector.expectation, &vector.authoritative_finding)
        } else {
            EvidenceMatchV2::NoMatch
        };
        let observed = match observed {
            EvidenceMatchV2::Exact => "exact",
            EvidenceMatchV2::Partial => "partial",
            EvidenceMatchV2::NoMatch => "no_match",
        };
        if observed != vector.expected {
            return Err(AdapterError::Verification(format!(
                "{} expected {} but observed {observed}",
                vector.vector_id, vector.expected
            )));
        }
    }
    Ok((
        u64::try_from(suite.precedence_vectors.len()).unwrap_or(u64::MAX),
        u64::try_from(suite.matching_vectors.len()).unwrap_or(u64::MAX),
    ))
}

fn verify_source_has_no_execution(root: &Path) -> Result<(), AdapterError> {
    let library = String::from_utf8(read(root, "phase16/src/lib.rs")?)
        .map_err(|_| AdapterError::Verification("Phase 16 source is not UTF-8".to_owned()))?;
    let binary = String::from_utf8(read(root, "phase16/src/main.rs")?).map_err(|_| {
        AdapterError::Verification("Phase 16 binary source is not UTF-8".to_owned())
    })?;
    let command_constructor = ["Command", "::new"].concat();
    let tcp_api = ["Tcp", "Stream"].concat();
    let udp_api = ["Udp", "Socket"].concat();
    if library.contains(&command_constructor)
        || binary.contains(&command_constructor)
        || library.contains(&tcp_api)
        || library.contains(&udp_api)
        || binary.contains(&tcp_api)
        || binary.contains(&udp_api)
    {
        return Err(AdapterError::Verification(
            "Phase 16 contains a process-launch or network constructor".to_owned(),
        ));
    }
    Ok(())
}

/// Verifies Phase 16 entirely offline from committed Phase 13–15 evidence.
///
/// # Errors
///
/// Fails for immutable hash drift, conformance-vector failure, report mutation, projection loss,
/// nondeterminism, process-policy drift, or a diagnostic population other than 10 exact and 46
/// no-match vulnerable outcomes.
pub fn verify_repository(root: &Path) -> Result<VerificationSummary, AdapterError> {
    secure_bench_phase15::verify_repository(root)
        .map_err(|error| AdapterError::Verification(error.to_string()))?;
    for (path, expected) in PHASE15_HASHES {
        if fingerprint(&read(root, path)?) != expected {
            return Err(AdapterError::Verification(format!(
                "immutable Phase 15 artifact `{path}` differs"
            )));
        }
    }
    if fingerprint(&read(root, PHASE14_RESULT_PATH)?) != PHASE14_RESULT_SHA256 {
        return Err(AdapterError::Verification(
            "immutable Phase 14 result differs".to_owned(),
        ));
    }
    verify_source_has_no_execution(root)?;
    let policy: AdapterPolicy = parse_json(&read(root, POLICY_PATH)?, "Phase 16 adapter policy")?;
    if policy.schema_version != "secure-bench-adapter-precedence-policy-v2"
        || policy.policy_version != ADAPTER_POLICY_VERSION
        || policy.benchmark_version != BENCHMARK_VERSION
        || policy.authoritative_route != "evidence_contract_v2"
        || policy.legacy_route != LEGACY_ROUTE_VERSION
        || policy.precedence.len() != 6
        || policy.fail_closed.len() != 7
        || !policy.non_enrichment.starts_with("Legacy evidence never")
        || !policy
            .process_separation
            .starts_with("Process termination adjudication")
        || !policy
            .historical_boundary
            .contains("Phase 0 through Phase 15")
    {
        return Err(AdapterError::Verification(
            "Phase 16 adapter policy is incomplete or changed".to_owned(),
        ));
    }
    let taxonomy = load_taxonomy(&read(root, TAXONOMY_PATH)?)
        .map_err(|error| AdapterError::Verification(error.to_string()))?;
    let contract: EvidenceContractV2 =
        parse_json(&read(root, CONTRACT_PATH)?, "evidence contract")?;
    secure_bench_core::schema::validate_evidence_contract_v2(&contract)
        .map_err(|error| AdapterError::Verification(error.to_string()))?;
    if contract.contract_version != EVIDENCE_CONTRACT_VERSION
        || contract.taxonomy.taxonomy_version != "1.0.0"
    {
        return Err(AdapterError::Verification(
            "Evidence Contract v2 or taxonomy version differs".to_owned(),
        ));
    }
    let (precedence_vectors, matching_vectors) = verify_conformance(root, &taxonomy, &contract)?;
    let expectations: ExpectationsDocument =
        parse_json(&read(root, EXPECTATIONS_PATH)?, "Phase 13 expectations")?;
    let expectation_map = expectations
        .records
        .iter()
        .map(|record| (record.case_id.as_str(), record))
        .collect::<BTreeMap<_, _>>();
    let cases_bytes = read(root, RUN_CASES_PATH)?;
    let mut reports = 0_u64;
    let mut authoritative_findings = 0_u64;
    let mut diagnostic_exact = 0_u64;
    let mut diagnostic_partial = 0_u64;
    let mut diagnostic_no_match = 0_u64;
    let mut flagged_controls = 0_u64;
    let mut clean_controls = 0_u64;
    let mut policy_exit_findings_reports = 0_u64;
    let mut finding_ids = BTreeSet::new();
    for line in cases_bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let case: RunCase = parse_json(line, "Phase 14 run case")?;
        let expectation = expectation_map
            .get(case.execution.case_id.as_str())
            .ok_or_else(|| {
                AdapterError::Verification(format!(
                    "{} expectation is absent",
                    case.execution.case_id
                ))
            })?;
        if expectation.value_id.is_empty()
            || expectation.evidence_contract_version != EVIDENCE_CONTRACT_VERSION
            || expectation.authoritative_projection != "evidence_contract_v2"
            || expectation.legacy_override_permitted
        {
            return Err(AdapterError::Verification(format!(
                "{} prospective expectation boundary differs",
                case.execution.case_id
            )));
        }
        let report_relative = safe_relative(&case.execution.report_path)?;
        let report = read(root, &format!("{RUN_ROOT}/{report_relative}"))?;
        if fingerprint(&report) != case.execution.report_fingerprint {
            return Err(AdapterError::Verification(format!(
                "{} retained report bytes differ",
                case.execution.case_id
            )));
        }
        let first = project_report(
            &case.execution.case_id,
            &report,
            AdapterRoute::AuthoritativeV2,
            &taxonomy,
        )?;
        let second = project_report(
            &case.execution.case_id,
            &report,
            AdapterRoute::AuthoritativeV2,
            &taxonomy,
        )?;
        if first != second || first.report_sha256 != case.execution.report_fingerprint {
            return Err(AdapterError::Verification(format!(
                "{} projection is not deterministic",
                case.execution.case_id
            )));
        }
        for finding in &first.findings {
            if finding.projection != ProjectionKind::AuthoritativeV2
                || finding.authoritative_projection.is_none()
                || !finding_ids.insert(finding.finding_id.clone())
            {
                return Err(AdapterError::Verification(format!(
                    "{} did not preserve one unique authoritative projection",
                    case.execution.case_id
                )));
            }
        }
        reports += 1;
        authoritative_findings += u64::try_from(first.findings.len()).unwrap_or(u64::MAX);
        let exit_code = case.execution.process_exit_code.ok_or_else(|| {
            AdapterError::Verification(format!(
                "{} lacks normal exit evidence",
                case.execution.case_id
            ))
        })?;
        let decision = adjudicate_status(
            ProcessTermination::Exited(exit_code),
            ReportAssessment::AdapterValid {
                findings: u64::try_from(first.findings.len()).unwrap_or(u64::MAX),
            },
        );
        if process_status_name(decision)? != case.process_status {
            return Err(AdapterError::Verification(format!(
                "{} process status changed",
                case.execution.case_id
            )));
        }
        if decision == ProcessStatusDecision::PolicyExitWithValidFindingsReport {
            policy_exit_findings_reports += 1;
        }
        match expectation.kind.as_str() {
            "vulnerable" => {
                let expected = expectation
                    .vulnerability_expectation
                    .as_ref()
                    .ok_or_else(|| {
                        AdapterError::Verification(format!(
                            "{} vulnerable expectation is absent",
                            case.execution.case_id
                        ))
                    })?;
                if first.findings.len() != 1 {
                    return Err(AdapterError::Verification(format!(
                        "{} does not retain exactly one finding",
                        case.execution.case_id
                    )));
                }
                let finding = &first.findings[0];
                let outcome = if finding.primary_cwe == expected.primary_cwe {
                    match_evidence_v2(&contract, expected, &finding.canonical)
                } else {
                    EvidenceMatchV2::NoMatch
                };
                match outcome {
                    EvidenceMatchV2::Exact => diagnostic_exact += 1,
                    EvidenceMatchV2::Partial => diagnostic_partial += 1,
                    EvidenceMatchV2::NoMatch => diagnostic_no_match += 1,
                }
            }
            "safe_control" if first.findings.is_empty() => clean_controls += 1,
            "safe_control" => flagged_controls += 1,
            _ => {
                return Err(AdapterError::Verification(format!(
                    "{} has an unknown expectation kind",
                    case.execution.case_id
                )));
            }
        }
    }
    if reports != 112
        || authoritative_findings != 96
        || diagnostic_exact != 10
        || diagnostic_partial != 0
        || diagnostic_no_match != 46
        || flagged_controls != 40
        || clean_controls != 16
        || precedence_vectors != 8
        || matching_vectors != 16
        || policy_exit_findings_reports != 96
    {
        return Err(AdapterError::Verification(format!(
            "population differs: reports={reports} findings={authoritative_findings} exact={diagnostic_exact} partial={diagnostic_partial} no_match={diagnostic_no_match} flagged={flagged_controls} clean={clean_controls} precedence={precedence_vectors} matching={matching_vectors} policy_exit={policy_exit_findings_reports}"
        )));
    }
    Ok(VerificationSummary {
        reports,
        authoritative_findings,
        diagnostic_exact,
        diagnostic_partial,
        diagnostic_no_match,
        flagged_controls,
        clean_controls,
        precedence_vectors,
        matching_vectors,
        policy_exit_findings_reports,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repository_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
    }

    fn taxonomy() -> Result<FrozenTaxonomy, AdapterError> {
        let root = repository_root();
        load_taxonomy(&read(&root, TAXONOMY_PATH)?)
            .map_err(|error| AdapterError::Verification(error.to_string()))
    }

    fn project_value(value: &Value) -> Result<ReportProjection, AdapterError> {
        project_report(
            "phase16-test",
            &serde_json::to_vec(value).map_err(|_| AdapterError::Serialization)?,
            AdapterRoute::AuthoritativeV2,
            &taxonomy()?,
        )
    }

    #[test]
    fn executes_every_phase15_conformance_vector() -> Result<(), AdapterError> {
        let root = repository_root();
        let taxonomy = taxonomy()?;
        let contract: EvidenceContractV2 =
            parse_json(&read(&root, CONTRACT_PATH)?, "evidence contract")?;
        assert_eq!(verify_conformance(&root, &taxonomy, &contract)?, (8, 16));
        Ok(())
    }

    #[test]
    fn rejects_malformed_incomplete_and_unsupported_v2_without_fallback() {
        let mut missing_path = synthetic_report();
        missing_path["findings"][0]["evidence_contract_v2"]
            .as_object_mut()
            .and_then(|object| object.remove("path"));
        assert!(matches!(
            project_value(&missing_path),
            Err(AdapterError::InvalidEvidenceSchema(_))
        ));

        let mut unsupported = synthetic_report();
        unsupported["findings"][0]["evidence_contract_v2"]["contract_version"] =
            Value::String("3.0.0".to_owned());
        assert!(matches!(
            project_value(&unsupported),
            Err(AdapterError::UnsupportedEvidenceVersion)
        ));
    }

    #[test]
    fn rejects_missing_endpoints_invalid_spans_and_disconnected_value_paths() {
        let mut missing_source = synthetic_report();
        missing_source["findings"][0]["evidence_contract_v2"]["path"][0]["role"] =
            Value::String("propagation".to_owned());
        assert!(matches!(
            project_value(&missing_source),
            Err(AdapterError::InvalidEvidenceSemantics(_))
        ));

        let mut missing_source_identity = synthetic_report();
        missing_source_identity["findings"][0]["evidence_contract_v2"]["path"][0]
            .as_object_mut()
            .and_then(|object| object.remove("source_kind"));
        assert!(matches!(
            project_value(&missing_source_identity),
            Err(AdapterError::InvalidEvidenceSemantics(_))
        ));

        let mut missing_sink_identity = synthetic_report();
        missing_sink_identity["findings"][0]["evidence_contract_v2"]["path"][2]
            .as_object_mut()
            .and_then(|object| object.remove("sink_kind"));
        assert!(matches!(
            project_value(&missing_sink_identity),
            Err(AdapterError::InvalidEvidenceSemantics(_))
        ));

        let mut invalid_span = synthetic_report();
        invalid_span["findings"][0]["evidence_contract_v2"]["path"][0]["span"]["span"]["start_line"] =
            json!(0);
        assert!(matches!(
            project_value(&invalid_span),
            Err(AdapterError::InvalidEvidenceSchema(_))
        ));

        let mut disconnected = synthetic_report();
        disconnected["findings"][0]["evidence_contract_v2"]["connected_edges"][0] =
            Value::Bool(false);
        assert!(matches!(
            project_value(&disconnected),
            Err(AdapterError::InvalidEvidenceSemantics(_))
        ));

        let mut missing_identity = synthetic_report();
        missing_identity["findings"][0]["evidence_contract_v2"]
            .as_object_mut()
            .and_then(|object| object.remove("connected_edges"));
        assert!(matches!(
            project_value(&missing_identity),
            Err(AdapterError::InvalidEvidenceSchema(_))
        ));
    }

    #[test]
    fn rejects_taxonomy_drift_and_invalid_barrier_semantics() -> Result<(), AdapterError> {
        let mut drift = synthetic_report();
        drift["findings"][0]["taxonomy"]["taxonomy_version"] = Value::String("1.1.0".to_owned());
        assert!(matches!(
            project_value(&drift),
            Err(AdapterError::InvalidTaxonomy(_))
        ));

        let mut cwe_drift = synthetic_report();
        cwe_drift["findings"][0]["primary_cwe"]["id"] = Value::String("CWE-22".to_owned());
        assert!(matches!(
            project_value(&cwe_drift),
            Err(AdapterError::InvalidTaxonomy(_))
        ));

        let mut barrier = synthetic_report();
        barrier["findings"][0]["evidence_contract_v2"]["effective_barriers"] =
            json!(["rejects_and_terminates"]);
        assert!(matches!(
            project_value(&barrier),
            Err(AdapterError::InvalidEvidenceSemantics(_))
        ));

        let mut valid_barrier = synthetic_report();
        let barrier_node = json!({
            "role": "guard",
            "effect": "rejects_and_terminates",
            "span": {"path": "src/example.ts", "span": {"start_byte": 24, "end_byte": 25, "start_line": 3, "start_column": 13, "end_line": 3, "end_column": 14}},
            "summarizable": false
        });
        valid_barrier["findings"][0]["evidence_contract_v2"]["path"]
            .as_array_mut()
            .ok_or(AdapterError::Serialization)?
            .insert(2, barrier_node);
        valid_barrier["findings"][0]["evidence_contract_v2"]["connected_edges"] =
            json!([true, true, true]);
        valid_barrier["findings"][0]["evidence_contract_v2"]["effective_barriers"] =
            json!(["rejects_and_terminates"]);
        valid_barrier["findings"][0]
            .as_object_mut()
            .and_then(|object| object.remove("evidence_path"));
        let projected = project_value(&valid_barrier)?;
        assert_eq!(
            projected.findings[0].canonical.effective_barriers,
            [EvidenceEffectV2::RejectsAndTerminates]
        );
        Ok(())
    }

    #[test]
    fn finding_ids_follow_authoritative_semantics_not_legacy_or_report_bytes()
    -> Result<(), AdapterError> {
        let first = synthetic_report();
        let projected_first = project_value(&first)?;
        let mut second = first.clone();
        second["findings"][0]["title"] = Value::String("non-scoring prose".to_owned());
        second["findings"][0]["evidence_path"] = Value::Array(Vec::new());
        let projected_second = project_value(&second)?;
        assert_ne!(
            projected_first.report_sha256,
            projected_second.report_sha256
        );
        assert_eq!(
            projected_first.findings[0].finding_id,
            projected_second.findings[0].finding_id
        );
        assert_eq!(
            projected_first.findings[0].canonical,
            projected_second.findings[0].canonical
        );
        Ok(())
    }

    #[test]
    fn process_status_remains_separate_and_preserves_policy_exit_reports() {
        let projected = project_value(&synthetic_report());
        assert_eq!(
            report_assessment(&projected),
            ReportAssessment::AdapterValid { findings: 1 }
        );
        assert_eq!(
            adjudicate_status(ProcessTermination::Exited(1), report_assessment(&projected)),
            ProcessStatusDecision::PolicyExitWithValidFindingsReport
        );
        let mut invalid = synthetic_report();
        invalid["findings"][0]["evidence_contract_v2"]["contract_version"] =
            Value::String("9.0.0".to_owned());
        let invalid = project_value(&invalid);
        assert_eq!(report_assessment(&invalid), ReportAssessment::Malformed);
        assert_eq!(
            adjudicate_status(ProcessTermination::Exited(1), report_assessment(&invalid)),
            ProcessStatusDecision::MalformedReport
        );
    }

    #[test]
    fn retained_reports_project_deterministically_without_rescoring() -> Result<(), AdapterError> {
        let summary = verify_repository(&repository_root())?;
        assert_eq!(summary.reports, 112);
        assert_eq!(summary.authoritative_findings, 96);
        assert_eq!(summary.diagnostic_exact, 10);
        assert_eq!(summary.diagnostic_partial, 0);
        assert_eq!(summary.diagnostic_no_match, 46);
        assert_eq!(summary.flagged_controls, 40);
        assert_eq!(summary.clean_controls, 16);
        Ok(())
    }
}
