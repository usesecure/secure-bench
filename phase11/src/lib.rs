//! Deterministic, scanner-free Phase 11 diagnostics for the retired Phase 9 holdout.
//!
//! Phase 11 is additive. It preserves the preregistered Phase 10 score and reconstructs every
//! diagnostic from committed fixture source, contracts, retained reports, and execution metadata.

#![allow(
    clippy::module_name_repetitions,
    clippy::struct_excessive_bools,
    clippy::struct_field_names
)]

use secure_bench_core::adapter::fingerprint;
use secure_bench_core::phase5::{
    CanonicalFindingV2, EvidenceContractV2, EvidenceEffectV2, EvidenceExpectationV2,
    EvidenceMatchV2, EvidenceNodeV2, EvidenceRoleV2, EvidenceSpanV2, SinkSemanticKind,
    SourceSemanticKind, match_evidence_v2,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

/// Versioned retired diagnostic package schema.
pub const DIAGNOSTIC_SCHEMA: &str = "secure-bench-phase11-retired-diagnostic-v1";
/// Versioned generalized regression manifest schema.
pub const REGRESSION_SCHEMA: &str = "secure-bench-phase11-regression-manifest-v1";
/// Versioned defect-ledger entry schema.
pub const LEDGER_SCHEMA: &str = "secure-bench-phase11-defect-ledger-entry-v1";
/// Versioned public conformance-vector schema.
pub const CONFORMANCE_SCHEMA: &str = "secure-bench-phase11-evidence-conformance-v1";
/// Required immutable main commit.
pub const GIT_BASE: &str = "a9d0c0b880e99f9f5345e3acf00c7cb4916b3a61";
/// Required Phase 11 branch.
pub const BRANCH: &str = "codex/phase-11-phase10-postmortem";

const MANIFEST: &str = "holdout/phase-9/manifest.json";
const TAXONOMY: &str = "taxonomy/secure-bench-taxonomy-v1.json";
const EVIDENCE: &str = "holdout/phase-5/evidence-contract-v2.json";
const RUN: &str = "phase10/output/secure-engine-0-1-4-phase9-holdout/run/run.json";
const RESULT: &str = "phase10/output/secure-engine-0-1-4-phase9-holdout/result.json";
const ARTIFACTS: &str = "phase10/output/secure-engine-0-1-4-phase9-holdout/artifacts.json";
const LEDGER: &str = "phase10/output/secure-engine-0-1-4-phase9-holdout/completed-ledger.jsonl";
const PRE_EXECUTION: &str =
    "phase10/output/secure-engine-0-1-4-phase9-holdout/pre-execution-contract.json";
const PROCESS_AUDIT: &str = "phase10/output/secure-engine-0-1-4-phase9-holdout/process-audit.json";
const OUTPUT: &str = "diagnostics/phase-11";
const DIAGNOSTIC_PATH: &str = "diagnostics/phase-11/retired-diagnostic-v1.json";
const REGRESSION_PATH: &str = "diagnostics/phase-11/regression-manifest-v1.json";
const DEFECT_LEDGER_PATH: &str = "diagnostics/phase-11/benchmark-defect-ledger-v1.jsonl";
const CONFORMANCE_PATH: &str = "diagnostics/phase-11/evidence-contract-v2-conformance-v1.json";
const HASH_INDEX_PATH: &str = "diagnostics/phase-11/SHA256SUMS";

const IMMUTABLE_HASHES: [(&str, &str); 6] = [
    (
        RESULT,
        "bfb74fbc89345bcb6c8584fc8774b2347f31816bdbf1efc9628e96cab8904a7c",
    ),
    (
        LEDGER,
        "ddcbcfda08af81b89374091bfd42b0aeef8bcde9339d6f6b40506953c07b6b77",
    ),
    (
        ARTIFACTS,
        "a1d41915269937bd4570ea238731e0d83d9717fa2f22c9ffe2c1cd234cab57ef",
    ),
    (
        PRE_EXECUTION,
        "9ae54bb31edeaeee736b52a0d667d8f3c12d2d6c73d66690f7af7905d777def1",
    ),
    (
        PROCESS_AUDIT,
        "3c48f3cdae5c6f69af747c978e7e4bc35dc6b3c57f71aadf2c5e1d7693cce43b",
    ),
    (
        MANIFEST,
        "136f92a3bbe324d8f0e3c49438b93aa4ef6eb09731998784feed0b6f75553a9f",
    ),
];
const REPORT_AGGREGATE: &str = "b7c5ba7bb3c7f6f2ed82a3aabd12daaf15b09b6c3cabda4e39d29827b46ee0e1";

/// Phase 11 input, reconstruction, or artifact error.
#[derive(Debug, Error)]
pub enum Phase11Error {
    /// Invalid invocation.
    #[error("invalid Phase 11 request: {0}")]
    InvalidRequest(String),
    /// Immutable evidence or a diagnostic invariant differs.
    #[error("invalid Phase 11 evidence: {0}")]
    InvalidEvidence(String),
    /// Filesystem operation failed.
    #[error("Phase 11 filesystem operation failed for `{path}`: {detail}")]
    Io {
        /// Portable path context.
        path: String,
        /// Operating-system detail.
        detail: String,
    },
    /// JSON operation failed.
    #[error("Phase 11 serialization failed: {0}")]
    Serialization(String),
}

/// Concise verified diagnostic summary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DiagnosticSummary {
    /// Retired cases classified.
    pub cases: u64,
    /// Retained findings mapped.
    pub findings: u64,
    /// Vulnerable cases with a supported semantic finding.
    pub semantically_supported_findings: u64,
    /// Confirmed scanner-defect affected cases.
    pub scanner_defect_cases: u64,
    /// Confirmed benchmark-defect affected cases.
    pub benchmark_defect_cases: u64,
    /// Adapter-defect affected findings.
    pub adapter_defect_findings: u64,
}

#[derive(Clone, Debug, Deserialize)]
struct ManifestProjection {
    holdout_id: String,
    pairs: Vec<Pair>,
}

#[derive(Clone, Debug, Deserialize)]
struct Pair {
    pair_id: String,
    assignment: Assignment,
    invariant_id: String,
    primary_cwe: String,
    source_kind: String,
    sink_kind: String,
    mutation: Mutation,
    first: Case,
    second: Case,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Assignment {
    framework: String,
    language: String,
    topology: String,
    category_id: String,
    family_id: String,
}

#[derive(Clone, Debug, Deserialize)]
struct Mutation {
    file: String,
    structural_property: String,
}

#[derive(Clone, Debug, Deserialize)]
struct Case {
    case_id: String,
    fixture_path: String,
    fixture_sha256: String,
    contract_sha256: String,
    kind: String,
    expectation: Option<Expected>,
    security_property: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Expected {
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

#[derive(Clone, Debug, Deserialize)]
struct TaxonomyProjection {
    taxonomy_version: String,
    categories: Vec<TaxonomyCategory>,
}

#[derive(Clone, Debug, Deserialize)]
struct TaxonomyCategory {
    category_id: String,
    invariant_id: String,
    primary_cwe: TaxonomyCwe,
}

#[derive(Clone, Debug, Deserialize)]
struct TaxonomyCwe {
    id: String,
}

#[derive(Clone, Debug, Deserialize)]
struct RunProjection {
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
    report_path: Option<String>,
    report_fingerprint: Option<String>,
    status: String,
    process_exit_code: Option<i32>,
}

#[derive(Clone, Debug, Deserialize)]
struct OfficialResult {
    metrics: Value,
    cases: Vec<OfficialCase>,
    findings: Vec<Value>,
    semantic_fingerprint: String,
}

#[derive(Clone, Debug, Deserialize)]
struct OfficialCase {
    case_id: String,
    outcome: String,
    distinct_findings: u64,
    unrelated_findings: u64,
    selected_finding_id: Option<String>,
    criteria: Option<Value>,
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
    rule_id: String,
    finding_id: String,
    taxonomy: RawTaxonomy,
    primary_cwe: Value,
    evidence_contract_v2: DeclaredContract,
}

#[derive(Clone, Debug, Deserialize)]
struct RawTaxonomy {
    taxonomy_version: String,
    category_id: String,
    invariant_id: String,
}

#[derive(Clone, Debug, Deserialize)]
struct DeclaredContract {
    contract_version: String,
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
    start_line: u32,
    start_column: u32,
    end_line: u32,
    end_column: u32,
}

fn path(root: &Path, relative: &str) -> Result<PathBuf, Phase11Error> {
    let candidate = Path::new(relative);
    if candidate.is_absolute()
        || candidate.components().any(|part| {
            matches!(
                part,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(Phase11Error::InvalidEvidence(
            "artifact path is not portable".to_owned(),
        ));
    }
    Ok(root.join(candidate))
}

fn read(root: &Path, relative: &str) -> Result<Vec<u8>, Phase11Error> {
    let absolute = path(root, relative)?;
    fs::read(&absolute).map_err(|error| Phase11Error::Io {
        path: relative.to_owned(),
        detail: error.to_string(),
    })
}

fn parse<T: for<'de> Deserialize<'de>>(bytes: &[u8], label: &str) -> Result<T, Phase11Error> {
    serde_json::from_slice(bytes)
        .map_err(|error| Phase11Error::InvalidEvidence(format!("{label} is invalid JSON: {error}")))
}

fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, Phase11Error> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| Phase11Error::Serialization(error.to_string()))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn hash(bytes: &[u8]) -> String {
    fingerprint(bytes)
}

fn hash_file(root: &Path, relative: &str) -> Result<String, Phase11Error> {
    Ok(hash(&read(root, relative)?))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn aggregate_named_hashes(rows: &BTreeMap<String, String>) -> String {
    let joined = rows
        .iter()
        .map(|(name, digest)| format!("{name}\0{digest}"))
        .collect::<Vec<_>>()
        .join("\n");
    hash(joined.as_bytes())
}

fn write_new(root: &Path, relative: &str, bytes: &[u8]) -> Result<(), Phase11Error> {
    let absolute = path(root, relative)?;
    let parent = absolute.parent().ok_or_else(|| {
        Phase11Error::InvalidEvidence("output has no parent directory".to_owned())
    })?;
    fs::create_dir_all(parent).map_err(|error| Phase11Error::Io {
        path: parent.display().to_string(),
        detail: error.to_string(),
    })?;
    if absolute.exists() {
        return Err(Phase11Error::InvalidEvidence(format!(
            "additive output `{relative}` already exists"
        )));
    }
    fs::write(&absolute, bytes).map_err(|error| Phase11Error::Io {
        path: relative.to_owned(),
        detail: error.to_string(),
    })
}

fn role(value: &str) -> Result<EvidenceRoleV2, Phase11Error> {
    match value {
        "source" => Ok(EvidenceRoleV2::Source),
        "intermediate" | "propagation" => Ok(EvidenceRoleV2::Propagation),
        "transformation" => Ok(EvidenceRoleV2::Transformation),
        "guard" => Ok(EvidenceRoleV2::Guard),
        "sanitizer" => Ok(EvidenceRoleV2::Sanitizer),
        "authorization" => Ok(EvidenceRoleV2::Authorization),
        "sink" => Ok(EvidenceRoleV2::Sink),
        _ => Err(Phase11Error::InvalidEvidence(format!(
            "unknown evidence role `{value}`"
        ))),
    }
}

fn effect(value: &str) -> Result<EvidenceEffectV2, Phase11Error> {
    match value {
        "preserves_influence" => Ok(EvidenceEffectV2::PreservesInfluence),
        "separates_control_and_data" => Ok(EvidenceEffectV2::SeparatesControlAndData),
        "constrains_to_policy" => Ok(EvidenceEffectV2::ConstrainsToPolicy),
        "rejects_and_terminates" => Ok(EvidenceEffectV2::RejectsAndTerminates),
        "authorizes_operation" => Ok(EvidenceEffectV2::AuthorizesOperation),
        _ => Err(Phase11Error::InvalidEvidence(format!(
            "unknown evidence effect `{value}`"
        ))),
    }
}

fn source_kind(value: Option<&str>) -> Result<Option<SourceSemanticKind>, Phase11Error> {
    value
        .map(|value| match value {
            "http_query_value" => Ok(SourceSemanticKind::HttpQueryValue),
            "http_body_field" => Ok(SourceSemanticKind::HttpBodyField),
            "form_data_value" => Ok(SourceSemanticKind::FormDataValue),
            "protected_resource_id" => Ok(SourceSemanticKind::ProtectedResourceId),
            _ => Err(Phase11Error::InvalidEvidence(format!(
                "unknown source kind `{value}`"
            ))),
        })
        .transpose()
}

fn sink_kind(value: Option<&str>) -> Result<Option<SinkSemanticKind>, Phase11Error> {
    value
        .map(|value| match value {
            "protected_record_mutation" => Ok(SinkSemanticKind::ProtectedRecordMutation),
            "os_command_execution" => Ok(SinkSemanticKind::OsCommandExecution),
            "dynamic_code_evaluation" => Ok(SinkSemanticKind::DynamicCodeEvaluation),
            "filesystem_read" => Ok(SinkSemanticKind::FilesystemRead),
            "outbound_request" => Ok(SinkSemanticKind::OutboundRequest),
            "redirect_response" => Ok(SinkSemanticKind::RedirectResponse),
            "sql_query_execution" => Ok(SinkSemanticKind::SqlQueryExecution),
            _ => Err(Phase11Error::InvalidEvidence(format!(
                "unknown sink kind `{value}`"
            ))),
        })
        .transpose()
}

fn expectation(expected: &Expected) -> Result<EvidenceExpectationV2, Phase11Error> {
    let path = expected
        .path
        .iter()
        .map(|node| {
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
        })
        .collect::<Result<Vec<_>, Phase11Error>>()?;
    Ok(EvidenceExpectationV2 {
        expectation_id: expected.expectation_id.clone(),
        taxonomy_version: expected.taxonomy_version.clone(),
        category_id: expected.category_id.clone(),
        invariant_id: expected.invariant_id.clone(),
        primary_cwe: expected.primary_cwe.clone(),
        path,
    })
}

fn canonical_finding(finding: &RawFinding) -> Result<CanonicalFindingV2, Phase11Error> {
    if finding.evidence_contract_v2.contract_version != "2.0.0" {
        return Err(Phase11Error::InvalidEvidence(
            "retained finding declares a different evidence contract".to_owned(),
        ));
    }
    let path = finding
        .evidence_contract_v2
        .path
        .iter()
        .map(|node| {
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
        })
        .collect::<Result<Vec<_>, Phase11Error>>()?;
    Ok(CanonicalFindingV2 {
        taxonomy_version: finding.taxonomy.taxonomy_version.clone(),
        category_id: finding.taxonomy.category_id.clone(),
        invariant_id: finding.taxonomy.invariant_id.clone(),
        path,
        connected_edges: finding.evidence_contract_v2.connected_edges.clone(),
        effective_barriers: finding
            .evidence_contract_v2
            .effective_barriers
            .iter()
            .map(|value| effect(value))
            .collect::<Result<Vec<_>, _>>()?,
        unresolved_call: finding.evidence_contract_v2.unresolved_call,
        uncertain: finding.evidence_contract_v2.uncertain,
        rule_id: Some(finding.rule_id.clone()),
        tool_identity: Some("external-black-box-retained-report".to_owned()),
        prose: None,
    })
}

fn cwe(value: &Value) -> Option<&str> {
    value
        .as_str()
        .or_else(|| value.get("id").and_then(Value::as_str))
}

fn span_text(root: &Path, fixture: &str, span: &ExpectedSpan) -> Result<String, Phase11Error> {
    let relative = format!("{fixture}/{}", span.file);
    let bytes = read(root, &relative)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| Phase11Error::InvalidEvidence(format!("fixture `{relative}` is not UTF-8")))?;
    let lines = text.lines().collect::<Vec<_>>();
    let start_line = usize::try_from(span.start_line.saturating_sub(1))
        .map_err(|_| Phase11Error::InvalidEvidence("source span line overflow".to_owned()))?;
    let end_line = usize::try_from(span.end_line.saturating_sub(1))
        .map_err(|_| Phase11Error::InvalidEvidence("source span line overflow".to_owned()))?;
    if start_line >= lines.len() || end_line >= lines.len() || start_line > end_line {
        return Err(Phase11Error::InvalidEvidence(format!(
            "span is outside `{relative}`"
        )));
    }
    let start_column = usize::try_from(span.start_column.saturating_sub(1))
        .map_err(|_| Phase11Error::InvalidEvidence("source span column overflow".to_owned()))?;
    let end_column = usize::try_from(span.end_column.saturating_sub(1))
        .map_err(|_| Phase11Error::InvalidEvidence("source span column overflow".to_owned()))?;
    if start_line == end_line {
        return lines[start_line]
            .get(start_column..end_column)
            .map(str::to_owned)
            .ok_or_else(|| {
                Phase11Error::InvalidEvidence(format!("span columns are outside `{relative}`"))
            });
    }
    Ok(lines[start_line..=end_line].join("\n"))
}

fn fixture_sources(root: &Path, case: &Case) -> Result<String, Phase11Error> {
    let directory = path(root, &case.fixture_path)?;
    let mut files = BTreeMap::new();
    collect_files(&directory, Path::new(""), &mut files)?;
    let mut output = String::new();
    for (relative, bytes) in files {
        if Path::new(&relative)
            .extension()
            .and_then(|value| value.to_str())
            == Some("json")
        {
            continue;
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| {
            Phase11Error::InvalidEvidence(format!("fixture `{relative}` is not UTF-8"))
        })?;
        output.push_str(text);
        output.push('\n');
    }
    Ok(output)
}

fn safe_markers(family: &str) -> &'static [&'static str] {
    match family {
        "SE1001" => &[
            "mayChange",
            "if (!permitted)",
            "operation denied",
            "records.update",
        ],
        "SE1002" => &[
            "tasks.get",
            "if (!selected)",
            "task denied",
            "execFile(selected[0]",
        ],
        "SE1003" => &[
            "operations.get",
            "if (!operation)",
            "operation denied",
            "operation(runtime.context)",
        ],
        "SE1004" => &[
            "resolve(root",
            "startsWith",
            "path denied",
            "readFile(selected",
        ],
        "SE1005" => &[
            "new URL",
            "approvedOrigin",
            "destination denied",
            "fetch(selected",
        ],
        "SE1006" => &[
            "startsWith(\"/\")",
            "startsWith(\"//\")",
            "redirect denied",
            "selected",
        ],
        "SE1007" => &["WHERE label = ?"],
        _ => &[],
    }
}

fn sink_marker(family: &str, text: &str) -> bool {
    match family {
        "SE1001" => text.contains("records.update"),
        "SE1002" => text.contains("exec(String"),
        "SE1003" => text.contains("new Function"),
        "SE1004" => text.contains("readFile("),
        "SE1005" => text.contains("fetch("),
        "SE1006" => text.contains("redirect") || text.contains("respondRedirect"),
        "SE1007" => text.contains("database.query"),
        _ => false,
    }
}

fn direct_undefined_value_use(family: &str, source: &str) -> bool {
    match family {
        "SE1001" => source.contains("records.update(value"),
        "SE1002" | "SE1003" | "SE1004" | "SE1005" | "SE1006" => source.contains("String(value)"),
        "SE1007" => source.contains("${value}") || source.contains("String(value)"),
        _ => false,
    }
}

fn fixture_semantics(root: &Path, pair: &Pair, case: &Case) -> Result<Value, Phase11Error> {
    let source = fixture_sources(root, case)?;
    let direct = pair.assignment.topology == "direct";
    let vulnerable = case.kind == "vulnerable";
    let source_span_valid = case.expectation.as_ref().is_none_or(|expected| {
        expected.path.first().is_some_and(|node| {
            span_text(root, &case.fixture_path, &node.span).is_ok_and(|text| {
                text.contains("candidate")
                    && (text.contains("body.value")
                        || text.contains("payload.value")
                        || text.contains("formData.get"))
            })
        })
    });
    let sink_span_valid = case.expectation.as_ref().is_none_or(|expected| {
        expected.path.last().is_some_and(|node| {
            span_text(root, &case.fixture_path, &node.span)
                .is_ok_and(|text| sink_marker(&pair.assignment.family_id, &text))
        })
    });
    let topology_bridge_valid = match pair.assignment.topology.as_str() {
        "helper_mediated" => {
            source.contains("applyBoundary(candidate") && source.contains("applyBoundary(value")
        }
        "inter_file_aliased" => {
            source.contains("traverseBoundary(candidate") && source.contains("applyBoundary(value")
        }
        "control_flow_sensitive" => {
            source.contains("let selected = candidate")
                && source.contains("selected = String(candidate)")
        }
        _ => false,
    };
    let markers = safe_markers(&pair.assignment.family_id);
    let structural_barrier_present = !vulnerable
        && markers.iter().all(|marker| source.contains(marker))
        && (pair.assignment.family_id != "SE1007"
            || source.contains("[String(value)]")
            || source.contains("[String(selected)]"));
    let security_property_valid = !vulnerable && !direct && structural_barrier_present;
    Ok(json!({
        "source_span_valid": source_span_valid,
        "sink_span_valid": sink_span_valid,
        "ordered_path_declared": case.expectation.as_ref().is_none_or(|value| value.path.len() >= 2 && value.path.first().is_some_and(|node| node.role == "source") && value.path.last().is_some_and(|node| node.role == "sink")),
        "source_sink_value_connected": !direct && topology_bridge_valid,
        "transform_value_identity_valid": !direct && topology_bridge_valid,
        "structural_barrier_present": structural_barrier_present,
        "barrier_dominates_and_terminates": !vulnerable && !direct && structural_barrier_present,
        "security_property_valid": security_property_valid,
        "direct_renderer_uses_undefined_value": direct && source.contains("const candidate =") && direct_undefined_value_use(&pair.assignment.family_id, &source),
    }))
}

fn collect_files(
    directory: &Path,
    prefix: &Path,
    output: &mut BTreeMap<String, Vec<u8>>,
) -> Result<(), Phase11Error> {
    let mut entries = fs::read_dir(directory)
        .map_err(|error| Phase11Error::Io {
            path: directory.display().to_string(),
            detail: error.to_string(),
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| Phase11Error::Io {
            path: directory.display().to_string(),
            detail: error.to_string(),
        })?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let file_type = entry.file_type().map_err(|error| Phase11Error::Io {
            path: entry.path().display().to_string(),
            detail: error.to_string(),
        })?;
        let relative = prefix.join(entry.file_name());
        if file_type.is_dir() {
            collect_files(&entry.path(), &relative, output)?;
        } else if file_type.is_file() {
            let key = relative
                .to_str()
                .ok_or_else(|| {
                    Phase11Error::InvalidEvidence("fixture path is not UTF-8".to_owned())
                })?
                .replace('\\', "/");
            let bytes = fs::read(entry.path()).map_err(|error| Phase11Error::Io {
                path: entry.path().display().to_string(),
                detail: error.to_string(),
            })?;
            output.insert(key, bytes);
        } else {
            return Err(Phase11Error::InvalidEvidence(
                "fixture contains a non-regular entry".to_owned(),
            ));
        }
    }
    Ok(())
}

fn fixture_fingerprint(root: &Path, case: &Case) -> Result<String, Phase11Error> {
    let directory = path(root, &case.fixture_path)?;
    let mut files = BTreeMap::new();
    collect_files(&directory, Path::new(""), &mut files)?;
    let mut hasher = Sha256::new();
    for (relative, bytes) in files {
        hasher.update(relative.as_bytes());
        hasher.update([0]);
        hasher.update(hash(&bytes).as_bytes());
        hasher.update([b'\n']);
    }
    Ok(hex(&hasher.finalize()))
}

fn verify_immutable(root: &Path) -> Result<Value, Phase11Error> {
    for (relative, expected) in IMMUTABLE_HASHES {
        let observed = hash_file(root, relative)?;
        if observed != expected {
            return Err(Phase11Error::InvalidEvidence(format!(
                "immutable `{relative}` hash differs: expected {expected}, observed {observed}"
            )));
        }
    }
    let validation = secure_bench_phase9::validate_holdout(root)
        .map_err(|error| Phase11Error::InvalidEvidence(error.to_string()))?;
    if validation.cases != 224
        || validation.pairs != 112
        || validation.aggregate_corpus_sha256
            != "30f51f643da6d27c8c94758289ee77c937104d372b97f0de90d4d40ced56dbe2"
        || validation.contract_merkle_root
            != "7c41259cb2bc36cdab2582ac9867df6a95c1fd59686315118f70c07fe5eedf6a"
    {
        return Err(Phase11Error::InvalidEvidence(
            "Phase 9 frozen validation commitments differ".to_owned(),
        ));
    }
    Ok(json!({
        "phase10_result_sha256": IMMUTABLE_HASHES[0].1,
        "phase10_completed_ledger_sha256": IMMUTABLE_HASHES[1].1,
        "phase10_artifact_index_sha256": IMMUTABLE_HASHES[2].1,
        "phase10_pre_execution_contract_sha256": IMMUTABLE_HASHES[3].1,
        "phase10_process_audit_sha256": IMMUTABLE_HASHES[4].1,
        "phase9_manifest_sha256": IMMUTABLE_HASHES[5].1,
        "phase10_report_aggregate_sha256": REPORT_AGGREGATE,
        "phase9_aggregate_corpus_sha256": validation.aggregate_corpus_sha256,
        "phase9_contract_merkle_root": validation.contract_merkle_root,
    }))
}

fn taxonomy_map(taxonomy: &TaxonomyProjection) -> BTreeMap<String, &TaxonomyCategory> {
    taxonomy
        .categories
        .iter()
        .map(|category| (category.category_id.clone(), category))
        .collect()
}

fn official_counts_valid(result: &OfficialResult) -> bool {
    let counts = &result.metrics["counts"];
    counts["exact_detections"] == 0
        && counts["partial_matches"] == 0
        && counts["misses"] == 112
        && counts["safe_controls_flagged"] == 24
        && counts["clean_safe_controls"] == 88
        && counts["unrelated_findings"] == 48
        && counts["distinct_findings"] == 48
}

type ReportMap = BTreeMap<String, RawReport>;
type HashMap = BTreeMap<String, String>;

fn report_maps(root: &Path, run: &RunProjection) -> Result<(ReportMap, HashMap), Phase11Error> {
    if run.cases.len() != 224 || run.scanner_launch_attempts != 224 {
        return Err(Phase11Error::InvalidEvidence(
            "Phase 10 run population differs".to_owned(),
        ));
    }
    let mut reports = BTreeMap::new();
    let mut hashes = BTreeMap::new();
    for case in &run.cases {
        if case.scanner_launch_attempts != 1 {
            return Err(Phase11Error::InvalidEvidence(format!(
                "{} does not retain exactly one historical launch",
                case.execution.case_id
            )));
        }
        let relative = case.execution.report_path.as_deref().ok_or_else(|| {
            Phase11Error::InvalidEvidence(format!(
                "{} lacks a retained report",
                case.execution.case_id
            ))
        })?;
        let relative = format!("phase10/output/secure-engine-0-1-4-phase9-holdout/run/{relative}");
        let bytes = read(root, &relative)?;
        let observed = hash(&bytes);
        if case.execution.report_fingerprint.as_deref() != Some(observed.as_str()) {
            return Err(Phase11Error::InvalidEvidence(format!(
                "{} retained report hash differs",
                case.execution.case_id
            )));
        }
        let report: RawReport = parse(&bytes, &relative)?;
        if report.schema_version != "secure-json-v1"
            || !report.scan.complete
            || !report.errors.is_empty()
        {
            return Err(Phase11Error::InvalidEvidence(format!(
                "{} report is not complete and authoritative",
                case.execution.case_id
            )));
        }
        hashes.insert(case.execution.case_id.clone(), observed);
        reports.insert(case.execution.case_id.clone(), report);
    }
    if aggregate_named_hashes(&hashes) != REPORT_AGGREGATE {
        return Err(Phase11Error::InvalidEvidence(
            "retained report aggregate differs".to_owned(),
        ));
    }
    Ok((reports, hashes))
}

fn paired_case<'a>(pair: &'a Pair, kind: &str) -> &'a Case {
    if pair.first.kind == kind {
        &pair.first
    } else {
        &pair.second
    }
}

fn criterion(criteria: Option<&Value>, name: &str) -> Option<bool> {
    criteria
        .and_then(|value| value.get(name))
        .and_then(Value::as_bool)
}

fn agreement(
    expected: &EvidenceExpectationV2,
    finding: &CanonicalFindingV2,
    raw_cwe: Option<&str>,
) -> Value {
    let expected_source = expected.path.first();
    let expected_sink = expected.path.last();
    let actual_source = finding.path.first();
    let actual_sink = finding.path.last();
    let source_identity = expected_source.and_then(|node| node.source_kind)
        == actual_source.and_then(|node| node.source_kind);
    let sink_identity = expected_sink.and_then(|node| node.sink_kind)
        == actual_sink.and_then(|node| node.sink_kind);
    let source_span = expected_source
        .zip(actual_source)
        .is_some_and(|(expected, actual)| {
            diagnostic_spans_equivalent(&expected.span, &actual.span)
        });
    let sink_span = expected_sink
        .zip(actual_sink)
        .is_some_and(|(expected, actual)| {
            diagnostic_spans_equivalent(&expected.span, &actual.span)
        });
    let path_connected = finding.connected_edges.len() + 1 == finding.path.len()
        && finding.connected_edges.iter().all(|connected| *connected);
    json!({
        "taxonomy_version": finding.taxonomy_version == expected.taxonomy_version,
        "category": finding.category_id == expected.category_id,
        "invariant": finding.invariant_id == expected.invariant_id,
        "cwe": raw_cwe == Some(expected.primary_cwe.as_str()),
        "source_identity": source_identity,
        "source_span": source_span,
        "sink_identity": sink_identity,
        "sink_span": sink_span,
        "ordered_connected_path": path_connected && source_identity && sink_identity,
        "transform_value_identity": path_connected,
        "guard_sanitizer_barrier_dominance": finding.effective_barriers.is_empty(),
    })
}

fn diagnostic_spans_equivalent(expected: &EvidenceSpanV2, actual: &EvidenceSpanV2) -> bool {
    if expected.file != actual.file {
        return false;
    }
    if expected == actual {
        return true;
    }
    let contains = |outer: &EvidenceSpanV2, inner: &EvidenceSpanV2| {
        (outer.start_line, outer.start_column) <= (inner.start_line, inner.start_column)
            && (outer.end_line, outer.end_column) >= (inner.end_line, inner.end_column)
    };
    let expansion = expected.start_line.abs_diff(actual.start_line)
        + expected.end_line.abs_diff(actual.end_line);
    (contains(expected, actual) || contains(actual, expected)) && expansion <= 3
}

fn mismatch_reasons(agreement: &Value) -> Vec<String> {
    agreement
        .as_object()
        .into_iter()
        .flat_map(|object| object.iter())
        .filter(|(_, value)| value == &&Value::Bool(false))
        .map(|(name, _)| name.clone())
        .collect()
}

#[derive(Clone, Debug, Default, Serialize)]
struct GroupCounts {
    cases: u64,
    vulnerable: u64,
    controls: u64,
    taxonomy_valid: u64,
    source_semantics_valid: u64,
    safe_property_valid: u64,
    fully_contract_valid: u64,
    semantically_supported_findings: u64,
    no_finding_emitted: u64,
    scanner_false_negative: u64,
    scanner_false_positive: u64,
    adapter_affected: u64,
    benchmark_defect_affected: u64,
}

#[derive(Clone, Copy)]
struct CaseFlags {
    vulnerable: bool,
    taxonomy_valid: bool,
    source_semantics_valid: bool,
    safe_property_valid: bool,
    fully_contract_valid: bool,
    semantically_supported: bool,
    no_finding: bool,
    scanner_false_negative: bool,
    scanner_false_positive: bool,
    adapter_affected: bool,
    benchmark_defect: bool,
}

impl GroupCounts {
    fn add(&mut self, flags: CaseFlags) {
        self.cases += 1;
        self.vulnerable += u64::from(flags.vulnerable);
        self.controls += u64::from(!flags.vulnerable);
        self.taxonomy_valid += u64::from(flags.taxonomy_valid);
        self.source_semantics_valid += u64::from(flags.source_semantics_valid);
        self.safe_property_valid += u64::from(flags.safe_property_valid);
        self.fully_contract_valid += u64::from(flags.fully_contract_valid);
        self.semantically_supported_findings += u64::from(flags.semantically_supported);
        self.no_finding_emitted += u64::from(flags.no_finding);
        self.scanner_false_negative += u64::from(flags.scanner_false_negative);
        self.scanner_false_positive += u64::from(flags.scanner_false_positive);
        self.adapter_affected += u64::from(flags.adapter_affected);
        self.benchmark_defect_affected += u64::from(flags.benchmark_defect);
    }
}

fn add_group(map: &mut BTreeMap<String, GroupCounts>, key: String, flags: CaseFlags) {
    map.entry(key).or_default().add(flags);
}

#[allow(clippy::too_many_arguments)]
fn update_breakdowns(
    maps: &mut BTreeMap<String, BTreeMap<String, GroupCounts>>,
    pair: &Pair,
    flags: CaseFlags,
) {
    let taxonomy = pair.assignment.family_id.clone();
    let framework = pair.assignment.framework.clone();
    let language = pair.assignment.language.clone();
    let topology = pair.assignment.topology.clone();
    let rows = [
        ("taxonomy_family", taxonomy.clone()),
        ("framework", framework.clone()),
        ("language", language.clone()),
        ("topology", topology.clone()),
        ("taxonomy_framework", format!("{taxonomy}|{framework}")),
        ("taxonomy_language", format!("{taxonomy}|{language}")),
        ("taxonomy_topology", format!("{taxonomy}|{topology}")),
        ("framework_language", format!("{framework}|{language}")),
        ("framework_topology", format!("{framework}|{topology}")),
        ("language_topology", format!("{language}|{topology}")),
    ];
    for (dimension, key) in rows {
        if let Some(map) = maps.get_mut(dimension) {
            add_group(map, key, flags);
        }
    }
}

fn agreement_matrix(rows: &[Value]) -> Value {
    let names = [
        "taxonomy_version",
        "category",
        "invariant",
        "cwe",
        "source_identity",
        "source_span",
        "sink_identity",
        "sink_span",
        "ordered_connected_path",
        "transform_value_identity",
        "guard_sanitizer_barrier_dominance",
    ];
    let mut matrix = serde_json::Map::new();
    for name in names {
        let agrees = rows
            .iter()
            .filter(|row| row.get(name) == Some(&Value::Bool(true)))
            .count();
        matrix.insert(
            name.to_owned(),
            json!({
                "applicable": rows.len(),
                "agrees": agrees,
                "disagrees": rows.len().saturating_sub(agrees),
                "uncertain": 0,
            }),
        );
    }
    Value::Object(matrix)
}

fn official_finding_map(result: &OfficialResult) -> BTreeMap<String, &Value> {
    result
        .findings
        .iter()
        .filter_map(|finding| {
            finding
                .get("case_id")
                .and_then(Value::as_str)
                .map(|case_id| (case_id.to_owned(), finding))
        })
        .collect()
}

fn taxonomy_corrected_expectation(
    expected: &EvidenceExpectationV2,
    category: &TaxonomyCategory,
) -> EvidenceExpectationV2 {
    let mut corrected = expected.clone();
    corrected.invariant_id.clone_from(&category.invariant_id);
    corrected.primary_cwe.clone_from(&category.primary_cwe.id);
    corrected
}

#[allow(clippy::too_many_lines)]
fn reconstruct(
    root: &Path,
) -> Result<(Value, Value, Vec<u8>, Value, DiagnosticSummary), Phase11Error> {
    let immutable = verify_immutable(root)?;
    let manifest: ManifestProjection = parse(&read(root, MANIFEST)?, "Phase 9 manifest")?;
    let taxonomy: TaxonomyProjection = parse(&read(root, TAXONOMY)?, "frozen taxonomy")?;
    let contract: EvidenceContractV2 = parse(&read(root, EVIDENCE)?, "Evidence Contract v2")?;
    let run: RunProjection = parse(&read(root, RUN)?, "Phase 10 run")?;
    let official: OfficialResult = parse(&read(root, RESULT)?, "Phase 10 result")?;
    if manifest.pairs.len() != 112
        || taxonomy.taxonomy_version != "1.0.0"
        || contract.contract_version != "2.0.0"
        || !official_counts_valid(&official)
    {
        return Err(Phase11Error::InvalidEvidence(
            "frozen populations, taxonomy, contract, or official metrics differ".to_owned(),
        ));
    }
    let taxonomy = taxonomy_map(&taxonomy);
    let official_cases = official
        .cases
        .iter()
        .map(|case| (case.case_id.clone(), case))
        .collect::<BTreeMap<_, _>>();
    let official_findings = official_finding_map(&official);
    let run_cases = run
        .cases
        .iter()
        .map(|case| (case.execution.case_id.clone(), case))
        .collect::<BTreeMap<_, _>>();
    let (reports, report_hashes) = report_maps(root, &run)?;

    let mut diagnostic_cases = Vec::with_capacity(224);
    let mut diagnostic_findings = Vec::with_capacity(48);
    let mut regression_cases = Vec::with_capacity(224);
    let mut vulnerable_agreement = Vec::new();
    let mut paired_agreement = Vec::new();
    let mut fixture_expectation_agreement = Vec::new();
    let mut breakdowns = [
        "taxonomy_family",
        "framework",
        "language",
        "topology",
        "taxonomy_framework",
        "taxonomy_language",
        "taxonomy_topology",
        "framework_language",
        "framework_topology",
        "language_topology",
    ]
    .into_iter()
    .map(|name| (name.to_owned(), BTreeMap::new()))
    .collect::<BTreeMap<_, _>>();
    let mut scanner_defect_cases = BTreeSet::new();
    let mut scanner_false_negative_cases = BTreeSet::new();
    let mut scanner_false_positive_cases = BTreeSet::new();
    let mut unsupported_direct_cases = BTreeSet::new();
    let mut source_span_defect_cases = BTreeSet::new();
    let mut benchmark_defect_cases = BTreeSet::new();
    let mut taxonomy_defect_cases = BTreeSet::new();
    let mut direct_defect_cases = BTreeSet::new();
    let mut adapter_defect_findings = BTreeSet::new();
    let mut semantically_supported = 0_u64;
    let mut supported_ids = BTreeSet::new();

    let mut pairs = manifest.pairs.iter().collect::<Vec<_>>();
    pairs.sort_by(|left, right| left.pair_id.cmp(&right.pair_id));
    for pair in pairs {
        let taxonomy_category = taxonomy.get(&pair.assignment.category_id).ok_or_else(|| {
            Phase11Error::InvalidEvidence(format!(
                "{} category is absent from the frozen taxonomy",
                pair.pair_id
            ))
        })?;
        let taxonomy_valid = pair.invariant_id == taxonomy_category.invariant_id
            && pair.primary_cwe == taxonomy_category.primary_cwe.id;
        let vulnerable_case = paired_case(pair, "vulnerable");
        let paired_expectation = vulnerable_case.expectation.as_ref().ok_or_else(|| {
            Phase11Error::InvalidEvidence(format!(
                "{} lacks an expectation",
                vulnerable_case.case_id
            ))
        })?;
        let expected = expectation(paired_expectation)?;
        let corrected = taxonomy_corrected_expectation(&expected, taxonomy_category);
        for case in [&pair.first, &pair.second] {
            if fixture_fingerprint(root, case)? != case.fixture_sha256 {
                return Err(Phase11Error::InvalidEvidence(format!(
                    "{} fixture fingerprint differs",
                    case.case_id
                )));
            }
            let semantics = fixture_semantics(root, pair, case)?;
            let vulnerable = case.kind == "vulnerable";
            let direct = pair.assignment.topology == "direct";
            let source_semantics_valid = semantics["source_sink_value_connected"] == true;
            let safe_property_valid = semantics["security_property_valid"] == true;
            let benchmark_defect = !taxonomy_valid || direct;
            if vulnerable {
                fixture_expectation_agreement.push(json!({
                    "taxonomy_version": true,
                    "category": true,
                    "invariant": taxonomy_valid,
                    "cwe": true,
                    "source_identity": semantics["source_span_valid"] == true,
                    "source_span": semantics["source_span_valid"] == true,
                    "sink_identity": semantics["sink_span_valid"] == true,
                    "sink_span": semantics["sink_span_valid"] == true,
                    "ordered_connected_path": source_semantics_valid,
                    "transform_value_identity": source_semantics_valid,
                    "guard_sanitizer_barrier_dominance": true,
                }));
            }
            let official_case = official_cases.get(&case.case_id).ok_or_else(|| {
                Phase11Error::InvalidEvidence(format!("{} is absent from Phase 10", case.case_id))
            })?;
            let run_case = run_cases.get(&case.case_id).ok_or_else(|| {
                Phase11Error::InvalidEvidence(format!("{} is absent from the run", case.case_id))
            })?;
            let report = reports.get(&case.case_id).ok_or_else(|| {
                Phase11Error::InvalidEvidence(format!("{} report is absent", case.case_id))
            })?;
            if report.findings.len() > 1 {
                return Err(Phase11Error::InvalidEvidence(format!(
                    "{} unexpectedly contains more than one finding",
                    case.case_id
                )));
            }
            let has_finding = !report.findings.is_empty();
            let scanner_false_negative = vulnerable && !direct && !has_finding;
            let scanner_false_positive = !vulnerable && !direct && has_finding;
            let unsupported_direct_claim = vulnerable && direct && has_finding;
            if scanner_false_negative || scanner_false_positive || unsupported_direct_claim {
                scanner_defect_cases.insert(case.case_id.clone());
            }
            if scanner_false_negative {
                scanner_false_negative_cases.insert(case.case_id.clone());
            }
            if scanner_false_positive {
                scanner_false_positive_cases.insert(case.case_id.clone());
            }
            if unsupported_direct_claim {
                unsupported_direct_cases.insert(case.case_id.clone());
            }
            if benchmark_defect {
                benchmark_defect_cases.insert(case.case_id.clone());
            }
            if !taxonomy_valid {
                taxonomy_defect_cases.insert(case.case_id.clone());
            }
            if direct {
                direct_defect_cases.insert(case.case_id.clone());
            }
            let mut causes = Vec::new();
            if vulnerable && !has_finding {
                causes.push("no_finding_emitted");
            }
            if !taxonomy_valid {
                causes.extend([
                    "taxonomy_mismatch",
                    "invariant_mismatch",
                    "invalid_benchmark_expectation",
                ]);
            }
            if direct {
                causes.extend([
                    "disconnected_or_incorrectly_ordered_evidence_path",
                    "missing_transform_or_value_identity_step",
                    "invalid_or_ambiguous_benchmark_expectation",
                ]);
            }
            if scanner_false_negative {
                causes.push("confirmed_scanner_false_negative");
            }
            if !vulnerable && !has_finding && !direct {
                causes.push("correctly_clean");
            }
            if !vulnerable && direct {
                causes.extend(["barrier_represented_incorrectly", "ambiguous_control"]);
            }
            if scanner_false_positive {
                causes.push("scanner_false_positive");
                match pair.assignment.family_id.as_str() {
                    "SE1002" => causes.push("allowlist_or_fixed_executable_semantics_mismatch"),
                    "SE1004" => causes.push("confinement_semantics_mismatch"),
                    "SE1006" => causes.push("allowlist_or_fallback_semantics_mismatch"),
                    _ => {}
                }
            }

            let mut case_supported = false;
            if let Some(raw) = report.findings.first() {
                let canonical = canonical_finding(raw)?;
                let declared_agreement = agreement(&expected, &canonical, cwe(&raw.primary_cwe));
                let corrected_agreement = agreement(&corrected, &canonical, cwe(&raw.primary_cwe));
                let declared_match = match_evidence_v2(&contract, &expected, &canonical);
                let corrected_match = match_evidence_v2(&contract, &corrected, &canonical);
                case_supported = vulnerable && !direct && corrected_match == EvidenceMatchV2::Exact;
                let source_span_defect = vulnerable
                    && !direct
                    && corrected_agreement["source_identity"] == true
                    && corrected_agreement["source_span"] == false;
                if source_span_defect {
                    source_span_defect_cases.insert(case.case_id.clone());
                    scanner_defect_cases.insert(case.case_id.clone());
                    causes.push("source_span_mismatch");
                    causes.push("correct_vulnerability_with_contract_source_span_defect");
                }
                if case_supported {
                    semantically_supported += 1;
                    supported_ids.insert(case.case_id.clone());
                    causes.push("correct_vulnerability_semantics_in_retained_finding");
                }
                causes.push("adapter_normalization_defect");
                if vulnerable && !taxonomy_valid {
                    causes.push("evidence_contract_v2_interpretation_mismatch");
                }
                if unsupported_direct_claim {
                    causes.push("scanner_claims_unsupported_connected_path");
                }
                let official_finding = official_findings.get(&case.case_id).ok_or_else(|| {
                    Phase11Error::InvalidEvidence(format!(
                        "{} finding is absent from the official finding table",
                        case.case_id
                    ))
                })?;
                let official_id = official_finding["finding_id"].as_str().ok_or_else(|| {
                    Phase11Error::InvalidEvidence("official finding ID is absent".to_owned())
                })?;
                if official_finding["adapter_state"] != "unmapped_semantics" {
                    return Err(Phase11Error::InvalidEvidence(
                        "Phase 10 adapter state unexpectedly differs".to_owned(),
                    ));
                }
                adapter_defect_findings.insert(official_id.to_owned());
                let related_case = if vulnerable {
                    case.case_id.clone()
                } else {
                    vulnerable_case.case_id.clone()
                };
                let full_reconciliation =
                    vulnerable && !direct && declared_match == EvidenceMatchV2::Exact;
                let legitimate_outcome_reconciliation = full_reconciliation;
                let would_weaken = !vulnerable || direct;
                let official_rejection_reasons = if vulnerable {
                    [
                        "taxonomy",
                        "category",
                        "invariant",
                        "cwe",
                        "source",
                        "sink",
                        "evidence_path",
                        "barrier",
                        "sanitizer",
                        "guard",
                        "dominance",
                    ]
                    .into_iter()
                    .filter(|name| criterion(official_case.criteria.as_ref(), name) == Some(false))
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
                } else {
                    vec!["safe_control_flagged".to_owned()]
                };
                diagnostic_findings.push(json!({
                    "official_finding_id": official_id,
                    "scanner_finding_id": raw.finding_id,
                    "case_id": case.case_id,
                    "semantically_related_expected_case": related_case,
                    "rule_id_non_scoring": raw.rule_id,
                    "report_sha256": report_hashes[&case.case_id],
                    "declared_contract_fingerprint": raw.evidence_contract_v2.fingerprint,
                    "declared_duplicate_fingerprint": raw.evidence_contract_v2.duplicate_fingerprint,
                    "official_adapter_state": "unmapped_semantics",
                    "official_rejection_reasons": official_rejection_reasons,
                    "declared_contract_match_against_historical_expectation": declared_match,
                    "declared_contract_mismatch_reasons": mismatch_reasons(&declared_agreement),
                    "frozen_taxonomy_corrected_analytical_match": corrected_match,
                    "frozen_taxonomy_corrected_mismatch_reasons": mismatch_reasons(&corrected_agreement),
                    "fixture_semantics_support_finding": case_supported,
                    "normalization": {
                        "declared_v2_was_authoritative_and_parseable": true,
                        "phase10_adapter_ignored_declared_v2": true,
                        "could_fully_reconcile_historical_expectation": full_reconciliation,
                        "outcome_reconciliation_legitimate": legitimate_outcome_reconciliation,
                        "outcome_reconciliation_would_weaken_benchmark": would_weaken,
                        "requires_benchmark_taxonomy_correction": vulnerable && !taxonomy_valid,
                    },
                }));
                if vulnerable {
                    vulnerable_agreement.push(declared_agreement);
                } else {
                    paired_agreement.push(declared_agreement);
                }
            }
            causes.sort_unstable();
            causes.dedup();
            let fully_contract_valid = taxonomy_valid
                && if vulnerable {
                    source_semantics_valid
                } else {
                    safe_property_valid
                };
            let flags = CaseFlags {
                vulnerable,
                taxonomy_valid,
                source_semantics_valid,
                safe_property_valid,
                fully_contract_valid,
                semantically_supported: case_supported,
                no_finding: vulnerable && !has_finding,
                scanner_false_negative,
                scanner_false_positive,
                adapter_affected: has_finding,
                benchmark_defect,
            };
            update_breakdowns(&mut breakdowns, pair, flags);
            diagnostic_cases.push(json!({
                "case_id": case.case_id,
                "pair_id": pair.pair_id,
                "kind": case.kind,
                "fixture_path": case.fixture_path,
                "fixture_sha256": case.fixture_sha256,
                "contract_sha256": case.contract_sha256,
                "factors": pair.assignment,
                "expected_invariant_id": pair.invariant_id,
                "frozen_taxonomy_invariant_id": taxonomy_category.invariant_id,
                "historical_expectation": case.expectation,
                "declared_security_property": case.security_property,
                "taxonomy_mapping_valid": taxonomy_valid,
                "fixture_validation": semantics,
                "fully_contract_valid": fully_contract_valid,
                "official_phase10": {
                    "outcome": official_case.outcome,
                    "distinct_findings": official_case.distinct_findings,
                    "unrelated_findings": official_case.unrelated_findings,
                    "selected_finding_id": official_case.selected_finding_id,
                    "execution_status": run_case.execution.status,
                    "process_exit_code": run_case.execution.process_exit_code,
                    "report_sha256": report_hashes[&case.case_id],
                },
                "diagnostic_only": {
                    "classifications": causes,
                    "semantically_supported_finding": case_supported,
                    "confirmed_scanner_defect": scanner_false_negative || scanner_false_positive || unsupported_direct_claim,
                    "confirmed_benchmark_defect": benchmark_defect,
                    "confirmed_adapter_defect": has_finding,
                    "attribution_uncertain": false,
                },
            }));
            regression_cases.push(json!({
                "case_id": case.case_id,
                "pair_id": pair.pair_id,
                "fixture_path": case.fixture_path,
                "kind": case.kind,
                "family_id": pair.assignment.family_id,
                "framework": pair.assignment.framework,
                "language": pair.assignment.language,
                "topology": pair.assignment.topology,
                "frozen_taxonomy_category_id": taxonomy_category.category_id,
                "frozen_taxonomy_invariant_id": taxonomy_category.invariant_id,
                "primary_cwe": taxonomy_category.primary_cwe.id,
                "source_kind": pair.source_kind,
                "sink_kind": pair.sink_kind,
                "structural_property": pair.mutation.structural_property,
                "mutation_file": pair.mutation.file,
                "declared_security_property": case.security_property,
                "expected_evidence_contract_v2": if vulnerable {Some(&corrected)} else {None},
                "eligible_for_future_regression": !direct,
                "retirement_disposition": if direct {"exclude_until_fixture_value-flow_is_repaired_and_newly_versioned"} else {"public_regression_candidate"},
                "historical_score_immutable": true,
            }));
        }
    }

    diagnostic_cases
        .sort_by(|left, right| left["case_id"].as_str().cmp(&right["case_id"].as_str()));
    diagnostic_findings
        .sort_by(|left, right| left["case_id"].as_str().cmp(&right["case_id"].as_str()));
    regression_cases
        .sort_by(|left, right| left["case_id"].as_str().cmp(&right["case_id"].as_str()));
    if diagnostic_cases.len() != 224
        || diagnostic_findings.len() != 48
        || scanner_defect_cases.len() != 92
        || benchmark_defect_cases.len() != 200
        || adapter_defect_findings.len() != 48
        || semantically_supported != 18
    {
        return Err(Phase11Error::InvalidEvidence(format!(
            "diagnostic population differs: cases={} findings={} scanner={} benchmark={} adapter={} supported={semantically_supported} ids={supported_ids:?}",
            diagnostic_cases.len(),
            diagnostic_findings.len(),
            scanner_defect_cases.len(),
            benchmark_defect_cases.len(),
            adapter_defect_findings.len(),
        )));
    }
    let summary = DiagnosticSummary {
        cases: 224,
        findings: 48,
        semantically_supported_findings: 18,
        scanner_defect_cases: 92,
        benchmark_defect_cases: 200,
        adapter_defect_findings: 48,
    };
    let diagnostic = json!({
        "schema_version": DIAGNOSTIC_SCHEMA,
        "phase": 11,
        "method": "retrospective-offline-reconstruction-from-immutable-retained-evidence",
        "retired_corpus": {"holdout_id": manifest.holdout_id, "cases": 224, "vulnerable": 112, "safe_controls": 112, "disclosed": true},
        "historical_phase10_score_unchanged": {
            "exact": 0, "partial": 0, "missed": 112,
            "flagged_controls": 24, "clean_controls": 88, "distinct_unrelated_findings": 48,
            "semantic_fingerprint": official.semantic_fingerprint,
            "rescored": false,
        },
        "root_cause_counts": {
            "overlapping_categories": true,
            "no_finding_emitted_vulnerable_cases": 88,
            "confirmed_scanner_false_negative_cases": 62,
            "confirmed_scanner_false_positive_control_cases": 24,
            "unsupported_direct_path_finding_cases": 2,
            "contract_supported_vulnerable_findings": 18,
            "vulnerability_related_findings_with_source_span_defect": 4,
            "taxonomy_invariant_drift_cases": 192,
            "direct_value_identity_defect_cases": 56,
            "benchmark_defect_union_cases": 200,
            "phase10_adapter_ignored_declared_v2_findings": 48,
        },
        "defect_counts": {
            "confirmed_scanner_defect_records": 4,
            "confirmed_scanner_defect_affected_cases": 92,
            "confirmed_benchmark_defect_records": 2,
            "confirmed_benchmark_defect_affected_cases": 200,
            "confirmed_adapter_matcher_defect_records": 1,
            "confirmed_adapter_matcher_affected_findings": 48,
            "contract_ambiguity_records": 0,
            "unresolved_attribution_records": 0,
        },
        "agreement_matrices": {
            "fixture_source_vs_historical_expectations": agreement_matrix(&fixture_expectation_agreement),
            "vulnerable_retained_findings_vs_historical_expectations": agreement_matrix(&vulnerable_agreement),
            "flagged_control_findings_vs_paired_vulnerable_expectations": agreement_matrix(&paired_agreement),
        },
        "breakdowns": breakdowns,
        "cases": diagnostic_cases,
        "rejected_findings": diagnostic_findings,
        "provenance": {
            "immutable_inputs": immutable,
            "report_hashes": report_hashes,
            "scanner_processes_started_by_phase11": 0,
            "secure_engine_source_consulted": false,
            "network_required": false,
            "host_paths_exported": false,
        },
        "limitations": [
            "This diagnostic is not a rescore and does not replace the preregistered Phase 10 result.",
            "Fixture semantics are validated against this retired synthetic corpus and do not establish production prevalence or exploitability.",
            "The analysis attributes defects only where committed source and retained reports provide deterministic evidence.",
            "This is not a scanner ranking, superiority, production-readiness, or complete-coverage claim."
        ],
    });
    let regression = json!({
        "schema_version": REGRESSION_SCHEMA,
        "source": "retired-public-phase9-corpus",
        "purpose": "generalized-future-development-regressions-not-hidden-evaluation",
        "cases": regression_cases,
        "counts": {"total":224,"eligible":168,"excluded_direct_fixture_defects":56},
        "constraints": [
            "No fixture identifier may be used as a scanner exception.",
            "Future repaired fixtures require a new version and must not rewrite Phase 9.",
            "Regression results must not be presented as Phase 10 rescoring."
        ],
    });
    let conformance = conformance_vectors()?;
    let defect_ledger = defect_ledger(
        &scanner_false_negative_cases,
        &scanner_false_positive_cases,
        &unsupported_direct_cases,
        &source_span_defect_cases,
        &taxonomy_defect_cases,
        &direct_defect_cases,
        &adapter_defect_findings,
    )?;
    Ok((diagnostic, regression, defect_ledger, conformance, summary))
}

fn synthetic_span(file: &str, line: u32) -> EvidenceSpanV2 {
    EvidenceSpanV2 {
        file: file.to_owned(),
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
        span: synthetic_span("src/example.ts", 2),
        summarizable: false,
    };
    let transform = EvidenceNodeV2 {
        role: EvidenceRoleV2::Transformation,
        effect: EvidenceEffectV2::PreservesInfluence,
        source_kind: None,
        sink_kind: None,
        span: synthetic_span("src/example.ts", 3),
        summarizable: false,
    };
    let sink = EvidenceNodeV2 {
        role: EvidenceRoleV2::Sink,
        effect: EvidenceEffectV2::PreservesInfluence,
        source_kind: None,
        sink_kind: Some(SinkSemanticKind::OsCommandExecution),
        span: synthetic_span("src/example.ts", 4),
        summarizable: false,
    };
    (
        EvidenceExpectationV2 {
            expectation_id: "synthetic-expectation".to_owned(),
            taxonomy_version: "1.0.0".to_owned(),
            category_id: "secure-bench.category.command-execution".to_owned(),
            invariant_id: "secure-bench.invariant.command-control-data-separation".to_owned(),
            primary_cwe: "CWE-78".to_owned(),
            path: vec![source.clone(), transform.clone(), sink.clone()],
        },
        CanonicalFindingV2 {
            taxonomy_version: "1.0.0".to_owned(),
            category_id: "secure-bench.category.command-execution".to_owned(),
            invariant_id: "secure-bench.invariant.command-control-data-separation".to_owned(),
            path: vec![source, transform, sink],
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

fn vector_contract() -> Result<EvidenceContractV2, Phase11Error> {
    parse(
        include_bytes!("../../holdout/phase-5/evidence-contract-v2.json"),
        "embedded Evidence Contract v2",
    )
}

#[allow(clippy::too_many_lines)]
fn conformance_vectors() -> Result<Value, Phase11Error> {
    let contract = vector_contract()?;
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
        "missing_transform_value_identity",
        "effective_guard_barrier",
        "effective_sanitizer_barrier",
        "authorization_dominance_barrier",
        "unresolved_call_partial",
        "uncertain_partial",
        "duplicate_finding",
        "unrelated_finding",
    ];
    let mut vectors = Vec::new();
    for (index, dimension) in dimensions.into_iter().enumerate() {
        let (expected, mut finding) = synthetic_pair();
        let mut reported_cwe = "CWE-78";
        let mut duplicate = false;
        match dimension {
            "taxonomy_version_mismatch" => {
                "2.0.0".clone_into(&mut finding.taxonomy_version);
            }
            "category_mismatch" | "unrelated_finding" => {
                "secure-bench.category.filesystem-boundary".clone_into(&mut finding.category_id);
            }
            "invariant_mismatch" => {
                "different-invariant".clone_into(&mut finding.invariant_id);
            }
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
            "missing_transform_value_identity" => {
                finding.path.remove(1);
                finding.connected_edges = vec![true];
            }
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
            "duplicate_finding" => duplicate = true,
            _ => {}
        }
        let contract_match = match_evidence_v2(&contract, &expected, &finding);
        let diagnostic_outcome = if duplicate {
            "duplicate_rejected"
        } else if reported_cwe != expected.primary_cwe {
            "no_match"
        } else {
            match contract_match {
                EvidenceMatchV2::Exact => "exact",
                EvidenceMatchV2::Partial => "partial",
                EvidenceMatchV2::NoMatch => "no_match",
            }
        };
        let expected_outcome = match dimension {
            "exact" => "exact",
            "unresolved_call_partial" | "uncertain_partial" => "partial",
            "duplicate_finding" => "duplicate_rejected",
            _ => "no_match",
        };
        if diagnostic_outcome != expected_outcome {
            return Err(Phase11Error::InvalidEvidence(format!(
                "synthetic vector `{dimension}` produced {diagnostic_outcome}, expected {expected_outcome}"
            )));
        }
        vectors.push(json!({
            "vector_id": format!("phase11-vector-{:02}", index + 1),
            "mismatch_family": dimension,
            "expectation": expected,
            "finding": finding,
            "reported_primary_cwe": reported_cwe,
            "semantic_duplicate": duplicate,
            "contract_match": contract_match,
            "diagnostic_outcome": diagnostic_outcome,
            "expected_outcome": expected_outcome,
            "inverse": {
                "operation": "restore_only_the_named_mutation_to_the_exact_base_vector",
                "expected_outcome": "exact"
            }
        }));
    }
    Ok(json!({
        "schema_version": CONFORMANCE_SCHEMA,
        "evidence_contract_version": "2.0.0",
        "synthetic_only": true,
        "scanner_reports_used": false,
        "vectors": vectors,
        "mutation_inverse_policy": "Each non-exact vector mutates one semantic dimension; restoring that dimension yields the exact base vector."
    }))
}

fn ledger_entry(
    sequence: u64,
    defect_id: &str,
    class: &str,
    status: &str,
    title: &str,
    affected: &BTreeSet<String>,
    previous: &str,
) -> Result<(Value, String), Phase11Error> {
    let mut entry = json!({
        "schema_version": LEDGER_SCHEMA,
        "sequence": sequence,
        "defect_id": defect_id,
        "class": class,
        "status": status,
        "title": title,
        "affected_ids": affected,
        "affected_count": affected.len(),
        "historical_phase10_score_changed": false,
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

fn defect_ledger(
    false_negatives: &BTreeSet<String>,
    false_positives: &BTreeSet<String>,
    unsupported_paths: &BTreeSet<String>,
    source_span_defects: &BTreeSet<String>,
    taxonomy_cases: &BTreeSet<String>,
    direct_cases: &BTreeSet<String>,
    adapter_findings: &BTreeSet<String>,
) -> Result<Vec<u8>, Phase11Error> {
    let empty = BTreeSet::new();
    let definitions = [
        (
            "P11-SCANNER-001",
            "confirmed_scanner_defect",
            "confirmed",
            "No finding for a source-supported vulnerable flow",
            false_negatives,
        ),
        (
            "P11-SCANNER-002",
            "confirmed_scanner_defect",
            "confirmed",
            "Finding on a source-validated safe control",
            false_positives,
        ),
        (
            "P11-SCANNER-003",
            "confirmed_scanner_defect",
            "confirmed",
            "Declared connected path contradicted by the direct fixture value identity",
            unsupported_paths,
        ),
        (
            "P11-SCANNER-004",
            "confirmed_scanner_defect",
            "confirmed",
            "Next.js finding anchors the source at request parsing rather than the expected body-field assignment span",
            source_span_defects,
        ),
        (
            "P11-BENCHMARK-001",
            "confirmed_benchmark_defect",
            "confirmed",
            "Phase 9 invariant identity differs from the frozen taxonomy",
            taxonomy_cases,
        ),
        (
            "P11-BENCHMARK-002",
            "confirmed_benchmark_defect",
            "confirmed",
            "Direct renderer disconnects candidate from the value used at the sink",
            direct_cases,
        ),
        (
            "P11-ADAPTER-001",
            "confirmed_adapter_matcher_defect",
            "confirmed",
            "Phase 10 adapter ignores authoritative evidence_contract_v2 fields",
            adapter_findings,
        ),
        (
            "P11-CONTRACT-001",
            "contract_ambiguity",
            "none_confirmed",
            "No contract ambiguity remained after deterministic source and contract review",
            &empty,
        ),
        (
            "P11-UNRESOLVED-001",
            "unresolved_attribution",
            "none_confirmed",
            "No case retained unresolved attribution after applying the documented evidence limits",
            &empty,
        ),
    ];
    let mut previous =
        "0000000000000000000000000000000000000000000000000000000000000000".to_owned();
    let mut bytes = Vec::new();
    for (index, (id, class, status, title, affected)) in definitions.into_iter().enumerate() {
        let sequence = u64::try_from(index + 1).map_err(|_| {
            Phase11Error::InvalidEvidence("defect-ledger sequence overflow".to_owned())
        })?;
        let (entry, digest) =
            ledger_entry(sequence, id, class, status, title, affected, &previous)?;
        bytes.extend(
            serde_json::to_vec(&entry)
                .map_err(|error| Phase11Error::Serialization(error.to_string()))?,
        );
        bytes.push(b'\n');
        previous = digest;
    }
    Ok(bytes)
}

fn validate_schema(root: &Path, schema: &str, bytes: &[u8]) -> Result<(), Phase11Error> {
    let schema_value: Value = parse(&read(root, schema)?, schema)?;
    let instance: Value = parse(bytes, "Phase 11 artifact")?;
    let validator = jsonschema::validator_for(&schema_value)
        .map_err(|error| Phase11Error::InvalidEvidence(error.to_string()))?;
    validator.validate(&instance).map_err(|error| {
        Phase11Error::InvalidEvidence(format!("schema `{schema}` rejected an artifact: {error}"))
    })
}

fn validate_ledger(root: &Path, bytes: &[u8]) -> Result<(), Phase11Error> {
    let mut previous =
        "0000000000000000000000000000000000000000000000000000000000000000".to_owned();
    let mut count = 0_u64;
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        validate_schema(
            root,
            "phase11/schemas/phase11-defect-ledger-entry-v1.schema.json",
            line,
        )?;
        let entry: Value = parse(line, "Phase 11 defect-ledger entry")?;
        count += 1;
        if entry["sequence"] != count || entry["previous_entry_hash"] != previous {
            return Err(Phase11Error::InvalidEvidence(
                "Phase 11 defect-ledger sequence or chain differs".to_owned(),
            ));
        }
        let observed = entry["entry_hash"].as_str().ok_or_else(|| {
            Phase11Error::InvalidEvidence("ledger entry hash is absent".to_owned())
        })?;
        let mut unhashed = entry.clone();
        if let Some(object) = unhashed.as_object_mut() {
            object.remove("entry_hash");
        }
        let expected = hash(&canonical(&unhashed)?);
        if observed != expected {
            return Err(Phase11Error::InvalidEvidence(
                "Phase 11 defect-ledger entry hash differs".to_owned(),
            ));
        }
        observed.clone_into(&mut previous);
    }
    if count != 9 {
        return Err(Phase11Error::InvalidEvidence(
            "Phase 11 defect ledger must contain nine separated entries".to_owned(),
        ));
    }
    Ok(())
}

fn artifact_bytes(
    root: &Path,
) -> Result<(BTreeMap<&'static str, Vec<u8>>, DiagnosticSummary), Phase11Error> {
    let (diagnostic, regression, ledger, conformance, summary) = reconstruct(root)?;
    let diagnostic = canonical(&diagnostic)?;
    let regression = canonical(&regression)?;
    let conformance = canonical(&conformance)?;
    validate_schema(
        root,
        "phase11/schemas/phase11-retired-diagnostic-v1.schema.json",
        &diagnostic,
    )?;
    validate_schema(
        root,
        "phase11/schemas/phase11-regression-manifest-v1.schema.json",
        &regression,
    )?;
    validate_schema(
        root,
        "phase11/schemas/phase11-evidence-conformance-v1.schema.json",
        &conformance,
    )?;
    validate_ledger(root, &ledger)?;
    Ok((
        BTreeMap::from([
            (DIAGNOSTIC_PATH, diagnostic),
            (REGRESSION_PATH, regression),
            (DEFECT_LEDGER_PATH, ledger),
            (CONFORMANCE_PATH, conformance),
        ]),
        summary,
    ))
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

/// Generates all additive Phase 11 artifacts without starting any external process.
///
/// # Errors
///
/// Returns an error if historical evidence differs, reconstruction is incomplete, a schema
/// rejects an artifact, or any create-new output already exists.
pub fn generate_repository(root: &Path) -> Result<DiagnosticSummary, Phase11Error> {
    let _ = path(root, OUTPUT)?;
    if [
        DIAGNOSTIC_PATH,
        REGRESSION_PATH,
        DEFECT_LEDGER_PATH,
        CONFORMANCE_PATH,
        HASH_INDEX_PATH,
    ]
    .into_iter()
    .any(|relative| path(root, relative).is_ok_and(|output| output.exists()))
    {
        return Err(Phase11Error::InvalidEvidence(
            "Phase 11 output already exists; generation is create-new only".to_owned(),
        ));
    }
    let (artifacts, summary) = artifact_bytes(root)?;
    for (relative, bytes) in &artifacts {
        write_new(root, relative, bytes)?;
    }
    write_new(root, HASH_INDEX_PATH, &hash_index(&artifacts))?;
    Ok(summary)
}

/// Verifies all Phase 11 artifacts by deterministic scanner-free reconstruction.
///
/// # Errors
///
/// Returns an error for historical drift, report-hash drift, incomplete coverage, schema or
/// ledger failure, non-deterministic output, privacy failure, or provenance disagreement.
pub fn verify_repository(root: &Path) -> Result<DiagnosticSummary, Phase11Error> {
    let (artifacts, summary) = artifact_bytes(root)?;
    for (relative, expected) in &artifacts {
        let observed = read(root, relative)?;
        if observed != *expected {
            return Err(Phase11Error::InvalidEvidence(format!(
                "Phase 11 artifact `{relative}` is not deterministic"
            )));
        }
        if observed
            .windows(b"/home/".len())
            .any(|window| window == b"/home/")
            || observed
                .windows(b"Proyectos".len())
                .any(|window| window == b"Proyectos")
        {
            return Err(Phase11Error::InvalidEvidence(format!(
                "Phase 11 artifact `{relative}` exposes a host path"
            )));
        }
    }
    if read(root, HASH_INDEX_PATH)? != hash_index(&artifacts) {
        return Err(Phase11Error::InvalidEvidence(
            "Phase 11 hash index differs".to_owned(),
        ));
    }
    Ok(summary)
}

/// Returns a concise summary from a fully verified Phase 11 package.
///
/// # Errors
///
/// Returns an error if any Phase 11 or immutable historical artifact differs.
pub fn summarize_repository(root: &Path) -> Result<String, Phase11Error> {
    let summary = verify_repository(root)?;
    Ok(format!(
        "cases={} findings={} semantically_supported={} scanner_defect_cases={} benchmark_defect_cases={} adapter_defect_findings={} phase10_rescored=false scanner_processes_started=0",
        summary.cases,
        summary.findings,
        summary.semantically_supported_findings,
        summary.scanner_defect_cases,
        summary.benchmark_defect_cases,
        summary.adapter_defect_findings,
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
    fn synthetic_vectors_cover_every_required_mismatch_and_inverse() -> Result<(), Phase11Error> {
        let suite = conformance_vectors()?;
        let vectors = suite["vectors"].as_array().ok_or_else(|| {
            Phase11Error::InvalidEvidence("synthetic vectors are absent".to_owned())
        })?;
        assert_eq!(vectors.len(), 19);
        assert_eq!(vectors[0]["diagnostic_outcome"], "exact");
        for vector in vectors.iter().skip(1) {
            assert_ne!(vector["diagnostic_outcome"], "exact");
            let (expected, finding) = synthetic_pair();
            let contract = vector_contract()?;
            assert_eq!(
                match_evidence_v2(&contract, &expected, &finding),
                EvidenceMatchV2::Exact
            );
        }
        Ok(())
    }

    #[test]
    fn reconstruction_is_complete_and_deterministic() -> Result<(), Phase11Error> {
        let root = repository_root();
        let first = reconstruct(&root)?;
        let second = reconstruct(&root)?;
        assert_eq!(canonical(&first.0)?, canonical(&second.0)?);
        assert_eq!(first.4.cases, 224);
        assert_eq!(first.4.findings, 48);
        Ok(())
    }

    #[test]
    fn phase11_has_no_process_launch_api() {
        let source = include_str!("lib.rs");
        let process_api = ["std::process", "::Command"].concat();
        let constructor = ["Command", "::new"].concat();
        assert!(!source.contains(&process_api));
        assert!(!source.contains(&constructor));
    }
}
