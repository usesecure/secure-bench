//! Secure Bench Phase 13 prospective holdout v4 authoring and validation.
//!
//! This crate creates an examination without executing a scanner. It freezes scanner-neutral
//! fixtures, Evidence Contract v2 expectations, commitments, provenance, and a genesis ledger.

use secure_bench_core::phase5::{
    EvidenceContractV2, EvidenceEffectV2, EvidenceExpectationV2, EvidenceNodeV2, EvidenceRoleV2,
    EvidenceSpanV2, SinkSemanticKind, SourceSemanticKind,
};
use secure_bench_core::taxonomy::{FrozenTaxonomy, TaxonomyCategory, load_taxonomy};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

const BENCHMARK_VERSION: &str = "0.2.1";
const HOLDOUT_ID: &str = "secure-bench-phase13-holdout-v4";
const BASE_COMMIT: &str = "e6f1de05967f6600c663929591c1ac933bc3eced";
const BRANCH: &str = "codex/phase-13-prospective-holdout-v4";
const TAXONOMY_PATH: &str = "taxonomy/secure-bench-taxonomy-v1.json";
const CONTRACT_PATH: &str = "holdout/phase-5/evidence-contract-v2.json";
const ADAPTER_POLICY_PATH: &str = "phase12/policies/adapter-precedence-v1.json";
const AUTHORING_POLICY_PATH: &str = "phase12/methodology/holdout-authoring-v1.json";
const PROCESS_POLICY_PATH: &str = "policies/process-status-v1.json";
const MANIFEST_PATH: &str = "prospective/phase-13-holdout-v4/manifest.json";
const EXPECTATIONS_PATH: &str =
    "prospective/phase-13-holdout-v4/contracts/evidence-expectations-v2.json";
const COMMITMENTS_PATH: &str = "prospective/phase-13-holdout-v4/commitments.json";
const LEDGER_PATH: &str = "prospective/phase-13-holdout-v4/execution-ledger.jsonl";
const PROVENANCE_PATH: &str = "prospective/phase-13-holdout-v4/provenance.json";
const CHECKSUMS_PATH: &str = "prospective/phase-13-holdout-v4/SHA256SUMS";
const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const HISTORICAL_BASELINE_SHA256: &str =
    "375ce87c5fce9be3caff282c821c796a9b56e3a1132404d92d40db7d89a7d52f";
const PHASE12_TREE_SHA256: &str =
    "e4e4ecce830b10fe34de99425b08bb2156d6b8c7e2112325d31fc0d2f89adb0f";
const PHASE10_RESULT_SHA256: &str =
    "bfb74fbc89345bcb6c8584fc8774b2347f31816bdbf1efc9628e96cab8904a7c";

const SCHEMA_PATHS: [&str; 5] = [
    "prospective/phase-13-holdout-v4/schemas/phase13-manifest-v1.schema.json",
    "prospective/phase-13-holdout-v4/schemas/phase13-expectations-v1.schema.json",
    "prospective/phase-13-holdout-v4/schemas/phase13-commitments-v1.schema.json",
    "prospective/phase-13-holdout-v4/schemas/phase13-ledger-entry-v1.schema.json",
    "prospective/phase-13-holdout-v4/schemas/phase13-provenance-v1.schema.json",
];

const REQUIRED_ADVERSARIAL_FEATURES: [&str; 20] = [
    "aliases_and_destructuring",
    "ambiguous_resolution",
    "authentication_vs_authorization",
    "conservative_unsupported_boundary",
    "control_flow_sensitive_join",
    "dynamic_code_near_miss",
    "fixed_executable_argument_array",
    "hostname_suffix_near_miss",
    "inter_file_helpers",
    "local_helpers",
    "non_dominating_guard",
    "non_terminating_guard",
    "ownership_tenant_and_role_checks",
    "parameterized_sql",
    "path_prefix_and_sibling_prefix",
    "recursion",
    "redirect_fallback",
    "url_protocol_and_userinfo",
    "value_preserving_wrappers",
    "wrappers_with_multiple_arguments",
];

/// Phase 13 request, authoring, or integrity failure.
#[derive(Debug, Error)]
pub enum Phase13Error {
    /// Invalid CLI or API request.
    #[error("invalid Phase 13 request: {0}")]
    InvalidRequest(String),
    /// Holdout contract or fixture failure.
    #[error("Phase 13 contract validation failed: {0}")]
    InvalidContract(String),
    /// Historical evidence drift.
    #[error("Phase 13 historical integrity failed: {0}")]
    HistoricalIntegrity(String),
    /// Filesystem operation failure.
    #[error("Phase 13 filesystem operation failed for `{path}`: {detail}")]
    Io {
        /// Portable path context.
        path: String,
        /// Operating-system detail.
        detail: String,
    },
    /// JSON serialization failure.
    #[error("Phase 13 serialization failed: {0}")]
    Serialization(String),
}

/// Scanner-free Phase 13 validation report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidationReport {
    /// Prospective Secure Bench version.
    pub benchmark_version: &'static str,
    /// Frozen pair count.
    pub pair_count: u64,
    /// Frozen case count.
    pub case_count: u64,
    /// Aggregate scanner-visible corpus hash.
    pub aggregate_corpus_sha256: String,
    /// Case-contract Merkle root.
    pub contract_merkle_root: String,
    /// Genesis ledger artifact hash.
    pub genesis_ledger_sha256: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum Framework {
    NodeJs,
    Express,
    NextAppRouter,
    ServerActions,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum SourceFormat {
    #[serde(rename = "javascript")]
    JavaScript,
    Jsx,
    #[serde(rename = "typescript")]
    TypeScript,
    Tsx,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum Topology {
    Direct,
    HelperMediated,
    InterFileAliased,
    ControlFlowSensitive,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CaseKind {
    Vulnerable,
    SafeControl,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct BarrierExpectation {
    role: EvidenceRoleV2,
    effect: EvidenceEffectV2,
    value_id: String,
    terminating: bool,
    dominates_sink: bool,
    span: EvidenceSpanV2,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct FrozenCaseExpectation {
    case_id: String,
    kind: CaseKind,
    evidence_contract_version: String,
    authoritative_projection: String,
    value_id: String,
    taxonomy_version: String,
    category_id: String,
    invariant_id: String,
    primary_cwe: String,
    source_kind: SourceSemanticKind,
    sink_kind: SinkSemanticKind,
    path: Vec<EvidenceNodeV2>,
    connected_edges: Vec<bool>,
    effective_barriers: Vec<BarrierExpectation>,
    vulnerability_expectation: Option<EvidenceExpectationV2>,
    legacy_override_permitted: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ExpectationsDocument {
    schema_version: String,
    holdout_id: String,
    evidence_contract_sha256: String,
    records: Vec<FrozenCaseExpectation>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CaseReference {
    case_id: String,
    fixture_path: String,
    fixture_sha256: String,
    contract_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LineRange {
    start: u32,
    end: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct MutationContract {
    file: String,
    vulnerable_lines: LineRange,
    control_lines: LineRange,
    vulnerable_fragment_sha256: String,
    control_fragment_sha256: String,
    security_invariant: String,
    bidirectional_exact: bool,
    metamorphic_rename_stable: bool,
    metamorphic_insertion_stable: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PairContract {
    pair_id: String,
    family_id: String,
    framework: Framework,
    source_format: SourceFormat,
    language_group: String,
    topology: Topology,
    adversarial_features: Vec<String>,
    presentation_order: Vec<String>,
    mutation: MutationContract,
    vulnerable: CaseReference,
    control: CaseReference,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct BalanceProof {
    families: BTreeMap<String, u64>,
    frameworks: BTreeMap<String, u64>,
    source_formats: BTreeMap<String, u64>,
    language_groups: BTreeMap<String, u64>,
    topologies: BTreeMap<String, u64>,
    framework_by_source_format: BTreeMap<String, BTreeMap<String, u64>>,
    framework_by_topology: BTreeMap<String, BTreeMap<String, u64>>,
    source_format_by_topology: BTreeMap<String, BTreeMap<String, u64>>,
    pairwise_cell_minimum: u64,
    pairwise_cell_maximum: u64,
    imbalance_justification: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct OverlapProof {
    historical_files_compared: u64,
    exact_matches: u64,
    maximum_normalized_overlap_basis_points: u64,
    rejection_threshold_basis_points: u64,
    limitation: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: String,
    benchmark_version: String,
    holdout_id: String,
    title: String,
    status: String,
    base_commit: String,
    branch: String,
    taxonomy_sha256: String,
    evidence_contract_sha256: String,
    adapter_policy_sha256: String,
    authoring_policy_sha256: String,
    process_status_policy_sha256: String,
    expectation_sha256: String,
    aggregate_corpus_sha256: String,
    contract_merkle_root: String,
    evaluator_sha256: String,
    balance: BalanceProof,
    overlap: OverlapProof,
    pairs: Vec<PairContract>,
    limitations: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CommitmentIndex {
    schema_version: String,
    holdout_id: String,
    manifest_sha256: String,
    expectations_sha256: String,
    aggregate_corpus_sha256: String,
    contract_merkle_root: String,
    evaluator_sha256: String,
    genesis_ledger_sha256: String,
    fixture_files: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LedgerEntry {
    schema_version: String,
    sequence: u64,
    event: String,
    holdout_id: String,
    manifest_sha256: String,
    aggregate_corpus_sha256: String,
    contract_merkle_root: String,
    previous_entry_hash: String,
    timestamp_utc: String,
    entry_hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::struct_excessive_bools)]
#[serde(deny_unknown_fields)]
struct Provenance {
    schema_version: String,
    benchmark_version: String,
    holdout_id: String,
    base_commit: String,
    release_tag: String,
    historical_baseline_sha256: String,
    phase12_tree_sha256: String,
    phase10_result_sha256: String,
    commitment_index_sha256: String,
    scanner_processes_started: u64,
    secure_engine_executed: bool,
    other_scanner_executed: bool,
    secure_engine_source_inspected: bool,
    previous_scanner_reports_used_for_authoring: bool,
    ai_provider_configured: bool,
    network_ai_calls: u64,
    result_or_score_created: bool,
}

#[derive(Clone, Copy)]
struct FamilySpec {
    family_id: &'static str,
    category_id: &'static str,
    source_kind: SourceSemanticKind,
    sink_kind: SinkSemanticKind,
    barrier_role: EvidenceRoleV2,
    barrier_effect: EvidenceEffectV2,
}

#[derive(Clone, Copy)]
struct Assignment {
    ordinal: usize,
    family_index: usize,
    variant: usize,
    framework: Framework,
    source_format: SourceFormat,
    topology: Topology,
}

#[derive(Clone)]
struct RenderedCase {
    files: BTreeMap<String, Vec<u8>>,
    source: (String, String),
    propagations: Vec<(String, String)>,
    sink: (String, String),
    barrier: Option<(String, String)>,
    mutation_file: String,
    mutation_fragment: String,
}

struct Bundle {
    files: BTreeMap<String, Vec<u8>>,
    report: ValidationReport,
}

const FAMILIES: [FamilySpec; 7] = [
    FamilySpec {
        family_id: "SE1001",
        category_id: "secure-bench.category.authorization-dominance",
        source_kind: SourceSemanticKind::ProtectedResourceId,
        sink_kind: SinkSemanticKind::ProtectedRecordMutation,
        barrier_role: EvidenceRoleV2::Authorization,
        barrier_effect: EvidenceEffectV2::AuthorizesOperation,
    },
    FamilySpec {
        family_id: "SE1002",
        category_id: "secure-bench.category.command-execution",
        source_kind: SourceSemanticKind::HttpQueryValue,
        sink_kind: SinkSemanticKind::OsCommandExecution,
        barrier_role: EvidenceRoleV2::Sanitizer,
        barrier_effect: EvidenceEffectV2::SeparatesControlAndData,
    },
    FamilySpec {
        family_id: "SE1003",
        category_id: "secure-bench.category.dynamic-code-execution",
        source_kind: SourceSemanticKind::HttpBodyField,
        sink_kind: SinkSemanticKind::DynamicCodeEvaluation,
        barrier_role: EvidenceRoleV2::Guard,
        barrier_effect: EvidenceEffectV2::RejectsAndTerminates,
    },
    FamilySpec {
        family_id: "SE1004",
        category_id: "secure-bench.category.filesystem-boundary",
        source_kind: SourceSemanticKind::HttpQueryValue,
        sink_kind: SinkSemanticKind::FilesystemRead,
        barrier_role: EvidenceRoleV2::Guard,
        barrier_effect: EvidenceEffectV2::ConstrainsToPolicy,
    },
    FamilySpec {
        family_id: "SE1005",
        category_id: "secure-bench.category.outbound-request-boundary",
        source_kind: SourceSemanticKind::HttpBodyField,
        sink_kind: SinkSemanticKind::OutboundRequest,
        barrier_role: EvidenceRoleV2::Guard,
        barrier_effect: EvidenceEffectV2::ConstrainsToPolicy,
    },
    FamilySpec {
        family_id: "SE1006",
        category_id: "secure-bench.category.redirect-boundary",
        source_kind: SourceSemanticKind::HttpQueryValue,
        sink_kind: SinkSemanticKind::RedirectResponse,
        barrier_role: EvidenceRoleV2::Guard,
        barrier_effect: EvidenceEffectV2::ConstrainsToPolicy,
    },
    FamilySpec {
        family_id: "SE1007",
        category_id: "secure-bench.category.sql-construction",
        source_kind: SourceSemanticKind::HttpBodyField,
        sink_kind: SinkSemanticKind::SqlQueryExecution,
        barrier_role: EvidenceRoleV2::Sanitizer,
        barrier_effect: EvidenceEffectV2::SeparatesControlAndData,
    },
];

fn io(path: &Path, error: &std::io::Error) -> Phase13Error {
    Phase13Error::Io {
        path: path.to_string_lossy().into_owned(),
        detail: error.to_string(),
    }
}

fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, Phase13Error> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| Phase13Error::Serialization(error.to_string()))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn safe_relative(relative: &str) -> Result<PathBuf, Phase13Error> {
    let path = Path::new(relative);
    if relative.is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(Phase13Error::InvalidContract(format!(
            "path `{relative}` is not a portable relative path"
        )));
    }
    Ok(path.to_path_buf())
}

fn read(root: &Path, relative: &str) -> Result<Vec<u8>, Phase13Error> {
    let path = root.join(safe_relative(relative)?);
    let metadata = fs::symlink_metadata(&path).map_err(|error| io(&path, &error))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(Phase13Error::InvalidContract(format!(
            "`{relative}` is not a regular file"
        )));
    }
    fs::read(&path).map_err(|error| io(&path, &error))
}

fn enum_name<T: Serialize>(value: T) -> Result<String, Phase13Error> {
    serde_json::to_value(value)
        .map_err(|error| Phase13Error::Serialization(error.to_string()))?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| Phase13Error::InvalidContract("factor is not textual".to_owned()))
}

fn assignments() -> Vec<Assignment> {
    const FRAMEWORKS: [[usize; 8]; 7] = [
        [0, 2, 0, 3, 2, 1, 1, 3],
        [3, 2, 3, 1, 0, 1, 2, 0],
        [1, 0, 3, 3, 0, 1, 2, 2],
        [1, 3, 2, 0, 1, 0, 3, 2],
        [3, 0, 0, 2, 3, 1, 1, 2],
        [1, 3, 1, 2, 2, 0, 0, 3],
        [2, 0, 3, 1, 1, 0, 3, 2],
    ];
    const FORMATS: [[usize; 8]; 7] = [
        [1, 2, 0, 3, 3, 0, 1, 2],
        [1, 0, 1, 0, 2, 3, 2, 3],
        [2, 0, 2, 3, 1, 0, 3, 1],
        [3, 0, 0, 1, 3, 2, 2, 1],
        [1, 3, 2, 0, 3, 0, 1, 2],
        [1, 0, 2, 2, 1, 3, 0, 3],
        [3, 0, 0, 2, 2, 1, 1, 3],
    ];
    const TOPOLOGIES: [[usize; 8]; 7] = [
        [3, 0, 1, 0, 2, 3, 1, 2],
        [2, 3, 1, 0, 2, 3, 0, 1],
        [1, 0, 3, 0, 2, 1, 3, 2],
        [2, 0, 1, 3, 2, 1, 0, 3],
        [3, 2, 3, 2, 1, 0, 0, 1],
        [2, 3, 2, 1, 0, 0, 3, 1],
        [1, 2, 2, 0, 3, 0, 1, 3],
    ];
    let frameworks = [
        Framework::NodeJs,
        Framework::Express,
        Framework::NextAppRouter,
        Framework::ServerActions,
    ];
    let formats = [
        SourceFormat::JavaScript,
        SourceFormat::Jsx,
        SourceFormat::TypeScript,
        SourceFormat::Tsx,
    ];
    let topologies = [
        Topology::Direct,
        Topology::HelperMediated,
        Topology::InterFileAliased,
        Topology::ControlFlowSensitive,
    ];
    let mut result = Vec::with_capacity(56);
    for family_index in 0..7 {
        for variant in 0..8 {
            result.push(Assignment {
                ordinal: result.len() + 1,
                family_index,
                variant,
                framework: frameworks[FRAMEWORKS[family_index][variant]],
                source_format: formats[FORMATS[family_index][variant]],
                topology: topologies[TOPOLOGIES[family_index][variant]],
            });
        }
    }
    result
}

fn extension(format: SourceFormat) -> &'static str {
    match format {
        SourceFormat::JavaScript => "js",
        SourceFormat::Jsx => "jsx",
        SourceFormat::TypeScript => "ts",
        SourceFormat::Tsx => "tsx",
    }
}

fn is_typed(format: SourceFormat) -> bool {
    matches!(format, SourceFormat::TypeScript | SourceFormat::Tsx)
}

fn has_jsx(format: SourceFormat) -> bool {
    matches!(format, SourceFormat::Jsx | SourceFormat::Tsx)
}

fn family_import(family_index: usize) -> &'static str {
    match family_index {
        0 => "import { access, records, sessionActor } from \"@fixture/services\";\n",
        1 => "import { exec, execFile } from \"node:child_process\";\n",
        3 => {
            "import { readFile } from \"node:fs/promises\";\nimport { isAbsolute, relative, resolve, sep } from \"node:path\";\n"
        }
        5 => "import { redirect } from \"next/navigation\";\n",
        6 => "import { db } from \"@fixture/database\";\n",
        _ => "",
    }
}

fn source_block(assignment: Assignment) -> (String, String) {
    let typed = if is_typed(assignment.source_format) {
        ": string"
    } else {
        ""
    };
    let (block, needle) = match assignment.framework {
        Framework::NodeJs => (
            format!("const candidate{typed} = String(request.query?.item ?? \"\");"),
            format!("const candidate{typed} = String(request.query?.item ?? \"\");"),
        ),
        Framework::Express => (
            format!(
                "const {{ item: supplied }} = request.query;\n  const candidate{typed} = String(supplied ?? \"\");"
            ),
            format!("const candidate{typed} = String(supplied ?? \"\");"),
        ),
        Framework::NextAppRouter => (
            format!(
                "const requestUrl = new URL(request.url);\n  const candidate{typed} = String(requestUrl.searchParams.get(\"item\") ?? \"\");"
            ),
            format!(
                "const candidate{typed} = String(requestUrl.searchParams.get(\"item\") ?? \"\");"
            ),
        ),
        Framework::ServerActions => (
            format!("const candidate{typed} = String(formData.get(\"item\") ?? \"\");"),
            format!("const candidate{typed} = String(formData.get(\"item\") ?? \"\");"),
        ),
    };
    (block, needle)
}

fn handler_open(assignment: Assignment) -> String {
    let typed = is_typed(assignment.source_format);
    match assignment.framework {
        Framework::NodeJs => format!(
            "export async function serve(request{}) {{",
            if typed { ": any" } else { "" }
        ),
        Framework::Express => format!(
            "export async function route(request{}, response{}) {{\n  void response;",
            if typed { ": any" } else { "" },
            if typed { ": any" } else { "" }
        ),
        Framework::NextAppRouter => format!(
            "export async function POST(request{}) {{",
            if typed { ": Request" } else { "" }
        ),
        Framework::ServerActions => format!(
            "export async function submit(formData{}) {{",
            if typed { ": FormData" } else { "" }
        ),
    }
}

fn entry_prelude(assignment: Assignment, family_import: &str) -> String {
    if matches!(assignment.framework, Framework::ServerActions) {
        format!("\"use server\";\n{family_import}")
    } else {
        family_import.to_owned()
    }
}

fn unique_statement(assignment: Assignment) -> String {
    let stamp = format!(
        "v4-{:02}-{:02}",
        assignment.family_index + 1,
        assignment.variant + 1
    );
    let visual = if has_jsx(assignment.source_format) {
        "\n  const statusView = <output data-length={candidate.length} />;\n  void statusView;"
    } else {
        ""
    };
    let boundary = match assignment.variant {
        6 if is_typed(assignment.source_format) => "\n  const optionalBoundary = (globalThis as Record<string, unknown>)[\"resolveCandidate\"];\n  const opaqueValue = typeof optionalBoundary === \"function\" ? optionalBoundary(candidate) : candidate;\n  void opaqueValue;".to_owned(),
        6 => "\n  const optionalBoundary = globalThis[\"resolveCandidate\"];\n  const opaqueValue = typeof optionalBoundary === \"function\" ? optionalBoundary(candidate) : candidate;\n  void opaqueValue;".to_owned(),
        7 if is_typed(assignment.source_format) => "\n  function recursiveAlias(value: string, remaining: number): string {\n    return remaining <= 0 ? value : recursiveAlias(value, remaining - 1);\n  }\n  const recursiveValue = recursiveAlias(candidate, 1);\n  void recursiveValue;".to_owned(),
        7 => "\n  function recursiveAlias(value, remaining) {\n    return remaining <= 0 ? value : recursiveAlias(value, remaining - 1);\n  }\n  const recursiveValue = recursiveAlias(candidate, 1);\n  void recursiveValue;".to_owned(),
        _ => String::new(),
    };
    format!("\n  const specimenStamp = \"{stamp}\";\n  void specimenStamp;{visual}{boundary}")
}

fn adversarial_features(assignment: Assignment) -> Vec<String> {
    let mut features = BTreeSet::new();
    features.insert("value_preserving_wrappers");
    if matches!(assignment.framework, Framework::Express) {
        features.insert("aliases_and_destructuring");
    }
    match assignment.topology {
        Topology::Direct => {}
        Topology::HelperMediated => {
            features.insert("local_helpers");
            features.insert("wrappers_with_multiple_arguments");
        }
        Topology::InterFileAliased => {
            features.insert("aliases_and_destructuring");
            features.insert("inter_file_helpers");
            features.insert("wrappers_with_multiple_arguments");
        }
        Topology::ControlFlowSensitive => {
            features.insert("control_flow_sensitive_join");
        }
    }
    match assignment.family_index {
        0 => {
            features.insert("authentication_vs_authorization");
            features.insert("ownership_tenant_and_role_checks");
        }
        1 => {
            features.insert("fixed_executable_argument_array");
            features.insert("non_dominating_guard");
            features.insert("non_terminating_guard");
        }
        2 => {
            features.insert("dynamic_code_near_miss");
        }
        3 => {
            features.insert("non_terminating_guard");
            features.insert("path_prefix_and_sibling_prefix");
        }
        4 => {
            features.insert("hostname_suffix_near_miss");
            features.insert("url_protocol_and_userinfo");
        }
        5 => {
            features.insert("redirect_fallback");
        }
        6 => {
            features.insert("parameterized_sql");
        }
        _ => {}
    }
    if assignment.variant == 6 {
        features.insert("ambiguous_resolution");
        features.insert("conservative_unsupported_boundary");
    }
    if assignment.variant == 7 {
        features.insert("recursion");
    }
    features.into_iter().map(str::to_owned).collect()
}

#[allow(clippy::too_many_lines)]
fn family_fragment(
    assignment: Assignment,
    variable: &str,
    control: bool,
) -> (String, String, Option<String>) {
    let variant = assignment.variant;
    match assignment.family_index {
        0 if !control => {
            let fragment = format!(
                "const actor = await sessionActor();\n  if (!actor) {{ throw new Error(\"unauthenticated\"); }}\n  return records.update({variable}, {{ state: \"archived\" }});"
            );
            (
                fragment,
                format!("records.update({variable}, {{ state: \"archived\" }})"),
                None,
            )
        }
        0 => {
            let action = ["archive", "transfer", "rename", "publish"][variant % 4];
            let subject_check = match variant {
                0 | 1 => "decision.ownerId !== actor.id",
                2 | 3 => "decision.tenantId !== actor.tenantId",
                4 | 5 => "!actor.roles.includes(\"editor\")",
                _ => {
                    "decision.ownerId !== actor.id || decision.tenantId !== actor.tenantId || !actor.roles.includes(\"editor\")"
                }
            };
            let barrier = format!(
                "if (!decision.allowed || {subject_check} || !decision.actions.includes(\"{action}\")) {{ throw new Error(\"forbidden\"); }}"
            );
            let fragment = format!(
                "const actor = await sessionActor();\n  if (!actor) {{ throw new Error(\"unauthenticated\"); }}\n  const decision = await access.authorize(actor, \"{action}\", {variable});\n  {barrier}\n  return records.update({variable}, {{ state: \"archived\" }});"
            );
            (
                fragment,
                format!("records.update({variable}, {{ state: \"archived\" }})"),
                Some(barrier),
            )
        }
        1 if !control => (
            format!(
                "if ({variable}.includes(\";\")) {{ Promise.reject(new Error(\"suspicious input\")); }}\n  return exec({variable});"
            ),
            format!("exec({variable})"),
            None,
        ),
        1 => {
            let fragment = format!(
                "const executable = \"/usr/bin/printf\";\n  return execFile(executable, [\"%s\", {variable}], {{ shell: false }});"
            );
            (
                fragment,
                format!("execFile(executable, [\"%s\", {variable}], {{ shell: false }})"),
                Some(format!(
                    "execFile(executable, [\"%s\", {variable}], {{ shell: false }})"
                )),
            )
        }
        2 if !control => (
            format!("const evaluate = globalThis[\"Function\"];\n  return evaluate({variable})();"),
            format!("evaluate({variable})"),
            None,
        ),
        2 => {
            let barrier =
                "if (program === undefined) { throw new Error(\"unsupported operation\"); }"
                    .to_owned();
            let fragment = format!(
                "const programs = new Map([[\"sum\", \"return 1 + 1\"], [\"status\", \"return 'ok'\"]]);\n  const program = programs.get({variable});\n  {barrier}\n  const evaluate = globalThis[\"Function\"];\n  return evaluate(program)();"
            );
            (fragment, "evaluate(program)".to_owned(), Some(barrier))
        }
        3 if !control => (
            format!(
                "const requestedPath = resolve(\"/srv/records\", {variable});\n  if (!requestedPath.startsWith(\"/srv/records\")) {{ console.warn(\"unexpected prefix\"); }}\n  return readFile(requestedPath, \"utf8\");"
            ),
            "readFile(requestedPath, \"utf8\")".to_owned(),
            None,
        ),
        3 => {
            let barrier = "if (relativePath === \"..\" || relativePath.startsWith(`..${sep}`) || isAbsolute(relativePath)) { throw new Error(\"outside data root\"); }".to_owned();
            let fragment = format!(
                "const dataRoot = resolve(\"/srv/records\");\n  const requestedPath = resolve(dataRoot, {variable});\n  const relativePath = relative(dataRoot, requestedPath);\n  {barrier}\n  return readFile(requestedPath, \"utf8\");"
            );
            (
                fragment,
                "readFile(requestedPath, \"utf8\")".to_owned(),
                Some(barrier),
            )
        }
        4 if !control => (
            format!(
                "if ({variable}.endsWith(\".example.invalid\")) {{ void {variable}; }}\n  return fetch({variable});"
            ),
            format!("fetch({variable})"),
            None,
        ),
        4 => {
            let barrier = "if (destination.protocol !== \"https:\" || destination.username !== \"\" || destination.password !== \"\" || !allowedHosts.has(destination.hostname)) { throw new Error(\"destination denied\"); }".to_owned();
            let fragment = format!(
                "const destination = new URL({variable});\n  const allowedHosts = new Set([\"api.example.invalid\", \"media.example.invalid\"]);\n  {barrier}\n  return fetch(destination);"
            );
            (fragment, "fetch(destination)".to_owned(), Some(barrier))
        }
        5 if !control => (
            format!(
                "const destination = {variable} || \"/portal/fallback\";\n  return redirect(destination);"
            ),
            "redirect(destination)".to_owned(),
            None,
        ),
        5 => {
            let barrier = "if (destination.origin !== applicationOrigin || !destination.pathname.startsWith(\"/portal/\")) { throw new Error(\"redirect denied\"); }".to_owned();
            let fragment = format!(
                "const applicationOrigin = \"https://app.example.invalid\";\n  const destination = new URL({variable}, applicationOrigin);\n  {barrier}\n  return redirect(destination.pathname + destination.search);"
            );
            (
                fragment,
                "redirect(destination.pathname + destination.search)".to_owned(),
                Some(barrier),
            )
        }
        6 if !control => (
            format!(
                "return db.query(\"SELECT * FROM inventory WHERE sku = '\" + {variable} + \"'\");"
            ),
            format!("db.query(\"SELECT * FROM inventory WHERE sku = '\" + {variable} + \"'\")"),
            None,
        ),
        6 => {
            let sink =
                format!("db.query(\"SELECT * FROM inventory WHERE sku = $1\", [{variable}])");
            (format!("return {sink};"), sink.clone(), Some(sink))
        }
        _ => (String::new(), String::new(), None),
    }
}

fn indent(fragment: &str, spaces: usize) -> String {
    let prefix = " ".repeat(spaces);
    fragment
        .lines()
        .map(|line| format!("{prefix}{line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[allow(clippy::too_many_lines)]
fn render_case(assignment: Assignment, control: bool) -> RenderedCase {
    let ext = extension(assignment.source_format);
    let entry = format!("entry.{ext}");
    let bridge = format!("bridge.{ext}");
    let (source, source_needle) = source_block(assignment);
    let helper_types = if is_typed(assignment.source_format) {
        ": string"
    } else {
        ""
    };
    let import = family_import(assignment.family_index);
    let mut files = BTreeMap::new();
    let mut propagations = Vec::new();
    let (sink_file, sink_needle, barrier, mutation_file, mutation_fragment);

    match assignment.topology {
        Topology::Direct => {
            let (fragment, sink, guard) = family_fragment(assignment, "candidate", control);
            let prelude = entry_prelude(assignment, import);
            let content = format!(
                "{prelude}{}\n  {source}{}\n{}\n}}\n",
                handler_open(assignment),
                unique_statement(assignment),
                indent(&fragment, 2)
            );
            files.insert(entry.clone(), content.into_bytes());
            sink_file = entry.clone();
            sink_needle = sink;
            barrier = guard.map(|needle| (entry.clone(), needle));
            mutation_file = entry.clone();
            mutation_fragment = fragment;
        }
        Topology::HelperMediated => {
            let (fragment, sink, guard) = family_fragment(assignment, "candidate", control);
            let prelude = entry_prelude(assignment, import);
            let helper = format!(
                "async function relay(candidate{helper_types}, scope{helper_types}) {{\n  void scope;\n{}\n}}\n",
                indent(&fragment, 2)
            );
            let call = format!(
                "return relay(candidate, \"scope-{:02}\");",
                assignment.ordinal
            );
            let content = format!(
                "{prelude}{helper}\n{}\n  {source}{}\n  {call}\n}}\n",
                handler_open(assignment),
                unique_statement(assignment)
            );
            files.insert(entry.clone(), content.into_bytes());
            propagations.push((entry.clone(), call));
            sink_file = entry.clone();
            sink_needle = sink;
            barrier = guard.map(|needle| (entry.clone(), needle));
            mutation_file = entry.clone();
            mutation_fragment = fragment;
        }
        Topology::InterFileAliased => {
            let (fragment, sink, guard) = family_fragment(assignment, "candidate", control);
            let module_path = if is_typed(assignment.source_format) {
                "./bridge"
            } else {
                "./bridge.js"
            };
            let call = format!(
                "return relay(candidate, \"scope-{:02}\");",
                assignment.ordinal
            );
            let relay_import = format!("import {{ perform as relay }} from \"{module_path}\";\n");
            let entry_header = entry_prelude(assignment, &relay_import);
            let entry_content = format!(
                "{entry_header}{}\n  {source}{}\n  {call}\n}}\n",
                handler_open(assignment),
                unique_statement(assignment)
            );
            let bridge_content = format!(
                "{import}export async function perform(candidate{helper_types}, scope{helper_types}) {{\n  void scope;\n{}\n}}\n",
                indent(&fragment, 2)
            );
            files.insert(entry.clone(), entry_content.into_bytes());
            files.insert(bridge.clone(), bridge_content.into_bytes());
            propagations.push((entry.clone(), call));
            propagations.push((bridge.clone(), "void scope;".to_owned()));
            sink_file = bridge.clone();
            sink_needle = sink;
            barrier = guard.map(|needle| (bridge.clone(), needle));
            mutation_file = bridge;
            mutation_fragment = fragment;
        }
        Topology::ControlFlowSensitive => {
            let (fragment, sink, guard) = family_fragment(assignment, "selected", control);
            let join = "selected = candidate.trim();".to_owned();
            let prelude = entry_prelude(assignment, import);
            let content = format!(
                "{prelude}{}\n  {source}{}\n  let selected = candidate;\n  if (candidate.length > 0 && candidate !== \"fallback\") {{\n    {join}\n  }}\n{}\n}}\n",
                handler_open(assignment),
                unique_statement(assignment),
                indent(&fragment, 2)
            );
            files.insert(entry.clone(), content.into_bytes());
            propagations.push((entry.clone(), join));
            sink_file = entry.clone();
            sink_needle = sink;
            barrier = guard.map(|needle| (entry.clone(), needle));
            mutation_file = entry.clone();
            mutation_fragment = fragment;
        }
    }

    RenderedCase {
        files,
        source: (entry, source_needle),
        propagations,
        sink: (sink_file, sink_needle),
        barrier,
        mutation_file,
        mutation_fragment,
    }
}

fn span_for(
    files: &BTreeMap<String, Vec<u8>>,
    file: &str,
    needle: &str,
) -> Result<EvidenceSpanV2, Phase13Error> {
    let bytes = files
        .get(file)
        .ok_or_else(|| Phase13Error::InvalidContract(format!("fixture file `{file}` is absent")))?;
    let text = std::str::from_utf8(bytes)
        .map_err(|error| Phase13Error::InvalidContract(error.to_string()))?;
    let start = text
        .find(needle)
        .ok_or_else(|| Phase13Error::InvalidContract(format!("needle is absent from `{file}`")))?;
    if text[start + needle.len()..].contains(needle) {
        return Err(Phase13Error::InvalidContract(format!(
            "needle is not unique in `{file}`"
        )));
    }
    let before = &text[..start];
    let start_line = u32::try_from(before.bytes().filter(|byte| *byte == b'\n').count() + 1)
        .map_err(|_| Phase13Error::InvalidContract("span line overflow".to_owned()))?;
    let start_column = u32::try_from(
        before
            .rsplit_once('\n')
            .map_or(before.len(), |(_, suffix)| suffix.len())
            + 1,
    )
    .map_err(|_| Phase13Error::InvalidContract("span column overflow".to_owned()))?;
    let line_count = needle.bytes().filter(|byte| *byte == b'\n').count();
    let end_line = start_line
        .checked_add(
            u32::try_from(line_count)
                .map_err(|_| Phase13Error::InvalidContract("span end-line overflow".to_owned()))?,
        )
        .ok_or_else(|| Phase13Error::InvalidContract("span end-line overflow".to_owned()))?;
    let end_column = if let Some((_, suffix)) = needle.rsplit_once('\n') {
        u32::try_from(suffix.len() + 1)
    } else {
        u32::try_from(usize::try_from(start_column).unwrap_or_default() + needle.len())
    }
    .map_err(|_| Phase13Error::InvalidContract("span end-column overflow".to_owned()))?;
    Ok(EvidenceSpanV2 {
        file: file.to_owned(),
        start_line,
        start_column,
        end_line,
        end_column,
    })
}

fn taxonomy_category<'a>(
    taxonomy: &'a FrozenTaxonomy,
    category_id: &str,
) -> Result<&'a TaxonomyCategory, Phase13Error> {
    taxonomy
        .categories
        .iter()
        .find(|category| category.category_id == category_id)
        .ok_or_else(|| {
            Phase13Error::InvalidContract(format!("taxonomy category `{category_id}` is absent"))
        })
}

fn build_expectation(
    case_id: &str,
    kind: CaseKind,
    assignment: Assignment,
    rendered: &RenderedCase,
    taxonomy: &FrozenTaxonomy,
) -> Result<FrozenCaseExpectation, Phase13Error> {
    let family = FAMILIES[assignment.family_index];
    let category = taxonomy_category(taxonomy, family.category_id)?;
    let value_id = format!("phase13-flow-{:03}", assignment.ordinal);
    let mut path = vec![EvidenceNodeV2 {
        role: EvidenceRoleV2::Source,
        effect: EvidenceEffectV2::PreservesInfluence,
        source_kind: Some(family.source_kind),
        sink_kind: None,
        span: span_for(&rendered.files, &rendered.source.0, &rendered.source.1)?,
        summarizable: false,
    }];
    for (file, needle) in &rendered.propagations {
        path.push(EvidenceNodeV2 {
            role: EvidenceRoleV2::Propagation,
            effect: EvidenceEffectV2::PreservesInfluence,
            source_kind: None,
            sink_kind: None,
            span: span_for(&rendered.files, file, needle)?,
            summarizable: true,
        });
    }
    let barrier = if let Some((file, needle)) = &rendered.barrier {
        let barrier = BarrierExpectation {
            role: family.barrier_role,
            effect: family.barrier_effect,
            value_id: value_id.clone(),
            terminating: true,
            dominates_sink: true,
            span: span_for(&rendered.files, file, needle)?,
        };
        path.push(EvidenceNodeV2 {
            role: family.barrier_role,
            effect: family.barrier_effect,
            source_kind: None,
            sink_kind: None,
            span: barrier.span.clone(),
            summarizable: false,
        });
        vec![barrier]
    } else {
        Vec::new()
    };
    path.push(EvidenceNodeV2 {
        role: EvidenceRoleV2::Sink,
        effect: EvidenceEffectV2::PreservesInfluence,
        source_kind: None,
        sink_kind: Some(family.sink_kind),
        span: span_for(&rendered.files, &rendered.sink.0, &rendered.sink.1)?,
        summarizable: false,
    });
    let vulnerable_path = path
        .iter()
        .filter(|node| {
            !matches!(
                node.role,
                EvidenceRoleV2::Guard | EvidenceRoleV2::Sanitizer | EvidenceRoleV2::Authorization
            )
        })
        .cloned()
        .collect::<Vec<_>>();
    let expectation = matches!(kind, CaseKind::Vulnerable).then(|| EvidenceExpectationV2 {
        expectation_id: format!("phase13-expectation-{:03}", assignment.ordinal),
        taxonomy_version: taxonomy.taxonomy_version.clone(),
        category_id: category.category_id.clone(),
        invariant_id: category.invariant_id.clone(),
        primary_cwe: category.primary_cwe.id.clone(),
        path: vulnerable_path,
    });
    Ok(FrozenCaseExpectation {
        case_id: case_id.to_owned(),
        kind,
        evidence_contract_version: "2.0.0".to_owned(),
        authoritative_projection: "evidence_contract_v2".to_owned(),
        value_id,
        taxonomy_version: taxonomy.taxonomy_version.clone(),
        category_id: category.category_id.clone(),
        invariant_id: category.invariant_id.clone(),
        primary_cwe: category.primary_cwe.id.clone(),
        source_kind: family.source_kind,
        sink_kind: family.sink_kind,
        connected_edges: vec![true; path.len().saturating_sub(1)],
        path,
        effective_barriers: barrier,
        vulnerability_expectation: expectation,
        legacy_override_permitted: false,
    })
}

fn fixture_hash(files: &BTreeMap<String, Vec<u8>>) -> String {
    let mut bytes = Vec::new();
    for (path, content) in files {
        bytes.extend_from_slice(path.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(sha256(content).as_bytes());
        bytes.push(b'\n');
    }
    sha256(&bytes)
}

fn line_range(bytes: &[u8], fragment: &str) -> Result<LineRange, Phase13Error> {
    let text = std::str::from_utf8(bytes)
        .map_err(|error| Phase13Error::InvalidContract(error.to_string()))?;
    let indented = indent(fragment, 2);
    let start = text
        .find(&indented)
        .ok_or_else(|| Phase13Error::InvalidContract("mutation fragment is absent".to_owned()))?;
    if text[start + indented.len()..].contains(&indented) {
        return Err(Phase13Error::InvalidContract(
            "mutation fragment is not unique".to_owned(),
        ));
    }
    let first = text[..start].bytes().filter(|byte| *byte == b'\n').count() + 1;
    let last = first + indented.lines().count().saturating_sub(1);
    Ok(LineRange {
        start: u32::try_from(first)
            .map_err(|_| Phase13Error::InvalidContract("mutation line overflow".to_owned()))?,
        end: u32::try_from(last)
            .map_err(|_| Phase13Error::InvalidContract("mutation line overflow".to_owned()))?,
    })
}

fn fragment_bytes(bytes: &[u8], range: &LineRange) -> Result<Vec<u8>, Phase13Error> {
    let text = std::str::from_utf8(bytes)
        .map_err(|error| Phase13Error::InvalidContract(error.to_string()))?;
    let lines = text.lines().collect::<Vec<_>>();
    let start = usize::try_from(range.start.saturating_sub(1))
        .map_err(|_| Phase13Error::InvalidContract("invalid mutation start".to_owned()))?;
    let end = usize::try_from(range.end)
        .map_err(|_| Phase13Error::InvalidContract("invalid mutation end".to_owned()))?;
    if start >= end || end > lines.len() {
        return Err(Phase13Error::InvalidContract(
            "mutation range is outside fixture".to_owned(),
        ));
    }
    Ok(lines[start..end].join("\n").into_bytes())
}

fn replace_lines(
    bytes: &[u8],
    range: &LineRange,
    replacement: &[u8],
) -> Result<Vec<u8>, Phase13Error> {
    let text = std::str::from_utf8(bytes)
        .map_err(|error| Phase13Error::InvalidContract(error.to_string()))?;
    let mut lines = text.lines().map(str::to_owned).collect::<Vec<_>>();
    let start = usize::try_from(range.start.saturating_sub(1))
        .map_err(|_| Phase13Error::InvalidContract("invalid mutation start".to_owned()))?;
    let end = usize::try_from(range.end)
        .map_err(|_| Phase13Error::InvalidContract("invalid mutation end".to_owned()))?;
    let replacement_lines = std::str::from_utf8(replacement)
        .map_err(|error| Phase13Error::InvalidContract(error.to_string()))?
        .lines()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    lines.splice(start..end, replacement_lines);
    let mut output = lines.join("\n").into_bytes();
    output.push(b'\n');
    Ok(output)
}

fn contract_hash(
    fixture_sha256: &str,
    expectation: &FrozenCaseExpectation,
) -> Result<String, Phase13Error> {
    Ok(sha256(&canonical_json(&serde_json::json!({
        "fixture_sha256": fixture_sha256,
        "expectation": expectation,
    }))?))
}

fn merkle_root(leaves: &[String]) -> Result<String, Phase13Error> {
    if leaves.is_empty() {
        return Err(Phase13Error::InvalidContract(
            "contract Merkle tree is empty".to_owned(),
        ));
    }
    let mut layer = leaves.to_vec();
    while layer.len() > 1 {
        if layer.len() % 2 == 1 {
            let last = layer
                .last()
                .cloned()
                .ok_or_else(|| Phase13Error::InvalidContract("Merkle layer is empty".to_owned()))?;
            layer.push(last);
        }
        layer = layer
            .chunks(2)
            .map(|pair| sha256(format!("{}{}", pair[0], pair[1]).as_bytes()))
            .collect();
    }
    layer
        .first()
        .cloned()
        .ok_or_else(|| Phase13Error::InvalidContract("Merkle root is absent".to_owned()))
}

fn count_factor<T: Serialize + Copy + Ord>(
    assignments: &[Assignment],
    project: impl Fn(Assignment) -> T,
) -> Result<BTreeMap<String, u64>, Phase13Error> {
    let mut counts = BTreeMap::new();
    for assignment in assignments {
        *counts.entry(enum_name(project(*assignment))?).or_insert(0) += 1;
    }
    Ok(counts)
}

fn contingency<A: Serialize + Copy + Ord, B: Serialize + Copy + Ord>(
    assignments: &[Assignment],
    first: impl Fn(Assignment) -> A,
    second: impl Fn(Assignment) -> B,
) -> Result<BTreeMap<String, BTreeMap<String, u64>>, Phase13Error> {
    let mut table = BTreeMap::new();
    for assignment in assignments {
        *table
            .entry(enum_name(first(*assignment))?)
            .or_insert_with(BTreeMap::new)
            .entry(enum_name(second(*assignment))?)
            .or_insert(0) += 1;
    }
    Ok(table)
}

fn balance_proof(assignments: &[Assignment]) -> Result<BalanceProof, Phase13Error> {
    let mut families = BTreeMap::new();
    for assignment in assignments {
        *families
            .entry(FAMILIES[assignment.family_index].family_id.to_owned())
            .or_insert(0) += 1;
    }
    let frameworks = count_factor(assignments, |assignment| assignment.framework)?;
    let source_formats = count_factor(assignments, |assignment| assignment.source_format)?;
    let topologies = count_factor(assignments, |assignment| assignment.topology)?;
    let mut language_groups = BTreeMap::new();
    for assignment in assignments {
        let language = if is_typed(assignment.source_format) {
            "typescript"
        } else {
            "javascript"
        };
        *language_groups.entry(language.to_owned()).or_insert(0) += 1;
    }
    let framework_by_source_format = contingency(
        assignments,
        |assignment| assignment.framework,
        |assignment| assignment.source_format,
    )?;
    let framework_by_topology = contingency(
        assignments,
        |assignment| assignment.framework,
        |assignment| assignment.topology,
    )?;
    let source_format_by_topology = contingency(
        assignments,
        |assignment| assignment.source_format,
        |assignment| assignment.topology,
    )?;
    let cells = framework_by_source_format
        .values()
        .chain(framework_by_topology.values())
        .chain(source_format_by_topology.values())
        .flat_map(|row| row.values().copied())
        .collect::<Vec<_>>();
    let minimum = cells.iter().copied().min().unwrap_or_default();
    let maximum = cells.iter().copied().max().unwrap_or_default();
    Ok(BalanceProof {
        families,
        frameworks,
        source_formats,
        language_groups,
        topologies,
        framework_by_source_format,
        framework_by_topology,
        source_format_by_topology,
        pairwise_cell_minimum: minimum,
        pairwise_cell_maximum: maximum,
        imbalance_justification: "Each 4x4 pairwise table contains 56 pairs, so perfect equality would require 3.5 pairs per cell; the preregistered schedule therefore uses only three or four pairs per cell.".to_owned(),
    })
}

fn collect_regular_files(
    absolute: &Path,
    relative: &Path,
    records: &mut BTreeMap<String, Vec<u8>>,
    source_only: bool,
) -> Result<(), Phase13Error> {
    let metadata = fs::symlink_metadata(absolute).map_err(|error| io(absolute, &error))?;
    if metadata.file_type().is_symlink() {
        return Err(Phase13Error::InvalidContract(format!(
            "path `{}` is a symlink",
            relative.display()
        )));
    }
    if metadata.is_file() {
        let extension = absolute.extension().and_then(|value| value.to_str());
        if !source_only || matches!(extension, Some("js" | "jsx" | "ts" | "tsx")) {
            records.insert(
                relative.to_string_lossy().replace('\\', "/"),
                fs::read(absolute).map_err(|error| io(absolute, &error))?,
            );
        }
        return Ok(());
    }
    if !metadata.is_dir() {
        return Err(Phase13Error::InvalidContract(format!(
            "path `{}` has an unsupported file type",
            relative.display()
        )));
    }
    let mut entries = fs::read_dir(absolute)
        .map_err(|error| io(absolute, &error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| io(absolute, &error))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let child_metadata =
            fs::symlink_metadata(entry.path()).map_err(|error| io(&entry.path(), &error))?;
        if entry.file_name() == "target" && child_metadata.is_dir() {
            continue;
        }
        collect_regular_files(
            &entry.path(),
            &relative.join(entry.file_name()),
            records,
            source_only,
        )?;
    }
    Ok(())
}

fn normalized_ngrams(bytes: &[u8]) -> BTreeSet<String> {
    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    let tokens = text
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(|token| {
            if token.bytes().all(|byte| byte.is_ascii_digit()) {
                "#".to_owned()
            } else {
                token.to_owned()
            }
        })
        .collect::<Vec<_>>();
    tokens.windows(5).map(|window| window.join(" ")).collect()
}

fn set_overlap_basis_points(first: &BTreeSet<String>, second: &BTreeSet<String>) -> u64 {
    let union = first.union(second).count();
    if union == 0 {
        return 0;
    }
    u64::try_from(first.intersection(second).count())
        .unwrap_or_default()
        .saturating_mul(10_000)
        / u64::try_from(union).unwrap_or(1)
}

fn overlap_proof(
    root: &Path,
    fixture_files: &BTreeMap<String, Vec<u8>>,
) -> Result<OverlapProof, Phase13Error> {
    let mut historical = BTreeMap::new();
    for relative in [
        "fixtures",
        "holdout",
        "diagnostics/phase-6/fixtures",
        "phase12/public-regression/cases",
    ] {
        collect_regular_files(
            &root.join(relative),
            Path::new(relative),
            &mut historical,
            true,
        )?;
    }
    let historical_projections = historical
        .values()
        .map(|bytes| (sha256(bytes), normalized_ngrams(bytes)))
        .collect::<Vec<_>>();
    let mut exact_matches = 0_u64;
    let mut maximum = 0_u64;
    for bytes in fixture_files.values() {
        let fixture_hash = sha256(bytes);
        let fixture_projection = normalized_ngrams(bytes);
        if historical_projections
            .iter()
            .any(|(historical_hash, _)| historical_hash == &fixture_hash)
        {
            exact_matches += 1;
        }
        for (_, historical_projection) in &historical_projections {
            maximum = maximum.max(set_overlap_basis_points(
                &fixture_projection,
                historical_projection,
            ));
        }
    }
    let threshold = 8_500;
    if exact_matches != 0 || maximum >= threshold {
        return Err(Phase13Error::InvalidContract(format!(
            "cross-corpus overlap is too high: exact={exact_matches}, normalized={maximum}"
        )));
    }
    Ok(OverlapProof {
        historical_files_compared: u64::try_from(historical.len()).map_err(|_| {
            Phase13Error::InvalidContract("historical source count overflow".to_owned())
        })?,
        exact_matches,
        maximum_normalized_overlap_basis_points: maximum,
        rejection_threshold_basis_points: threshold,
        limitation: "Exact hashes and normalized token five-gram Jaccard similarity are reproducible overlap proxies; they do not prove semantic independence.".to_owned(),
    })
}

fn file_tree_digest(root: &Path, relative: &str) -> Result<(u64, String), Phase13Error> {
    let mut files = BTreeMap::new();
    collect_regular_files(&root.join(relative), Path::new(relative), &mut files, false)?;
    let mut rows = Vec::new();
    for (path, bytes) in &files {
        rows.extend_from_slice(path.as_bytes());
        rows.push(0);
        rows.extend_from_slice(sha256(bytes).as_bytes());
        rows.push(0);
        rows.extend_from_slice(bytes.len().to_string().as_bytes());
        rows.push(b'\n');
    }
    Ok((
        u64::try_from(files.len())
            .map_err(|_| Phase13Error::InvalidContract("file count overflow".to_owned()))?,
        sha256(&rows),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoricalBaseline {
    schema_version: String,
    snapshot_version: String,
    cutoff_commit: String,
    excluded_mutable_surfaces: Vec<String>,
    closed_roots: Vec<HistoricalRoot>,
    protected_files: Vec<HistoricalFile>,
    aggregate_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoricalRoot {
    path: String,
    file_count: u64,
    content_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoricalFile {
    path: String,
    byte_length: u64,
    sha256: String,
}

fn verify_historical(root: &Path) -> Result<(), Phase13Error> {
    let baseline_bytes = read(root, "phase12/historical/phase0-11-baseline-v1.json")?;
    if sha256(&baseline_bytes) != HISTORICAL_BASELINE_SHA256 {
        return Err(Phase13Error::HistoricalIntegrity(
            "Phase 12.1 baseline manifest differs".to_owned(),
        ));
    }
    let baseline: HistoricalBaseline = serde_json::from_slice(&baseline_bytes)
        .map_err(|error| Phase13Error::HistoricalIntegrity(error.to_string()))?;
    if baseline.schema_version != "secure-bench-historical-baseline-v1"
        || baseline.snapshot_version != "1.0.0"
        || baseline.cutoff_commit != "86aa6f439c14eaa7e2fd7122687aca35f5aadc18"
        || baseline.aggregate_sha256
            != "54f14f90ca4ff7b91a2dad7d0e0f342083792a781ff293fee1a8e748d03d882a"
        || baseline.excluded_mutable_surfaces.is_empty()
    {
        return Err(Phase13Error::HistoricalIntegrity(
            "Phase 0–11 baseline identity differs".to_owned(),
        ));
    }
    for expected in baseline.closed_roots {
        safe_relative(&expected.path)
            .map_err(|error| Phase13Error::HistoricalIntegrity(error.to_string()))?;
        let (count, digest) = file_tree_digest(root, &expected.path)?;
        if count != expected.file_count || digest != expected.content_sha256 {
            return Err(Phase13Error::HistoricalIntegrity(format!(
                "historical root `{}` differs",
                expected.path
            )));
        }
    }
    for expected in baseline.protected_files {
        let bytes = read(root, &expected.path)?;
        if u64::try_from(bytes.len()).ok() != Some(expected.byte_length)
            || sha256(&bytes) != expected.sha256
        {
            return Err(Phase13Error::HistoricalIntegrity(format!(
                "historical file `{}` differs",
                expected.path
            )));
        }
    }
    let (phase12_count, phase12_digest) = file_tree_digest(root, "phase12")?;
    if phase12_count != 91 || phase12_digest != PHASE12_TREE_SHA256 {
        return Err(Phase13Error::HistoricalIntegrity(
            "Phase 12/12.1 tree differs".to_owned(),
        ));
    }
    for (path, expected) in [
        (
            "docs/phase-12-methodology.md",
            "d221251ff0b92f35c43f09e60453331e24e4e92f00cf620267054b4d0974511d",
        ),
        (
            "docs/phase-12-1-historical-verification.md",
            "86009f3c05edc242d3d7f9e745322d1f49bae97800b99eb663ce21c254f0d783",
        ),
        (
            "phase10/output/secure-engine-0-1-4-phase9-holdout/result.json",
            PHASE10_RESULT_SHA256,
        ),
    ] {
        if sha256(&read(root, path)?) != expected {
            return Err(Phase13Error::HistoricalIntegrity(format!(
                "historical artifact `{path}` differs"
            )));
        }
    }
    Ok(())
}

fn evaluator_hash(root: &Path) -> Result<String, Phase13Error> {
    let mut files = BTreeMap::new();
    for relative in [
        "prospective/phase-13-holdout-v4/src",
        "prospective/phase-13-holdout-v4/schemas",
    ] {
        collect_regular_files(&root.join(relative), Path::new(relative), &mut files, false)?;
    }
    for relative in [
        "prospective/phase-13-holdout-v4/Cargo.toml",
        "prospective/phase-13-holdout-v4/Cargo.lock",
    ] {
        files.insert(relative.to_owned(), read(root, relative)?);
    }
    let mut rows = Vec::new();
    for (path, bytes) in files {
        rows.extend_from_slice(path.as_bytes());
        rows.push(0);
        rows.extend_from_slice(sha256(&bytes).as_bytes());
        rows.push(b'\n');
    }
    Ok(sha256(&rows))
}

fn ledger_bytes(
    manifest_sha256: &str,
    aggregate_corpus_sha256: &str,
    contract_merkle_root: &str,
) -> Result<Vec<u8>, Phase13Error> {
    let body = serde_json::json!({
        "schema_version": "secure-bench-phase13-ledger-entry-v1",
        "sequence": 0,
        "event": "holdout_frozen",
        "holdout_id": HOLDOUT_ID,
        "manifest_sha256": manifest_sha256,
        "aggregate_corpus_sha256": aggregate_corpus_sha256,
        "contract_merkle_root": contract_merkle_root,
        "previous_entry_hash": ZERO_HASH,
        "timestamp_utc": "2026-07-17T00:00:00Z",
    });
    let entry_hash = sha256(&canonical_json(&body)?);
    let entry = LedgerEntry {
        schema_version: "secure-bench-phase13-ledger-entry-v1".to_owned(),
        sequence: 0,
        event: "holdout_frozen".to_owned(),
        holdout_id: HOLDOUT_ID.to_owned(),
        manifest_sha256: manifest_sha256.to_owned(),
        aggregate_corpus_sha256: aggregate_corpus_sha256.to_owned(),
        contract_merkle_root: contract_merkle_root.to_owned(),
        previous_entry_hash: ZERO_HASH.to_owned(),
        timestamp_utc: "2026-07-17T00:00:00Z".to_owned(),
        entry_hash,
    };
    let mut bytes = serde_json::to_vec(&entry)
        .map_err(|error| Phase13Error::Serialization(error.to_string()))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn validate_metamorphic(rendered: &RenderedCase) -> Result<(), Phase13Error> {
    for (path, bytes) in &rendered.files {
        let text = std::str::from_utf8(bytes)
            .map_err(|error| Phase13Error::InvalidContract(error.to_string()))?;
        let renamed = text.replace("specimenStamp", "renamedLocal");
        let inserted = text.replacen('{', "{\n  void 0;", 1);
        if path == &rendered.sink.0
            && (!renamed.contains(&rendered.sink.1) || !inserted.contains(&rendered.sink.1))
        {
            return Err(Phase13Error::InvalidContract(
                "metamorphic rewrite changed sink structure".to_owned(),
            ));
        }
        if let Some((barrier_file, barrier)) = &rendered.barrier
            && path == barrier_file
            && (!renamed.contains(barrier) || !inserted.contains(barrier))
        {
            return Err(Phase13Error::InvalidContract(
                "metamorphic rewrite changed barrier structure".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_fixture_privacy(files: &BTreeMap<String, Vec<u8>>) -> Result<(), Phase13Error> {
    let prohibited = [
        "secure-bench",
        "expectation",
        "vulnerable",
        "safe-control",
        "se100",
        "category.",
        "invariant.",
        "/home/",
        "danielcastrillon",
        "api_key",
        "access_token",
    ];
    for (path, bytes) in files {
        safe_relative(path)?;
        let normalized = String::from_utf8_lossy(bytes).to_ascii_lowercase();
        if let Some(term) = prohibited.iter().find(|term| normalized.contains(**term)) {
            return Err(Phase13Error::InvalidContract(format!(
                "scanner-visible fixture `{path}` leaks prohibited term `{term}`"
            )));
        }
    }
    Ok(())
}

fn validate_expectation_shape(expectation: &FrozenCaseExpectation) -> Result<(), Phase13Error> {
    if expectation.evidence_contract_version != "2.0.0"
        || expectation.authoritative_projection != "evidence_contract_v2"
        || expectation.legacy_override_permitted
        || expectation.path.len() < 2
        || expectation.connected_edges.len() + 1 != expectation.path.len()
        || expectation
            .connected_edges
            .iter()
            .any(|connected| !connected)
        || expectation.path.first().map(|node| node.role) != Some(EvidenceRoleV2::Source)
        || expectation.path.last().map(|node| node.role) != Some(EvidenceRoleV2::Sink)
        || expectation.path.first().and_then(|node| node.source_kind)
            != Some(expectation.source_kind)
        || expectation.path.last().and_then(|node| node.sink_kind) != Some(expectation.sink_kind)
    {
        return Err(Phase13Error::InvalidContract(format!(
            "case `{}` has an incomplete Evidence Contract v2 expectation",
            expectation.case_id
        )));
    }
    match expectation.kind {
        CaseKind::Vulnerable => {
            if expectation.vulnerability_expectation.is_none()
                || !expectation.effective_barriers.is_empty()
            {
                return Err(Phase13Error::InvalidContract(format!(
                    "vulnerable case `{}` has invalid barrier state",
                    expectation.case_id
                )));
            }
        }
        CaseKind::SafeControl => {
            if expectation.vulnerability_expectation.is_some()
                || expectation.effective_barriers.len() != 1
                || expectation.effective_barriers.iter().any(|barrier| {
                    !barrier.terminating
                        || !barrier.dominates_sink
                        || barrier.value_id != expectation.value_id
                })
            {
                return Err(Phase13Error::InvalidContract(format!(
                    "control case `{}` lacks one effective dominating barrier",
                    expectation.case_id
                )));
            }
        }
    }
    for node in &expectation.path {
        safe_relative(&node.span.file)?;
        if node.span.start_line == 0
            || node.span.start_column == 0
            || node.span.end_line < node.span.start_line
            || (node.span.end_line == node.span.start_line
                && node.span.end_column <= node.span.start_column)
        {
            return Err(Phase13Error::InvalidContract(format!(
                "case `{}` contains an invalid span",
                expectation.case_id
            )));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn build_bundle(root: &Path) -> Result<Bundle, Phase13Error> {
    verify_historical(root)?;
    let taxonomy_bytes = read(root, TAXONOMY_PATH)?;
    let taxonomy = load_taxonomy(&taxonomy_bytes)
        .map_err(|error| Phase13Error::InvalidContract(error.to_string()))?;
    let contract_bytes = read(root, CONTRACT_PATH)?;
    let contract: EvidenceContractV2 = serde_json::from_slice(&contract_bytes)
        .map_err(|error| Phase13Error::InvalidContract(error.to_string()))?;
    if taxonomy.taxonomy_version != "1.0.0"
        || contract.contract_version != "2.0.0"
        || contract.taxonomy.taxonomy_version != taxonomy.taxonomy_version
        || contract.taxonomy.content_hash != taxonomy.content_hash
    {
        return Err(Phase13Error::InvalidContract(
            "taxonomy 1.0.0 and Evidence Contract v2 binding differs".to_owned(),
        ));
    }
    secure_bench_core::schema::validate_evidence_contract_v2(&contract)
        .map_err(|error| Phase13Error::InvalidContract(error.to_string()))?;

    let schedule = assignments();
    let mut generated = BTreeMap::new();
    let mut scanner_files = BTreeMap::new();
    let mut records = Vec::with_capacity(112);
    let mut pairs = Vec::with_capacity(56);
    let mut contract_hashes = Vec::with_capacity(112);
    let mut seen_fixture_hashes = BTreeSet::new();

    for assignment in &schedule {
        let vulnerable = render_case(*assignment, false);
        let control = render_case(*assignment, true);
        validate_fixture_privacy(&vulnerable.files)?;
        validate_fixture_privacy(&control.files)?;
        validate_metamorphic(&vulnerable)?;
        validate_metamorphic(&control)?;
        if vulnerable.files.keys().collect::<Vec<_>>() != control.files.keys().collect::<Vec<_>>()
            || vulnerable.mutation_file != control.mutation_file
        {
            return Err(Phase13Error::InvalidContract(format!(
                "pair {} changes fixture shape",
                assignment.ordinal
            )));
        }
        for path in vulnerable.files.keys() {
            if path != &vulnerable.mutation_file
                && vulnerable.files.get(path) != control.files.get(path)
            {
                return Err(Phase13Error::InvalidContract(format!(
                    "pair {} changes a non-mutation file",
                    assignment.ordinal
                )));
            }
        }

        let vulnerable_bytes = vulnerable
            .files
            .get(&vulnerable.mutation_file)
            .ok_or_else(|| Phase13Error::InvalidContract("mutation file absent".to_owned()))?;
        let control_bytes = control
            .files
            .get(&control.mutation_file)
            .ok_or_else(|| Phase13Error::InvalidContract("mutation file absent".to_owned()))?;
        let vulnerable_lines = line_range(vulnerable_bytes, &vulnerable.mutation_fragment)?;
        let control_lines = line_range(control_bytes, &control.mutation_fragment)?;
        let vulnerable_fragment = fragment_bytes(vulnerable_bytes, &vulnerable_lines)?;
        let control_fragment = fragment_bytes(control_bytes, &control_lines)?;
        if replace_lines(vulnerable_bytes, &vulnerable_lines, &control_fragment)? != *control_bytes
            || replace_lines(control_bytes, &control_lines, &vulnerable_fragment)?
                != *vulnerable_bytes
        {
            return Err(Phase13Error::InvalidContract(format!(
                "pair {} is not an exact bidirectional mutation",
                assignment.ordinal
            )));
        }

        let first_case_number = assignment.ordinal * 2 - 1;
        let second_case_number = assignment.ordinal * 2;
        let vulnerable_id = format!("v4-case-{first_case_number:03}");
        let control_id = format!("v4-case-{second_case_number:03}");
        let vulnerable_path =
            format!("prospective/phase-13-holdout-v4/fixtures/unit-{first_case_number:03}");
        let control_path =
            format!("prospective/phase-13-holdout-v4/fixtures/unit-{second_case_number:03}");
        let vulnerable_expectation = build_expectation(
            &vulnerable_id,
            CaseKind::Vulnerable,
            *assignment,
            &vulnerable,
            &taxonomy,
        )?;
        let control_expectation = build_expectation(
            &control_id,
            CaseKind::SafeControl,
            *assignment,
            &control,
            &taxonomy,
        )?;
        validate_expectation_shape(&vulnerable_expectation)?;
        validate_expectation_shape(&control_expectation)?;
        let vulnerable_fixture_sha = fixture_hash(&vulnerable.files);
        let control_fixture_sha = fixture_hash(&control.files);
        if !seen_fixture_hashes.insert(vulnerable_fixture_sha.clone())
            || !seen_fixture_hashes.insert(control_fixture_sha.clone())
        {
            return Err(Phase13Error::InvalidContract(
                "duplicate Phase 13 fixture aggregate".to_owned(),
            ));
        }
        let vulnerable_contract_sha =
            contract_hash(&vulnerable_fixture_sha, &vulnerable_expectation)?;
        let control_contract_sha = contract_hash(&control_fixture_sha, &control_expectation)?;
        contract_hashes.push(vulnerable_contract_sha.clone());
        contract_hashes.push(control_contract_sha.clone());

        for (path, bytes) in &vulnerable.files {
            let destination = format!("{vulnerable_path}/{path}");
            generated.insert(destination.clone(), bytes.clone());
            scanner_files.insert(destination, bytes.clone());
        }
        for (path, bytes) in &control.files {
            let destination = format!("{control_path}/{path}");
            generated.insert(destination.clone(), bytes.clone());
            scanner_files.insert(destination, bytes.clone());
        }
        records.push(vulnerable_expectation);
        records.push(control_expectation);
        let presentation_order = if assignment.ordinal % 2 == 0 {
            vec![control_id.clone(), vulnerable_id.clone()]
        } else {
            vec![vulnerable_id.clone(), control_id.clone()]
        };
        pairs.push(PairContract {
            pair_id: format!("v4-pair-{:03}", assignment.ordinal),
            family_id: FAMILIES[assignment.family_index].family_id.to_owned(),
            framework: assignment.framework,
            source_format: assignment.source_format,
            language_group: if is_typed(assignment.source_format) {
                "typescript"
            } else {
                "javascript"
            }
            .to_owned(),
            topology: assignment.topology,
            adversarial_features: adversarial_features(*assignment),
            presentation_order,
            mutation: MutationContract {
                file: vulnerable.mutation_file.clone(),
                vulnerable_lines,
                control_lines,
                vulnerable_fragment_sha256: sha256(&vulnerable_fragment),
                control_fragment_sha256: sha256(&control_fragment),
                security_invariant: taxonomy_category(
                    &taxonomy,
                    FAMILIES[assignment.family_index].category_id,
                )?
                .invariant_id
                .clone(),
                bidirectional_exact: true,
                metamorphic_rename_stable: true,
                metamorphic_insertion_stable: true,
            },
            vulnerable: CaseReference {
                case_id: vulnerable_id,
                fixture_path: vulnerable_path,
                fixture_sha256: vulnerable_fixture_sha,
                contract_sha256: vulnerable_contract_sha,
            },
            control: CaseReference {
                case_id: control_id,
                fixture_path: control_path,
                fixture_sha256: control_fixture_sha,
                contract_sha256: control_contract_sha,
            },
        });
    }

    let expectations = ExpectationsDocument {
        schema_version: "secure-bench-phase13-expectations-v1".to_owned(),
        holdout_id: HOLDOUT_ID.to_owned(),
        evidence_contract_sha256: sha256(&contract_bytes),
        records,
    };
    let expectations_bytes = canonical_json(&expectations)?;
    let expectations_sha256 = sha256(&expectations_bytes);
    generated.insert(EXPECTATIONS_PATH.to_owned(), expectations_bytes);

    let mut corpus_rows = Vec::new();
    for (path, bytes) in &scanner_files {
        corpus_rows.extend_from_slice(path.as_bytes());
        corpus_rows.push(0);
        corpus_rows.extend_from_slice(sha256(bytes).as_bytes());
        corpus_rows.push(b'\n');
    }
    let aggregate_corpus_sha256 = sha256(&corpus_rows);
    contract_hashes.sort();
    let contract_merkle_root = merkle_root(&contract_hashes)?;
    let evaluator_sha256 = evaluator_hash(root)?;
    let manifest = Manifest {
        schema_version: "secure-bench-phase13-manifest-v1".to_owned(),
        benchmark_version: BENCHMARK_VERSION.to_owned(),
        holdout_id: HOLDOUT_ID.to_owned(),
        title: "Secure Bench prospective holdout v4".to_owned(),
        status: "frozen and intentionally unexecuted".to_owned(),
        base_commit: BASE_COMMIT.to_owned(),
        branch: BRANCH.to_owned(),
        taxonomy_sha256: sha256(&taxonomy_bytes),
        evidence_contract_sha256: sha256(&contract_bytes),
        adapter_policy_sha256: sha256(&read(root, ADAPTER_POLICY_PATH)?),
        authoring_policy_sha256: sha256(&read(root, AUTHORING_POLICY_PATH)?),
        process_status_policy_sha256: sha256(&read(root, PROCESS_POLICY_PATH)?),
        expectation_sha256: expectations_sha256.clone(),
        aggregate_corpus_sha256: aggregate_corpus_sha256.clone(),
        contract_merkle_root: contract_merkle_root.clone(),
        evaluator_sha256: evaluator_sha256.clone(),
        balance: balance_proof(&schedule)?,
        overlap: overlap_proof(root, &scanner_files)?,
        pairs,
        limitations: vec![
            "This is a frozen examination definition, not a scanner result or score.".to_owned(),
            "No result supports rankings, superiority, production readiness, or complete coverage.".to_owned(),
            "Exact and normalized overlap checks are proxies and cannot prove semantic independence.".to_owned(),
            "Ambiguous, recursive, and unsupported-boundary cases require conservative evidence rather than assumed reachability.".to_owned(),
        ],
    };
    let manifest_bytes = canonical_json(&manifest)?;
    let manifest_sha256 = sha256(&manifest_bytes);
    generated.insert(MANIFEST_PATH.to_owned(), manifest_bytes);
    let ledger = ledger_bytes(
        &manifest_sha256,
        &aggregate_corpus_sha256,
        &contract_merkle_root,
    )?;
    let genesis_ledger_sha256 = sha256(&ledger);
    generated.insert(LEDGER_PATH.to_owned(), ledger);
    let fixture_files = scanner_files
        .iter()
        .map(|(path, bytes)| (path.clone(), sha256(bytes)))
        .collect::<BTreeMap<_, _>>();
    let commitments = CommitmentIndex {
        schema_version: "secure-bench-phase13-commitments-v1".to_owned(),
        holdout_id: HOLDOUT_ID.to_owned(),
        manifest_sha256,
        expectations_sha256,
        aggregate_corpus_sha256: aggregate_corpus_sha256.clone(),
        contract_merkle_root: contract_merkle_root.clone(),
        evaluator_sha256,
        genesis_ledger_sha256: genesis_ledger_sha256.clone(),
        fixture_files,
    };
    let commitments_bytes = canonical_json(&commitments)?;
    let commitment_index_sha256 = sha256(&commitments_bytes);
    generated.insert(COMMITMENTS_PATH.to_owned(), commitments_bytes);
    let provenance = Provenance {
        schema_version: "secure-bench-phase13-provenance-v1".to_owned(),
        benchmark_version: BENCHMARK_VERSION.to_owned(),
        holdout_id: HOLDOUT_ID.to_owned(),
        base_commit: BASE_COMMIT.to_owned(),
        release_tag: "v0.2.1".to_owned(),
        historical_baseline_sha256: HISTORICAL_BASELINE_SHA256.to_owned(),
        phase12_tree_sha256: PHASE12_TREE_SHA256.to_owned(),
        phase10_result_sha256: PHASE10_RESULT_SHA256.to_owned(),
        commitment_index_sha256,
        scanner_processes_started: 0,
        secure_engine_executed: false,
        other_scanner_executed: false,
        secure_engine_source_inspected: false,
        previous_scanner_reports_used_for_authoring: false,
        ai_provider_configured: false,
        network_ai_calls: 0,
        result_or_score_created: false,
    };
    generated.insert(PROVENANCE_PATH.to_owned(), canonical_json(&provenance)?);

    let mut checksum_inputs = generated.clone();
    for relative in SCHEMA_PATHS.iter().copied().chain([
        "prospective/phase-13-holdout-v4/Cargo.toml",
        "prospective/phase-13-holdout-v4/Cargo.lock",
        "prospective/phase-13-holdout-v4/src/lib.rs",
        "prospective/phase-13-holdout-v4/src/main.rs",
        "docs/phase-13-holdout-v4.md",
    ]) {
        checksum_inputs.insert(relative.to_owned(), read(root, relative)?);
    }
    let mut checksums = Vec::new();
    for (path, bytes) in &checksum_inputs {
        checksums.extend_from_slice(format!("{}  {path}\n", sha256(bytes)).as_bytes());
    }
    generated.insert(CHECKSUMS_PATH.to_owned(), checksums);

    Ok(Bundle {
        files: generated,
        report: ValidationReport {
            benchmark_version: BENCHMARK_VERSION,
            pair_count: 56,
            case_count: 112,
            aggregate_corpus_sha256,
            contract_merkle_root,
            genesis_ledger_sha256,
        },
    })
}

fn validate_schema(root: &Path, schema_path: &str, instance: &[u8]) -> Result<(), Phase13Error> {
    let schema: Value = serde_json::from_slice(&read(root, schema_path)?)
        .map_err(|error| Phase13Error::InvalidContract(error.to_string()))?;
    let instance: Value = serde_json::from_slice(instance)
        .map_err(|error| Phase13Error::InvalidContract(error.to_string()))?;
    jsonschema::validator_for(&schema)
        .map_err(|error| Phase13Error::InvalidContract(error.to_string()))?
        .validate(&instance)
        .map_err(|error| {
            Phase13Error::InvalidContract(format!(
                "schema `{schema_path}` rejected artifact: {error}"
            ))
        })
}

fn validate_artifact_schemas(
    root: &Path,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<(), Phase13Error> {
    for (artifact, schema) in [
        (MANIFEST_PATH, SCHEMA_PATHS[0]),
        (EXPECTATIONS_PATH, SCHEMA_PATHS[1]),
        (COMMITMENTS_PATH, SCHEMA_PATHS[2]),
        (LEDGER_PATH, SCHEMA_PATHS[3]),
        (PROVENANCE_PATH, SCHEMA_PATHS[4]),
    ] {
        validate_schema(
            root,
            schema,
            files.get(artifact).ok_or_else(|| {
                Phase13Error::InvalidContract(format!("artifact `{artifact}` is absent"))
            })?,
        )?;
    }
    Ok(())
}

fn validate_balance(proof: &BalanceProof) -> Result<(), Phase13Error> {
    if proof.families.len() != 7
        || proof.families.values().any(|count| *count != 8)
        || proof.frameworks.len() != 4
        || proof.frameworks.values().any(|count| *count != 14)
        || proof.source_formats.len() != 4
        || proof.source_formats.values().any(|count| *count != 14)
        || proof.language_groups.get("javascript") != Some(&28)
        || proof.language_groups.get("typescript") != Some(&28)
        || proof.topologies.len() != 4
        || proof.topologies.values().any(|count| *count != 14)
        || proof.pairwise_cell_minimum != 3
        || proof.pairwise_cell_maximum != 4
    {
        return Err(Phase13Error::InvalidContract(
            "factor balance differs from the preregistered 56-pair design".to_owned(),
        ));
    }
    for table in [
        &proof.framework_by_source_format,
        &proof.framework_by_topology,
        &proof.source_format_by_topology,
    ] {
        if table.len() != 4
            || table
                .values()
                .any(|row| row.len() != 4 || row.values().any(|count| !matches!(*count, 3 | 4)))
        {
            return Err(Phase13Error::InvalidContract(
                "pairwise factor table is not maximally balanced".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_adversarial_coverage(pairs: &[PairContract]) -> Result<(), Phase13Error> {
    let mut covered = BTreeSet::new();
    for pair in pairs {
        if pair.adversarial_features.is_empty()
            || !pair
                .adversarial_features
                .windows(2)
                .all(|window| window[0] < window[1])
        {
            return Err(Phase13Error::InvalidContract(format!(
                "pair `{}` has an empty, duplicate, or noncanonical adversarial feature set",
                pair.pair_id
            )));
        }
        covered.extend(pair.adversarial_features.iter().cloned());
    }
    let required = REQUIRED_ADVERSARIAL_FEATURES
        .iter()
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>();
    if covered != required {
        let missing = required.difference(&covered).cloned().collect::<Vec<_>>();
        let undeclared = covered.difference(&required).cloned().collect::<Vec<_>>();
        return Err(Phase13Error::InvalidContract(format!(
            "adversarial coverage differs: missing={missing:?}, undeclared={undeclared:?}"
        )));
    }
    Ok(())
}

fn validate_committed_fixture_boundary(
    root: &Path,
    expected_bundle: &BTreeMap<String, Vec<u8>>,
) -> Result<(), Phase13Error> {
    let relative = Path::new("prospective/phase-13-holdout-v4/fixtures");
    let mut actual = BTreeMap::new();
    collect_regular_files(&root.join(relative), relative, &mut actual, false)?;
    let expected = expected_bundle
        .iter()
        .filter(|(path, _)| path.starts_with("prospective/phase-13-holdout-v4/fixtures/"))
        .map(|(path, bytes)| (path.clone(), bytes.clone()))
        .collect::<BTreeMap<_, _>>();
    if actual != expected {
        let added = actual
            .keys()
            .filter(|path| !expected.contains_key(*path))
            .count();
        let missing = expected
            .keys()
            .filter(|path| !actual.contains_key(*path))
            .count();
        let changed = actual
            .iter()
            .filter(|(path, bytes)| expected.get(*path).is_some_and(|value| value != *bytes))
            .count();
        return Err(Phase13Error::InvalidContract(format!(
            "committed fixture boundary differs: added={added}, missing={missing}, changed={changed}"
        )));
    }
    Ok(())
}

fn validate_ledger(bytes: &[u8]) -> Result<(), Phase13Error> {
    if bytes.split(|byte| *byte == b'\n').count() != 2 || !bytes.ends_with(b"\n") {
        return Err(Phase13Error::InvalidContract(
            "genesis ledger is not exactly one JSONL record".to_owned(),
        ));
    }
    let entry: LedgerEntry = serde_json::from_slice(bytes)
        .map_err(|error| Phase13Error::InvalidContract(error.to_string()))?;
    if entry.sequence != 0
        || entry.event != "holdout_frozen"
        || entry.previous_entry_hash != ZERO_HASH
    {
        return Err(Phase13Error::InvalidContract(
            "genesis ledger lifecycle differs".to_owned(),
        ));
    }
    let body = serde_json::json!({
        "schema_version": entry.schema_version,
        "sequence": entry.sequence,
        "event": entry.event,
        "holdout_id": entry.holdout_id,
        "manifest_sha256": entry.manifest_sha256,
        "aggregate_corpus_sha256": entry.aggregate_corpus_sha256,
        "contract_merkle_root": entry.contract_merkle_root,
        "previous_entry_hash": entry.previous_entry_hash,
        "timestamp_utc": entry.timestamp_utc,
    });
    if sha256(&canonical_json(&body)?) != entry.entry_hash {
        return Err(Phase13Error::InvalidContract(
            "genesis ledger entry hash differs".to_owned(),
        ));
    }
    Ok(())
}

fn validate_bundle(root: &Path, bundle: &Bundle, committed: bool) -> Result<(), Phase13Error> {
    validate_artifact_schemas(root, &bundle.files)?;
    let manifest: Manifest = serde_json::from_slice(
        bundle
            .files
            .get(MANIFEST_PATH)
            .ok_or_else(|| Phase13Error::InvalidContract("manifest absent".to_owned()))?,
    )
    .map_err(|error| Phase13Error::InvalidContract(error.to_string()))?;
    let expectations: ExpectationsDocument = serde_json::from_slice(
        bundle
            .files
            .get(EXPECTATIONS_PATH)
            .ok_or_else(|| Phase13Error::InvalidContract("expectations absent".to_owned()))?,
    )
    .map_err(|error| Phase13Error::InvalidContract(error.to_string()))?;
    let commitments: CommitmentIndex = serde_json::from_slice(
        bundle
            .files
            .get(COMMITMENTS_PATH)
            .ok_or_else(|| Phase13Error::InvalidContract("commitments absent".to_owned()))?,
    )
    .map_err(|error| Phase13Error::InvalidContract(error.to_string()))?;
    let provenance: Provenance = serde_json::from_slice(
        bundle
            .files
            .get(PROVENANCE_PATH)
            .ok_or_else(|| Phase13Error::InvalidContract("provenance absent".to_owned()))?,
    )
    .map_err(|error| Phase13Error::InvalidContract(error.to_string()))?;
    validate_balance(&manifest.balance)?;
    validate_adversarial_coverage(&manifest.pairs)?;
    if manifest.pairs.len() != 56
        || expectations.records.len() != 112
        || expectations
            .records
            .iter()
            .filter(|record| matches!(record.kind, CaseKind::Vulnerable))
            .count()
            != 56
        || expectations
            .records
            .iter()
            .filter(|record| matches!(record.kind, CaseKind::SafeControl))
            .count()
            != 56
        || manifest.aggregate_corpus_sha256 != commitments.aggregate_corpus_sha256
        || manifest.contract_merkle_root != commitments.contract_merkle_root
        || manifest.expectation_sha256 != commitments.expectations_sha256
        || sha256(
            bundle
                .files
                .get(MANIFEST_PATH)
                .ok_or_else(|| Phase13Error::InvalidContract("manifest absent".to_owned()))?,
        ) != commitments.manifest_sha256
        || sha256(
            bundle
                .files
                .get(LEDGER_PATH)
                .ok_or_else(|| Phase13Error::InvalidContract("ledger absent".to_owned()))?,
        ) != commitments.genesis_ledger_sha256
        || sha256(
            bundle
                .files
                .get(COMMITMENTS_PATH)
                .ok_or_else(|| Phase13Error::InvalidContract("commitments absent".to_owned()))?,
        ) != provenance.commitment_index_sha256
        || provenance.scanner_processes_started != 0
        || provenance.secure_engine_executed
        || provenance.other_scanner_executed
        || provenance.secure_engine_source_inspected
        || provenance.previous_scanner_reports_used_for_authoring
        || provenance.ai_provider_configured
        || provenance.network_ai_calls != 0
        || provenance.result_or_score_created
    {
        return Err(Phase13Error::InvalidContract(
            "manifest, commitment, ledger, or provenance binding differs".to_owned(),
        ));
    }
    for expectation in &expectations.records {
        validate_expectation_shape(expectation)?;
    }
    validate_ledger(
        bundle
            .files
            .get(LEDGER_PATH)
            .ok_or_else(|| Phase13Error::InvalidContract("ledger absent".to_owned()))?,
    )?;
    if committed {
        validate_committed_fixture_boundary(root, &bundle.files)?;
        for (relative, expected) in &bundle.files {
            let actual = read(root, relative)?;
            if &actual != expected {
                return Err(Phase13Error::InvalidContract(format!(
                    "committed artifact `{relative}` differs from deterministic reconstruction"
                )));
            }
        }
    }
    Ok(())
}

/// Generates and freezes the deterministic Phase 13 examination.
///
/// This function writes only the prospective Phase 13 namespace and never starts a process.
///
/// # Errors
///
/// Returns an error for historical drift, an invalid contract, unsafe paths, or I/O failure.
pub fn generate_repository(root: &Path) -> Result<ValidationReport, Phase13Error> {
    let bundle = build_bundle(root)?;
    validate_bundle(root, &bundle, false)?;
    for (relative, bytes) in &bundle.files {
        let path = root.join(safe_relative(relative)?);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| io(parent, &error))?;
        }
        fs::write(&path, bytes).map_err(|error| io(&path, &error))?;
    }
    Ok(bundle.report)
}

/// Validates the committed Phase 13 examination by deterministic reconstruction.
///
/// # Errors
///
/// Returns an error for historical, schema, taxonomy, fixture, balance, privacy, provenance,
/// mutation, overlap, commitment, ledger, or byte-reconstruction drift.
pub fn validate_repository(root: &Path) -> Result<ValidationReport, Phase13Error> {
    let bundle = build_bundle(root)?;
    validate_bundle(root, &bundle, true)?;
    Ok(bundle.report)
}

/// Returns an answer-free aggregate summary after complete validation.
///
/// # Errors
///
/// Returns an error if repository validation fails.
pub fn summarize(root: &Path) -> Result<String, Phase13Error> {
    let report = validate_repository(root)?;
    Ok(format!(
        "benchmark_version={} holdout=v4 pairs={} cases={} intentionally_unexecuted=112 scanner_scoring_scope=0 scanner_processes_started=0 aggregate_corpus_sha256={} contract_merkle_root={}",
        report.benchmark_version,
        report.pair_count,
        report.case_count,
        report.aggregate_corpus_sha256,
        report.contract_merkle_root
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .map(Path::to_path_buf)
            .unwrap_or_default()
    }

    #[test]
    fn schedule_is_maximally_balanced() -> Result<(), Phase13Error> {
        let proof = balance_proof(&assignments())?;
        validate_balance(&proof)
    }

    #[test]
    fn malformed_expectations_and_legacy_override_fail_closed() -> Result<(), Phase13Error> {
        let repository = root();
        let bundle = build_bundle(&repository)?;
        let bytes = bundle
            .files
            .get(EXPECTATIONS_PATH)
            .ok_or_else(|| Phase13Error::InvalidContract("expectations absent".to_owned()))?;
        let mut document: ExpectationsDocument = serde_json::from_slice(bytes)
            .map_err(|error| Phase13Error::InvalidContract(error.to_string()))?;
        document.records[0].legacy_override_permitted = true;
        assert!(validate_expectation_shape(&document.records[0]).is_err());
        document.records[0].legacy_override_permitted = false;
        document.records[0].connected_edges.clear();
        assert!(validate_expectation_shape(&document.records[0]).is_err());
        Ok(())
    }

    #[test]
    fn weak_and_nondominating_barriers_fail_closed() -> Result<(), Phase13Error> {
        let repository = root();
        let bundle = build_bundle(&repository)?;
        let bytes = bundle
            .files
            .get(EXPECTATIONS_PATH)
            .ok_or_else(|| Phase13Error::InvalidContract("expectations absent".to_owned()))?;
        let document: ExpectationsDocument = serde_json::from_slice(bytes)
            .map_err(|error| Phase13Error::InvalidContract(error.to_string()))?;
        let control = document
            .records
            .iter()
            .find(|record| matches!(record.kind, CaseKind::SafeControl))
            .cloned()
            .ok_or_else(|| Phase13Error::InvalidContract("control absent".to_owned()))?;

        let mut nonterminating = control.clone();
        nonterminating.effective_barriers[0].terminating = false;
        assert!(validate_expectation_shape(&nonterminating).is_err());

        let mut nondominating = control.clone();
        nondominating.effective_barriers[0].dominates_sink = false;
        assert!(validate_expectation_shape(&nondominating).is_err());

        let mut wrong_value = control;
        wrong_value.effective_barriers[0].value_id = "unrelated-value".to_owned();
        assert!(validate_expectation_shape(&wrong_value).is_err());
        Ok(())
    }

    #[test]
    fn balance_and_adversarial_coverage_mutations_fail_closed() -> Result<(), Phase13Error> {
        let mut proof = balance_proof(&assignments())?;
        proof.frameworks.insert("node_js".to_owned(), 13);
        assert!(validate_balance(&proof).is_err());

        let repository = root();
        let bundle = build_bundle(&repository)?;
        let bytes = bundle
            .files
            .get(MANIFEST_PATH)
            .ok_or_else(|| Phase13Error::InvalidContract("manifest absent".to_owned()))?;
        let mut manifest: Manifest = serde_json::from_slice(bytes)
            .map_err(|error| Phase13Error::InvalidContract(error.to_string()))?;
        manifest.pairs[0].adversarial_features.clear();
        assert!(validate_adversarial_coverage(&manifest.pairs).is_err());
        Ok(())
    }

    #[test]
    fn ledger_rewriting_and_malformed_records_fail_closed() -> Result<(), Phase13Error> {
        let repository = root();
        let bundle = build_bundle(&repository)?;
        let ledger = bundle
            .files
            .get(LEDGER_PATH)
            .ok_or_else(|| Phase13Error::InvalidContract("ledger absent".to_owned()))?;
        let mut rewritten: LedgerEntry = serde_json::from_slice(ledger)
            .map_err(|error| Phase13Error::InvalidContract(error.to_string()))?;
        rewritten.sequence = 1;
        assert!(validate_ledger(&canonical_json(&rewritten)?).is_err());
        assert!(validate_ledger(b"{malformed}\n").is_err());
        Ok(())
    }

    #[test]
    fn deterministic_reconstruction_is_byte_identical() -> Result<(), Phase13Error> {
        let repository = root();
        let first = build_bundle(&repository)?;
        let second = build_bundle(&repository)?;
        assert_eq!(first.files, second.files);
        assert_eq!(first.report, second.report);
        Ok(())
    }

    #[test]
    fn mutation_metamorphic_privacy_and_overlap_checks_pass() -> Result<(), Phase13Error> {
        let repository = root();
        let bundle = build_bundle(&repository)?;
        validate_bundle(&repository, &bundle, false)
    }

    #[test]
    fn path_traversal_is_rejected() {
        assert!(safe_relative("../answers.json").is_err());
        assert!(safe_relative("/absolute/report.json").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_substitution_is_rejected() -> Result<(), Phase13Error> {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().map_err(|error| io(Path::new("tempdir"), &error))?;
        let regular = directory.path().join("regular.js");
        fs::write(&regular, b"export {};\n").map_err(|error| io(&regular, &error))?;
        let link = directory.path().join("alias.js");
        symlink(&regular, &link).map_err(|error| io(&link, &error))?;
        let mut files = BTreeMap::new();
        assert!(
            collect_regular_files(directory.path(), Path::new("fixtures"), &mut files, false)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn committed_holdout_validates_when_present() -> Result<(), Phase13Error> {
        let repository = root();
        if repository.join(MANIFEST_PATH).exists() {
            let report = validate_repository(&repository)?;
            assert_eq!(report.pair_count, 56);
            assert_eq!(report.case_count, 112);
        }
        Ok(())
    }

    #[test]
    fn crate_has_no_process_or_network_launch_api() {
        let source = include_str!("lib.rs");
        assert!(!source.contains(&["std::", "process"].concat()));
        assert!(!source.contains(&["Command", "::new"].concat()));
        assert!(!source.contains(&["Tcp", "Stream"].concat()));
    }
}
