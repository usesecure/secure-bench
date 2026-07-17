//! Deterministic, scanner-free authoring and validation of Secure Bench Phase 9.
//!
//! Phase 9 defines a future examination. This crate writes or reads committed synthetic fixture
//! text and JSON contracts only; it has no process-launching, network, or scanner integration API.

#![allow(clippy::struct_field_names, clippy::too_many_lines)]

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

/// Phase 9 operation failure.
#[derive(Debug, Error)]
pub enum Phase9Error {
    /// Invalid command-line or API request.
    #[error("invalid Phase 9 request: {0}")]
    InvalidRequest(String),
    /// A frozen contract, fixture, or invariant failed validation.
    #[error("invalid Phase 9 contract: {0}")]
    InvalidContract(String),
    /// A filesystem operation failed.
    #[error("Phase 9 filesystem operation failed for `{path}`: {detail}")]
    Io {
        /// Portable path context.
        path: String,
        /// Operating-system error detail.
        detail: String,
    },
    /// JSON serialization failed.
    #[error("Phase 9 JSON serialization failed: {0}")]
    Serialization(String),
}

/// Public aggregate validation report. It intentionally contains no case-level answers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidationReport {
    /// Vulnerable/control pairs.
    pub pairs: u64,
    /// Total isolated cases.
    pub cases: u64,
    /// Vulnerable cases.
    pub vulnerable: u64,
    /// Safe controls.
    pub controls: u64,
    /// JavaScript cases.
    pub java_script: u64,
    /// TypeScript cases.
    pub type_script: u64,
    /// Node.js cases.
    pub node_js: u64,
    /// Express cases.
    pub express: u64,
    /// Next.js App Router cases.
    pub next_app_router: u64,
    /// Server Actions cases.
    pub server_actions: u64,
    /// Direct-topology cases.
    pub direct: u64,
    /// Helper-mediated cases.
    pub helper_mediated: u64,
    /// Inter-file aliased cases.
    pub inter_file_aliased: u64,
    /// Control-flow-sensitive cases.
    pub control_flow_sensitive: u64,
    /// Aggregate corpus commitment.
    pub aggregate_corpus_sha256: String,
    /// Contract Merkle root.
    pub contract_merkle_root: String,
    /// Canonical manifest hash.
    pub manifest_sha256: String,
    /// Genesis ledger hash.
    pub ledger_genesis_sha256: String,
}

const HOLDOUT_ID: &str = "phase-9-orthogonal-holdout-v3";
const HOLDOUT_ROOT: &str = "holdout/phase-9";
const MANIFEST_PATH: &str = "holdout/phase-9/manifest.json";
const COMMITMENTS_PATH: &str = "holdout/phase-9/commitments.json";
const LEDGER_PATH: &str = "holdout/phase-9/execution-ledger.jsonl";
const TAXONOMY_PATH: &str = "taxonomy/secure-bench-taxonomy-v1.json";
const EVIDENCE_CONTRACT_PATH: &str = "holdout/phase-5/evidence-contract-v2.json";
const BASE_COMMIT: &str = "b4f562b14eb1446a94285a6d88bcf8d35cd3637b";
const FROZEN_AT: &str = "2026-07-17T12:00:00Z";
const EXPECTED_PAIRS: usize = 112;
const EXPECTED_CASES: usize = 224;
const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

const MANIFEST_SCHEMA_PATH: &str = "schemas/phase9-holdout-v3.schema.json";
const COMMITMENTS_SCHEMA_PATH: &str = "schemas/phase9-commitments-v1.schema.json";
const LEDGER_SCHEMA_PATH: &str = "schemas/phase9-ledger-entry-v1.schema.json";

const CATEGORIES: [Category; 7] = [
    Category {
        se_id: "SE1001",
        category_id: "secure-bench.category.authorization-dominance",
        invariant_id: "secure-bench.invariant.authorization-before-sensitive-operation",
        cwe: "CWE-862",
        source_kind: "protected_resource_id",
        sink_kind: "protected_record_mutation",
        property: "A principal, operation, and resource authorization decision dominates the protected mutation and denial terminates.",
    },
    Category {
        se_id: "SE1002",
        category_id: "secure-bench.category.command-execution",
        invariant_id: "secure-bench.invariant.untrusted-data-cannot-select-command-program-or-arguments",
        cwe: "CWE-78",
        source_kind: "http_body_field",
        sink_kind: "os_command_execution",
        property: "Untrusted data cannot select an operating-system command, executable, or argument vector.",
    },
    Category {
        se_id: "SE1003",
        category_id: "secure-bench.category.dynamic-code-execution",
        invariant_id: "secure-bench.invariant.untrusted-data-cannot-become-executable-code",
        cwe: "CWE-95",
        source_kind: "http_body_field",
        sink_kind: "dynamic_code_evaluation",
        property: "Untrusted data cannot become executable program text.",
    },
    Category {
        se_id: "SE1004",
        category_id: "secure-bench.category.filesystem-boundary",
        invariant_id: "secure-bench.invariant.filesystem-access-remains-under-approved-root",
        cwe: "CWE-22",
        source_kind: "http_body_field",
        sink_kind: "filesystem_read",
        property: "Filesystem reads remain under the approved root after canonical resolution.",
    },
    Category {
        se_id: "SE1005",
        category_id: "secure-bench.category.outbound-request-boundary",
        invariant_id: "secure-bench.invariant.outbound-destination-is-policy-approved",
        cwe: "CWE-918",
        source_kind: "http_body_field",
        sink_kind: "outbound_request",
        property: "The final outbound protocol and origin are approved before the request is issued.",
    },
    Category {
        se_id: "SE1006",
        category_id: "secure-bench.category.redirect-boundary",
        invariant_id: "secure-bench.invariant.redirect-destination-is-local-or-approved",
        cwe: "CWE-601",
        source_kind: "http_body_field",
        sink_kind: "redirect_response",
        property: "Redirect destinations are local paths or explicitly approved origins.",
    },
    Category {
        se_id: "SE1007",
        category_id: "secure-bench.category.sql-construction",
        invariant_id: "secure-bench.invariant.untrusted-data-is-bound-not-concatenated-into-sql",
        cwe: "CWE-89",
        source_kind: "http_body_field",
        sink_kind: "sql_query_execution",
        property: "Untrusted data is bound as a query parameter and never changes SQL structure.",
    },
];

const FRAMEWORKS: [&str; 4] = ["node_js", "express", "next_app_router", "server_actions"];
const LANGUAGES: [&str; 2] = ["java_script", "type_script"];
const TOPOLOGIES: [&str; 4] = [
    "direct",
    "helper_mediated",
    "inter_file_aliased",
    "control_flow_sensitive",
];

#[derive(Clone, Copy)]
struct Category {
    se_id: &'static str,
    category_id: &'static str,
    invariant_id: &'static str,
    cwe: &'static str,
    source_kind: &'static str,
    sink_kind: &'static str,
    property: &'static str,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Assignment {
    ordinal: u64,
    framework: String,
    language: String,
    topology: String,
    category_id: String,
    family_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Span {
    file: String,
    start_line: u64,
    start_column: u64,
    end_line: u64,
    end_column: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PathNode {
    role: String,
    effect: String,
    source_kind: Option<String>,
    sink_kind: Option<String>,
    span: Span,
    summarizable: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Expectation {
    expectation_id: String,
    taxonomy_version: String,
    category_id: String,
    invariant_id: String,
    primary_cwe: String,
    path: Vec<PathNode>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CaseKind {
    Vulnerable,
    SafeControl,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Provenance {
    origin: String,
    license: String,
    revision: String,
    modifications: String,
    authors: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CaseContract {
    case_id: String,
    fixture_path: String,
    fixture_sha256: String,
    contract_sha256: String,
    kind: CaseKind,
    expectation: Option<Expectation>,
    security_property: Option<String>,
    provenance: Provenance,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LineRange {
    start: u64,
    end: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct MutationContract {
    file: String,
    first_fragment_sha256: String,
    second_fragment_sha256: String,
    first_lines: LineRange,
    second_lines: LineRange,
    structural_property: String,
    inverse_required: bool,
    identifier_literal_only_forbidden: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PairContract {
    pair_id: String,
    assignment: Assignment,
    invariant_id: String,
    primary_cwe: String,
    source_kind: String,
    sink_kind: String,
    mutation: MutationContract,
    first: CaseContract,
    second: CaseContract,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct EvidenceBinding {
    path: String,
    schema_version: String,
    contract_version: String,
    sha256: String,
    decision: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TaxonomyBinding {
    path: String,
    schema_version: String,
    taxonomy_version: String,
    sha256: String,
    content_hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DesignCommitments {
    aggregate_corpus_sha256: String,
    contract_merkle_root: String,
    schedule_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct BalanceDesign {
    pairs: u64,
    cases: u64,
    vulnerable: u64,
    safe_controls: u64,
    category_pairs_each: u64,
    framework_pairs_each: u64,
    language_pairs_each: u64,
    topology_pairs_each: u64,
    category_framework_pairs_each: u64,
    category_language_pairs_each: u64,
    category_topology_pairs_each: u64,
    framework_language_pairs_each: u64,
    framework_topology_pairs_each: u64,
    language_topology_pairs_each: u64,
    first_slot_vulnerable: u64,
    first_slot_safe: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Design {
    schedule_id: String,
    schedule_sha256: String,
    balance: BalanceDesign,
    deconfounding: Vec<String>,
    mutation_checks: Vec<String>,
    orthogonality_checks: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Protocol {
    evaluation_state: String,
    one_shot_future_evaluation: bool,
    network: String,
    ai_validation: String,
    scanner_projection: String,
    expected_data_visibility: String,
    ledger_path: String,
    result_path_template: String,
    result_write_mode: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: String,
    holdout_id: String,
    title: String,
    description: String,
    methodology_version: String,
    git_base: String,
    branch: String,
    frozen_at_utc: String,
    neutrality: String,
    taxonomy: TaxonomyBinding,
    evidence_contract: EvidenceBinding,
    protocol: Protocol,
    design: Design,
    historical_integrity: BTreeMap<String, String>,
    commitments: DesignCommitments,
    pairs: Vec<PairContract>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CommitmentIndex {
    schema_version: String,
    holdout_id: String,
    manifest_sha256: String,
    evidence_contract_sha256: String,
    taxonomy_sha256: String,
    aggregate_corpus_sha256: String,
    contract_merkle_root: String,
    schedule_sha256: String,
    genesis_ledger_sha256: String,
    pair_count: u64,
    case_count: u64,
    authoring_source_sha256: String,
    schema_files: BTreeMap<String, String>,
    historical_integrity: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LedgerEntry {
    schema_version: String,
    sequence: u64,
    event: String,
    holdout_id: String,
    manifest_sha256: String,
    evidence_contract_sha256: String,
    taxonomy_sha256: String,
    aggregate_corpus_sha256: String,
    commitment_root: String,
    previous_entry_hash: String,
    timestamp_utc: String,
    entry_hash: String,
}

#[derive(Clone)]
struct RenderedCase {
    files: BTreeMap<String, Vec<u8>>,
    source_file: String,
    source_needle: String,
    intermediate: Option<(String, String)>,
    sink_file: String,
    sink_needle: String,
    mutation_file: String,
    mutation_fragment: String,
}

struct Bundle {
    files: BTreeMap<String, Vec<u8>>,
    report: ValidationReport,
}

type PairBuild = (Vec<PairContract>, BTreeMap<String, Vec<u8>>);

fn fingerprint(bytes: &[u8]) -> String {
    hex_digest(&Sha256::digest(bytes))
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, Phase9Error> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| Phase9Error::Serialization(error.to_string()))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn io_error(path: &Path, error: &std::io::Error) -> Phase9Error {
    Phase9Error::Io {
        path: path.display().to_string(),
        detail: error.to_string(),
    }
}

fn safe_join(root: &Path, relative: &str) -> Result<PathBuf, Phase9Error> {
    let path = Path::new(relative);
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(Phase9Error::InvalidContract(format!(
            "unsafe relative path `{relative}`"
        )));
    }
    Ok(root.join(path))
}

fn read(root: &Path, relative: &str) -> Result<Vec<u8>, Phase9Error> {
    let path = safe_join(root, relative)?;
    let metadata = fs::symlink_metadata(&path).map_err(|error| io_error(&path, &error))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(Phase9Error::InvalidContract(format!(
            "expected regular file `{relative}`"
        )));
    }
    fs::read(&path).map_err(|error| io_error(&path, &error))
}

fn schedule() -> Vec<Assignment> {
    let mut assignments = Vec::with_capacity(EXPECTED_PAIRS);
    let mut ordinal = 1_u64;
    for (category_index, category) in CATEGORIES.iter().enumerate() {
        for (framework_index, framework) in FRAMEWORKS.iter().enumerate() {
            for (language_index, language) in LANGUAGES.iter().enumerate() {
                for replicate in 0..2 {
                    let topology_index =
                        (category_index + framework_index + language_index + 2 * replicate) % 4;
                    assignments.push(Assignment {
                        ordinal,
                        framework: (*framework).to_owned(),
                        language: (*language).to_owned(),
                        topology: TOPOLOGIES[topology_index].to_owned(),
                        category_id: category.category_id.to_owned(),
                        family_id: category.se_id.to_owned(),
                    });
                    ordinal += 1;
                }
            }
        }
    }
    assignments
}

fn category_for(assignment: &Assignment) -> Result<Category, Phase9Error> {
    CATEGORIES
        .iter()
        .copied()
        .find(|category| category.category_id == assignment.category_id)
        .ok_or_else(|| Phase9Error::InvalidContract("unknown category assignment".to_owned()))
}

fn first_is_vulnerable(assignment: &Assignment) -> Result<bool, Phase9Error> {
    let category = CATEGORIES
        .iter()
        .position(|category| category.category_id == assignment.category_id)
        .ok_or_else(|| Phase9Error::InvalidContract("unknown category assignment".to_owned()))?;
    let framework = FRAMEWORKS
        .iter()
        .position(|value| *value == assignment.framework)
        .ok_or_else(|| Phase9Error::InvalidContract("unknown framework assignment".to_owned()))?;
    let language = LANGUAGES
        .iter()
        .position(|value| *value == assignment.language)
        .ok_or_else(|| Phase9Error::InvalidContract("unknown language assignment".to_owned()))?;
    let replicate = usize::from(assignment.ordinal.is_multiple_of(2));
    Ok((category + framework + language + replicate).is_multiple_of(2))
}

fn package_json(case_number: u64, framework: &str) -> Result<Vec<u8>, Phase9Error> {
    let pair_number = case_number.div_ceil(2);
    let dependencies = match framework {
        "express" => serde_json::json!({"express": "5.1.0"}),
        "next_app_router" | "server_actions" => {
            serde_json::json!({"next": "15.4.0", "react": "19.1.0"})
        }
        _ => serde_json::json!({}),
    };
    canonical_json(&serde_json::json!({
        "name": format!("phase9-fixture-{pair_number:03}"),
        "version": "1.0.0",
        "private": true,
        "type": "module",
        "engines": {"node": ">=22"},
        "dependencies": dependencies
    }))
}

fn source_path(framework: &str, language: &str) -> String {
    let extension = if language == "type_script" {
        "ts"
    } else {
        "js"
    };
    match framework {
        "next_app_router" => format!("app/api/dispatch/route.{extension}"),
        "server_actions" => format!("app/actions.{extension}"),
        _ => format!("src/dispatch.{extension}"),
    }
}

fn boundary_path(framework: &str, language: &str) -> String {
    let extension = if language == "type_script" {
        "ts"
    } else {
        "js"
    };
    if matches!(framework, "next_app_router" | "server_actions") {
        format!("app/boundary.{extension}")
    } else {
        format!("src/boundary.{extension}")
    }
}

fn relative_boundary_import() -> &'static str {
    "./boundary"
}

fn handler_parts(assignment: &Assignment) -> (String, String, String) {
    let typed = assignment.language == "type_script";
    match assignment.framework.as_str() {
        "node_js" => {
            let signature = if typed {
                "export async function dispatch(packet: { body: { value: unknown } }, runtime: any) {"
            } else {
                "export async function dispatch(packet, runtime) {"
            };
            (
                String::new(),
                signature.to_owned(),
                "  const candidate = packet.body.value;".to_owned(),
            )
        }
        "express" => {
            let signature = if typed {
                "export async function dispatch(request: any, response: any, runtime: any) {"
            } else {
                "export async function dispatch(request, response, runtime) {"
            };
            (
                String::new(),
                signature.to_owned(),
                "  runtime.response = response;\n  const candidate = request.body.value;"
                    .to_owned(),
            )
        }
        "next_app_router" => {
            let signature = if typed {
                "export async function POST(request: Request) {"
            } else {
                "export async function POST(request) {"
            };
            let source = if typed {
                "  const runtime: any = (globalThis as any).__phase9Runtime;\n  const payload = await request.json();\n  const candidate = payload.value;"
            } else {
                "  const runtime = globalThis.__phase9Runtime;\n  const payload = await request.json();\n  const candidate = payload.value;"
            };
            (String::new(), signature.to_owned(), source.to_owned())
        }
        "server_actions" => {
            let signature = if typed {
                "export async function submit(formData: FormData) {"
            } else {
                "export async function submit(formData) {"
            };
            let source = if typed {
                "  const runtime: any = (globalThis as any).__phase9Runtime;\n  const candidate = formData.get(\"value\");"
            } else {
                "  const runtime = globalThis.__phase9Runtime;\n  const candidate = formData.get(\"value\");"
            };
            (
                "\"use server\";\n\n".to_owned(),
                signature.to_owned(),
                source.to_owned(),
            )
        }
        _ => (String::new(), String::new(), String::new()),
    }
}

fn indent_block(block: &str, spaces: usize) -> String {
    let prefix = " ".repeat(spaces);
    block
        .lines()
        .map(|line| format!("{prefix}{line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn family_fragments(category: Category, framework: &str, value: &str) -> (String, String, String) {
    match category.se_id {
        "SE1001" => (
            format!(
                "await runtime.records.update({value}, {{ state: \"approved\" }});\nreturn {{ updated: true }};"
            ),
            format!(
                "const permitted = await runtime.policy.mayChange(runtime.actor, {value}, \"approve\");\nif (!permitted) {{\n  throw new Error(\"operation denied\");\n}}\nawait runtime.records.update({value}, {{ state: \"approved\" }});\nreturn {{ updated: true }};"
            ),
            "records.update".to_owned(),
        ),
        "SE1002" => (
            format!(
                "const {{ exec }} = await import(\"node:child_process\");\nexec(String({value}), {{ timeout: 1200 }}, () => {{}});\nreturn {{ queued: true }};"
            ),
            format!(
                "const tasks = new Map([[\"refresh\", [\"/usr/bin/printf\", [\"refresh\"]]], [\"status\", [\"/usr/bin/printf\", [\"status\"]]]]);\nconst selected = tasks.get(String({value}));\nif (!selected) {{\n  throw new Error(\"task denied\");\n}}\nconst {{ execFile }} = await import(\"node:child_process\");\nexecFile(selected[0], selected[1], {{ timeout: 1200 }}, () => {{}});\nreturn {{ queued: true }};"
            ),
            "exec(String".to_owned(),
        ),
        "SE1003" => (
            format!(
                "const operation = new Function(\"context\", String({value}));\nreturn operation(runtime.context);"
            ),
            format!(
                "const operations = new Map([[\"total\", (context) => context.total], [\"count\", (context) => context.count]]);\nconst operation = operations.get(String({value}));\nif (!operation) {{\n  throw new Error(\"operation denied\");\n}}\nreturn operation(runtime.context);"
            ),
            "new Function".to_owned(),
        ),
        "SE1004" => (
            format!(
                "const {{ readFile }} = await import(\"node:fs/promises\");\nreturn readFile(String({value}), \"utf8\");"
            ),
            format!(
                "const {{ resolve, sep }} = await import(\"node:path\");\nconst root = resolve(runtime.storageRoot);\nconst selected = resolve(root, String({value}));\nif (selected !== root && !selected.startsWith(`${{root}}${{sep}}`)) {{\n  throw new Error(\"path denied\");\n}}\nconst {{ readFile }} = await import(\"node:fs/promises\");\nreturn readFile(selected, \"utf8\");"
            ),
            "readFile(".to_owned(),
        ),
        "SE1005" => (
            format!(
                "const response = await fetch(String({value}), {{ signal: AbortSignal.timeout(1200) }});\nreturn {{ status: response.status }};"
            ),
            format!(
                "const selected = new URL(String({value}));\nif (selected.protocol !== \"https:\" || selected.origin !== runtime.approvedOrigin) {{\n  throw new Error(\"destination denied\");\n}}\nconst response = await fetch(selected, {{ signal: AbortSignal.timeout(1200), redirect: \"error\" }});\nreturn {{ status: response.status }};"
            ),
            "fetch(".to_owned(),
        ),
        "SE1006" => {
            let redirect = match framework {
                "express" => format!("return runtime.response.redirect(String({value}));"),
                "next_app_router" | "server_actions" => format!(
                    "const {{ redirect }} = await import(\"next/navigation\");\nreturn redirect(String({value}));"
                ),
                _ => format!("return runtime.respondRedirect(String({value}));"),
            };
            let safe_redirect = match framework {
                "express" => "return runtime.response.redirect(selected);",
                "next_app_router" | "server_actions" => {
                    "const { redirect } = await import(\"next/navigation\");\nreturn redirect(selected);"
                }
                _ => "return runtime.respondRedirect(selected);",
            };
            let needle = match framework {
                "express" => "response.redirect",
                "next_app_router" | "server_actions" => "redirect(String",
                _ => "respondRedirect",
            };
            (
                redirect,
                format!(
                    "const selected = String({value});\nif (!selected.startsWith(\"/\") || selected.startsWith(\"//\") || selected.includes(\"\\\\\")) {{\n  throw new Error(\"redirect denied\");\n}}\n{safe_redirect}"
                ),
                needle.to_owned(),
            )
        }
        "SE1007" => (
            format!(
                "return runtime.database.query(`SELECT id, label FROM catalog WHERE label = '${{{value}}}'`);"
            ),
            format!(
                "return runtime.database.query(\"SELECT id, label FROM catalog WHERE label = ?\", [String({value})]);"
            ),
            "database.query".to_owned(),
        ),
        _ => (String::new(), String::new(), String::new()),
    }
}

fn framework_boundary_prelude(framework: &str) -> &'static str {
    match framework {
        "node_js" => {
            "  const channel = runtime.channel ?? \"primary\";\n  if (channel.length === 0) {\n    throw new Error(\"channel required\");\n  }"
        }
        "express" => {
            "  if (!runtime.response || runtime.response.headersSent) {\n    throw new Error(\"response unavailable\");\n  }"
        }
        "next_app_router" => {
            "  const phase = await runtime.currentPhase();\n  if (phase === \"closed\") {\n    throw new Error(\"phase closed\");\n  }"
        }
        "server_actions" => {
            "  for (const flag of runtime.flags ?? []) {\n    if (flag === \"closed\") {\n      throw new Error(\"invocation closed\");\n    }\n  }"
        }
        _ => "",
    }
}

fn render_case(
    assignment: &Assignment,
    category: Category,
    vulnerable: bool,
    case_number: u64,
) -> Result<RenderedCase, Phase9Error> {
    let entry_path = source_path(&assignment.framework, &assignment.language);
    let boundary_path = boundary_path(&assignment.framework, &assignment.language);
    let (prefix, signature, source_lines) = handler_parts(assignment);
    if signature.is_empty() {
        return Err(Phase9Error::InvalidContract(
            "unsupported framework in renderer".to_owned(),
        ));
    }
    let (unsafe_fragment, safe_fragment, sink_needle) =
        family_fragments(category, &assignment.framework, "value");
    let selected_fragment = if vulnerable {
        unsafe_fragment
    } else {
        safe_fragment
    };
    let mut files = BTreeMap::new();
    files.insert(
        "package.json".to_owned(),
        package_json(case_number, &assignment.framework)?,
    );

    let (entry, boundary, source_needle, intermediate, sink_file, mutation_file) = match assignment
        .topology
        .as_str()
    {
        "direct" => {
            let fragment = indent_block(&selected_fragment, 2);
            let content = format!("{prefix}{signature}\n{source_lines}\n{fragment}\n}}\n");
            (
                content,
                None,
                source_lines
                    .lines()
                    .last()
                    .unwrap_or_default()
                    .trim()
                    .to_owned(),
                None,
                entry_path.clone(),
                entry_path.clone(),
            )
        }
        "helper_mediated" => {
            let typed = if assignment.language == "type_script" {
                ": unknown, runtime: any"
            } else {
                ", runtime"
            };
            let helper_signature = if assignment.language == "type_script" {
                format!("async function applyBoundary(value{typed}) {{")
            } else {
                "async function applyBoundary(value, runtime) {".to_owned()
            };
            let fragment = indent_block(&selected_fragment, 2);
            let content = format!(
                "{prefix}{signature}\n{source_lines}\n  return applyBoundary(candidate, runtime);\n}}\n\n{helper_signature}\n{fragment}\n}}\n"
            );
            (
                content,
                None,
                source_lines
                    .lines()
                    .last()
                    .unwrap_or_default()
                    .trim()
                    .to_owned(),
                Some((entry_path.clone(), "applyBoundary(candidate".to_owned())),
                entry_path.clone(),
                entry_path.clone(),
            )
        }
        "inter_file_aliased" => {
            let import = format!(
                "import {{ applyBoundary as traverseBoundary }} from \"{}\";\n\n",
                relative_boundary_import()
            );
            let content = format!(
                "{prefix}{import}{signature}\n{source_lines}\n  return traverseBoundary(candidate, runtime);\n}}\n"
            );
            let helper_signature = if assignment.language == "type_script" {
                "export async function applyBoundary(value: unknown, runtime: any) {"
            } else {
                "export async function applyBoundary(value, runtime) {"
            };
            let fragment = indent_block(&selected_fragment, 2);
            let prelude = framework_boundary_prelude(&assignment.framework);
            let bridge = format!("{helper_signature}\n{prelude}\n{fragment}\n}}\n");
            (
                content,
                Some(bridge),
                source_lines
                    .lines()
                    .last()
                    .unwrap_or_default()
                    .trim()
                    .to_owned(),
                Some((entry_path.clone(), "traverseBoundary(candidate".to_owned())),
                boundary_path.clone(),
                boundary_path.clone(),
            )
        }
        "control_flow_sensitive" => {
            let (unsafe_selected, safe_selected, _) =
                family_fragments(category, &assignment.framework, "selected");
            let selected_fragment = if vulnerable {
                unsafe_selected
            } else {
                safe_selected
            };
            let fragment = indent_block(&selected_fragment, 2);
            let content = format!(
                "{prefix}{signature}\n{source_lines}\n  let selected = candidate;\n  if (runtime.channel === \"secondary\") {{\n    selected = String(candidate);\n  }} else if (runtime.channel === \"primary\") {{\n    selected = candidate;\n  }}\n  if (selected === undefined || selected === null) {{\n    throw new Error(\"value required\");\n  }}\n{fragment}\n}}\n"
            );
            (
                content,
                None,
                source_lines
                    .lines()
                    .last()
                    .unwrap_or_default()
                    .trim()
                    .to_owned(),
                Some((
                    entry_path.clone(),
                    "selected = String(candidate)".to_owned(),
                )),
                entry_path.clone(),
                entry_path.clone(),
            )
        }
        _ => {
            return Err(Phase9Error::InvalidContract(
                "unsupported topology in renderer".to_owned(),
            ));
        }
    };

    files.insert(entry_path.clone(), entry.as_bytes().to_vec());
    if let Some(boundary) = boundary {
        files.insert(boundary_path, boundary.as_bytes().to_vec());
    }
    let mutation_content = files
        .get(&mutation_file)
        .ok_or_else(|| Phase9Error::InvalidContract("mutation file missing".to_owned()))?;
    let mutation_text = std::str::from_utf8(mutation_content)
        .map_err(|_| Phase9Error::InvalidContract("fixture is not UTF-8".to_owned()))?;
    let fragment = if assignment.topology == "control_flow_sensitive" {
        let (unsafe_selected, safe_selected, _) =
            family_fragments(category, &assignment.framework, "selected");
        if vulnerable {
            indent_block(&unsafe_selected, 2)
        } else {
            indent_block(&safe_selected, 2)
        }
    } else {
        indent_block(&selected_fragment, 2)
    };
    if !mutation_text.contains(&fragment) {
        return Err(Phase9Error::InvalidContract(
            "mutation fragment is not uniquely embedded".to_owned(),
        ));
    }
    Ok(RenderedCase {
        files,
        source_file: entry_path,
        source_needle,
        intermediate,
        sink_file,
        sink_needle,
        mutation_file,
        mutation_fragment: fragment,
    })
}

fn span_for(file: &str, content: &[u8], needle: &str) -> Result<Span, Phase9Error> {
    let text = std::str::from_utf8(content)
        .map_err(|_| Phase9Error::InvalidContract("fixture is not UTF-8".to_owned()))?;
    let start = text.find(needle).ok_or_else(|| {
        Phase9Error::InvalidContract(format!("span anchor `{needle}` is absent from `{file}`"))
    })?;
    if text[start + needle.len()..].contains(needle) {
        return Err(Phase9Error::InvalidContract(format!(
            "span anchor `{needle}` is ambiguous in `{file}`"
        )));
    }
    let prefix = &text[..start];
    let start_line = prefix.bytes().filter(|byte| *byte == b'\n').count() as u64 + 1;
    let start_column = prefix
        .rsplit_once('\n')
        .map_or(prefix.len(), |(_, line)| line.len()) as u64
        + 1;
    let end_line = start_line + needle.bytes().filter(|byte| *byte == b'\n').count() as u64;
    let end_column = if let Some((_, tail)) = needle.rsplit_once('\n') {
        tail.len() as u64 + 1
    } else {
        start_column + needle.len() as u64
    };
    Ok(Span {
        file: file.to_owned(),
        start_line,
        start_column,
        end_line,
        end_column,
    })
}

fn line_range(content: &[u8], fragment: &str) -> Result<LineRange, Phase9Error> {
    let text = std::str::from_utf8(content)
        .map_err(|_| Phase9Error::InvalidContract("fixture is not UTF-8".to_owned()))?;
    let start = text
        .find(fragment)
        .ok_or_else(|| Phase9Error::InvalidContract("mutation fragment is absent".to_owned()))?;
    let start_line = text[..start].bytes().filter(|byte| *byte == b'\n').count() as u64 + 1;
    let line_count = fragment.bytes().filter(|byte| *byte == b'\n').count() as u64 + 1;
    Ok(LineRange {
        start: start_line,
        end: start_line + line_count - 1,
    })
}

fn fixture_fingerprint(files: &BTreeMap<String, Vec<u8>>) -> String {
    let mut hasher = Sha256::new();
    for (path, bytes) in files {
        hasher.update(path.as_bytes());
        hasher.update([0]);
        hasher.update(fingerprint(bytes).as_bytes());
        hasher.update([b'\n']);
    }
    hex_digest(&hasher.finalize())
}

fn case_contract_hash(
    kind: &CaseKind,
    expectation: Option<&Expectation>,
    security_property: Option<&String>,
) -> Result<String, Phase9Error> {
    canonical_json(&serde_json::json!({
        "kind": kind,
        "expectation": expectation,
        "security_property": security_property,
    }))
    .map(|bytes| fingerprint(&bytes))
}

fn provenance() -> Provenance {
    Provenance {
        origin: "First-party synthetic Secure Bench Phase 9 fixture".to_owned(),
        license: "Apache-2.0".to_owned(),
        revision: "original".to_owned(),
        modifications: "None; authored specifically for the frozen Phase 9 holdout v3.".to_owned(),
        authors: vec!["Secure Bench contributors".to_owned()],
    }
}

fn expectation_for(
    assignment: &Assignment,
    category: Category,
    case_id: &str,
    rendered: &RenderedCase,
) -> Result<Expectation, Phase9Error> {
    let source_bytes = rendered
        .files
        .get(&rendered.source_file)
        .ok_or_else(|| Phase9Error::InvalidContract("expected source file is absent".to_owned()))?;
    let sink_bytes = rendered
        .files
        .get(&rendered.sink_file)
        .ok_or_else(|| Phase9Error::InvalidContract("expected sink file is absent".to_owned()))?;
    let mut path = vec![PathNode {
        role: "source".to_owned(),
        effect: "preserves_influence".to_owned(),
        source_kind: Some(if category.se_id == "SE1001" {
            category.source_kind.to_owned()
        } else if assignment.framework == "server_actions" {
            "form_data_value".to_owned()
        } else {
            category.source_kind.to_owned()
        }),
        sink_kind: None,
        span: span_for(&rendered.source_file, source_bytes, &rendered.source_needle)?,
        summarizable: false,
    }];
    if let Some((file, needle)) = &rendered.intermediate {
        let bytes = rendered.files.get(file).ok_or_else(|| {
            Phase9Error::InvalidContract("expected intermediate file is absent".to_owned())
        })?;
        path.push(PathNode {
            role: "intermediate".to_owned(),
            effect: "preserves_influence".to_owned(),
            source_kind: None,
            sink_kind: None,
            span: span_for(file, bytes, needle)?,
            summarizable: true,
        });
    }
    path.push(PathNode {
        role: "sink".to_owned(),
        effect: "preserves_influence".to_owned(),
        source_kind: None,
        sink_kind: Some(category.sink_kind.to_owned()),
        span: span_for(&rendered.sink_file, sink_bytes, &rendered.sink_needle)?,
        summarizable: false,
    });
    Ok(Expectation {
        expectation_id: format!("expectation-{case_id}"),
        taxonomy_version: "1.0.0".to_owned(),
        category_id: category.category_id.to_owned(),
        invariant_id: category.invariant_id.to_owned(),
        primary_cwe: category.cwe.to_owned(),
        path,
    })
}

fn make_case_contract(
    assignment: &Assignment,
    category: Category,
    case_number: u64,
    vulnerable: bool,
    rendered: &RenderedCase,
) -> Result<CaseContract, Phase9Error> {
    let case_id = format!("case-v3-{case_number:04}");
    let kind = if vulnerable {
        CaseKind::Vulnerable
    } else {
        CaseKind::SafeControl
    };
    let expectation = if vulnerable {
        Some(expectation_for(assignment, category, &case_id, rendered)?)
    } else {
        None
    };
    let security_property = if vulnerable {
        None
    } else {
        Some(category.property.to_owned())
    };
    let contract_sha256 =
        case_contract_hash(&kind, expectation.as_ref(), security_property.as_ref())?;
    Ok(CaseContract {
        case_id: case_id.clone(),
        fixture_path: format!("{HOLDOUT_ROOT}/cases/{case_id}"),
        fixture_sha256: fixture_fingerprint(&rendered.files),
        contract_sha256,
        kind,
        expectation,
        security_property,
        provenance: provenance(),
    })
}

fn line_fragment(content: &[u8], range: &LineRange) -> Result<Vec<u8>, Phase9Error> {
    let text = std::str::from_utf8(content)
        .map_err(|_| Phase9Error::InvalidContract("fixture is not UTF-8".to_owned()))?;
    let lines = text.lines().collect::<Vec<_>>();
    let start = usize::try_from(range.start.saturating_sub(1))
        .map_err(|_| Phase9Error::InvalidContract("line range overflow".to_owned()))?;
    let end = usize::try_from(range.end)
        .map_err(|_| Phase9Error::InvalidContract("line range overflow".to_owned()))?;
    if start >= end || end > lines.len() {
        return Err(Phase9Error::InvalidContract(
            "mutation line range is outside the file".to_owned(),
        ));
    }
    Ok(lines[start..end].join("\n").into_bytes())
}

fn build_pairs() -> Result<PairBuild, Phase9Error> {
    let assignments = schedule();
    let mut pairs = Vec::with_capacity(EXPECTED_PAIRS);
    let mut fixture_files = BTreeMap::new();
    for assignment in &assignments {
        let category = category_for(assignment)?;
        let first_number = assignment.ordinal * 2 - 1;
        let second_number = assignment.ordinal * 2;
        let vulnerable_first = first_is_vulnerable(assignment)?;
        let first_rendered = render_case(assignment, category, vulnerable_first, first_number)?;
        let second_rendered = render_case(assignment, category, !vulnerable_first, second_number)?;
        if first_rendered.mutation_file != second_rendered.mutation_file {
            return Err(Phase9Error::InvalidContract(
                "paired mutation paths differ".to_owned(),
            ));
        }
        let mutation_file = first_rendered.mutation_file.clone();
        let first_mutation_bytes = first_rendered.files.get(&mutation_file).ok_or_else(|| {
            Phase9Error::InvalidContract("first mutation file missing".to_owned())
        })?;
        let second_mutation_bytes = second_rendered.files.get(&mutation_file).ok_or_else(|| {
            Phase9Error::InvalidContract("second mutation file missing".to_owned())
        })?;
        let first_lines = line_range(first_mutation_bytes, &first_rendered.mutation_fragment)?;
        let second_lines = line_range(second_mutation_bytes, &second_rendered.mutation_fragment)?;
        let first_fragment = line_fragment(first_mutation_bytes, &first_lines)?;
        let second_fragment = line_fragment(second_mutation_bytes, &second_lines)?;
        let first = make_case_contract(
            assignment,
            category,
            first_number,
            vulnerable_first,
            &first_rendered,
        )?;
        let second = make_case_contract(
            assignment,
            category,
            second_number,
            !vulnerable_first,
            &second_rendered,
        )?;
        for (relative, bytes) in &first_rendered.files {
            fixture_files.insert(
                format!("{}/{}", first.fixture_path, relative),
                bytes.clone(),
            );
        }
        for (relative, bytes) in &second_rendered.files {
            fixture_files.insert(
                format!("{}/{}", second.fixture_path, relative),
                bytes.clone(),
            );
        }
        pairs.push(PairContract {
            pair_id: format!("pair-v3-{:03}", assignment.ordinal),
            assignment: assignment.clone(),
            invariant_id: category.invariant_id.to_owned(),
            primary_cwe: category.cwe.to_owned(),
            source_kind: category.source_kind.to_owned(),
            sink_kind: category.sink_kind.to_owned(),
            mutation: MutationContract {
                file: mutation_file,
                first_fragment_sha256: fingerprint(&first_fragment),
                second_fragment_sha256: fingerprint(&second_fragment),
                first_lines,
                second_lines,
                structural_property: category.property.to_owned(),
                inverse_required: true,
                identifier_literal_only_forbidden: true,
            },
            first,
            second,
        });
    }
    Ok((pairs, fixture_files))
}

fn aggregate_corpus(pairs: &[PairContract]) -> String {
    let mut rows = pairs
        .iter()
        .flat_map(|pair| [&pair.first, &pair.second])
        .map(|case| format!("{}\0{}", case.case_id, case.fixture_sha256))
        .collect::<Vec<_>>();
    rows.sort();
    fingerprint(rows.join("\n").as_bytes())
}

fn merkle_root(pairs: &[PairContract]) -> Result<String, Phase9Error> {
    let mut nodes = pairs
        .iter()
        .map(|pair| {
            canonical_json(&serde_json::json!({
                "pair_id": pair.pair_id,
                "assignment": pair.assignment,
                "first_case_id": pair.first.case_id,
                "first_fixture_sha256": pair.first.fixture_sha256,
                "first_contract_sha256": pair.first.contract_sha256,
                "second_case_id": pair.second.case_id,
                "second_fixture_sha256": pair.second.fixture_sha256,
                "second_contract_sha256": pair.second.contract_sha256,
                "mutation": pair.mutation,
            }))
            .map(|bytes| fingerprint(&bytes))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if nodes.is_empty() {
        return Err(Phase9Error::InvalidContract(
            "Merkle tree cannot be empty".to_owned(),
        ));
    }
    while nodes.len() > 1 {
        if !nodes.len().is_multiple_of(2) {
            let last = nodes
                .last()
                .cloned()
                .ok_or_else(|| Phase9Error::InvalidContract("Merkle layer is empty".to_owned()))?;
            nodes.push(last);
        }
        nodes = nodes
            .chunks_exact(2)
            .map(|pair| fingerprint(format!("{}{}", pair[0], pair[1]).as_bytes()))
            .collect();
    }
    nodes
        .pop()
        .ok_or_else(|| Phase9Error::InvalidContract("Merkle root is absent".to_owned()))
}

fn balance_design() -> BalanceDesign {
    BalanceDesign {
        pairs: 112,
        cases: 224,
        vulnerable: 112,
        safe_controls: 112,
        category_pairs_each: 16,
        framework_pairs_each: 28,
        language_pairs_each: 56,
        topology_pairs_each: 28,
        category_framework_pairs_each: 4,
        category_language_pairs_each: 8,
        category_topology_pairs_each: 4,
        framework_language_pairs_each: 14,
        framework_topology_pairs_each: 7,
        language_topology_pairs_each: 14,
        first_slot_vulnerable: 56,
        first_slot_safe: 56,
    }
}

fn collect_regular_files(
    root: &Path,
    relative: &Path,
    output: &mut Vec<PathBuf>,
) -> Result<(), Phase9Error> {
    let path = root.join(relative);
    let metadata = fs::symlink_metadata(&path).map_err(|error| io_error(&path, &error))?;
    if metadata.file_type().is_symlink() {
        return Err(Phase9Error::InvalidContract(format!(
            "symlink is forbidden in `{}`",
            relative.display()
        )));
    }
    if metadata.is_file() {
        output.push(relative.to_path_buf());
        return Ok(());
    }
    if !metadata.is_dir() {
        return Err(Phase9Error::InvalidContract(format!(
            "non-regular tree entry `{}`",
            relative.display()
        )));
    }
    let mut entries = fs::read_dir(&path)
        .map_err(|error| io_error(&path, &error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| io_error(&path, &error))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        collect_regular_files(root, &relative.join(entry.file_name()), output)?;
    }
    Ok(())
}

fn tree_fingerprint(root: &Path, relative: &str) -> Result<String, Phase9Error> {
    let mut files = Vec::new();
    collect_regular_files(root, Path::new(relative), &mut files)?;
    files.sort();
    let mut hasher = Sha256::new();
    for path in files {
        let bytes = read(root, &path.to_string_lossy().replace('\\', "/"))?;
        hasher.update(path.to_string_lossy().replace('\\', "/").as_bytes());
        hasher.update([0]);
        hasher.update(fingerprint(&bytes).as_bytes());
        hasher.update([b'\n']);
    }
    Ok(hex_digest(&hasher.finalize()))
}

fn historical_expected() -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "artifacts".to_owned(),
            "9dd993bf951c4c1816963d9d4c9a9f4b90e08ae5dd38f60a7572bfed8d18b811".to_owned(),
        ),
        (
            "baselines".to_owned(),
            "810fc4d48ce444dd09637b22b73651d83b83bd7af7e8411c66fb46a75c67bf87".to_owned(),
        ),
        (
            "fixtures".to_owned(),
            "19f34f14a2f76a06cc681531254b350a91ef168e8314598901054a67f62bba8b".to_owned(),
        ),
        (
            "holdout/phase-3".to_owned(),
            "47afef0b414b953eef4cf19c3ef6ea44de529cacf0058725edd42f2b4548d6e3".to_owned(),
        ),
        (
            "holdout/phase-5".to_owned(),
            "9972dba15ee17cd48d553fb7b534d5d5b8fd72a8b5dde62996513e11fa7cecc5".to_owned(),
        ),
        (
            "taxonomy".to_owned(),
            "ec0c76707cf65d1ddce1afd83dae2b4862c0aba91643667766eb0f3a6bcb127f".to_owned(),
        ),
    ])
}

fn verify_historical(root: &Path) -> Result<BTreeMap<String, String>, Phase9Error> {
    let expected = historical_expected();
    let mut drift = Vec::new();
    for (path, hash) in &expected {
        let actual = tree_fingerprint(root, path)?;
        if actual != *hash {
            drift.push(format!("`{path}` expected {hash}, actual {actual}"));
        }
    }
    if !drift.is_empty() {
        return Err(Phase9Error::InvalidContract(format!(
            "historical trees differ: {}",
            drift.join("; ")
        )));
    }
    Ok(expected)
}

fn schema_hashes(root: &Path) -> Result<BTreeMap<String, String>, Phase9Error> {
    [
        MANIFEST_SCHEMA_PATH,
        COMMITMENTS_SCHEMA_PATH,
        LEDGER_SCHEMA_PATH,
    ]
    .into_iter()
    .map(|path| read(root, path).map(|bytes| (path.to_owned(), fingerprint(&bytes))))
    .collect()
}

fn taxonomy_binding(root: &Path) -> Result<TaxonomyBinding, Phase9Error> {
    let bytes = read(root, TAXONOMY_PATH)?;
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|error| Phase9Error::InvalidContract(error.to_string()))?;
    Ok(TaxonomyBinding {
        path: TAXONOMY_PATH.to_owned(),
        schema_version: value
            .get("schema_version")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        taxonomy_version: value
            .get("taxonomy_version")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        sha256: fingerprint(&bytes),
        content_hash: value
            .get("content_hash")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
    })
}

fn evidence_binding(root: &Path) -> Result<EvidenceBinding, Phase9Error> {
    let bytes = read(root, EVIDENCE_CONTRACT_PATH)?;
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|error| Phase9Error::InvalidContract(error.to_string()))?;
    Ok(EvidenceBinding {
        path: EVIDENCE_CONTRACT_PATH.to_owned(),
        schema_version: value
            .get("schema_version")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        contract_version: value
            .get("contract_version")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        sha256: fingerprint(&bytes),
        decision: "reused_without_modification_because_v2_already_expresses_all_phase9_sources_sinks_barriers_paths_partials_and_duplicates".to_owned(),
    })
}

fn ledger_entry(
    manifest_sha256: &str,
    evidence_contract_sha256: &str,
    taxonomy_sha256: &str,
    corpus_sha256: &str,
    merkle_root: &str,
) -> Result<LedgerEntry, Phase9Error> {
    let body = serde_json::json!({
        "schema_version": "secure-bench-phase9-ledger-entry-v1",
        "sequence": 0,
        "event": "holdout_frozen",
        "holdout_id": HOLDOUT_ID,
        "manifest_sha256": manifest_sha256,
        "evidence_contract_sha256": evidence_contract_sha256,
        "taxonomy_sha256": taxonomy_sha256,
        "aggregate_corpus_sha256": corpus_sha256,
        "commitment_root": merkle_root,
        "previous_entry_hash": ZERO_HASH,
        "timestamp_utc": FROZEN_AT,
    });
    let entry_hash = fingerprint(&canonical_json(&body)?);
    Ok(LedgerEntry {
        schema_version: "secure-bench-phase9-ledger-entry-v1".to_owned(),
        sequence: 0,
        event: "holdout_frozen".to_owned(),
        holdout_id: HOLDOUT_ID.to_owned(),
        manifest_sha256: manifest_sha256.to_owned(),
        evidence_contract_sha256: evidence_contract_sha256.to_owned(),
        taxonomy_sha256: taxonomy_sha256.to_owned(),
        aggregate_corpus_sha256: corpus_sha256.to_owned(),
        commitment_root: merkle_root.to_owned(),
        previous_entry_hash: ZERO_HASH.to_owned(),
        timestamp_utc: FROZEN_AT.to_owned(),
        entry_hash,
    })
}

fn count_cases(pairs: &[PairContract]) -> impl Iterator<Item = &CaseContract> {
    pairs.iter().flat_map(|pair| [&pair.first, &pair.second])
}

fn report_from(
    manifest: &Manifest,
    manifest_bytes: &[u8],
    ledger_bytes: &[u8],
) -> ValidationReport {
    let mut report = ValidationReport {
        pairs: manifest.pairs.len() as u64,
        cases: count_cases(&manifest.pairs).count() as u64,
        vulnerable: 0,
        controls: 0,
        java_script: 0,
        type_script: 0,
        node_js: 0,
        express: 0,
        next_app_router: 0,
        server_actions: 0,
        direct: 0,
        helper_mediated: 0,
        inter_file_aliased: 0,
        control_flow_sensitive: 0,
        aggregate_corpus_sha256: manifest.commitments.aggregate_corpus_sha256.clone(),
        contract_merkle_root: manifest.commitments.contract_merkle_root.clone(),
        manifest_sha256: fingerprint(manifest_bytes),
        ledger_genesis_sha256: fingerprint(ledger_bytes),
    };
    for pair in &manifest.pairs {
        for case in [&pair.first, &pair.second] {
            match case.kind {
                CaseKind::Vulnerable => report.vulnerable += 1,
                CaseKind::SafeControl => report.controls += 1,
            }
            match pair.assignment.language.as_str() {
                "java_script" => report.java_script += 1,
                "type_script" => report.type_script += 1,
                _ => {}
            }
            match pair.assignment.framework.as_str() {
                "node_js" => report.node_js += 1,
                "express" => report.express += 1,
                "next_app_router" => report.next_app_router += 1,
                "server_actions" => report.server_actions += 1,
                _ => {}
            }
            match pair.assignment.topology.as_str() {
                "direct" => report.direct += 1,
                "helper_mediated" => report.helper_mediated += 1,
                "inter_file_aliased" => report.inter_file_aliased += 1,
                "control_flow_sensitive" => report.control_flow_sensitive += 1,
                _ => {}
            }
        }
    }
    report
}

fn build_bundle(root: &Path) -> Result<Bundle, Phase9Error> {
    let historical_integrity = verify_historical(root)?;
    let taxonomy = taxonomy_binding(root)?;
    let evidence_contract = evidence_binding(root)?;
    if taxonomy.schema_version != "secure-bench-taxonomy-v1"
        || taxonomy.taxonomy_version != "1.0.0"
        || evidence_contract.schema_version != "secure-bench-evidence-contract-v2"
        || evidence_contract.contract_version != "2.0.0"
    {
        return Err(Phase9Error::InvalidContract(
            "taxonomy or evidence-contract-v2 binding differs".to_owned(),
        ));
    }
    let assignments = schedule();
    let schedule_sha256 = fingerprint(&canonical_json(&assignments)?);
    let (pairs, fixture_files) = build_pairs()?;
    let aggregate_corpus_sha256 = aggregate_corpus(&pairs);
    let contract_merkle_root = merkle_root(&pairs)?;
    let manifest = Manifest {
        schema_version: "secure-bench-orthogonal-holdout-v3".to_owned(),
        holdout_id: HOLDOUT_ID.to_owned(),
        title: "Secure Bench Phase 9 Orthogonal Holdout v3".to_owned(),
        description: "A first-party synthetic, paired, counterbalanced future examination independent from the retired Phase 3 and executed Phase 5 corpora.".to_owned(),
        methodology_version: "9.0.0".to_owned(),
        git_base: BASE_COMMIT.to_owned(),
        branch: "codex/phase-9-holdout-v3".to_owned(),
        frozen_at_utc: FROZEN_AT.to_owned(),
        neutrality: "This phase freezes a neutral future examination only. It is not a production benchmark, scanner comparison, public ranking, superiority claim, or coverage claim.".to_owned(),
        taxonomy,
        evidence_contract,
        protocol: Protocol {
            evaluation_state: "not_executed".to_owned(),
            one_shot_future_evaluation: true,
            network: "blocked_for_every_future_scanner_process".to_owned(),
            ai_validation: "disabled_without_provider_credentials_endpoints_or_commands".to_owned(),
            scanner_projection: "one_isolated_fixture_directory_only_without_manifest_contracts_taxonomy_or_pair_sibling".to_owned(),
            expected_data_visibility: "matcher_only_after_scanner_execution_never_in_scanner_inputs_prompts_environment_or_filenames".to_owned(),
            ledger_path: LEDGER_PATH.to_owned(),
            result_path_template: "holdout/phase-9/results/{evaluation-id}.json".to_owned(),
            result_write_mode: "create_new_only".to_owned(),
        },
        design: Design {
            schedule_id: "counterbalanced-pairwise-orthogonal-112-pairs-v1".to_owned(),
            schedule_sha256: schedule_sha256.clone(),
            balance: balance_design(),
            deconfounding: vec![
                "every assignment has one vulnerable case and one safe control with identical framework language and topology".to_owned(),
                "first and second case positions are balanced within every category framework and language cell".to_owned(),
                "category framework language and topology pairwise margins are exact".to_owned(),
                "case identifiers package names and paths are opaque and answer-independent".to_owned(),
                "future scanner processes receive one isolated fixture without its pair sibling".to_owned(),
            ],
            mutation_checks: vec![
                "both directional line projections reproduce the paired file exactly".to_owned(),
                "all non-mutated files are byte-identical within a pair".to_owned(),
                "changed fragments differ after identifier and literal normalization".to_owned(),
                "safe controls preserve the source and sensitive operation while adding an effective barrier or structurally safe API".to_owned(),
            ],
            orthogonality_checks: vec![
                "no fixture fingerprint or source-file hash equals Phase 1 Phase 3 or Phase 5".to_owned(),
                "no normalized non-pair source shape is duplicated".to_owned(),
                "normalized token-shingle similarity rejects trivial prior-corpus and non-pair variants".to_owned(),
                "scanner-visible paths declarations package names and comments contain no expected labels".to_owned(),
            ],
        },
        historical_integrity: historical_integrity.clone(),
        commitments: DesignCommitments {
            aggregate_corpus_sha256: aggregate_corpus_sha256.clone(),
            contract_merkle_root: contract_merkle_root.clone(),
            schedule_sha256: schedule_sha256.clone(),
        },
        pairs,
    };
    let manifest_bytes = canonical_json(&manifest)?;
    let manifest_sha256 = fingerprint(&manifest_bytes);
    let ledger = ledger_entry(
        &manifest_sha256,
        &manifest.evidence_contract.sha256,
        &manifest.taxonomy.sha256,
        &aggregate_corpus_sha256,
        &contract_merkle_root,
    )?;
    let ledger_bytes = canonical_json(&ledger)?;
    let commitments = CommitmentIndex {
        schema_version: "secure-bench-phase9-commitments-v1".to_owned(),
        holdout_id: HOLDOUT_ID.to_owned(),
        manifest_sha256: manifest_sha256.clone(),
        evidence_contract_sha256: manifest.evidence_contract.sha256.clone(),
        taxonomy_sha256: manifest.taxonomy.sha256.clone(),
        aggregate_corpus_sha256: aggregate_corpus_sha256.clone(),
        contract_merkle_root: contract_merkle_root.clone(),
        schedule_sha256,
        genesis_ledger_sha256: fingerprint(&ledger_bytes),
        pair_count: EXPECTED_PAIRS as u64,
        case_count: EXPECTED_CASES as u64,
        authoring_source_sha256: tree_fingerprint(root, "phase9/src")?,
        schema_files: schema_hashes(root)?,
        historical_integrity,
    };
    let commitments_bytes = canonical_json(&commitments)?;
    let report = report_from(&manifest, &manifest_bytes, &ledger_bytes);
    let mut files = fixture_files;
    files.insert(MANIFEST_PATH.to_owned(), manifest_bytes);
    files.insert(COMMITMENTS_PATH.to_owned(), commitments_bytes);
    files.insert(LEDGER_PATH.to_owned(), ledger_bytes);
    Ok(Bundle { files, report })
}

fn validate_schema(root: &Path, schema_path: &str, instance: &[u8]) -> Result<(), Phase9Error> {
    let schema: Value = serde_json::from_slice(&read(root, schema_path)?)
        .map_err(|error| Phase9Error::InvalidContract(error.to_string()))?;
    let instance: Value = serde_json::from_slice(instance)
        .map_err(|error| Phase9Error::InvalidContract(error.to_string()))?;
    let validator = jsonschema::validator_for(&schema)
        .map_err(|error| Phase9Error::InvalidContract(error.to_string()))?;
    if let Err(error) = validator.validate(&instance) {
        return Err(Phase9Error::InvalidContract(format!(
            "schema `{schema_path}` rejected an artifact: {error}"
        )));
    }
    Ok(())
}

fn factor_count<F>(pairs: &[PairContract], key: F) -> BTreeMap<String, u64>
where
    F: Fn(&PairContract) -> String,
{
    let mut counts = BTreeMap::new();
    for pair in pairs {
        *counts.entry(key(pair)).or_insert(0) += 1;
    }
    counts
}

fn require_uniform(
    label: &str,
    counts: &BTreeMap<String, u64>,
    cells: usize,
    each: u64,
) -> Result<(), Phase9Error> {
    if counts.len() != cells || counts.values().any(|count| *count != each) {
        return Err(Phase9Error::InvalidContract(format!(
            "{label} balance differs from {cells} cells of {each}: {counts:?}"
        )));
    }
    Ok(())
}

fn validate_balance(pairs: &[PairContract]) -> Result<(), Phase9Error> {
    if pairs.len() != EXPECTED_PAIRS || count_cases(pairs).count() != EXPECTED_CASES {
        return Err(Phase9Error::InvalidContract(
            "Phase 9 pair or case count differs".to_owned(),
        ));
    }
    require_uniform(
        "category",
        &factor_count(pairs, |pair| pair.assignment.category_id.clone()),
        7,
        16,
    )?;
    require_uniform(
        "framework",
        &factor_count(pairs, |pair| pair.assignment.framework.clone()),
        4,
        28,
    )?;
    require_uniform(
        "language",
        &factor_count(pairs, |pair| pair.assignment.language.clone()),
        2,
        56,
    )?;
    require_uniform(
        "topology",
        &factor_count(pairs, |pair| pair.assignment.topology.clone()),
        4,
        28,
    )?;
    require_uniform(
        "category/framework",
        &factor_count(pairs, |pair| {
            format!(
                "{}|{}",
                pair.assignment.category_id, pair.assignment.framework
            )
        }),
        28,
        4,
    )?;
    require_uniform(
        "category/language",
        &factor_count(pairs, |pair| {
            format!(
                "{}|{}",
                pair.assignment.category_id, pair.assignment.language
            )
        }),
        14,
        8,
    )?;
    require_uniform(
        "category/topology",
        &factor_count(pairs, |pair| {
            format!(
                "{}|{}",
                pair.assignment.category_id, pair.assignment.topology
            )
        }),
        28,
        4,
    )?;
    require_uniform(
        "framework/language",
        &factor_count(pairs, |pair| {
            format!("{}|{}", pair.assignment.framework, pair.assignment.language)
        }),
        8,
        14,
    )?;
    require_uniform(
        "framework/topology",
        &factor_count(pairs, |pair| {
            format!("{}|{}", pair.assignment.framework, pair.assignment.topology)
        }),
        16,
        7,
    )?;
    require_uniform(
        "language/topology",
        &factor_count(pairs, |pair| {
            format!("{}|{}", pair.assignment.language, pair.assignment.topology)
        }),
        8,
        14,
    )?;
    let vulnerable = count_cases(pairs)
        .filter(|case| case.kind == CaseKind::Vulnerable)
        .count();
    let controls = count_cases(pairs)
        .filter(|case| case.kind == CaseKind::SafeControl)
        .count();
    let first_vulnerable = pairs
        .iter()
        .filter(|pair| pair.first.kind == CaseKind::Vulnerable)
        .count();
    if vulnerable != 112 || controls != 112 || first_vulnerable != 56 {
        return Err(Phase9Error::InvalidContract(
            "answer orientation is not exactly counterbalanced".to_owned(),
        ));
    }
    for pair in pairs {
        let kinds = BTreeSet::from([
            format!("{:?}", pair.first.kind),
            format!("{:?}", pair.second.kind),
        ]);
        if kinds.len() != 2
            || first_is_vulnerable(&pair.assignment)? != (pair.first.kind == CaseKind::Vulnerable)
        {
            return Err(Phase9Error::InvalidContract(format!(
                "pair `{}` is not a counterbalanced vulnerable/control inverse",
                pair.pair_id
            )));
        }
    }
    require_uniform(
        "first-slot category/framework/language/answer",
        &factor_count(pairs, |pair| {
            format!(
                "{}|{}|{}|{:?}",
                pair.assignment.category_id,
                pair.assignment.framework,
                pair.assignment.language,
                pair.first.kind
            )
        }),
        112,
        1,
    )?;
    require_uniform(
        "first-slot category/answer",
        &factor_count(pairs, |pair| {
            format!("{}|{:?}", pair.assignment.category_id, pair.first.kind)
        }),
        14,
        8,
    )?;
    require_uniform(
        "first-slot framework/answer",
        &factor_count(pairs, |pair| {
            format!("{}|{:?}", pair.assignment.framework, pair.first.kind)
        }),
        8,
        14,
    )?;
    require_uniform(
        "first-slot language/answer",
        &factor_count(pairs, |pair| {
            format!("{}|{:?}", pair.assignment.language, pair.first.kind)
        }),
        4,
        28,
    )?;
    require_uniform(
        "first-slot topology/answer",
        &factor_count(pairs, |pair| {
            format!("{}|{:?}", pair.assignment.topology, pair.first.kind)
        }),
        8,
        14,
    )?;
    Ok(())
}

fn split_lines_inclusive(bytes: &[u8]) -> Result<Vec<&str>, Phase9Error> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Phase9Error::InvalidContract("fixture is not UTF-8".to_owned()))?;
    Ok(text.split_inclusive('\n').collect())
}

fn replace_lines(
    original: &[u8],
    range: &LineRange,
    replacement: &[u8],
) -> Result<Vec<u8>, Phase9Error> {
    let lines = split_lines_inclusive(original)?;
    let start = usize::try_from(range.start.saturating_sub(1))
        .map_err(|_| Phase9Error::InvalidContract("line range overflow".to_owned()))?;
    let end = usize::try_from(range.end)
        .map_err(|_| Phase9Error::InvalidContract("line range overflow".to_owned()))?;
    if start >= end || end > lines.len() {
        return Err(Phase9Error::InvalidContract(
            "inverse mutation line range is invalid".to_owned(),
        ));
    }
    let mut output = String::new();
    for line in &lines[..start] {
        output.push_str(line);
    }
    let replacement = std::str::from_utf8(replacement)
        .map_err(|_| Phase9Error::InvalidContract("mutation is not UTF-8".to_owned()))?;
    output.push_str(replacement);
    if !replacement.ends_with('\n') {
        output.push('\n');
    }
    for line in &lines[end..] {
        output.push_str(line);
    }
    Ok(output.into_bytes())
}

fn structural_tokens(text: &str) -> Vec<String> {
    const KEYWORDS: [&str; 37] = [
        "async",
        "await",
        "break",
        "case",
        "catch",
        "class",
        "const",
        "continue",
        "default",
        "delete",
        "do",
        "else",
        "export",
        "extends",
        "false",
        "finally",
        "for",
        "function",
        "if",
        "import",
        "in",
        "instanceof",
        "let",
        "new",
        "null",
        "of",
        "return",
        "switch",
        "throw",
        "true",
        "try",
        "typeof",
        "undefined",
        "var",
        "while",
        "with",
        "yield",
    ];
    let bytes = text.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte.is_ascii_whitespace() {
            index += 1;
        } else if byte.is_ascii_alphabetic() || matches!(byte, b'_' | b'$') {
            let start = index;
            index += 1;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric() || matches!(bytes[index], b'_' | b'$'))
            {
                index += 1;
            }
            let word = &text[start..index];
            if KEYWORDS.contains(&word) {
                tokens.push(word.to_owned());
            } else {
                tokens.push("I".to_owned());
            }
        } else if byte.is_ascii_digit() {
            index += 1;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric() || matches!(bytes[index], b'.' | b'_'))
            {
                index += 1;
            }
            tokens.push("N".to_owned());
        } else if matches!(byte, b'\'' | b'"' | b'`') {
            let quote = byte;
            index += 1;
            while index < bytes.len() {
                if bytes[index] == b'\\' {
                    index = (index + 2).min(bytes.len());
                } else if bytes[index] == quote {
                    index += 1;
                    break;
                } else {
                    index += 1;
                }
            }
            tokens.push("S".to_owned());
        } else {
            tokens.push(char::from(byte).to_string());
            index += 1;
        }
    }
    tokens
}

fn token_shingles(tokens: &[String]) -> BTreeSet<String> {
    if tokens.len() < 5 {
        return BTreeSet::from([tokens.join(" ")]);
    }
    tokens.windows(5).map(|window| window.join(" ")).collect()
}

fn similarity_basis_points(left: &BTreeSet<String>, right: &BTreeSet<String>) -> u64 {
    let intersection = left.intersection(right).count() as u64;
    let union = left.union(right).count() as u64;
    intersection
        .saturating_mul(10_000)
        .checked_div(union)
        .unwrap_or(10_000)
}

fn source_extension(path: &str) -> bool {
    matches!(
        Path::new(path).extension().and_then(|value| value.to_str()),
        Some("js" | "jsx" | "ts" | "tsx")
    )
}

fn validate_mutations(root: &Path, pairs: &[PairContract]) -> Result<(), Phase9Error> {
    for pair in pairs {
        let first_root = &pair.first.fixture_path;
        let second_root = &pair.second.fixture_path;
        let first_file = read(root, &format!("{first_root}/{}", pair.mutation.file))?;
        let second_file = read(root, &format!("{second_root}/{}", pair.mutation.file))?;
        let first_fragment = line_fragment(&first_file, &pair.mutation.first_lines)?;
        let second_fragment = line_fragment(&second_file, &pair.mutation.second_lines)?;
        if fingerprint(&first_fragment) != pair.mutation.first_fragment_sha256
            || fingerprint(&second_fragment) != pair.mutation.second_fragment_sha256
            || replace_lines(&first_file, &pair.mutation.first_lines, &second_fragment)?
                != second_file
            || replace_lines(&second_file, &pair.mutation.second_lines, &first_fragment)?
                != first_file
        {
            return Err(Phase9Error::InvalidContract(format!(
                "pair `{}` failed exact bidirectional mutation projection",
                pair.pair_id
            )));
        }
        let first_shape =
            structural_tokens(std::str::from_utf8(&first_fragment).map_err(|_| {
                Phase9Error::InvalidContract("mutation fragment is not UTF-8".to_owned())
            })?);
        let second_shape =
            structural_tokens(std::str::from_utf8(&second_fragment).map_err(|_| {
                Phase9Error::InvalidContract("mutation fragment is not UTF-8".to_owned())
            })?);
        if first_shape == second_shape || first_shape.len().abs_diff(second_shape.len()) < 3 {
            return Err(Phase9Error::InvalidContract(format!(
                "pair `{}` mutation is only an identifier/literal variant",
                pair.pair_id
            )));
        }
        let mut first_files = Vec::new();
        collect_regular_files(root, Path::new(first_root), &mut first_files)?;
        let mut second_files = Vec::new();
        collect_regular_files(root, Path::new(second_root), &mut second_files)?;
        let first_rel = first_files
            .iter()
            .map(|path| path.strip_prefix(first_root).map(Path::to_path_buf))
            .collect::<Result<BTreeSet<_>, _>>()
            .map_err(|_| Phase9Error::InvalidContract("invalid first fixture path".to_owned()))?;
        let second_rel = second_files
            .iter()
            .map(|path| path.strip_prefix(second_root).map(Path::to_path_buf))
            .collect::<Result<BTreeSet<_>, _>>()
            .map_err(|_| Phase9Error::InvalidContract("invalid second fixture path".to_owned()))?;
        if first_rel != second_rel {
            return Err(Phase9Error::InvalidContract(format!(
                "pair `{}` file sets differ",
                pair.pair_id
            )));
        }
        for relative in first_rel {
            if relative != Path::new(&pair.mutation.file) {
                let relative = relative.to_string_lossy().replace('\\', "/");
                if read(root, &format!("{first_root}/{relative}"))?
                    != read(root, &format!("{second_root}/{relative}"))?
                {
                    return Err(Phase9Error::InvalidContract(format!(
                        "pair `{}` changed a non-mutation file",
                        pair.pair_id
                    )));
                }
            }
        }
    }
    Ok(())
}

fn prior_source_files(root: &Path) -> Result<Vec<(String, Vec<u8>)>, Phase9Error> {
    let roots = [
        "fixtures/vulnerable",
        "fixtures/safe",
        "holdout/phase-3/cases",
        "holdout/phase-5/cases",
    ];
    let mut output = Vec::new();
    for prior_root in roots {
        let mut paths = Vec::new();
        collect_regular_files(root, Path::new(prior_root), &mut paths)?;
        for path in paths {
            let portable = path.to_string_lossy().replace('\\', "/");
            if source_extension(&portable) {
                output.push((portable.clone(), read(root, &portable)?));
            }
        }
    }
    Ok(output)
}

fn validate_orthogonality(root: &Path, pairs: &[PairContract]) -> Result<(), Phase9Error> {
    let prior = prior_source_files(root)?;
    let prior_hashes = prior
        .iter()
        .map(|(_, bytes)| fingerprint(bytes))
        .collect::<BTreeSet<_>>();
    let prior_shapes = prior
        .iter()
        .filter_map(|(path, bytes)| {
            std::str::from_utf8(bytes).ok().map(|text| {
                (
                    path,
                    structural_tokens(text).join(" "),
                    token_shingles(&structural_tokens(text)),
                )
            })
        })
        .collect::<Vec<_>>();
    let mut fixture_hashes = BTreeSet::new();
    let mut seen_case_shapes: BTreeMap<String, String> = BTreeMap::new();
    let mut new_cases = Vec::new();
    for pair in pairs {
        for case in [&pair.first, &pair.second] {
            if !fixture_hashes.insert(case.fixture_sha256.clone()) {
                return Err(Phase9Error::InvalidContract(
                    "duplicate Phase 9 fixture fingerprint".to_owned(),
                ));
            }
            let mut paths = Vec::new();
            collect_regular_files(root, Path::new(&case.fixture_path), &mut paths)?;
            paths.sort();
            let mut aggregate_tokens = Vec::new();
            for path in paths {
                let portable = path.to_string_lossy().replace('\\', "/");
                if !source_extension(&portable) {
                    continue;
                }
                let bytes = read(root, &portable)?;
                if prior_hashes.contains(&fingerprint(&bytes)) {
                    return Err(Phase9Error::InvalidContract(format!(
                        "Phase 9 source `{portable}` duplicates a prior corpus file"
                    )));
                }
                let text = std::str::from_utf8(&bytes)
                    .map_err(|_| Phase9Error::InvalidContract("source is not UTF-8".to_owned()))?;
                let tokens = structural_tokens(text);
                let shape = tokens.join(" ");
                let shingles = token_shingles(&tokens);
                for (prior_path, prior_shape, prior_shingles) in &prior_shapes {
                    if shape == *prior_shape
                        || similarity_basis_points(&shingles, prior_shingles) >= 9_850
                    {
                        return Err(Phase9Error::InvalidContract(format!(
                            "Phase 9 source `{portable}` is a trivial structural variant of `{prior_path}`"
                        )));
                    }
                }
                let relative = path
                    .strip_prefix(&case.fixture_path)
                    .map_err(|_| {
                        Phase9Error::InvalidContract("source escaped fixture root".to_owned())
                    })?
                    .to_string_lossy()
                    .replace('\\', "/");
                aggregate_tokens.push(format!("FILE:{relative}"));
                aggregate_tokens.extend(tokens);
            }
            let aggregate_shape = aggregate_tokens.join(" ");
            if let Some(previous) = seen_case_shapes.get(&aggregate_shape) {
                if !previous.starts_with(&pair.pair_id) {
                    return Err(Phase9Error::InvalidContract(format!(
                        "non-pair fixtures `{previous}` and `{}` are normalized duplicates",
                        case.fixture_path
                    )));
                }
            } else {
                seen_case_shapes.insert(
                    aggregate_shape,
                    format!("{}:{}", pair.pair_id, case.fixture_path),
                );
            }
            new_cases.push((
                pair.pair_id.clone(),
                case.fixture_path.clone(),
                token_shingles(&aggregate_tokens),
            ));
        }
    }
    for (index, (left_pair, left_path, left)) in new_cases.iter().enumerate() {
        for (right_pair, right_path, right) in new_cases.iter().skip(index + 1) {
            if left_pair != right_pair && similarity_basis_points(left, right) >= 9_850 {
                return Err(Phase9Error::InvalidContract(format!(
                    "non-pair fixtures `{left_path}` and `{right_path}` are trivial structural variants"
                )));
            }
        }
    }
    Ok(())
}

fn validate_privacy(root: &Path, pairs: &[PairContract]) -> Result<(), Phase9Error> {
    let forbidden = [
        "vulnerable",
        "safe_control",
        "safe-control",
        "expected_finding",
        "secure-bench.category",
        "secure-bench.invariant",
        "cwe-",
        "/home/",
        "/users/",
        "c:\\users\\",
    ];
    for case in count_cases(pairs) {
        let lower_path = case.fixture_path.to_ascii_lowercase();
        if forbidden.iter().any(|term| lower_path.contains(term)) {
            return Err(Phase9Error::InvalidContract(format!(
                "scanner-visible path leaks expected or host metadata: `{}`",
                case.fixture_path
            )));
        }
        let mut paths = Vec::new();
        collect_regular_files(root, Path::new(&case.fixture_path), &mut paths)?;
        for path in paths {
            let portable = path.to_string_lossy().replace('\\', "/");
            let bytes = read(root, &portable)?;
            let text = String::from_utf8_lossy(&bytes).to_ascii_lowercase();
            if forbidden.iter().any(|term| text.contains(term)) {
                return Err(Phase9Error::InvalidContract(format!(
                    "scanner-visible fixture `{portable}` leaks expected or host metadata"
                )));
            }
        }
    }
    Ok(())
}

fn validate_committed_bundle(root: &Path, expected: &Bundle) -> Result<(), Phase9Error> {
    for (relative, expected_bytes) in &expected.files {
        let actual = read(root, relative)?;
        if actual != *expected_bytes {
            return Err(Phase9Error::InvalidContract(format!(
                "committed Phase 9 file `{relative}` differs from deterministic authoring"
            )));
        }
    }
    let mut actual_files = Vec::new();
    collect_regular_files(root, Path::new(HOLDOUT_ROOT), &mut actual_files)?;
    let actual = actual_files
        .into_iter()
        .map(|path| path.to_string_lossy().replace('\\', "/"))
        .collect::<BTreeSet<_>>();
    let expected_paths = expected.files.keys().cloned().collect::<BTreeSet<_>>();
    if actual != expected_paths {
        return Err(Phase9Error::InvalidContract(
            "Phase 9 contains an unexpected, missing, or uncommitted artifact".to_owned(),
        ));
    }
    Ok(())
}

fn semantic_validation(root: &Path, bundle: &Bundle) -> Result<(), Phase9Error> {
    let manifest_bytes = bundle
        .files
        .get(MANIFEST_PATH)
        .ok_or_else(|| Phase9Error::InvalidContract("manifest missing".to_owned()))?;
    let commitments_bytes = bundle
        .files
        .get(COMMITMENTS_PATH)
        .ok_or_else(|| Phase9Error::InvalidContract("commitments missing".to_owned()))?;
    let ledger_bytes = bundle
        .files
        .get(LEDGER_PATH)
        .ok_or_else(|| Phase9Error::InvalidContract("ledger missing".to_owned()))?;
    validate_schema(root, MANIFEST_SCHEMA_PATH, manifest_bytes)?;
    validate_schema(root, COMMITMENTS_SCHEMA_PATH, commitments_bytes)?;
    validate_schema(root, LEDGER_SCHEMA_PATH, ledger_bytes)?;
    let manifest: Manifest = serde_json::from_slice(manifest_bytes)
        .map_err(|error| Phase9Error::InvalidContract(error.to_string()))?;
    let commitments: CommitmentIndex = serde_json::from_slice(commitments_bytes)
        .map_err(|error| Phase9Error::InvalidContract(error.to_string()))?;
    let ledger: LedgerEntry = serde_json::from_slice(ledger_bytes)
        .map_err(|error| Phase9Error::InvalidContract(error.to_string()))?;
    if manifest.schema_version != "secure-bench-orthogonal-holdout-v3"
        || manifest.holdout_id != HOLDOUT_ID
        || manifest.git_base != BASE_COMMIT
        || manifest.protocol.evaluation_state != "not_executed"
        || manifest.evidence_contract.schema_version != "secure-bench-evidence-contract-v2"
        || manifest.evidence_contract.contract_version != "2.0.0"
        || !manifest.protocol.one_shot_future_evaluation
    {
        return Err(Phase9Error::InvalidContract(
            "Phase 9 lifecycle or reused evidence contract differs".to_owned(),
        ));
    }
    validate_balance(&manifest.pairs)?;
    if aggregate_corpus(&manifest.pairs) != manifest.commitments.aggregate_corpus_sha256
        || merkle_root(&manifest.pairs)? != manifest.commitments.contract_merkle_root
        || fingerprint(manifest_bytes) != commitments.manifest_sha256
        || fingerprint(ledger_bytes) != commitments.genesis_ledger_sha256
        || commitments.aggregate_corpus_sha256 != manifest.commitments.aggregate_corpus_sha256
        || commitments.contract_merkle_root != manifest.commitments.contract_merkle_root
        || ledger.manifest_sha256 != commitments.manifest_sha256
        || ledger.commitment_root != commitments.contract_merkle_root
        || ledger.aggregate_corpus_sha256 != commitments.aggregate_corpus_sha256
        || ledger.previous_entry_hash != ZERO_HASH
        || ledger.sequence != 0
        || ledger.event != "holdout_frozen"
    {
        return Err(Phase9Error::InvalidContract(
            "Phase 9 commitment or genesis-ledger binding differs".to_owned(),
        ));
    }
    let body = serde_json::json!({
        "schema_version": ledger.schema_version,
        "sequence": ledger.sequence,
        "event": ledger.event,
        "holdout_id": ledger.holdout_id,
        "manifest_sha256": ledger.manifest_sha256,
        "evidence_contract_sha256": ledger.evidence_contract_sha256,
        "taxonomy_sha256": ledger.taxonomy_sha256,
        "aggregate_corpus_sha256": ledger.aggregate_corpus_sha256,
        "commitment_root": ledger.commitment_root,
        "previous_entry_hash": ledger.previous_entry_hash,
        "timestamp_utc": ledger.timestamp_utc,
    });
    if fingerprint(&canonical_json(&body)?) != ledger.entry_hash {
        return Err(Phase9Error::InvalidContract(
            "Phase 9 genesis ledger entry hash differs".to_owned(),
        ));
    }
    Ok(())
}

fn create_file(path: &Path, bytes: &[u8]) -> Result<(), Phase9Error> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| io_error(parent, &error))?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| io_error(path, &error))?;
    file.write_all(bytes)
        .map_err(|error| io_error(path, &error))?;
    file.sync_all().map_err(|error| io_error(path, &error))
}

/// Authors the complete Phase 9 bundle using create-new-only writes.
///
/// # Errors
///
/// Returns an error when prerequisites differ, output exists, or a design invariant fails.
pub fn author_holdout(root: &Path) -> Result<ValidationReport, Phase9Error> {
    let output = safe_join(root, HOLDOUT_ROOT)?;
    if fs::symlink_metadata(&output).is_ok() {
        return Err(Phase9Error::InvalidRequest(
            "Phase 9 output already exists; authoring is create-new-only".to_owned(),
        ));
    }
    let bundle = build_bundle(root)?;
    for (relative, bytes) in &bundle.files {
        create_file(&safe_join(root, relative)?, bytes)?;
    }
    semantic_validation(root, &bundle)?;
    let manifest: Manifest =
        serde_json::from_slice(bundle.files.get(MANIFEST_PATH).ok_or_else(|| {
            Phase9Error::InvalidContract("manifest missing after authoring".to_owned())
        })?)
        .map_err(|error| Phase9Error::InvalidContract(error.to_string()))?;
    validate_mutations(root, &manifest.pairs)?;
    validate_orthogonality(root, &manifest.pairs)?;
    validate_privacy(root, &manifest.pairs)?;
    Ok(bundle.report)
}

/// Recomputes and verifies the complete committed Phase 9 bundle without launching a process.
///
/// # Errors
///
/// Returns an error for any artifact, schema, balance, privacy, duplicate, or commitment drift.
pub fn validate_holdout(root: &Path) -> Result<ValidationReport, Phase9Error> {
    let expected = build_bundle(root)?;
    validate_committed_bundle(root, &expected)?;
    semantic_validation(root, &expected)?;
    let manifest: Manifest = serde_json::from_slice(
        expected
            .files
            .get(MANIFEST_PATH)
            .ok_or_else(|| Phase9Error::InvalidContract("manifest missing".to_owned()))?,
    )
    .map_err(|error| Phase9Error::InvalidContract(error.to_string()))?;
    validate_mutations(root, &manifest.pairs)?;
    validate_orthogonality(root, &manifest.pairs)?;
    validate_privacy(root, &manifest.pairs)?;
    Ok(expected.report)
}

/// Loads only the validated public aggregate projection.
///
/// # Errors
///
/// Returns an error when any frozen Phase 9 invariant differs.
pub fn summarize_holdout(root: &Path) -> Result<ValidationReport, Phase9Error> {
    validate_holdout(root)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> &'static Path {
        Path::new("..")
    }

    #[test]
    fn schedule_is_pairwise_balanced_and_answer_counterbalanced() -> Result<(), Phase9Error> {
        let (pairs, _) = build_pairs()?;
        validate_balance(&pairs)
    }

    #[test]
    fn deterministic_bundle_is_byte_stable() -> Result<(), Phase9Error> {
        let first = build_bundle(root())?;
        let second = build_bundle(root())?;
        assert_eq!(first.files, second.files);
        assert_eq!(first.report, second.report);
        Ok(())
    }

    #[test]
    fn committed_holdout_validates_when_present() -> Result<(), Phase9Error> {
        if root().join(HOLDOUT_ROOT).exists() {
            let report = validate_holdout(root())?;
            assert_eq!(report.pairs, 112);
            assert_eq!(report.cases, 224);
        }
        Ok(())
    }

    #[test]
    fn structural_tokenization_rejects_identifier_only_changes() {
        assert_eq!(
            structural_tokens("const alpha = source.value;"),
            structural_tokens("const beta = request.input;")
        );
        assert_ne!(
            structural_tokens("return run(value);"),
            structural_tokens("if (!allowed) { throw denied; } return run(value);")
        );
    }

    #[test]
    fn source_has_no_process_or_network_launch_api() {
        let production = include_str!("lib.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap_or_default();
        assert!(!production.contains(&["std::process", "::Command"].concat()));
        assert!(!production.contains(&["Command", "::new"].concat()));
        assert!(!production.contains(&["execute_", "scanner"].concat()));
        assert!(!production.contains(&["/usr/bin/", "secure"].concat()));
        assert!(!production.contains("TcpStream"));
    }

    #[test]
    fn public_summary_contains_no_case_answers() -> Result<(), Phase9Error> {
        let bundle = build_bundle(root())?;
        let debug = format!("{:?}", bundle.report).to_ascii_lowercase();
        assert!(!debug.contains("case-v3-"));
        assert!(!debug.contains("expectation-"));
        Ok(())
    }
}
