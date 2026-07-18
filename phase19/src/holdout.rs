//! Deterministic, scanner-free authoring and validation for the Phase 19 holdout.

#![allow(clippy::too_many_lines)]

use jsonschema::Validator;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

const HOLDOUT_ID: &str = "secure-bench-phase19-multi-scanner-holdout-v1";
const SEED: &str = "secure-bench-phase19-ordering-seed-v1:8f2c731b6d5e409a";
const PAIRS: usize = 56;
const CASES: usize = 112;
const BASE_COMMIT: &str = "aee2c7094983cfb8bdc16cf59b1962add82ca1db";
const BASE_TREE: &str = "23faa0979e7bf641612a768d9952948bc6df2264";
const TAXONOMY_SHA256: &str = "059fe22d7707cf8d17f2c1621fdae9819787a1958ba2ef0421eca4e4ec858452";
const EVIDENCE_SCHEMA_SHA256: &str =
    "f4d2ee7f02a4bf1f668a44ac7770ed290acc388234eb3b6fa2963c0ea7a684f5";
const NORMALIZED_RULES_SHA256: &str =
    "06af4cf6d10da30ad585d57b781cf6aef734add03b90ea36c78e920c4c10a07c";
const METHODOLOGY_SHA256: &str = "ad6119de510efc64c6fe8f871e69106526e7b517e494612232706ca1310137f2";
const INTERNAL_OVERLAP_LIMIT: u64 = 9_850;
const HISTORICAL_OVERLAP_LIMIT: u64 = 9_500;

const FRAMEWORKS: [&str; 4] = ["node", "express", "next-app-router", "server-actions"];
const FORMATS: [&str; 4] = ["javascript", "jsx", "typescript", "tsx"];
const TOPOLOGIES: [&str; 4] = [
    "direct",
    "helper-mediated",
    "inter-file-aliased",
    "control-flow-sensitive",
];
const VARIANTS: [&str; 10] = [
    "misleading-names-comments",
    "aliases",
    "destructuring",
    "wrappers",
    "blocklists",
    "suffix-tricks",
    "mutable-allowlists",
    "non-dominating-guards",
    "caught-exceptions",
    "ambiguous-helpers",
];

// Each family has two occurrences of every framework, format, and topology. Across all families,
// every cell of each 4x4 pairwise table occurs either three or four times (the mathematical ideal
// for 56 observations over 16 cells).
const SCHEDULE: [[[usize; 3]; 8]; 7] = [
    [
        [1, 0, 1],
        [2, 2, 0],
        [1, 3, 3],
        [0, 1, 3],
        [3, 0, 2],
        [0, 1, 2],
        [3, 2, 1],
        [2, 3, 0],
    ],
    [
        [3, 3, 3],
        [1, 1, 3],
        [2, 0, 1],
        [0, 2, 2],
        [3, 3, 0],
        [2, 0, 0],
        [1, 2, 2],
        [0, 1, 1],
    ],
    [
        [3, 1, 3],
        [3, 0, 1],
        [1, 3, 2],
        [0, 1, 0],
        [2, 3, 1],
        [1, 2, 3],
        [2, 2, 2],
        [0, 0, 0],
    ],
    [
        [3, 2, 3],
        [0, 0, 3],
        [1, 2, 2],
        [2, 1, 0],
        [2, 3, 1],
        [0, 3, 0],
        [3, 1, 1],
        [1, 0, 2],
    ],
    [
        [3, 3, 2],
        [0, 2, 0],
        [3, 1, 0],
        [0, 2, 1],
        [2, 0, 2],
        [2, 3, 3],
        [1, 1, 1],
        [1, 0, 3],
    ],
    [
        [1, 3, 0],
        [1, 0, 0],
        [2, 2, 3],
        [3, 2, 1],
        [0, 0, 3],
        [0, 3, 1],
        [2, 1, 2],
        [3, 1, 2],
    ],
    [
        [0, 0, 2],
        [3, 0, 3],
        [2, 2, 3],
        [2, 1, 1],
        [0, 3, 2],
        [1, 1, 0],
        [1, 3, 1],
        [3, 2, 0],
    ],
];

const PRIOR_PUBLIC_ROOTS: [&str; 9] = [
    "fixtures/vulnerable",
    "fixtures/safe",
    "holdout/phase-3",
    "holdout/phase-5",
    "holdout/phase-9",
    "diagnostics/phase-6",
    "phase12/public-regression",
    "phase17/fixtures/conformance/workspace",
    "phase18/fixtures/conformance/workspace",
];

const STATIC_CHECKSUM_PATHS: [&str; 14] = [
    "phase19/Cargo.lock",
    "phase19/bindings/secure-engine-v0.1.6.json",
    "phase19/execution/opengrep-v1.22.0.json",
    "phase19/execution/secure-engine-v0.1.6.json",
    "phase19/execution/semgrep-ce-v1.170.0.json",
    "phase19/methodology/comparison-lanes-v1.json",
    "phase19/provenance/historical-integrity-v1.json",
    "phase19/provenance/secure-engine-v0.1.6.json",
    "phase19/rules/capability-normalized-v1.yml",
    "phase19/schemas/commitments-v1.schema.json",
    "phase19/schemas/execution-contract-v1.schema.json",
    "phase19/schemas/genesis-ledger-entry-v1.schema.json",
    "phase19/schemas/holdout-manifest-v1.schema.json",
    "phase19/schemas/secure-engine-binding-v1.schema.json",
];

/// Scanner-free Phase 19 authoring or validation failure.
#[derive(Debug, Error)]
pub enum HoldoutError {
    /// A filesystem operation failed.
    #[error("filesystem operation failed for {path}: {detail}")]
    Io {
        /// Affected path.
        path: String,
        /// Operating-system detail.
        detail: String,
    },
    /// Serialization or parsing failed.
    #[error("JSON operation failed: {0}")]
    Json(String),
    /// A frozen schema rejected an artifact.
    #[error("schema validation failed: {0}")]
    Schema(String),
    /// A semantic, balance, privacy, or integrity invariant failed.
    #[error("Phase 19 invariant failed: {0}")]
    Invariant(String),
}

#[derive(Clone, Copy)]
struct Family {
    id: &'static str,
    cwe: &'static str,
    source_kind: &'static str,
    sink_kind: &'static str,
    resource: &'static str,
    property: &'static str,
}

const FAMILIES: [Family; 7] = [
    Family {
        id: "SE1001",
        cwe: "CWE-862",
        source_kind: "protected_resource_id",
        sink_kind: "protected_record_mutation",
        resource: "protected-record",
        property: "resource-bound authorization dominates the protected mutation",
    },
    Family {
        id: "SE1002",
        cwe: "CWE-78",
        source_kind: "http_body_field",
        sink_kind: "os_command_execution",
        resource: "operating-system-command",
        property: "only a fixed executable and fixed argument array can reach process execution",
    },
    Family {
        id: "SE1003",
        cwe: "CWE-95",
        source_kind: "http_body_field",
        sink_kind: "dynamic_code_evaluation",
        resource: "application-operation",
        property: "request data selects a fixed operation and is never evaluated as code",
    },
    Family {
        id: "SE1004",
        cwe: "CWE-22",
        source_kind: "http_body_field",
        sink_kind: "filesystem_read",
        resource: "confined-filesystem-root",
        property: "canonical target remains within the canonical root before the read",
    },
    Family {
        id: "SE1005",
        cwe: "CWE-918",
        source_kind: "http_body_field",
        sink_kind: "outbound_request",
        resource: "outbound-origin",
        property: "HTTPS destination origin is in an exact immutable allowlist",
    },
    Family {
        id: "SE1006",
        cwe: "CWE-601",
        source_kind: "http_body_field",
        sink_kind: "redirect_response",
        resource: "redirect-origin",
        property: "resolved redirect destination has the exact application origin",
    },
    Family {
        id: "SE1007",
        cwe: "CWE-89",
        source_kind: "http_body_field",
        sink_kind: "sql_query_execution",
        resource: "parameterized-database-query",
        property: "request data is carried only in a bound SQL parameter",
    },
];

#[derive(Clone)]
struct Assignment {
    family: usize,
    framework: usize,
    format: usize,
    topology: usize,
    variant: Option<usize>,
    original_ordinal: usize,
}

struct RenderedPair {
    vulnerable: BTreeMap<String, String>,
    control: BTreeMap<String, String>,
    mutation_file: String,
    vulnerable_fragment: String,
    control_fragment: String,
    source_file: String,
    source_needle: String,
    propagation_needle: String,
    vulnerable_sink_needle: String,
    control_sink_needle: String,
    barrier_needle: String,
    barrier_role: &'static str,
    barrier_effects: Vec<&'static str>,
}

/// Summary returned by deterministic authoring or validation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct HoldoutSummary {
    /// Frozen pair count.
    pub pairs: usize,
    /// Frozen case count.
    pub cases: usize,
    /// Aggregate corpus hash.
    pub aggregate_corpus_sha256: String,
    /// Evidence Contract Merkle root.
    pub contract_merkle_root: String,
    /// Number of generated files including fixtures and frozen metadata.
    pub generated_files: usize,
}

struct Bundle {
    files: BTreeMap<String, Vec<u8>>,
    summary: HoldoutSummary,
}

/// Creates the frozen holdout using create-new semantics.
///
/// # Errors
///
/// Returns an error for any existing generated path or failed invariant.
pub fn author(root: &Path) -> Result<HoldoutSummary, HoldoutError> {
    let bundle = build_bundle(root)?;
    for relative in bundle.files.keys() {
        let path = root.join(relative);
        if path.exists() {
            return Err(HoldoutError::Invariant(format!(
                "authoring refuses to replace existing {relative}"
            )));
        }
    }
    for (relative, bytes) in &bundle.files {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| io(parent, error))?;
        }
        fs::write(&path, bytes).map_err(|error| io(&path, error))?;
    }
    Ok(bundle.summary)
}

/// Reconstructs the entire holdout in memory and compares every committed byte.
///
/// # Errors
///
/// Returns an error for missing, extra, or changed generated files or failed invariants.
pub fn validate(root: &Path) -> Result<HoldoutSummary, HoldoutError> {
    let bundle = build_bundle(root)?;
    for (relative, expected) in &bundle.files {
        let path = root.join(relative);
        let actual = read(&path)?;
        if &actual != expected {
            return Err(HoldoutError::Invariant(format!(
                "deterministic reconstruction differs at {relative}"
            )));
        }
    }
    let mut actual = Vec::new();
    collect_regular_files(&root.join("phase19/holdout"), &mut actual)?;
    let expected = bundle
        .files
        .keys()
        .map(|path| root.join(path))
        .collect::<BTreeSet<_>>();
    for path in actual {
        if !expected.contains(&path) {
            return Err(HoldoutError::Invariant(format!(
                "unexpected generated artifact {}",
                path.display()
            )));
        }
    }
    Ok(bundle.summary)
}

fn build_bundle(root: &Path) -> Result<Bundle, HoldoutError> {
    validate_static_inputs(root)?;
    let assignments = assignments();
    validate_balance(&assignments)?;

    let evidence_schema = validator(
        root,
        "phase16/schemas/declared-evidence-contract-v2.schema.json",
    )?;
    let mut files = BTreeMap::<String, Vec<u8>>::new();
    let mut pairs = Vec::<Value>::with_capacity(PAIRS);
    let mut evidence_leaves = Vec::<String>::with_capacity(CASES);
    let mut case_sources = Vec::<(usize, String, String)>::with_capacity(CASES);

    for (rank, assignment) in assignments.iter().enumerate() {
        let pair_id = format!("pair-p19-{:04}", rank + 1);
        let first_case_id = format!("case-p19-{:04}", rank * 2 + 1);
        let second_case_id = format!("case-p19-{:04}", rank * 2 + 2);
        let rendered = render_pair(assignment)?;
        validate_mutation(&rendered)?;
        let vulnerable_first = rank % 2 == 0;
        let (first_kind, second_kind) = if vulnerable_first {
            ("vulnerable", "control")
        } else {
            ("control", "vulnerable")
        };
        let (first_files, second_files) = if vulnerable_first {
            (&rendered.vulnerable, &rendered.control)
        } else {
            (&rendered.control, &rendered.vulnerable)
        };
        let first = case_value(
            root,
            &evidence_schema,
            assignment,
            &first_case_id,
            first_kind,
            first_files,
            &rendered,
        )?;
        let second = case_value(
            root,
            &evidence_schema,
            assignment,
            &second_case_id,
            second_kind,
            second_files,
            &rendered,
        )?;
        evidence_leaves.push(sha256(&canonical(&first["evidence"])?));
        evidence_leaves.push(sha256(&canonical(&second["evidence"])?));
        add_case_files(&mut files, &first_case_id, first_files)?;
        add_case_files(&mut files, &second_case_id, second_files)?;
        case_sources.push((rank, first_case_id.clone(), combined_source(first_files)));
        case_sources.push((rank, second_case_id.clone(), combined_source(second_files)));

        let family = FAMILIES[assignment.family];
        pairs.push(json!({
            "pair_id": pair_id,
            "assignment": {
                "family": family.id,
                "primary_cwe": family.cwe,
                "framework": FRAMEWORKS[assignment.framework],
                "source_format": FORMATS[assignment.format],
                "topology": TOPOLOGIES[assignment.topology],
                "adversarial_variant": assignment.variant.map(|index| VARIANTS[index]),
                "source_schedule_ordinal": assignment.original_ordinal
            },
            "invariants": {
                "value_identity": "candidate-to-selectedValue",
                "resource_identity": family.resource,
                "sink_kind": family.sink_kind,
                "source_kind": family.source_kind,
                "same_value_resource_and_sensitive_operation": true,
                "scanner_specific_syntax": false
            },
            "mutation": {
                "file": rendered.mutation_file,
                "vulnerable_fragment_sha256": sha256(rendered.vulnerable_fragment.as_bytes()),
                "control_fragment_sha256": sha256(rendered.control_fragment.as_bytes()),
                "bidirectional_inverse_verified": true,
                "only_one_file_differs": true
            },
            "first": first,
            "second": second
        }));
    }

    let overlap = overlap_report(root, &case_sources)?;
    let aggregate = aggregate_corpus(&files);
    let merkle = merkle_root(&evidence_leaves)?;
    let balance = balance_value(&assignments);
    let manifest = json!({
        "schema_version": "secure-bench-phase19-holdout-v1",
        "holdout_id": HOLDOUT_ID,
        "status": "frozen-before-execution",
        "seed": SEED,
        "ordering_procedure": "sort SHA-256(seed NUL family-index NUL family-local-index); assign opaque sequential pair/case IDs; alternate vulnerable orientation by randomized rank",
        "taxonomy": { "version": "1.0.0", "path": "taxonomy/secure-bench-taxonomy-v1.json", "sha256": TAXONOMY_SHA256 },
        "evidence_contract": { "version": "2.0.0", "path": "phase16/schemas/declared-evidence-contract-v2.schema.json", "sha256": EVIDENCE_SCHEMA_SHA256 },
        "counts": { "pairs": PAIRS, "cases": CASES, "vulnerable": PAIRS, "controls": PAIRS },
        "aggregate_corpus_sha256": aggregate,
        "contract_merkle_root": merkle,
        "balance": balance,
        "pairs": pairs
    });
    validate_value(
        root,
        "phase19/schemas/holdout-manifest-v1.schema.json",
        &manifest,
    )?;
    let manifest_bytes = pretty(&manifest)?;

    let execution_contracts = execution_hashes(root)?;
    let provenance = json!({
        "schema_version": "secure-bench-phase19-holdout-provenance-v1",
        "holdout_id": HOLDOUT_ID,
        "frozen_at_utc": "2026-07-18T00:00:00Z",
        "authoring": {
            "generator": "secure-bench-phase19-binding/holdout-v1",
            "scanner_free": true,
            "holdout_cases_executed": 0,
            "network_operations": 0,
            "ai_providers": 0,
            "credential_flows": 0
        },
        "base": { "commit": BASE_COMMIT, "tree": BASE_TREE },
        "inputs": {
            "taxonomy_sha256": TAXONOMY_SHA256,
            "evidence_contract_schema_sha256": EVIDENCE_SCHEMA_SHA256,
            "normalized_rules_sha256": NORMALIZED_RULES_SHA256,
            "comparison_methodology_sha256": METHODOLOGY_SHA256,
            "secure_engine_binding_sha256": "f0a37799d4bc6b66eef8b4d9fcfc0eae3c9272b00bc3901ce996917f4cdcc1e1",
            "execution_contracts": execution_contracts
        },
        "overlap": overlap,
        "historical_corpus_roots_compared": PRIOR_PUBLIC_ROOTS,
        "phase13_phase14_boundary": "not read or consumed; integrity is bound only by the Phase 18 base tree",
        "limitations": [
            "This phase freezes an examination and contains no scanner observations or scores.",
            "OpenGrep and Semgrep native lanes are unavailable because no eligible offline native ruleset is frozen.",
            "Secure Engine capability-normalized lane is unavailable because v0.1.6 exposes no public external-rule interface.",
            "Static fixtures model bounded framework entrypoints and do not claim complete real-world coverage."
        ]
    });
    let provenance_bytes = pretty(&provenance)?;

    let commitments = json!({
        "schema_version": "secure-bench-phase19-commitments-v1",
        "holdout_id": HOLDOUT_ID,
        "frozen_before_execution": true,
        "seed_sha256": sha256(SEED.as_bytes()),
        "aggregate_corpus_sha256": aggregate,
        "contract_merkle_root": merkle,
        "manifest_sha256": sha256(&manifest_bytes),
        "provenance_sha256": sha256(&provenance_bytes),
        "execution_contracts": execution_contracts,
        "ruleset_sha256": NORMALIZED_RULES_SHA256,
        "methodology_sha256": METHODOLOGY_SHA256,
        "balance": balance,
        "overlap": overlap,
        "checksum_scope": "all generated holdout files plus frozen Phase 19 bindings, execution contracts, schemas, rules, methodology, and provenance; excludes SHA256SUMS itself"
    });
    validate_value(
        root,
        "phase19/schemas/commitments-v1.schema.json",
        &commitments,
    )?;
    let commitments_bytes = pretty(&commitments)?;
    let mut ledger = json!({
        "schema_version": "secure-bench-phase19-ledger-entry-v1",
        "sequence": 0,
        "event": "holdout_frozen",
        "holdout_id": HOLDOUT_ID,
        "status": "genesis-no-execution",
        "manifest_sha256": sha256(&manifest_bytes),
        "commitments_sha256": sha256(&commitments_bytes),
        "aggregate_corpus_sha256": aggregate,
        "contract_merkle_root": merkle,
        "previous_entry_hash": "0".repeat(64),
        "entry_hash": "0".repeat(64)
    });
    let ledger_hash = sha256(&canonical_without(&ledger, "entry_hash")?);
    ledger["entry_hash"] = Value::String(ledger_hash);
    validate_value(
        root,
        "phase19/schemas/genesis-ledger-entry-v1.schema.json",
        &ledger,
    )?;
    let mut ledger_bytes = canonical(&ledger)?;
    ledger_bytes.push(b'\n');

    files.insert("phase19/holdout/manifest.json".to_owned(), manifest_bytes);
    files.insert(
        "phase19/holdout/provenance.json".to_owned(),
        provenance_bytes,
    );
    files.insert(
        "phase19/holdout/commitments.json".to_owned(),
        commitments_bytes,
    );
    files.insert(
        "phase19/holdout/genesis-ledger.jsonl".to_owned(),
        ledger_bytes,
    );
    let sums = checksum_file(root, &files)?;
    files.insert("phase19/holdout/SHA256SUMS".to_owned(), sums);
    privacy_check(&files)?;

    Ok(Bundle {
        summary: HoldoutSummary {
            pairs: PAIRS,
            cases: CASES,
            aggregate_corpus_sha256: aggregate,
            contract_merkle_root: merkle,
            generated_files: files.len(),
        },
        files,
    })
}

fn assignments() -> Vec<Assignment> {
    let mut values = Vec::with_capacity(PAIRS);
    for (family, rows) in SCHEDULE.iter().enumerate() {
        for (local, row) in rows.iter().enumerate() {
            values.push(Assignment {
                family,
                framework: row[0],
                format: row[1],
                topology: row[2],
                variant: None,
                original_ordinal: family * 8 + local + 1,
            });
        }
    }
    values.sort_by_key(|assignment| {
        sha256(
            format!(
                "{SEED}\0{}\0{}",
                assignment.family, assignment.original_ordinal
            )
            .as_bytes(),
        )
    });
    let requested_family = [
        None,
        None,
        None,
        None,
        Some(2),
        Some(5),
        Some(4),
        None,
        None,
        Some(1),
    ];
    let mut used = BTreeSet::new();
    for (variant, family) in requested_family.into_iter().enumerate() {
        if let Some((index, assignment)) =
            values.iter_mut().enumerate().find(|(index, assignment)| {
                !used.contains(index) && family.is_none_or(|value| assignment.family == value)
            })
        {
            assignment.variant = Some(variant);
            used.insert(index);
        }
    }
    values
}

fn render_pair(assignment: &Assignment) -> Result<RenderedPair, HoldoutError> {
    let family = FAMILIES[assignment.family];
    let extension = ["js", "jsx", "ts", "tsx"][assignment.format];
    let typed = assignment.format >= 2;
    let jsx = matches!(assignment.format, 1 | 3);
    let entry_path = match assignment.framework {
        0 => format!("src/endpoint.{extension}"),
        1 => format!("src/router.{extension}"),
        2 => format!("app/api/dispatch/route.{extension}"),
        3 => format!("app/actions.{extension}"),
        _ => return Err(HoldoutError::Invariant("unknown framework".to_owned())),
    };
    let operation_path = match assignment.framework {
        2 | 3 => format!("app/operation.{extension}"),
        _ => format!("src/operation.{extension}"),
    };
    let source_expression = source_expression(assignment.framework, assignment.family);
    let source_needle = source_expression.clone();
    let source_setup = source_setup(assignment.framework, assignment.family, typed);
    let context_setup = context_setup(assignment.framework, assignment.family);
    let type_decl = if typed {
        "type OperationContext = { actorId?: string; patch?: unknown; extend?: boolean; mode?: number };\n"
    } else {
        ""
    };
    let context_type = if typed { ": OperationContext" } else { "" };
    let params_type = if typed { ": string" } else { "" };
    let (
        support,
        vulnerable_body,
        control_body,
        vulnerable_sink,
        control_sink,
        barrier,
        role,
        effects,
    ) = family_code(family, params_type)?;
    let variant = variant_prelude(assignment.variant, assignment.original_ordinal);
    let vulnerable_fragment = format!("{variant}{vulnerable_body}");
    let control_fragment = format!("{variant}{control_body}");
    let directive = if assignment.framework == 3 {
        "\"use server\";\n\n"
    } else {
        ""
    };
    let jsx_tail = if jsx {
        "  const presentation = <span>{String(result)}</span>;\n  void presentation;\n"
    } else {
        ""
    };
    let handler_head = handler_head(assignment.framework, typed);
    let handler_tail = handler_tail(assignment.framework, jsx_tail);
    let nonce_line = format!(
        "  const braid{} = candidate.slice(0, {} % 5);\n  if (braid{}.length > candidate.length) {{ throw new Error(\"unreachable\"); }}\n",
        assignment.original_ordinal,
        assignment.original_ordinal + 7,
        assignment.original_ordinal
    );
    let call = "  const result = await operate(candidate, context);\n";
    let mut vulnerable = BTreeMap::new();
    let mut control = BTreeMap::new();

    match assignment.topology {
        0 => {
            let common_head = format!(
                "{directive}{type_decl}{support}\n{handler_head}{source_setup}{context_setup}{nonce_line}"
            );
            vulnerable.insert(
                entry_path.clone(),
                format!(
                    "{common_head}{}{jsx_tail}{handler_tail}",
                    indent(&vulnerable_fragment, 2)
                ),
            );
            control.insert(
                entry_path.clone(),
                format!(
                    "{common_head}{}{jsx_tail}{handler_tail}",
                    indent(&control_fragment, 2)
                ),
            );
        }
        1 | 3 => {
            let branch_open = if assignment.topology == 3 {
                "  if (candidate.length >= 0) {\n"
            } else {
                ""
            };
            let branch_close = if assignment.topology == 3 {
                "    return result;\n  }\n  throw new Error(\"unreachable\");\n"
            } else {
                "  return result;\n"
            };
            let function_head = format!(
                "async function operate(candidate{params_type}, context{context_type}) {{\n{branch_open}"
            );
            let body_indent = if assignment.topology == 3 { 4 } else { 2 };
            let common_entry = format!(
                "{directive}{type_decl}{support}\n{handler_head}{source_setup}{context_setup}{nonce_line}{call}{jsx_tail}{handler_tail}\n"
            );
            vulnerable.insert(
                entry_path.clone(),
                format!(
                    "{common_entry}{function_head}{}{branch_close}}}\n",
                    indent(&vulnerable_fragment, body_indent)
                ),
            );
            control.insert(
                entry_path.clone(),
                format!(
                    "{common_entry}{function_head}{}{branch_close}}}\n",
                    indent(&control_fragment, body_indent)
                ),
            );
        }
        2 => {
            let import_path = match assignment.framework {
                2 => format!("../../operation.{extension}"),
                _ => format!("./operation.{extension}"),
            };
            let entry = format!(
                "{directive}import {{ operate as relayOperation }} from \"{import_path}\";\n\n{handler_head}{source_setup}{context_setup}{nonce_line}  const result = await relayOperation(candidate, context);\n{jsx_tail}{handler_tail}"
            );
            vulnerable.insert(entry_path.clone(), entry.clone());
            control.insert(entry_path.clone(), entry);
            let operation_head = format!(
                "{type_decl}{support}\nexport async function operate(candidate{params_type}, context{context_type}) {{\n"
            );
            vulnerable.insert(
                operation_path.clone(),
                format!(
                    "{operation_head}{}  return result;\n}}\n",
                    indent(&vulnerable_fragment, 2)
                ),
            );
            control.insert(
                operation_path.clone(),
                format!(
                    "{operation_head}{}  return result;\n}}\n",
                    indent(&control_fragment, 2)
                ),
            );
        }
        _ => return Err(HoldoutError::Invariant("unknown topology".to_owned())),
    }
    let package = b"{\n  \"private\": true,\n  \"type\": \"module\"\n}\n";
    vulnerable.insert(
        "package.json".to_owned(),
        String::from_utf8_lossy(package).into_owned(),
    );
    control.insert(
        "package.json".to_owned(),
        String::from_utf8_lossy(package).into_owned(),
    );
    let mutation_file = if assignment.topology == 2 {
        operation_path
    } else {
        entry_path.clone()
    };
    Ok(RenderedPair {
        vulnerable,
        control,
        mutation_file: mutation_file.clone(),
        vulnerable_fragment: indent(
            &vulnerable_fragment,
            if assignment.topology == 3 { 4 } else { 2 },
        ),
        control_fragment: indent(
            &control_fragment,
            if assignment.topology == 3 { 4 } else { 2 },
        ),
        source_file: entry_path,
        source_needle,
        propagation_needle: "selectedValue".to_owned(),
        vulnerable_sink_needle: vulnerable_sink.to_owned(),
        control_sink_needle: control_sink.to_owned(),
        barrier_needle: barrier.to_owned(),
        barrier_role: role,
        barrier_effects: effects,
    })
}

fn source_expression(framework: usize, family: usize) -> String {
    let field = if family == 0 { "resourceId" } else { "value" };
    match framework {
        0 | 2 => format!("payload[\"{field}\"]"),
        1 => format!("request.body[\"{field}\"]"),
        3 => format!("formData.get(\"{field}\")"),
        _ => String::new(),
    }
}

fn source_setup(framework: usize, family: usize, typed: bool) -> String {
    let expression = source_expression(framework, family);
    let payload = if matches!(framework, 0 | 2) {
        if typed {
            "  const payload = (await request.json()) as Record<string, unknown>;\n"
        } else {
            "  const payload = await request.json();\n"
        }
    } else {
        ""
    };
    format!("{payload}  const candidate = String({expression} ?? \"\");\n")
}

fn context_setup(framework: usize, family: usize) -> String {
    if family != 0 {
        return "  const context = { extend: false, mode: 0 };\n".to_owned();
    }
    let actor = match framework {
        0 | 2 => "payload[\"actorId\"]",
        1 => "request.body[\"actorId\"]",
        3 => "formData.get(\"actorId\")",
        _ => "\"\"",
    };
    let patch = match framework {
        0 | 2 => "payload[\"patch\"]",
        1 => "request.body[\"patch\"]",
        3 => "formData.get(\"patch\")",
        _ => "null",
    };
    format!("  const context = {{ actorId: String({actor} ?? \"\"), patch: {patch} ?? {{}} }};\n")
}

fn handler_head(framework: usize, typed: bool) -> String {
    match (framework, typed) {
        (0, false) => "export async function handler(request) {\n".to_owned(),
        (0, true) => "export async function handler(request: Request) {\n".to_owned(),
        (1, false) => "export async function handler(request, response) {\n".to_owned(),
        (1, true) => "export async function handler(request: { body: Record<string, unknown> }, response: { json(value: unknown): unknown }) {\n".to_owned(),
        (2, false) => "export async function POST(request) {\n".to_owned(),
        (2, true) => "export async function POST(request: Request) {\n".to_owned(),
        (3, false) => "export async function action(formData) {\n".to_owned(),
        (3, true) => "export async function action(formData: FormData) {\n".to_owned(),
        _ => String::new(),
    }
}

fn handler_tail(framework: usize, jsx_tail: &str) -> String {
    let _ = jsx_tail;
    match framework {
        0 | 3 => "  return { ok: Boolean(result) };\n}\n".to_owned(),
        1 => "  return response.json({ ok: Boolean(result) });\n}\n".to_owned(),
        2 => "  return Response.json({ ok: Boolean(result) });\n}\n".to_owned(),
        _ => String::new(),
    }
}

#[allow(clippy::type_complexity)]
fn family_code(
    family: Family,
    parameter_type: &str,
) -> Result<
    (
        String,
        String,
        String,
        &'static str,
        &'static str,
        &'static str,
        &'static str,
        Vec<&'static str>,
    ),
    HoldoutError,
> {
    let code = match family.id {
        "SE1001" => (
            "const records = { update: async (resource, patch) => ({ resource, patch }) };\nconst grants = new Map([[\"acct_admin\", new Set([\"document:record_alpha:update\"])]]);\nconst policy = { allows: async (actor, operation, resource) => grants.get(actor)?.has(`document:${resource}:${operation}`) ?? false };\n".to_owned(),
            "const selectedValue = flowValue;\nconst result = await records.update(selectedValue, context.patch);\n".to_owned(),
            "const selectedValue = flowValue;\nif (!(await policy.allows(context.actorId, \"update\", selectedValue))) {\n  throw new Error(\"denied\");\n}\nconst result = await records.update(selectedValue, context.patch);\n".to_owned(),
            "records.update(selectedValue, context.patch)",
            "records.update(selectedValue, context.patch)",
            "await policy.allows(context.actorId, \"update\", selectedValue)",
            "authorization",
            vec!["authorizes_operation", "rejects_and_terminates"],
        ),
        "SE1002" => (
            "import { exec, execFile } from \"node:child_process\";\n".to_owned(),
            "const selectedValue = flowValue;\nconst result = exec(selectedValue);\n".to_owned(),
            "const selectedValue = flowValue;\nconst fixedExecutables = Object.freeze({ status: Object.freeze([\"/usr/bin/systemctl\", Object.freeze([\"status\", \"--no-pager\"])]), date: Object.freeze([\"/usr/bin/date\", Object.freeze([\"--iso-8601=seconds\"])]) });\nconst executable = fixedExecutables[selectedValue];\nif (!executable) { throw new Error(\"unsupported operation\"); }\nconst result = execFile(executable[0], executable[1]);\n".to_owned(),
            "exec(selectedValue)",
            "execFile(executable[0], executable[1])",
            "const executable = fixedExecutables[selectedValue]",
            "sanitizer",
            vec!["separates_control_and_data", "rejects_and_terminates"],
        ),
        "SE1003" => (
            String::new(),
            "const selectedValue = flowValue;\nconst result = (0, eval)(selectedValue);\n".to_owned(),
            format!("const selectedValue = flowValue;\nconst fixedOperations = Object.freeze({{ add: (left{parameter_type}, right{parameter_type}) => Number(left) + Number(right), multiply: (left{parameter_type}, right{parameter_type}) => Number(left) * Number(right) }});\nconst operation = fixedOperations[selectedValue];\nif (!operation) {{ throw new Error(\"unsupported operation\"); }}\nconst result = operation(2, 3);\n"),
            "(0, eval)(selectedValue)",
            "operation(2, 3)",
            "const operation = fixedOperations[selectedValue]",
            "sanitizer",
            vec!["separates_control_and_data", "rejects_and_terminates"],
        ),
        "SE1004" => (
            "import { readFile, realpath } from \"node:fs/promises\";\nimport { join, sep } from \"node:path\";\nconst ROOT = \"/srv/app/public\";\n".to_owned(),
            "const selectedValue = flowValue;\nconst target = join(ROOT, selectedValue);\nconst result = await readFile(target, \"utf8\");\n".to_owned(),
            "const selectedValue = flowValue;\nconst rootReal = await realpath(ROOT);\nconst target = await realpath(join(rootReal, selectedValue));\nif (target !== rootReal && !target.startsWith(rootReal + sep)) {\n  throw new Error(\"outside root\");\n}\nconst result = await readFile(target, \"utf8\");\n".to_owned(),
            "readFile(target, \"utf8\")",
            "readFile(target, \"utf8\")",
            "const rootReal = await realpath(ROOT)",
            "guard",
            vec!["constrains_to_policy", "rejects_and_terminates"],
        ),
        "SE1005" => (
            String::new(),
            "const selectedValue = flowValue;\nconst result = await fetch(selectedValue, { redirect: \"manual\" });\n".to_owned(),
            "const selectedValue = flowValue;\nconst allowedOrigins = Object.freeze([\"https://api.example.test\"]);\nconst destination = new URL(selectedValue);\nif (destination.protocol !== \"https:\" || !allowedOrigins.includes(destination.origin)) {\n  throw new Error(\"origin denied\");\n}\nconst result = await fetch(destination, { redirect: \"manual\" });\n".to_owned(),
            "fetch(selectedValue, { redirect: \"manual\" })",
            "fetch(destination, { redirect: \"manual\" })",
            "const allowedOrigins = Object.freeze([\"https://api.example.test\"])",
            "guard",
            vec!["constrains_to_policy", "rejects_and_terminates"],
        ),
        "SE1006" => (
            "const ORIGIN = \"https://app.example.test\";\n".to_owned(),
            "const selectedValue = flowValue;\nconst result = Response.redirect(selectedValue, 302);\n".to_owned(),
            "const selectedValue = flowValue;\nconst destination = new URL(selectedValue, ORIGIN);\nif (destination.origin !== ORIGIN) { throw new Error(\"origin denied\"); }\nconst result = Response.redirect(destination, 302);\n".to_owned(),
            "Response.redirect(selectedValue, 302)",
            "Response.redirect(destination, 302)",
            "if (destination.origin !== ORIGIN)",
            "guard",
            vec!["constrains_to_policy", "rejects_and_terminates"],
        ),
        "SE1007" => (
            "const db = { query: async (text, values = []) => ({ text, values }) };\n".to_owned(),
            "const selectedValue = flowValue;\nconst result = await db.query(\"SELECT title FROM documents WHERE id = \" + selectedValue);\n".to_owned(),
            "const selectedValue = flowValue;\nconst result = await db.query(\"SELECT title FROM documents WHERE id = $1\", [selectedValue]);\n".to_owned(),
            "db.query(\"SELECT title FROM documents WHERE id = \" + selectedValue)",
            "db.query(\"SELECT title FROM documents WHERE id = $1\", [selectedValue])",
            "db.query(\"SELECT title FROM documents WHERE id = $1\", [selectedValue])",
            "sanitizer",
            vec!["separates_control_and_data"],
        ),
        _ => return Err(HoldoutError::Invariant("unknown family".to_owned())),
    };
    Ok(code)
}

fn variant_prelude(variant: Option<usize>, ordinal: usize) -> String {
    match variant {
        Some(0) => "// Compatibility name: verifiedInput still carries request data.\nconst verifiedInput = candidate;\nconst flowValue = verifiedInput;\n".to_owned(),
        Some(1) => "const aliasOne = candidate;\nconst aliasTwo = aliasOne;\nconst flowValue = aliasTwo;\n".to_owned(),
        Some(2) => "const { value: destructuredValue } = { value: candidate };\nconst flowValue = destructuredValue;\n".to_owned(),
        Some(3) => "const unwrapValue = (box) => box.payload;\nconst flowValue = unwrapValue({ payload: candidate });\n".to_owned(),
        Some(4) => "const blockedValues = new Set([\"forbidden\"]);\nif (blockedValues.has(candidate)) { throw new Error(\"blocked\"); }\nconst flowValue = candidate;\n".to_owned(),
        Some(5) => "const flowValue = candidate.endsWith(\".trusted\") ? candidate.slice(0, -8) : candidate;\n".to_owned(),
        Some(6) => "const policyHints = [\"fixed\"];\nif (context.extend === true) { policyHints.push(candidate); }\nconst flowValue = candidate;\n".to_owned(),
        Some(7) => "if (candidate.length === 0) { Promise.resolve().then(() => { throw new Error(\"late rejection\"); }); }\nconst flowValue = candidate;\n".to_owned(),
        Some(8) => "try { if (candidate === \"blocked\") { throw new Error(\"compatibility\"); } } catch { /* request continues */ }\nconst flowValue = candidate;\n".to_owned(),
        Some(9) => "const helpers = [(value) => value, (value) => String(value)];\nconst flowValue = helpers[context.mode === 1 ? 1 : 0](candidate);\n".to_owned(),
        _ => format!("const structuralMarker{ordinal} = candidate.length + {ordinal};\nvoid structuralMarker{ordinal};\nconst flowValue = candidate;\n"),
    }
}

fn indent(value: &str, spaces: usize) -> String {
    let prefix = " ".repeat(spaces);
    let mut output = String::new();
    for line in value.lines() {
        output.push_str(&prefix);
        output.push_str(line);
        output.push('\n');
    }
    output
}

fn case_value(
    root: &Path,
    evidence_schema: &Validator,
    assignment: &Assignment,
    case_id: &str,
    classification: &str,
    files: &BTreeMap<String, String>,
    rendered: &RenderedPair,
) -> Result<Value, HoldoutError> {
    let family = FAMILIES[assignment.family];
    let source = files
        .get(&rendered.source_file)
        .ok_or_else(|| HoldoutError::Invariant(format!("missing source file for {case_id}")))?;
    let mutation = files
        .get(&rendered.mutation_file)
        .ok_or_else(|| HoldoutError::Invariant(format!("missing mutation file for {case_id}")))?;
    let source_span = location(&rendered.source_file, source, &rendered.source_needle)?;
    let propagation_span = location(
        &rendered.mutation_file,
        mutation,
        &rendered.propagation_needle,
    )?;
    let sink_needle = if classification == "vulnerable" {
        &rendered.vulnerable_sink_needle
    } else {
        &rendered.control_sink_needle
    };
    let sink_span = location(&rendered.mutation_file, mutation, sink_needle)?;
    let mut path = vec![
        json!({ "role": "source", "effect": "preserves_influence", "source_kind": family.source_kind, "span": source_span, "summarizable": true }),
        json!({ "role": "propagation", "effect": "preserves_influence", "span": propagation_span, "summarizable": true }),
    ];
    let mut barriers = Vec::<Value>::new();
    if classification == "control" {
        let barrier_span = location(&rendered.mutation_file, mutation, &rendered.barrier_needle)?;
        path.push(json!({
            "role": rendered.barrier_role,
            "effect": rendered.barrier_effects[0],
            "span": barrier_span,
            "summarizable": true
        }));
        barriers = rendered
            .barrier_effects
            .iter()
            .map(|effect| Value::String((*effect).to_owned()))
            .collect();
    }
    path.push(json!({ "role": "sink", "effect": "preserves_influence", "sink_kind": family.sink_kind, "span": sink_span, "summarizable": true }));
    let normalized = normalize_source(&combined_source(files));
    let evidence = json!({
        "contract_version": "2.0.0",
        "semantics_version": "secure-evidence-semantics-v2",
        "path": path,
        "connected_edges": vec![true; if classification == "control" { 3 } else { 2 }],
        "effective_barriers": barriers,
        "unresolved_call": false,
        "uncertain": false,
        "fingerprint": sha256(format!("phase19-evidence\0{case_id}\0{}\0{classification}", family.id).as_bytes()),
        "duplicate_fingerprint": sha256(normalized.as_bytes())
    });
    evidence_schema
        .validate(&evidence)
        .map_err(|error| HoldoutError::Schema(format!("{case_id} evidence: {error}")))?;
    validate_evidence_semantics(&evidence, files, classification)?;
    let file_values = files
        .iter()
        .map(|(path, body)| json!({ "path": path, "sha256": sha256(body.as_bytes()), "bytes": body.len() }))
        .collect::<Vec<_>>();
    let value = json!({
        "case_id": case_id,
        "classification": classification,
        "fixture_path": format!("phase19/holdout/cases/{case_id}"),
        "files": file_values,
        "expected_findings": usize::from(classification == "vulnerable"),
        "security_property": if classification == "control" { Some(family.property) } else { None },
        "evidence": evidence
    });
    let _ = root;
    Ok(value)
}

fn location(path: &str, source: &str, needle: &str) -> Result<Value, HoldoutError> {
    let start = source
        .find(needle)
        .ok_or_else(|| HoldoutError::Invariant(format!("needle `{needle}` missing from {path}")))?;
    let end = start + needle.len();
    let before = &source[..start];
    let start_line = before.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let start_column = before
        .rsplit_once('\n')
        .map_or(start + 1, |(_, tail)| tail.len() + 1);
    let end_before = &source[..end];
    let end_line = end_before.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let end_column = end_before
        .rsplit_once('\n')
        .map_or(end + 1, |(_, tail)| tail.len() + 1);
    Ok(json!({
        "path": path,
        "span": {
            "start_byte": start,
            "end_byte": end,
            "start_line": start_line,
            "start_column": start_column,
            "end_line": end_line,
            "end_column": end_column
        }
    }))
}

fn validate_evidence_semantics(
    evidence: &Value,
    files: &BTreeMap<String, String>,
    classification: &str,
) -> Result<(), HoldoutError> {
    let path = evidence["path"]
        .as_array()
        .ok_or_else(|| HoldoutError::Invariant("evidence path is not an array".to_owned()))?;
    let edges = evidence["connected_edges"]
        .as_array()
        .ok_or_else(|| HoldoutError::Invariant("connected edges are not an array".to_owned()))?;
    if edges.len() + 1 != path.len() || edges.iter().any(|edge| edge != &Value::Bool(true)) {
        return Err(HoldoutError::Invariant(
            "evidence path is disconnected".to_owned(),
        ));
    }
    if classification == "control"
        && evidence["effective_barriers"]
            .as_array()
            .is_none_or(Vec::is_empty)
    {
        return Err(HoldoutError::Invariant(
            "control has no effective barrier".to_owned(),
        ));
    }
    if classification == "vulnerable"
        && evidence["effective_barriers"]
            .as_array()
            .is_some_and(|values| !values.is_empty())
    {
        return Err(HoldoutError::Invariant(
            "vulnerable case unexpectedly declares an effective barrier".to_owned(),
        ));
    }
    for node in path {
        let location = &node["span"];
        let file = location["path"].as_str().ok_or_else(|| {
            HoldoutError::Invariant("evidence path has no source path".to_owned())
        })?;
        let body = files.get(file).ok_or_else(|| {
            HoldoutError::Invariant(format!("evidence references missing file {file}"))
        })?;
        let start = usize::try_from(location["span"]["start_byte"].as_u64().unwrap_or(u64::MAX))
            .unwrap_or(usize::MAX);
        let end = usize::try_from(location["span"]["end_byte"].as_u64().unwrap_or(u64::MAX))
            .unwrap_or(usize::MAX);
        if start >= end
            || end > body.len()
            || !body.is_char_boundary(start)
            || !body.is_char_boundary(end)
        {
            return Err(HoldoutError::Invariant(format!(
                "invalid evidence span in {file}"
            )));
        }
    }
    Ok(())
}

fn validate_mutation(pair: &RenderedPair) -> Result<(), HoldoutError> {
    if pair.vulnerable.keys().collect::<Vec<_>>() != pair.control.keys().collect::<Vec<_>>() {
        return Err(HoldoutError::Invariant("pair file sets differ".to_owned()));
    }
    let differences = pair
        .vulnerable
        .iter()
        .filter(|(path, body)| pair.control.get(*path) != Some(*body))
        .map(|(path, _)| path)
        .collect::<Vec<_>>();
    if differences != [&pair.mutation_file] {
        return Err(HoldoutError::Invariant(
            "pair does not differ in exactly its declared mutation file".to_owned(),
        ));
    }
    let vulnerable = pair
        .vulnerable
        .get(&pair.mutation_file)
        .ok_or_else(|| HoldoutError::Invariant("missing vulnerable mutation file".to_owned()))?;
    let control = pair
        .control
        .get(&pair.mutation_file)
        .ok_or_else(|| HoldoutError::Invariant("missing control mutation file".to_owned()))?;
    if vulnerable.matches(&pair.vulnerable_fragment).count() != 1
        || control.matches(&pair.control_fragment).count() != 1
        || vulnerable.replacen(&pair.vulnerable_fragment, &pair.control_fragment, 1) != *control
        || control.replacen(&pair.control_fragment, &pair.vulnerable_fragment, 1) != *vulnerable
    {
        return Err(HoldoutError::Invariant(
            "pair mutation is not an exact bidirectional inverse".to_owned(),
        ));
    }
    Ok(())
}

fn validate_balance(assignments: &[Assignment]) -> Result<(), HoldoutError> {
    if assignments.len() != PAIRS {
        return Err(HoldoutError::Invariant("pair count drift".to_owned()));
    }
    for family in 0..7 {
        if assignments.iter().filter(|a| a.family == family).count() != 8 {
            return Err(HoldoutError::Invariant("family imbalance".to_owned()));
        }
        for dimension in 0..3 {
            for value in 0..4 {
                let count = assignments
                    .iter()
                    .filter(|a| a.family == family && dimension_value(a, dimension) == value)
                    .count();
                if count != 2 {
                    return Err(HoldoutError::Invariant(
                        "family factor imbalance".to_owned(),
                    ));
                }
            }
        }
    }
    for dimension in 0..3 {
        for value in 0..4 {
            if assignments
                .iter()
                .filter(|a| dimension_value(a, dimension) == value)
                .count()
                != 14
            {
                return Err(HoldoutError::Invariant("factor imbalance".to_owned()));
            }
        }
    }
    for left in 0..3 {
        for right in (left + 1)..3 {
            for left_value in 0..4 {
                for right_value in 0..4 {
                    let count = assignments
                        .iter()
                        .filter(|a| {
                            dimension_value(a, left) == left_value
                                && dimension_value(a, right) == right_value
                        })
                        .count();
                    if !matches!(count, 3 | 4) {
                        return Err(HoldoutError::Invariant(
                            "4x4 pairwise cell is not mathematically balanced".to_owned(),
                        ));
                    }
                }
            }
        }
    }
    let variants = assignments
        .iter()
        .filter_map(|assignment| assignment.variant)
        .collect::<BTreeSet<_>>();
    if variants != (0..VARIANTS.len()).collect::<BTreeSet<_>>() {
        return Err(HoldoutError::Invariant(
            "adversarial variant set drift".to_owned(),
        ));
    }
    Ok(())
}

fn dimension_value(assignment: &Assignment, dimension: usize) -> usize {
    match dimension {
        0 => assignment.framework,
        1 => assignment.format,
        _ => assignment.topology,
    }
}

fn balance_value(assignments: &[Assignment]) -> Value {
    let families = FAMILIES
        .iter()
        .enumerate()
        .map(|(index, family)| {
            (
                family.id.to_owned(),
                assignments.iter().filter(|a| a.family == index).count(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let factors = [
        ("frameworks", FRAMEWORKS.as_slice(), 0),
        ("source_formats", FORMATS.as_slice(), 1),
        ("topologies", TOPOLOGIES.as_slice(), 2),
    ];
    let mut singles = serde_json::Map::new();
    singles.insert("families".to_owned(), json!(families));
    for (name, labels, dimension) in factors {
        let counts = labels
            .iter()
            .enumerate()
            .map(|(index, label)| {
                (
                    (*label).to_owned(),
                    assignments
                        .iter()
                        .filter(|a| dimension_value(a, dimension) == index)
                        .count(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        singles.insert(name.to_owned(), json!(counts));
    }
    let mut pairwise = serde_json::Map::new();
    for (left_name, left_labels, left_dimension) in [
        (
            "family",
            FAMILIES.iter().map(|family| family.id).collect::<Vec<_>>(),
            3usize,
        ),
        ("framework", FRAMEWORKS.to_vec(), 0),
        ("source_format", FORMATS.to_vec(), 1),
        ("topology", TOPOLOGIES.to_vec(), 2),
    ] {
        for (right_name, right_labels, right_dimension) in [
            ("framework", FRAMEWORKS.to_vec(), 0usize),
            ("source_format", FORMATS.to_vec(), 1),
            ("topology", TOPOLOGIES.to_vec(), 2),
        ] {
            if left_dimension >= right_dimension && left_dimension != 3 {
                continue;
            }
            if left_dimension == 3 || left_dimension < right_dimension {
                let mut cells = Vec::new();
                for (left_index, left_label) in left_labels.iter().enumerate() {
                    for (right_index, right_label) in right_labels.iter().enumerate() {
                        let count = assignments
                            .iter()
                            .filter(|assignment| {
                                let left = if left_dimension == 3 {
                                    assignment.family
                                } else {
                                    dimension_value(assignment, left_dimension)
                                };
                                left == left_index
                                    && dimension_value(assignment, right_dimension) == right_index
                            })
                            .count();
                        cells.push(
                            json!({ "left": left_label, "right": right_label, "count": count }),
                        );
                    }
                }
                pairwise.insert(format!("{left_name}_x_{right_name}"), Value::Array(cells));
            }
        }
    }
    let variant_counts = VARIANTS
        .iter()
        .enumerate()
        .map(|(index, variant)| {
            (
                (*variant).to_owned(),
                assignments
                    .iter()
                    .filter(|assignment| assignment.variant == Some(index))
                    .count(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    json!({
        "single": Value::Object(singles),
        "pairwise": Value::Object(pairwise),
        "orientation": { "vulnerable_first": 28, "control_first": 28 },
        "adversarial_variants": variant_counts
    })
}

fn add_case_files(
    output: &mut BTreeMap<String, Vec<u8>>,
    case_id: &str,
    source: &BTreeMap<String, String>,
) -> Result<(), HoldoutError> {
    for (path, body) in source {
        let relative = format!("phase19/holdout/cases/{case_id}/{path}");
        if output
            .insert(relative.clone(), body.as_bytes().to_vec())
            .is_some()
        {
            return Err(HoldoutError::Invariant(format!(
                "duplicate generated path {relative}"
            )));
        }
    }
    Ok(())
}

fn aggregate_corpus(files: &BTreeMap<String, Vec<u8>>) -> String {
    let mut bytes = Vec::new();
    for (path, body) in files {
        if path.starts_with("phase19/holdout/cases/") {
            bytes.extend_from_slice(path.as_bytes());
            bytes.push(0);
            bytes.extend_from_slice(sha256(body).as_bytes());
            bytes.push(b'\n');
        }
    }
    sha256(&bytes)
}

fn merkle_root(leaves: &[String]) -> Result<String, HoldoutError> {
    if leaves.is_empty() {
        return Err(HoldoutError::Invariant(
            "empty contract Merkle tree".to_owned(),
        ));
    }
    let mut layer = leaves.to_vec();
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        for chunk in layer.chunks(2) {
            let right = chunk.get(1).unwrap_or(&chunk[0]);
            next.push(sha256(format!("node\0{}\0{right}", chunk[0]).as_bytes()));
        }
        layer = next;
    }
    Ok(layer[0].clone())
}

fn overlap_report(root: &Path, cases: &[(usize, String, String)]) -> Result<Value, HoldoutError> {
    let mut exact_fingerprints = BTreeSet::new();
    for (_, id, source) in cases {
        if !exact_fingerprints.insert(sha256(source.as_bytes())) {
            return Err(HoldoutError::Invariant(format!(
                "duplicate exact case detected at {id}"
            )));
        }
    }
    let normalized = cases
        .iter()
        .map(|(pair, id, source)| (*pair, id, normalize_source(source)))
        .collect::<Vec<_>>();
    let mut fingerprints = BTreeSet::new();
    for (_, id, source) in &normalized {
        let fingerprint = sha256(source.as_bytes());
        if !fingerprints.insert(fingerprint) {
            return Err(HoldoutError::Invariant(format!(
                "duplicate normalized case detected at {id}"
            )));
        }
    }
    let mut internal_max = 0;
    for left in 0..normalized.len() {
        for right in (left + 1)..normalized.len() {
            if normalized[left].0 != normalized[right].0 {
                internal_max = internal_max.max(jaccard_basis_points(
                    &normalized[left].2,
                    &normalized[right].2,
                ));
            }
        }
    }
    if internal_max > INTERNAL_OVERLAP_LIMIT {
        return Err(HoldoutError::Invariant(format!(
            "cross-pair normalized overlap {internal_max} exceeds {INTERNAL_OVERLAP_LIMIT}"
        )));
    }
    let mut prior_files = Vec::new();
    for relative in PRIOR_PUBLIC_ROOTS {
        let path = root.join(relative);
        if path.exists() {
            collect_source_files(&path, &mut prior_files)?;
        }
    }
    let mut historical_max = 0;
    for path in &prior_files {
        let prior = normalize_source(&String::from_utf8_lossy(&read(path)?));
        for (_, _, source) in &normalized {
            historical_max = historical_max.max(jaccard_basis_points(source, &prior));
        }
    }
    if historical_max > HISTORICAL_OVERLAP_LIMIT {
        return Err(HoldoutError::Invariant(format!(
            "historical normalized overlap {historical_max} exceeds {HISTORICAL_OVERLAP_LIMIT}"
        )));
    }
    Ok(json!({
        "normalization": "lowercase lexical tokens; strings and numbers normalized; comments removed; seven-token shingles",
        "new_case_exact_fingerprints_unique": true,
        "new_case_normalized_fingerprints_unique": true,
        "internal_cross_pair_max_basis_points": internal_max,
        "internal_limit_basis_points": INTERNAL_OVERLAP_LIMIT,
        "historical_max_basis_points": historical_max,
        "historical_limit_basis_points": HISTORICAL_OVERLAP_LIMIT,
        "prior_public_source_files_compared": prior_files.len(),
        "phase13_phase14_consumed": false
    }))
}

fn normalize_source(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut tokens = Vec::<String>::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index].is_ascii_whitespace() {
            index += 1;
        } else if index + 1 < bytes.len() && bytes[index] == b'/' && bytes[index + 1] == b'/' {
            index += 2;
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
        } else if index + 1 < bytes.len() && bytes[index] == b'/' && bytes[index + 1] == b'*' {
            index += 2;
            while index + 1 < bytes.len() && !(bytes[index] == b'*' && bytes[index + 1] == b'/') {
                index += 1;
            }
            index = (index + 2).min(bytes.len());
        } else if matches!(bytes[index], b'\'' | b'"' | b'`') {
            let quote = bytes[index];
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
            tokens.push("<str>".to_owned());
        } else if bytes[index].is_ascii_digit() {
            while index < bytes.len() && bytes[index].is_ascii_digit() {
                index += 1;
            }
            tokens.push("<num>".to_owned());
        } else if bytes[index].is_ascii_alphanumeric() || matches!(bytes[index], b'_' | b'$') {
            let start = index;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric() || matches!(bytes[index], b'_' | b'$'))
            {
                index += 1;
            }
            tokens.push(String::from_utf8_lossy(&bytes[start..index]).to_ascii_lowercase());
        } else {
            tokens.push(char::from(bytes[index]).to_string());
            index += 1;
        }
    }
    tokens.join(" ")
}

fn jaccard_basis_points(left: &str, right: &str) -> u64 {
    let shingles = |value: &str| {
        let tokens = value.split_whitespace().collect::<Vec<_>>();
        tokens
            .windows(7)
            .map(|window| window.join(" "))
            .collect::<BTreeSet<_>>()
    };
    let left_set = shingles(left);
    let right_set = shingles(right);
    let union = left_set.union(&right_set).count();
    if union == 0 {
        return 0;
    }
    (left_set.intersection(&right_set).count() as u64 * 10_000) / union as u64
}

fn combined_source(files: &BTreeMap<String, String>) -> String {
    files
        .iter()
        .filter(|(path, _)| is_source(path))
        .map(|(path, body)| format!("{path}\n{body}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn is_source(path: &str) -> bool {
    [".js", ".jsx", ".ts", ".tsx"]
        .iter()
        .any(|extension| path.ends_with(extension))
}

fn collect_source_files(path: &Path, output: &mut Vec<PathBuf>) -> Result<(), HoldoutError> {
    if path.is_symlink() {
        return Ok(());
    }
    if path.is_file() {
        if path.to_str().is_some_and(is_source) {
            output.push(path.to_path_buf());
        }
        return Ok(());
    }
    let mut entries = fs::read_dir(path)
        .map_err(|error| io(path, error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| io(path, error))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        collect_source_files(&entry.path(), output)?;
    }
    Ok(())
}

fn validate_static_inputs(root: &Path) -> Result<(), HoldoutError> {
    for (path, expected) in [
        ("taxonomy/secure-bench-taxonomy-v1.json", TAXONOMY_SHA256),
        (
            "phase16/schemas/declared-evidence-contract-v2.schema.json",
            EVIDENCE_SCHEMA_SHA256,
        ),
        (
            "phase19/rules/capability-normalized-v1.yml",
            NORMALIZED_RULES_SHA256,
        ),
        (
            "phase19/methodology/comparison-lanes-v1.json",
            METHODOLOGY_SHA256,
        ),
        (
            "phase19/bindings/secure-engine-v0.1.6.json",
            "f0a37799d4bc6b66eef8b4d9fcfc0eae3c9272b00bc3901ce996917f4cdcc1e1",
        ),
    ] {
        let actual = sha256(&read(&root.join(path))?);
        if actual != expected {
            return Err(HoldoutError::Invariant(format!(
                "frozen input hash drift at {path}"
            )));
        }
    }
    for path in [
        "phase19/execution/secure-engine-v0.1.6.json",
        "phase19/execution/opengrep-v1.22.0.json",
        "phase19/execution/semgrep-ce-v1.170.0.json",
    ] {
        let value = parse_value(&root.join(path))?;
        validate_value(
            root,
            "phase19/schemas/execution-contract-v1.schema.json",
            &value,
        )?;
        validate_execution_contract(&value, root)?;
    }
    Ok(())
}

fn validate_execution_contract(value: &Value, root: &Path) -> Result<(), HoldoutError> {
    let serialized = serde_json::to_string(value).map_err(json_error)?;
    let version = value["scanner"]["version"].as_str().ok_or_else(|| {
        HoldoutError::Invariant("execution contract has no scanner version".to_owned())
    })?;
    let artifact_url = value["artifact"]["url"].as_str().ok_or_else(|| {
        HoldoutError::Invariant("execution contract has no artifact URL".to_owned())
    })?;
    if serialized.contains("/latest")
        || !artifact_url.contains(version)
        || value["artifact"]["rebuild_allowed"] != Value::Bool(false)
        || value["artifact"]["version_probe_allowed"] != Value::Bool(false)
        || value["isolation"]["network_allowed"] != Value::Bool(false)
        || value["ai"]["enabled"] != Value::Bool(false)
        || value["reporting"]["combine_lanes"] != Value::Bool(false)
    {
        return Err(HoldoutError::Invariant(
            "execution contract violates isolation or lane freeze".to_owned(),
        ));
    }
    if let Some(runtime) = value["artifact"]["runtime"].as_object() {
        let lock_path = runtime
            .get("dependency_lock")
            .and_then(Value::as_str)
            .ok_or_else(|| HoldoutError::Invariant("runtime lock path is absent".to_owned()))?;
        let expected = runtime
            .get("dependency_lock_sha256")
            .and_then(Value::as_str)
            .ok_or_else(|| HoldoutError::Invariant("runtime lock hash is absent".to_owned()))?;
        if sha256(&read(&root.join(lock_path))?) != expected {
            return Err(HoldoutError::Invariant(
                "runtime dependency lock hash drift".to_owned(),
            ));
        }
    }
    for lane in ["native", "capability_normalized"] {
        let lane_value = &value["lanes"][lane];
        match lane_value["availability"].as_str() {
            Some("available") => {
                if lane_value["command_template"].is_null() || lane_value["ruleset"].is_null() {
                    return Err(HoldoutError::Invariant(format!(
                        "available {lane} lane is incomplete"
                    )));
                }
                if let Some(path) = lane_value["ruleset"]["path"].as_str() {
                    let expected = lane_value["ruleset"]["sha256"].as_str().ok_or_else(|| {
                        HoldoutError::Invariant("local ruleset has no digest".to_owned())
                    })?;
                    if sha256(&read(&root.join(path))?) != expected {
                        return Err(HoldoutError::Invariant(
                            "local ruleset hash drift".to_owned(),
                        ));
                    }
                }
            }
            Some("unsupported") => {
                if lane_value["reason"].as_str().is_none_or(str::is_empty)
                    || !lane_value["command_template"].is_null()
                    || !lane_value["ruleset"].is_null()
                {
                    return Err(HoldoutError::Invariant(format!(
                        "unsupported {lane} lane is not explicit"
                    )));
                }
            }
            _ => {
                return Err(HoldoutError::Invariant(
                    "invalid lane availability".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

fn execution_hashes(root: &Path) -> Result<BTreeMap<String, String>, HoldoutError> {
    [
        (
            "secure-engine",
            "phase19/execution/secure-engine-v0.1.6.json",
        ),
        ("opengrep", "phase19/execution/opengrep-v1.22.0.json"),
        ("semgrep-ce", "phase19/execution/semgrep-ce-v1.170.0.json"),
    ]
    .into_iter()
    .map(|(id, path)| Ok((id.to_owned(), sha256(&read(&root.join(path))?))))
    .collect()
}

fn privacy_check(files: &BTreeMap<String, Vec<u8>>) -> Result<(), HoldoutError> {
    let forbidden_metadata = [
        "/home/",
        "authorization: bearer",
        "api_key",
        "api-key",
        "secure_ai_",
        "openai_api_key",
        "anthropic_api_key",
    ];
    let forbidden_source = [
        "se100",
        "cwe-",
        "vulnerable",
        "expected_findings",
        "opengrep",
        "semgrep",
        "joern",
    ];
    for (path, bytes) in files {
        let lower = String::from_utf8_lossy(bytes).to_ascii_lowercase();
        if forbidden_metadata
            .iter()
            .any(|needle| lower.contains(needle))
        {
            return Err(HoldoutError::Invariant(format!(
                "privacy-sensitive text in {path}"
            )));
        }
        if path.contains("/cases/")
            && is_source(path)
            && forbidden_source.iter().any(|needle| lower.contains(needle))
        {
            return Err(HoldoutError::Invariant(format!(
                "expectation or scanner leakage in {path}"
            )));
        }
    }
    Ok(())
}

fn checksum_file(root: &Path, files: &BTreeMap<String, Vec<u8>>) -> Result<Vec<u8>, HoldoutError> {
    let mut checksummed = files.clone();
    for relative in STATIC_CHECKSUM_PATHS {
        checksummed.insert(relative.to_owned(), read(&root.join(relative))?);
    }
    let mut output = String::new();
    for (path, bytes) in checksummed {
        output.push_str(&sha256(&bytes));
        output.push_str("  ");
        output.push_str(&path);
        output.push('\n');
    }
    Ok(output.into_bytes())
}

fn validator(root: &Path, relative: &str) -> Result<Validator, HoldoutError> {
    let schema = parse_value(&root.join(relative))?;
    jsonschema::validator_for(&schema).map_err(|error| HoldoutError::Schema(error.to_string()))
}

fn validate_value(root: &Path, schema_path: &str, value: &Value) -> Result<(), HoldoutError> {
    validator(root, schema_path)?
        .validate(value)
        .map_err(|error| HoldoutError::Schema(format!("{schema_path}: {error}")))
}

fn canonical(value: &Value) -> Result<Vec<u8>, HoldoutError> {
    serde_json::to_vec(value).map_err(json_error)
}

fn canonical_without(value: &Value, omitted: &str) -> Result<Vec<u8>, HoldoutError> {
    let mut copy = value.clone();
    copy.as_object_mut()
        .ok_or_else(|| HoldoutError::Json("canonical object expected".to_owned()))?
        .remove(omitted);
    canonical(&copy)
}

fn pretty(value: &Value) -> Result<Vec<u8>, HoldoutError> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(json_error)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn parse_value(path: &Path) -> Result<Value, HoldoutError> {
    serde_json::from_slice(&read(path)?).map_err(json_error)
}

#[allow(clippy::needless_pass_by_value)]
fn json_error(error: serde_json::Error) -> HoldoutError {
    HoldoutError::Json(error.to_string())
}

fn read(path: &Path) -> Result<Vec<u8>, HoldoutError> {
    fs::read(path).map_err(|error| io(path, error))
}

#[allow(clippy::needless_pass_by_value)]
fn io(path: &Path, error: std::io::Error) -> HoldoutError {
    HoldoutError::Io {
        path: path.display().to_string(),
        detail: error.to_string(),
    }
}

fn collect_regular_files(path: &Path, output: &mut Vec<PathBuf>) -> Result<(), HoldoutError> {
    if path.is_symlink() {
        return Err(HoldoutError::Invariant(format!(
            "generated holdout contains symlink {}",
            path.display()
        )));
    }
    if path.is_file() {
        output.push(path.to_path_buf());
        return Ok(());
    }
    let mut entries = fs::read_dir(path)
        .map_err(|error| io(path, error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| io(path, error))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        collect_regular_files(&entry.path(), output)?;
    }
    Ok(())
}

fn sha256(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::{assignments, build_bundle, validate, validate_balance};
    use std::path::{Path, PathBuf};

    fn root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
    }

    #[test]
    fn frozen_schedule_is_mathematically_balanced() -> Result<(), Box<dyn std::error::Error>> {
        validate_balance(&assignments())?;
        Ok(())
    }

    #[test]
    fn reconstruction_is_byte_deterministic() -> Result<(), Box<dyn std::error::Error>> {
        let first = build_bundle(&root())?;
        let second = build_bundle(&root())?;
        assert_eq!(first.files, second.files);
        assert_eq!(first.summary, second.summary);
        Ok(())
    }

    #[test]
    fn committed_holdout_matches_reconstruction() -> Result<(), Box<dyn std::error::Error>> {
        let summary = validate(&root())?;
        assert_eq!(summary.pairs, 56);
        assert_eq!(summary.cases, 112);
        Ok(())
    }
}
