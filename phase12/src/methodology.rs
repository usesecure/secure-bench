//! Versioned prospective adapter and future-holdout authoring policies.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Adapter precedence policy schema identity.
pub const ADAPTER_POLICY_SCHEMA: &str = "secure-bench-phase12-adapter-policy-v1";
/// Future holdout-authoring contract schema identity.
pub const HOLDOUT_POLICY_SCHEMA: &str = "secure-bench-phase12-holdout-authoring-v1";
/// Phase 12 provenance schema identity.
pub const PROVENANCE_SCHEMA: &str = "secure-bench-phase12-provenance-v1";

/// Public prospective adapter policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterPolicy {
    /// Schema identity.
    pub schema_version: String,
    /// Policy semantic version.
    pub policy_version: String,
    /// Secure Bench behavior version.
    pub benchmark_version: String,
    /// Ordered selection precedence.
    pub precedence: Vec<String>,
    /// Fail-closed conditions.
    pub fail_closed_conditions: Vec<String>,
    /// Explicit compatibility conditions.
    pub legacy_compatibility: Vec<String>,
    /// Semantics retained without lossy normalization.
    pub preserved_semantics: Vec<String>,
    /// Process-status separation statement.
    pub process_status_separation: String,
}

/// Prospective authoring contract for a later unseen holdout.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HoldoutAuthoringPolicy {
    /// Schema identity.
    pub schema_version: String,
    /// Methodology semantic version.
    pub methodology_version: String,
    /// Intended later phase.
    pub intended_phase: String,
    /// Public material classification.
    pub material_status: String,
    /// Pre-execution validation requirements.
    pub pre_execution_validation: Vec<String>,
    /// Immutable commitment requirements.
    pub immutable_commitments: Vec<String>,
    /// Counterbalancing requirements.
    pub counterbalancing: Vec<String>,
    /// Isolation requirements.
    pub isolation: Vec<String>,
    /// One-shot execution requirements.
    pub one_shot_execution: Vec<String>,
    /// Process-status policy requirements.
    pub process_status_policy: Vec<String>,
    /// Public-summary answer confidentiality requirements.
    pub answer_confidentiality: Vec<String>,
    /// Post-run disclosure and retirement requirements.
    pub post_run_retirement: Vec<String>,
    /// Explicitly absent future artifacts.
    pub prohibited_artifacts_created: Vec<String>,
}

/// Scanner-free Phase 12 provenance record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase12Provenance {
    /// Schema identity.
    pub schema_version: String,
    /// Secure Bench prospective version.
    pub benchmark_version: String,
    /// Required unchanged main commit.
    pub base_commit: String,
    /// Exact Phase 11 diagnostic input hashes.
    pub phase11_inputs: BTreeMap<String, String>,
    /// Canonical taxonomy artifact hash.
    pub taxonomy_sha256: String,
    /// Evidence Contract v2 artifact hash.
    pub evidence_contract_sha256: String,
    /// Process-status policy artifact hash.
    pub process_status_policy_sha256: String,
    /// Aggregate of every preserved Phase 0–11 payload path and hash.
    pub historical_payload_sha256: String,
    /// Included historical roots.
    pub historical_roots: Vec<String>,
    /// Official Phase 10 result hash, retained without rescoring.
    pub official_phase10_result_sha256: String,
    /// Explicit scanner/external-process audit.
    pub process_audit: ProcessAudit,
    /// Explicit future-holdout absence audit.
    pub phase13_audit: Phase13Audit,
    /// Neutral interpretation limitations.
    pub limitations: Vec<String>,
}

/// Scanner and external-process audit.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessAudit {
    /// Scanner process count.
    pub scanner_processes_started: u64,
    /// External process count.
    pub external_processes_started: u64,
    /// Whether Secure Engine was executed.
    pub secure_engine_executed: bool,
    /// Whether Secure Engine source was inspected.
    pub secure_engine_source_inspected: bool,
    /// Whether the Phase 10 result was rescored.
    pub phase10_rescored: bool,
}

/// Future holdout absence audit.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::struct_excessive_bools)]
#[serde(deny_unknown_fields)]
pub struct Phase13Audit {
    /// Whether fixtures were created.
    pub fixtures_created: bool,
    /// Whether answers were created.
    pub answers_created: bool,
    /// Whether a manifest was created.
    pub manifest_created: bool,
    /// Whether a ledger was created.
    pub ledger_created: bool,
}

/// Constructs the prospective adapter precedence policy.
#[must_use]
pub fn adapter_policy() -> AdapterPolicy {
    AdapterPolicy {
        schema_version: ADAPTER_POLICY_SCHEMA.to_owned(),
        policy_version: "1.0.0".to_owned(),
        benchmark_version: "0.2.0".to_owned(),
        precedence: vec![
            "A complete declared evidence_contract_v2 projection is the authoritative scoring input.".to_owned(),
            "Generic report evidence, prose, rule identifiers, and scanner identities are non-authoritative.".to_owned(),
            "A legacy compatibility projection is eligible only when v2 is absent and the caller explicitly selects its versioned route.".to_owned(),
        ],
        fail_closed_conditions: vec![
            "Malformed, incomplete, unknown, or version-mismatched authoritative v2 projection.".to_owned(),
            "Conflicting declared v2 and legacy projections.".to_owned(),
            "Taxonomy version, category, invariant, or primary CWE outside the frozen canonical tuple.".to_owned(),
            "Missing source or sink identity, invalid span, invalid path order, or inconsistent edge cardinality.".to_owned(),
        ],
        legacy_compatibility: vec![
            "Compatibility adapters are identified by name and semantic version in provenance.".to_owned(),
            "Compatibility never replaces, repairs, or overrides a present v2 projection.".to_owned(),
            "No scanner-specific rule, fixture identifier, prose alias, or score exception is permitted.".to_owned(),
        ],
        preserved_semantics: vec![
            "source and sink semantic identity",
            "portable source and sink spans",
            "ordered connected evidence path",
            "transform and concrete value identity",
            "guards and sanitizers",
            "terminating barriers",
            "authorization and dominance semantics",
            "uncertainty and unresolved-call state",
            "semantic duplicate fingerprint",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        process_status_separation: "Process termination is adjudicated under the versioned process-status policy only after report authority and validity are established; adapter matching never infers a crash from an exit code.".to_owned(),
    }
}

/// Constructs the public authoring contract without creating later holdout material.
#[must_use]
pub fn holdout_authoring_policy() -> HoldoutAuthoringPolicy {
    HoldoutAuthoringPolicy {
        schema_version: HOLDOUT_POLICY_SCHEMA.to_owned(),
        methodology_version: "1.0.0".to_owned(),
        intended_phase: "Phase 13".to_owned(),
        material_status: "public authoring contract only; no unseen cases or answers".to_owned(),
        pre_execution_validation: vec![
            "Validate every fixture fingerprint, exact source and sink span, connected path, concrete value identity, taxonomy tuple, barrier, mutation inverse, and eligibility before sealing.".to_owned(),
            "Validate schemas, licenses, provenance, duplicate identities, answer leakage, privacy, and deterministic reconstruction before sealing.".to_owned(),
            "Public summaries disclose only aggregate design counts and commitment hashes, never case source, case identifiers, assignments, expectations, or mutation answers.".to_owned(),
        ],
        immutable_commitments: vec![
            "Commit the taxonomy, evidence contract, evaluator tree, adapter policy, process-status policy, per-file hashes, aggregate corpus hash, contract Merkle root, manifest hash, and genesis ledger hash before execution.".to_owned(),
            "Any post-seal change creates a new holdout version; sealed artifacts are never regenerated in place.".to_owned(),
        ],
        counterbalancing: vec![
            "Balance vulnerable/control assignment and presentation order within every declared stratum.".to_owned(),
            "Measure and publish factor intersections before sealing without exposing case answers.".to_owned(),
            "Reject duplicate templates, correlated answer positions, and factor cells below the preregistered minimum.".to_owned(),
        ],
        isolation: vec![
            "Run every scanner process in a fresh read-only fixture copy with outbound network access blocked.".to_owned(),
            "Use explicit argument arrays, bounded output, process groups, timeouts, resource limits, and sanitized environment provenance.".to_owned(),
            "Hash fixture copies before and after execution and retain per-process isolation attestations.".to_owned(),
        ],
        one_shot_execution: vec![
            "Reserve execution in an append-only chained ledger before starting the first case.".to_owned(),
            "Execute each eligible case exactly once; do not rerun failures, unfavorable outcomes, malformed output, or timeouts.".to_owned(),
            "Account for every case and terminate the ledger exactly once with immutable artifact hashes.".to_owned(),
        ],
        process_status_policy: vec![
            "Adjudicate report authority before interpreting a normal nonzero exit code.".to_owned(),
            "Distinguish policy findings exits, genuine crashes, timeouts, missing output, malformed output, internal report errors, clean reports, and findings reports.".to_owned(),
            "Never grant clean credit to a failed, missing, malformed, timed-out, or internally errored execution.".to_owned(),
        ],
        answer_confidentiality: vec![
            "Keep expectations, mutation answers, matcher inputs, and fixture classifications outside scanner-visible trees and commands.".to_owned(),
            "Reject secrets, credentials, absolute paths, usernames, private endpoints, and answer-bearing filenames.".to_owned(),
        ],
        post_run_retirement: vec![
            "Publish the preregistered aggregate result, raw accounting, limitations, and complete provenance without ranking or superiority claims.".to_owned(),
            "Retire and disclose the holdout after its designated lifecycle; all later use is development regression, not an unbiased examination.".to_owned(),
            "Preserve the original one-shot result and ledger even if a later protocol defect is found; corrections are additive and separately versioned.".to_owned(),
        ],
        prohibited_artifacts_created: vec![
            "Phase 13 fixtures".to_owned(),
            "Phase 13 answers".to_owned(),
            "Phase 13 manifest".to_owned(),
            "Phase 13 execution ledger".to_owned(),
        ],
    }
}
