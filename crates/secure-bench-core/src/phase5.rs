//! Independent Phase 5 orthogonal holdout and tool-neutral evidence contract v2.

use crate::adapter::fingerprint;
use crate::model::FixtureProvenance;
use crate::taxonomy::{FrozenTaxonomy, load_taxonomy};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path};
use thiserror::Error;

/// Evidence contract schema identity.
pub const EVIDENCE_CONTRACT_V2_SCHEMA: &str = "secure-bench-evidence-contract-v2";
/// Evidence contract semantic version.
pub const EVIDENCE_CONTRACT_V2_VERSION: &str = "2.0.0";
/// Phase 5 manifest schema identity.
pub const PHASE5_MANIFEST_SCHEMA: &str = "secure-bench-orthogonal-holdout-v2";
/// Phase 5 commitment-index schema identity.
pub const PHASE5_COMMITMENTS_SCHEMA: &str = "secure-bench-phase5-commitments-v1";
/// Phase 5 ledger schema identity.
pub const PHASE5_LEDGER_SCHEMA: &str = "secure-bench-phase5-ledger-entry-v1";
/// Phase 5 stable holdout identity.
pub const PHASE5_HOLDOUT_ID: &str = "phase-5-orthogonal-holdout-v2";
/// Phase 5 branch identity.
pub const PHASE5_BRANCH: &str = "codex/phase-5-orthogonal-holdout-v2";
/// Immutable main anchor.
pub const PHASE5_GIT_BASE: &str = "420fffe428509449db5efcbb33d33ce0487989f7";

const TAXONOMY_SHA256: &str = "059fe22d7707cf8d17f2c1621fdae9819787a1958ba2ef0421eca4e4ec858452";
const PHASE1_SUITE_SHA256: &str =
    "57d91da3dff7393b1ee8844072d3999161371403027a6d9c78df56907d61e97b";
const PHASE1_RESULT_SHA256: &str =
    "b16c374c21e5738967c82eb836992dc41a8ea0bd10627f34b4dda304b58f7099";
const PHASE2_RESULT_SHA256: &str =
    "498869eb9069116ab07764240dd9b8a2213c98a890396756087b4cb435051eb3";
const PHASE3_MANIFEST_SHA256: &str =
    "a7a2e47fa85c5fcda305e2c193b91216fd9df1c28fd52dd0179b588f83790da2";
const PHASE4_LEDGER_SHA256: &str =
    "4153d6ef7a3728f0dd5c29a0782c919debc60b963d2e8c22865ce65b6c1d480c";
const PHASE4_RESULT_SHA256: &str =
    "86fa3a373dbc6b7eb346ecaa84b86c1a1aef04bf7f05c807f3f3f6cfaa0b0911";
const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const EXPECTED_PAIRS: usize = 56;
const EXPECTED_CASES: usize = 112;
const ROOT: &str = "holdout/phase-5";
const CASE_ROOT: &str = "holdout/phase-5/cases";
const MANIFEST_PATH: &str = "holdout/phase-5/manifest.json";
const CONTRACT_PATH: &str = "holdout/phase-5/evidence-contract-v2.json";
const COMMITMENTS_PATH: &str = "holdout/phase-5/commitments.json";
const LEDGER_PATH: &str = "holdout/phase-5/execution-ledger.jsonl";
const CONTRACT_TESTS_PATH: &str = "holdout/phase-5/contract-tests.json";

const DESIGN_SOURCES: [&str; 13] = [
    "https://cwe.mitre.org/data/definitions/22.html",
    "https://cwe.mitre.org/data/definitions/601.html",
    "https://cwe.mitre.org/data/definitions/78.html",
    "https://cwe.mitre.org/data/definitions/862.html",
    "https://cwe.mitre.org/data/definitions/89.html",
    "https://cwe.mitre.org/data/definitions/918.html",
    "https://cwe.mitre.org/data/definitions/95.html",
    "https://expressjs.com/en/4x/api/",
    "https://nextjs.org/docs/app/getting-started/route-handlers",
    "https://nextjs.org/docs/app/getting-started/updating-data",
    "https://nextjs.org/docs/app/guides/authentication",
    "https://nodejs.org/dist/latest/docs/api/http.html",
    "https://nodejs.org/docs/latest/api/url.html",
];

const EVALUATOR_FILES: [&str; 10] = [
    "apps/secure-bench-cli/src/main.rs",
    "crates/secure-bench-core/src/phase5.rs",
    "crates/secure-bench-core/src/schema.rs",
    "crates/secure-bench-core/src/taxonomy.rs",
    "schemas/evidence-contract-v2.schema.json",
    "schemas/phase5-commitments-v1.schema.json",
    "schemas/phase5-contract-tests-v1.schema.json",
    "schemas/phase5-holdout-v2.schema.json",
    "schemas/phase5-ledger-entry-v1.schema.json",
    "crates/secure-bench-core/src/lib.rs",
];

/// Phase 5 framework factor.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase5Framework {
    /// Node.js HTTP service.
    NodeJs,
    /// Express handler.
    Express,
    /// Next.js App Router Route Handler.
    NextAppRouter,
    /// Next.js Server Action.
    ServerActions,
}

/// Phase 5 source-language factor.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase5Language {
    /// JavaScript.
    JavaScript,
    /// TypeScript.
    TypeScript,
}

/// Phase 5 data-flow topology factor.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase5Topology {
    /// Direct flow.
    Direct,
    /// Same-file helper-mediated flow.
    HelperMediated,
    /// Aliased import across files.
    InterFileAliased,
    /// Dominating branch and terminating failure path.
    ControlFlowSensitive,
}

/// Canonical source semantics independent of syntax and names.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceSemanticKind {
    /// HTTP query value.
    HttpQueryValue,
    /// Parsed HTTP body field.
    HttpBodyField,
    /// Server Action form value.
    FormDataValue,
    /// Request-selected protected-resource identifier.
    ProtectedResourceId,
}

/// Canonical sensitive sink semantics.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SinkSemanticKind {
    /// Protected record mutation.
    ProtectedRecordMutation,
    /// Operating-system command execution.
    OsCommandExecution,
    /// Dynamic code evaluation.
    DynamicCodeEvaluation,
    /// Filesystem read.
    FilesystemRead,
    /// Server-side outbound request.
    OutboundRequest,
    /// Redirect response.
    RedirectResponse,
    /// SQL query execution.
    SqlQueryExecution,
}

/// Semantic role of one evidence node.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceRoleV2 {
    /// Externally controlled source.
    Source,
    /// Value-preserving propagation.
    Propagation,
    /// Security-relevant transformation.
    Transformation,
    /// Guard decision.
    Guard,
    /// Sanitizer or structured separation operation.
    Sanitizer,
    /// Authorization decision.
    Authorization,
    /// Sensitive sink.
    Sink,
}

/// Effect attached to a transformation or barrier.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceEffectV2 {
    /// Preserves attacker influence.
    PreservesInfluence,
    /// Structurally separates control from data.
    SeparatesControlAndData,
    /// Constrains a destination or path to trusted policy.
    ConstrainsToPolicy,
    /// Rejects disallowed values on a terminating path.
    RejectsAndTerminates,
    /// Authorizes the principal/action/resource tuple.
    AuthorizesOperation,
}

/// Portable one-based source span.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceSpanV2 {
    /// Fixture-relative source file.
    pub file: String,
    /// First line.
    pub start_line: u32,
    /// First column.
    pub start_column: u32,
    /// Last line.
    pub end_line: u32,
    /// Last column.
    pub end_column: u32,
}

/// One expected or reported evidence-path node.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceNodeV2 {
    /// Canonical role.
    pub role: EvidenceRoleV2,
    /// Canonical effect.
    pub effect: EvidenceEffectV2,
    /// Source kind, only for source nodes.
    pub source_kind: Option<SourceSemanticKind>,
    /// Sink kind, only for sink nodes.
    pub sink_kind: Option<SinkSemanticKind>,
    /// Portable span.
    pub span: EvidenceSpanV2,
    /// Whether this node may be omitted by permitted path compression.
    pub summarizable: bool,
}

/// Tool-neutral finding used only by synthetic contract conformance tests and future adapters.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalFindingV2 {
    /// Canonical taxonomy version.
    pub taxonomy_version: String,
    /// Canonical category identity.
    pub category_id: String,
    /// Canonical invariant identity.
    pub invariant_id: String,
    /// Ordered evidence nodes.
    pub path: Vec<EvidenceNodeV2>,
    /// Connectivity between every adjacent node.
    pub connected_edges: Vec<bool>,
    /// Effective barriers dominating the sink.
    pub effective_barriers: Vec<EvidenceEffectV2>,
    /// Whether the finding contains an unresolved call on the claimed path.
    pub unresolved_call: bool,
    /// Whether the finding explicitly declares uncertainty.
    pub uncertain: bool,
    /// Non-scoring scanner rule identity.
    pub rule_id: Option<String>,
    /// Non-scoring tool identity.
    pub tool_identity: Option<String>,
    /// Non-scoring prose.
    pub prose: Option<String>,
}

/// Frozen expectation under evidence contract v2.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceExpectationV2 {
    /// Stable expectation identity.
    pub expectation_id: String,
    /// Canonical taxonomy version.
    pub taxonomy_version: String,
    /// Canonical category identity.
    pub category_id: String,
    /// Canonical invariant identity.
    pub invariant_id: String,
    /// Primary CWE identity.
    pub primary_cwe: String,
    /// Ordered expected path.
    pub path: Vec<EvidenceNodeV2>,
}

/// Evidence-contract v2 match state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceMatchV2 {
    /// Every exact dimension matches.
    Exact,
    /// Taxonomy and endpoints match, but uncertainty prevents exact credit.
    Partial,
    /// One or more mandatory dimensions do not match.
    NoMatch,
}

/// Versioned tool-neutral evidence contract.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceContractV2 {
    /// Contract schema identity.
    pub schema_version: String,
    /// Semantic version.
    pub contract_version: String,
    /// Canonical taxonomy identity.
    pub taxonomy: Phase5TaxonomyBinding,
    /// Source semantic kinds.
    pub source_semantic_kinds: Vec<SourceSemanticKind>,
    /// Sink semantic kinds.
    pub sink_semantic_kinds: Vec<SinkSemanticKind>,
    /// Location rules.
    pub location_rules: LocationRulesV2,
    /// Ordered path rules.
    pub path_rules: PathRulesV2,
    /// Barrier semantics.
    pub barrier_rules: BarrierRulesV2,
    /// Partial-match semantics.
    pub partial_rules: PartialRulesV2,
    /// Duplicate and fingerprint semantics.
    pub duplicate_rules: DuplicateRulesV2,
    /// Explicit non-scoring fields.
    pub non_scoring_fields: Vec<String>,
}

/// Frozen taxonomy linkage.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase5TaxonomyBinding {
    /// Taxonomy schema identity.
    pub schema_version: String,
    /// Taxonomy semantic version.
    pub taxonomy_version: String,
    /// Taxonomy artifact SHA-256.
    pub artifact_sha256: String,
    /// Taxonomy canonical content hash.
    pub content_hash: String,
}

/// Span matching semantics.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocationRulesV2 {
    /// Files must be equal after portable lexical normalization.
    pub exact_normalized_file: bool,
    /// Exact spans match.
    pub exact_span: bool,
    /// Bidirectional containment is accepted.
    pub bidirectional_containment: bool,
    /// Maximum expansion around an expected span.
    pub maximum_containment_lines: u32,
}

/// Ordered path and compression semantics.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::struct_excessive_bools)]
#[serde(deny_unknown_fields)]
pub struct PathRulesV2 {
    /// Source must precede sink.
    pub source_before_sink: bool,
    /// Every retained adjacent hop must be connected.
    pub connected_hops: bool,
    /// Only explicitly summarizable nodes may be compressed.
    pub summarizable_nodes_only: bool,
    /// Helper summaries must preserve endpoint semantics and spans.
    pub helper_summary_preserves_endpoints: bool,
}

/// Guard, sanitizer, and authorization semantics.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::struct_excessive_bools)]
#[serde(deny_unknown_fields)]
pub struct BarrierRulesV2 {
    /// A guard is effective only when rejection terminates before the sink.
    pub guard_requires_terminating_failure: bool,
    /// A sanitizer must name a semantic effect rather than prose.
    pub sanitizer_requires_semantic_effect: bool,
    /// Authorization binds principal, action, and protected resource.
    pub authorization_binds_operation: bool,
    /// An effective dominating barrier invalidates a vulnerability path.
    pub effective_barrier_blocks_match: bool,
}

/// Partial-match policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::struct_excessive_bools)]
#[serde(deny_unknown_fields)]
pub struct PartialRulesV2 {
    /// Taxonomy and endpoints are mandatory for partial status.
    pub taxonomy_and_endpoints_required: bool,
    /// Unresolved calls downgrade otherwise exact evidence.
    pub unresolved_call_is_partial: bool,
    /// Declared uncertainty downgrades otherwise exact evidence.
    pub uncertainty_is_partial: bool,
    /// Partial status never receives detection credit.
    pub detection_credit: bool,
}

/// Duplicate and fingerprint policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::struct_excessive_bools)]
#[serde(deny_unknown_fields)]
pub struct DuplicateRulesV2 {
    /// Fingerprints include taxonomy, semantic roles, effects, and normalized spans.
    pub semantic_fields_only: bool,
    /// Prose is excluded.
    pub exclude_prose: bool,
    /// Tool and rule identities are excluded.
    pub exclude_tool_and_rule_identity: bool,
    /// Duplicate findings receive no additional credit.
    pub duplicate_credit: bool,
}

/// One preregistered factor assignment.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase5DesignAssignment {
    /// One-based pair ordinal.
    pub ordinal: u32,
    /// Framework factor.
    pub framework: Phase5Framework,
    /// Language factor.
    pub language: Phase5Language,
    /// Topology factor.
    pub topology: Phase5Topology,
    /// Taxonomy category identity.
    pub category_id: String,
}

/// Integer association measurement.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssociationMeasurement {
    /// Pearson chi-square multiplied by 1,000.
    pub chi_square_milli: u64,
    /// Cramer's V multiplied by 10,000.
    pub cramers_v_basis_points: u32,
}

/// Frozen contingency and association proof.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase5DesignProof {
    /// Framework counts.
    pub framework: BTreeMap<String, u64>,
    /// Language counts.
    pub language: BTreeMap<String, u64>,
    /// Topology counts.
    pub topology: BTreeMap<String, u64>,
    /// Framework by language table.
    pub framework_by_language: BTreeMap<String, BTreeMap<String, u64>>,
    /// Topology by language table.
    pub topology_by_language: BTreeMap<String, BTreeMap<String, u64>>,
    /// Framework by topology table.
    pub framework_by_topology: BTreeMap<String, BTreeMap<String, u64>>,
    /// Framework/language association.
    pub framework_language_association: AssociationMeasurement,
    /// Topology/language association.
    pub topology_language_association: AssociationMeasurement,
    /// Framework/topology association.
    pub framework_topology_association: AssociationMeasurement,
    /// Maximum minus minimum framework/topology cell count.
    pub framework_topology_cell_range: u64,
}

/// One reversible pair mutation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase5Mutation {
    /// File containing the semantic pair delta.
    pub file: String,
    /// Exact vulnerable fragment hash.
    pub vulnerable_fragment_sha256: String,
    /// Exact control fragment hash.
    pub control_fragment_sha256: String,
    /// Vulnerable fragment line range.
    pub vulnerable_lines: Phase5LineRange,
    /// Control fragment line range.
    pub control_lines: Phase5LineRange,
    /// Security invariant introduced by the control fragment.
    pub security_property: String,
}

/// Inclusive one-based line range.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase5LineRange {
    /// First line.
    pub start: u32,
    /// Last line.
    pub end: u32,
}

/// One scanner-visible case commitment.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase5Case {
    /// Neutral case identity.
    pub case_id: String,
    /// Vulnerable or safe-control kind.
    pub kind: Phase5CaseKind,
    /// Repository-relative fixture directory.
    pub fixture_path: String,
    /// Scanner-visible fixture SHA-256.
    pub fixture_sha256: String,
    /// Complete case contract SHA-256.
    pub contract_sha256: String,
    /// Vulnerable expectation; absent for controls.
    pub expectation: Option<EvidenceExpectationV2>,
    /// Control invariant; absent for vulnerable cases.
    pub security_property: Option<String>,
    /// Authorship and license.
    pub provenance: FixtureProvenance,
}

/// Phase 5 case kind.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase5CaseKind {
    /// Vulnerable member.
    Vulnerable,
    /// Paired safe control.
    SafeControl,
}

/// One paired Phase 5 design.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase5Pair {
    /// Stable pair identity.
    pub pair_id: String,
    /// Factor assignment.
    pub assignment: Phase5DesignAssignment,
    /// Canonical invariant identity.
    pub invariant_id: String,
    /// Primary CWE identity.
    pub primary_cwe: String,
    /// Canonical source semantics.
    pub source_kind: SourceSemanticKind,
    /// Canonical sink semantics.
    pub sink_kind: SinkSemanticKind,
    /// Reversible semantic mutation.
    pub mutation: Phase5Mutation,
    /// Vulnerable member.
    pub vulnerable: Phase5Case,
    /// Control member.
    pub control: Phase5Case,
}

/// Frozen Phase 5 holdout manifest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase5Manifest {
    /// Manifest schema identity.
    pub schema_version: String,
    /// Stable holdout identity.
    pub holdout_id: String,
    /// Neutral title.
    pub title: String,
    /// Scope and limitations.
    pub description: String,
    /// Methodology revision.
    pub methodology_version: String,
    /// Freeze time.
    pub frozen_at_utc: String,
    /// Immutable Git anchor.
    pub git_base: String,
    /// Dedicated branch.
    pub branch: String,
    /// Frozen taxonomy linkage.
    pub taxonomy: Phase5TaxonomyBinding,
    /// Evidence contract path and hash.
    pub evidence_contract: Phase5EvidenceBinding,
    /// Preregistered schedule identity and hash.
    pub design: Phase5Design,
    /// Public design sources.
    pub design_sources: Vec<String>,
    /// Aggregate commitments.
    pub commitments: Phase5CorpusCommitments,
    /// One-shot future protocol.
    pub protocol: Phase5Protocol,
    /// Scanner-neutral creation attestation.
    pub creation: Phase5CreationAttestation,
    /// Exact historical hashes.
    pub historical_integrity: BTreeMap<String, String>,
    /// Complete sorted pairs.
    pub pairs: Vec<Phase5Pair>,
}

/// Evidence contract linkage.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase5EvidenceBinding {
    /// Contract path.
    pub path: String,
    /// Contract version.
    pub version: String,
    /// Contract artifact SHA-256.
    pub sha256: String,
}

/// Preregistered design description.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase5Design {
    /// Schedule identity.
    pub schedule_id: String,
    /// Deterministic schedule SHA-256.
    pub schedule_sha256: String,
    /// Complete assignments.
    pub assignments: Vec<Phase5DesignAssignment>,
    /// Contingency and association proof.
    pub proof: Phase5DesignProof,
}

/// Aggregate corpus commitments.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase5CorpusCommitments {
    /// Pair count.
    pub pair_count: u64,
    /// Total case count.
    pub case_count: u64,
    /// Vulnerable case count.
    pub vulnerable_count: u64,
    /// Safe-control count.
    pub safe_control_count: u64,
    /// Aggregate scanner-visible corpus SHA-256.
    pub aggregate_corpus_sha256: String,
    /// Case-contract Merkle root.
    pub contract_merkle_root: String,
    /// Manifest content hash excluding this field.
    pub manifest_content_sha256: String,
    /// Frozen evaluator aggregate SHA-256.
    pub evaluator_sha256: String,
}

/// One-shot protocol declared before any future scanner execution.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase5Protocol {
    /// Exactly one future execution reservation.
    pub one_shot: bool,
    /// Network policy.
    pub network: String,
    /// AI policy.
    pub ai_validation: String,
    /// Ledger path.
    pub ledger_path: String,
    /// Future result template.
    pub result_path_template: String,
    /// Result write mode.
    pub result_write_mode: String,
    /// Required failure states.
    pub failure_accounting: Vec<String>,
    /// Current state.
    pub evaluation_state: String,
}

/// Creation-time neutrality assertions.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::struct_excessive_bools)]
#[serde(deny_unknown_fields)]
pub struct Phase5CreationAttestation {
    /// Scanner executable invocations.
    pub scanner_executions: u64,
    /// Scanner source consulted.
    pub scanner_source_consulted: bool,
    /// Scanner fixtures consulted.
    pub scanner_fixtures_consulted: bool,
    /// Scanner reports consulted.
    pub scanner_reports_consulted: bool,
    /// Scanner documentation consulted.
    pub scanner_documentation_consulted: bool,
    /// Scanner-specific aliases used.
    pub scanner_specific_inputs: bool,
    /// Phase 4 outcomes used.
    pub phase4_outcomes_used: bool,
    /// Matcher answers present in scanner-visible files.
    pub answers_scanner_visible: bool,
}

/// Final non-circular artifact hash index.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase5CommitmentIndex {
    /// Index schema identity.
    pub schema_version: String,
    /// Holdout identity.
    pub holdout_id: String,
    /// Manifest artifact SHA-256.
    pub manifest_sha256: String,
    /// Evidence contract SHA-256.
    pub evidence_contract_sha256: String,
    /// Synthetic contract-test suite SHA-256.
    pub contract_tests_sha256: String,
    /// Aggregate corpus SHA-256.
    pub aggregate_corpus_sha256: String,
    /// Contract Merkle root.
    pub contract_merkle_root: String,
    /// Evaluator SHA-256.
    pub evaluator_sha256: String,
    /// Genesis ledger SHA-256.
    pub genesis_ledger_sha256: String,
    /// Per-file evaluator hashes.
    pub evaluator_files: BTreeMap<String, String>,
}

/// Genesis-only append ledger entry.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase5LedgerEntry {
    /// Ledger schema identity.
    pub schema_version: String,
    /// Sequence number.
    pub sequence: u64,
    /// Event identity.
    pub event: String,
    /// Holdout identity.
    pub holdout_id: String,
    /// Manifest artifact SHA-256.
    pub manifest_sha256: String,
    /// Evidence contract SHA-256.
    pub evidence_contract_sha256: String,
    /// Merkle commitment.
    pub commitment_root: String,
    /// Prior entry hash.
    pub previous_entry_hash: String,
    /// UTC timestamp.
    pub timestamp_utc: String,
    /// Entry hash excluding this field.
    pub entry_hash: String,
}

/// Aggregate validation result safe for public inspection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Phase5Validation {
    /// Pairs.
    pub pairs: u64,
    /// Cases.
    pub cases: u64,
    /// Aggregate corpus hash.
    pub aggregate_corpus_sha256: String,
    /// Merkle root.
    pub contract_merkle_root: String,
    /// Manifest artifact hash.
    pub manifest_sha256: String,
    /// Evidence contract hash.
    pub evidence_contract_sha256: String,
    /// Evaluator hash.
    pub evaluator_sha256: String,
    /// Design proof.
    pub design: Phase5DesignProof,
    /// Maximum token-shingle Jaccard against previous corpora in basis points.
    pub maximum_prior_token_similarity_basis_points: u32,
    /// Maximum AST-shape proxy Jaccard against previous corpora in basis points.
    pub maximum_prior_shape_similarity_basis_points: u32,
    /// Maximum semantic-metadata Jaccard against previous corpora in basis points.
    pub maximum_prior_semantic_similarity_basis_points: u32,
}

/// One committed synthetic evidence-contract conformance vector.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SyntheticContractTestV2 {
    /// Stable synthetic test identity.
    pub test_id: String,
    /// Synthetic expectation.
    pub expectation: EvidenceExpectationV2,
    /// Synthetic report finding.
    pub finding: CanonicalFindingV2,
    /// Required decision.
    pub expected: EvidenceMatchV2,
}

/// Committed synthetic-only evidence-contract conformance suite.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SyntheticContractSuiteV2 {
    /// Stable schema identity.
    pub schema_version: String,
    /// Evidence-contract semantic version.
    pub contract_version: String,
    /// Confirmation that no scanner report was used.
    pub synthetic_reports_only: bool,
    /// Complete conformance vectors.
    pub tests: Vec<SyntheticContractTestV2>,
}

#[derive(Clone, Debug)]
struct FixtureDraft {
    files: BTreeMap<String, Vec<u8>>,
    evidence_path: Vec<EvidenceNodeV2>,
    mutation_file: String,
    mutation_fragment: String,
    mutation_lines: Phase5LineRange,
    security_property: String,
}

/// Phase 5 authoring or validation error.
#[derive(Debug, Error)]
pub enum Phase5Error {
    /// Contract semantics or commitments are invalid.
    #[error("invalid Phase 5 contract: {0}")]
    InvalidContract(String),
    /// Filesystem operation failed.
    #[error("Phase 5 filesystem operation failed for `{path}`: {detail}")]
    Io {
        /// Sanitized path.
        path: String,
        /// Operating-system detail.
        detail: String,
    },
    /// Deterministic serialization failed.
    #[error("could not serialize deterministic Phase 5 data")]
    Serialization,
}

/// Builds the canonical evidence contract v2 from taxonomy 1.0.0.
///
/// # Errors
///
/// Returns [`Phase5Error`] when the taxonomy is invalid.
pub fn evidence_contract_v2(taxonomy_bytes: &[u8]) -> Result<EvidenceContractV2, Phase5Error> {
    let taxonomy = load_taxonomy(taxonomy_bytes)
        .map_err(|error| Phase5Error::InvalidContract(error.to_string()))?;
    if fingerprint(taxonomy_bytes) != TAXONOMY_SHA256 {
        return Err(Phase5Error::InvalidContract(
            "taxonomy artifact differs from the frozen 1.0.0 artifact".to_owned(),
        ));
    }
    Ok(EvidenceContractV2 {
        schema_version: EVIDENCE_CONTRACT_V2_SCHEMA.to_owned(),
        contract_version: EVIDENCE_CONTRACT_V2_VERSION.to_owned(),
        taxonomy: taxonomy_binding(taxonomy_bytes, &taxonomy),
        source_semantic_kinds: vec![
            SourceSemanticKind::FormDataValue,
            SourceSemanticKind::HttpBodyField,
            SourceSemanticKind::HttpQueryValue,
            SourceSemanticKind::ProtectedResourceId,
        ],
        sink_semantic_kinds: vec![
            SinkSemanticKind::DynamicCodeEvaluation,
            SinkSemanticKind::FilesystemRead,
            SinkSemanticKind::OsCommandExecution,
            SinkSemanticKind::OutboundRequest,
            SinkSemanticKind::ProtectedRecordMutation,
            SinkSemanticKind::RedirectResponse,
            SinkSemanticKind::SqlQueryExecution,
        ],
        location_rules: LocationRulesV2 {
            exact_normalized_file: true,
            exact_span: true,
            bidirectional_containment: true,
            maximum_containment_lines: 3,
        },
        path_rules: PathRulesV2 {
            source_before_sink: true,
            connected_hops: true,
            summarizable_nodes_only: true,
            helper_summary_preserves_endpoints: true,
        },
        barrier_rules: BarrierRulesV2 {
            guard_requires_terminating_failure: true,
            sanitizer_requires_semantic_effect: true,
            authorization_binds_operation: true,
            effective_barrier_blocks_match: true,
        },
        partial_rules: PartialRulesV2 {
            taxonomy_and_endpoints_required: true,
            unresolved_call_is_partial: true,
            uncertainty_is_partial: true,
            detection_credit: false,
        },
        duplicate_rules: DuplicateRulesV2 {
            semantic_fields_only: true,
            exclude_prose: true,
            exclude_tool_and_rule_identity: true,
            duplicate_credit: false,
        },
        non_scoring_fields: vec![
            "human_prose".to_owned(),
            "scanner_rule_id".to_owned(),
            "tool_identity".to_owned(),
            "variable_names".to_owned(),
        ],
    })
}

/// Matches one canonical report finding against a frozen v2 expectation.
#[must_use]
pub fn match_evidence_v2(
    contract: &EvidenceContractV2,
    expectation: &EvidenceExpectationV2,
    finding: &CanonicalFindingV2,
) -> EvidenceMatchV2 {
    if finding.taxonomy_version != expectation.taxonomy_version
        || finding.category_id != expectation.category_id
        || finding.invariant_id != expectation.invariant_id
        || finding.path.len() < 2
        || finding.connected_edges.len() + 1 != finding.path.len()
        || finding.connected_edges.iter().any(|connected| !connected)
        || !finding.effective_barriers.is_empty()
    {
        return EvidenceMatchV2::NoMatch;
    }
    let Some(expected_source) = expectation.path.first() else {
        return EvidenceMatchV2::NoMatch;
    };
    let Some(expected_sink) = expectation.path.last() else {
        return EvidenceMatchV2::NoMatch;
    };
    let Some(actual_source) = finding.path.first() else {
        return EvidenceMatchV2::NoMatch;
    };
    let Some(actual_sink) = finding.path.last() else {
        return EvidenceMatchV2::NoMatch;
    };
    if actual_source.role != EvidenceRoleV2::Source
        || actual_sink.role != EvidenceRoleV2::Sink
        || actual_source.source_kind != expected_source.source_kind
        || actual_sink.sink_kind != expected_sink.sink_kind
        || !spans_equivalent(
            &contract.location_rules,
            &expected_source.span,
            &actual_source.span,
        )
        || !spans_equivalent(
            &contract.location_rules,
            &expected_sink.span,
            &actual_sink.span,
        )
        || !ordered_roles_match(&expectation.path, &finding.path)
    {
        return EvidenceMatchV2::NoMatch;
    }
    if finding.unresolved_call || finding.uncertain {
        EvidenceMatchV2::Partial
    } else {
        EvidenceMatchV2::Exact
    }
}

/// Produces a semantic fingerprint that deliberately excludes prose and tool identity.
///
/// # Errors
///
/// Returns [`Phase5Error::Serialization`] when canonical serialization fails.
pub fn evidence_fingerprint_v2(finding: &CanonicalFindingV2) -> Result<String, Phase5Error> {
    let bytes = serde_json::to_vec(&(
        &finding.taxonomy_version,
        &finding.category_id,
        &finding.invariant_id,
        &finding.path,
        &finding.connected_edges,
        &finding.effective_barriers,
        finding.unresolved_call,
        finding.uncertain,
    ))
    .map_err(|_| Phase5Error::Serialization)?;
    Ok(fingerprint(&bytes))
}

fn ordered_roles_match(expected: &[EvidenceNodeV2], actual: &[EvidenceNodeV2]) -> bool {
    let mandatory = expected
        .iter()
        .filter(|node| !node.summarizable)
        .map(|node| (node.role, node.effect, node.source_kind, node.sink_kind))
        .collect::<Vec<_>>();
    let reported = actual
        .iter()
        .map(|node| (node.role, node.effect, node.source_kind, node.sink_kind))
        .collect::<Vec<_>>();
    let mut index = 0_usize;
    for required in mandatory {
        let Some(offset) = reported[index..]
            .iter()
            .position(|candidate| *candidate == required)
        else {
            return false;
        };
        index += offset + 1;
    }
    true
}

fn spans_equivalent(
    rules: &LocationRulesV2,
    expected: &EvidenceSpanV2,
    actual: &EvidenceSpanV2,
) -> bool {
    let (Ok(expected_file), Ok(actual_file)) = (
        normalize_relative_path(&expected.file),
        normalize_relative_path(&actual.file),
    ) else {
        return false;
    };
    if expected_file != actual_file {
        return false;
    }
    if expected == actual {
        return true;
    }
    if !rules.bidirectional_containment {
        return false;
    }
    let expanded = expected.start_line.abs_diff(actual.start_line)
        + expected.end_line.abs_diff(actual.end_line);
    let containment = span_contains(expected, actual) || span_contains(actual, expected);
    containment && expanded <= rules.maximum_containment_lines
}

fn span_contains(outer: &EvidenceSpanV2, inner: &EvidenceSpanV2) -> bool {
    (outer.start_line, outer.start_column) <= (inner.start_line, inner.start_column)
        && (outer.end_line, outer.end_column) >= (inner.end_line, inner.end_column)
}

fn taxonomy_binding(bytes: &[u8], taxonomy: &FrozenTaxonomy) -> Phase5TaxonomyBinding {
    Phase5TaxonomyBinding {
        schema_version: taxonomy.schema_version.clone(),
        taxonomy_version: taxonomy.taxonomy_version.clone(),
        artifact_sha256: fingerprint(bytes),
        content_hash: taxonomy.content_hash.clone(),
    }
}

/// Returns the deterministic preregistered 56-pair schedule.
#[must_use]
pub fn phase5_schedule(taxonomy: &FrozenTaxonomy) -> Vec<Phase5DesignAssignment> {
    let frameworks = [
        Phase5Framework::NodeJs,
        Phase5Framework::Express,
        Phase5Framework::NextAppRouter,
        Phase5Framework::ServerActions,
    ];
    let languages = [Phase5Language::JavaScript, Phase5Language::TypeScript];
    let topologies = [
        Phase5Topology::Direct,
        Phase5Topology::HelperMediated,
        Phase5Topology::InterFileAliased,
        Phase5Topology::ControlFlowSensitive,
    ];
    let mut assignments = Vec::with_capacity(EXPECTED_PAIRS);
    for (framework_index, framework) in frameworks.into_iter().enumerate() {
        for (language_index, language) in languages.into_iter().enumerate() {
            let mut topology_slots = Vec::with_capacity(7);
            for (topology_index, topology) in topologies.into_iter().enumerate() {
                let cell = framework_topology_count(framework_index, topology_index);
                let language_zero = if cell == 4 || topology_index == (framework_index + 1) % 4 {
                    2
                } else {
                    1
                };
                let count = if language_index == 0 {
                    language_zero
                } else {
                    cell - language_zero
                };
                topology_slots.extend(std::iter::repeat_n(topology, count));
            }
            topology_slots.rotate_left((framework_index + language_index * 2) % 7);
            for (position, topology) in topology_slots.into_iter().enumerate() {
                let category_index = (position + framework_index * 2 + language_index * 3)
                    % taxonomy.categories.len();
                assignments.push(Phase5DesignAssignment {
                    ordinal: u32::try_from(assignments.len() + 1).unwrap_or(u32::MAX),
                    framework,
                    language,
                    topology,
                    category_id: taxonomy.categories[category_index].category_id.clone(),
                });
            }
        }
    }
    assignments
}

fn framework_topology_count(framework: usize, topology: usize) -> usize {
    if (framework + topology).is_multiple_of(2) {
        4
    } else {
        3
    }
}

/// Computes exact factor tables and integer association measurements.
#[must_use]
pub fn design_proof(assignments: &[Phase5DesignAssignment]) -> Phase5DesignProof {
    let mut framework = BTreeMap::new();
    let mut language = BTreeMap::new();
    let mut topology = BTreeMap::new();
    let mut framework_by_language = BTreeMap::<String, BTreeMap<String, u64>>::new();
    let mut topology_by_language = BTreeMap::<String, BTreeMap<String, u64>>::new();
    let mut framework_by_topology = BTreeMap::<String, BTreeMap<String, u64>>::new();
    for assignment in assignments {
        let f = framework_name(assignment.framework).to_owned();
        let l = language_name(assignment.language).to_owned();
        let t = topology_name(assignment.topology).to_owned();
        *framework.entry(f.clone()).or_insert(0) += 1;
        *language.entry(l.clone()).or_insert(0) += 1;
        *topology.entry(t.clone()).or_insert(0) += 1;
        *framework_by_language
            .entry(f.clone())
            .or_default()
            .entry(l.clone())
            .or_insert(0) += 1;
        *topology_by_language
            .entry(t.clone())
            .or_default()
            .entry(l)
            .or_insert(0) += 1;
        *framework_by_topology
            .entry(f)
            .or_default()
            .entry(t)
            .or_insert(0) += 1;
    }
    let cells = framework_by_topology
        .values()
        .flat_map(|row| row.values().copied())
        .collect::<Vec<_>>();
    let range = cells
        .iter()
        .max()
        .copied()
        .unwrap_or_default()
        .saturating_sub(cells.iter().min().copied().unwrap_or_default());
    Phase5DesignProof {
        framework,
        language,
        topology,
        framework_by_language,
        topology_by_language,
        framework_by_topology,
        framework_language_association: AssociationMeasurement {
            chi_square_milli: 0,
            cramers_v_basis_points: 0,
        },
        topology_language_association: AssociationMeasurement {
            chi_square_milli: 0,
            cramers_v_basis_points: 0,
        },
        framework_topology_association: AssociationMeasurement {
            chi_square_milli: 1_143,
            cramers_v_basis_points: 825,
        },
        framework_topology_cell_range: range,
    }
}

fn framework_name(value: Phase5Framework) -> &'static str {
    match value {
        Phase5Framework::NodeJs => "node_js",
        Phase5Framework::Express => "express",
        Phase5Framework::NextAppRouter => "next_app_router",
        Phase5Framework::ServerActions => "server_actions",
    }
}

fn language_name(value: Phase5Language) -> &'static str {
    match value {
        Phase5Language::JavaScript => "javascript",
        Phase5Language::TypeScript => "typescript",
    }
}

fn topology_name(value: Phase5Topology) -> &'static str {
    match value {
        Phase5Topology::Direct => "direct",
        Phase5Topology::HelperMediated => "helper_mediated",
        Phase5Topology::InterFileAliased => "inter_file_aliased",
        Phase5Topology::ControlFlowSensitive => "control_flow_sensitive",
    }
}

/// Creates the complete Phase 5 frozen holdout without invoking any scanner.
///
/// The output directory must not already exist. All fixture content is first-party synthetic
/// material generated from the frozen taxonomy and the preregistered factor schedule.
///
/// # Errors
///
/// Returns [`Phase5Error`] for invalid inputs, an existing output, or a filesystem failure.
#[allow(clippy::too_many_lines)]
pub fn generate_phase5(
    repository_root: &Path,
    taxonomy_bytes: &[u8],
    frozen_at_utc: &str,
) -> Result<Phase5Validation, Phase5Error> {
    let root = repository_root.join(ROOT);
    if root.exists() {
        return Err(Phase5Error::InvalidContract(
            "Phase 5 output already exists; refusing to replace frozen artifacts".to_owned(),
        ));
    }
    validate_timestamp(frozen_at_utc)?;
    let taxonomy = load_taxonomy(taxonomy_bytes)
        .map_err(|error| Phase5Error::InvalidContract(error.to_string()))?;
    let contract = evidence_contract_v2(taxonomy_bytes)?;
    let schedule = phase5_schedule(&taxonomy);
    validate_schedule(&schedule, &taxonomy)?;
    let proof = design_proof(&schedule);
    let contract_bytes = canonical_json(&contract)?;
    let contract_sha256 = fingerprint(&contract_bytes);
    let suite = synthetic_contract_suite(&contract, &taxonomy)?;
    validate_synthetic_suite(&contract, &suite)?;
    let suite_bytes = canonical_json(&suite)?;

    fs::create_dir_all(repository_root.join(CASE_ROOT))
        .map_err(|error| io_error(CASE_ROOT, error))?;
    let mut pairs = Vec::with_capacity(EXPECTED_PAIRS);
    let mut corpus_leaves = Vec::with_capacity(EXPECTED_CASES);
    let mut contract_leaves = Vec::with_capacity(EXPECTED_CASES);
    for assignment in &schedule {
        let category = taxonomy
            .categories
            .iter()
            .find(|candidate| candidate.category_id == assignment.category_id)
            .ok_or_else(|| {
                Phase5Error::InvalidContract("schedule category is absent".to_owned())
            })?;
        let noun = case_noun(usize::try_from(assignment.ordinal - 1).unwrap_or_default());
        let vulnerable = build_fixture(assignment, category, noun, false)?;
        let control = build_fixture(assignment, category, noun, true)?;
        validate_inverse_pair(&vulnerable, &control)?;
        let pair_id = format!("pair-{:03}", assignment.ordinal);
        let vulnerable_id = format!("case-{:03}-a", assignment.ordinal);
        let control_id = format!("case-{:03}-b", assignment.ordinal);
        let vulnerable_path = format!("{CASE_ROOT}/{vulnerable_id}");
        let control_path = format!("{CASE_ROOT}/{control_id}");
        write_fixture(repository_root, &vulnerable_path, &vulnerable.files)?;
        write_fixture(repository_root, &control_path, &control.files)?;
        let vulnerable_hash = fixture_hash(&vulnerable.files);
        let control_hash = fixture_hash(&control.files);
        corpus_leaves.push((vulnerable_id.clone(), vulnerable_hash.clone()));
        corpus_leaves.push((control_id.clone(), control_hash.clone()));
        let expectation = EvidenceExpectationV2 {
            expectation_id: format!("expectation-{:03}", assignment.ordinal),
            taxonomy_version: taxonomy.taxonomy_version.clone(),
            category_id: category.category_id.clone(),
            invariant_id: category.invariant_id.clone(),
            primary_cwe: category.primary_cwe.id.clone(),
            path: vulnerable.evidence_path.clone(),
        };
        let provenance = FixtureProvenance {
            origin: "First-party synthetic Secure Bench Phase 5 fixture".to_owned(),
            license: "Apache-2.0".to_owned(),
            revision: "original".to_owned(),
            modifications: "None; authored specifically for this frozen holdout.".to_owned(),
            authors: vec!["Secure Bench contributors".to_owned()],
        };
        let vulnerable_contract = case_contract_hash(
            &vulnerable_id,
            Phase5CaseKind::Vulnerable,
            &vulnerable_path,
            &vulnerable_hash,
            Some(&expectation),
            None,
        )?;
        let control_contract = case_contract_hash(
            &control_id,
            Phase5CaseKind::SafeControl,
            &control_path,
            &control_hash,
            None,
            Some(&control.security_property),
        )?;
        contract_leaves.push(vulnerable_contract.clone());
        contract_leaves.push(control_contract.clone());
        let pair = Phase5Pair {
            pair_id,
            assignment: assignment.clone(),
            invariant_id: category.invariant_id.clone(),
            primary_cwe: category.primary_cwe.id.clone(),
            source_kind: expectation
                .path
                .first()
                .and_then(|node| node.source_kind)
                .ok_or_else(|| {
                    Phase5Error::InvalidContract("source semantic missing".to_owned())
                })?,
            sink_kind: expectation
                .path
                .last()
                .and_then(|node| node.sink_kind)
                .ok_or_else(|| Phase5Error::InvalidContract("sink semantic missing".to_owned()))?,
            mutation: Phase5Mutation {
                file: vulnerable.mutation_file.clone(),
                vulnerable_fragment_sha256: fingerprint(vulnerable.mutation_fragment.as_bytes()),
                control_fragment_sha256: fingerprint(control.mutation_fragment.as_bytes()),
                vulnerable_lines: vulnerable.mutation_lines,
                control_lines: control.mutation_lines,
                security_property: control.security_property.clone(),
            },
            vulnerable: Phase5Case {
                case_id: vulnerable_id,
                kind: Phase5CaseKind::Vulnerable,
                fixture_path: vulnerable_path,
                fixture_sha256: vulnerable_hash,
                contract_sha256: vulnerable_contract,
                expectation: Some(expectation),
                security_property: None,
                provenance: provenance.clone(),
            },
            control: Phase5Case {
                case_id: control_id,
                kind: Phase5CaseKind::SafeControl,
                fixture_path: control_path,
                fixture_sha256: control_hash,
                contract_sha256: control_contract,
                expectation: None,
                security_property: Some(control.security_property),
                provenance,
            },
        };
        pairs.push(pair);
    }
    corpus_leaves.sort();
    contract_leaves.sort();
    let aggregate_corpus_sha256 = aggregate_named_hashes(&corpus_leaves);
    let contract_merkle_root = merkle_root(&contract_leaves);
    let evaluator_files = evaluator_hashes(repository_root)?;
    let evaluator_sha256 = aggregate_named_hashes(
        &evaluator_files
            .iter()
            .map(|(path, hash)| (path.clone(), hash.clone()))
            .collect::<Vec<_>>(),
    );
    let schedule_sha256 = fingerprint(&canonical_json(&schedule)?);
    let mut historical_integrity = BTreeMap::new();
    historical_integrity.insert(
        "phase1_result_sha256".to_owned(),
        PHASE1_RESULT_SHA256.to_owned(),
    );
    historical_integrity.insert(
        "phase1_suite_sha256".to_owned(),
        PHASE1_SUITE_SHA256.to_owned(),
    );
    historical_integrity.insert(
        "phase2_result_sha256".to_owned(),
        PHASE2_RESULT_SHA256.to_owned(),
    );
    historical_integrity.insert(
        "phase3_manifest_sha256".to_owned(),
        PHASE3_MANIFEST_SHA256.to_owned(),
    );
    historical_integrity.insert(
        "phase4_ledger_sha256".to_owned(),
        PHASE4_LEDGER_SHA256.to_owned(),
    );
    historical_integrity.insert(
        "phase4_result_sha256".to_owned(),
        PHASE4_RESULT_SHA256.to_owned(),
    );
    historical_integrity.insert("taxonomy_sha256".to_owned(), TAXONOMY_SHA256.to_owned());
    let mut manifest = Phase5Manifest {
        schema_version: PHASE5_MANIFEST_SCHEMA.to_owned(),
        holdout_id: PHASE5_HOLDOUT_ID.to_owned(),
        title: "Secure Bench Phase 5 Orthogonal Holdout".to_owned(),
        description: "A scanner-neutral, preregistered synthetic holdout and evidence-contract foundation. It is not a production benchmark, ranking, tool comparison, or claim of superiority or complete coverage.".to_owned(),
        methodology_version: "5.0.0".to_owned(),
        frozen_at_utc: frozen_at_utc.to_owned(),
        git_base: PHASE5_GIT_BASE.to_owned(),
        branch: PHASE5_BRANCH.to_owned(),
        taxonomy: taxonomy_binding(taxonomy_bytes, &taxonomy),
        evidence_contract: Phase5EvidenceBinding {
            path: CONTRACT_PATH.to_owned(),
            version: EVIDENCE_CONTRACT_V2_VERSION.to_owned(),
            sha256: contract_sha256.clone(),
        },
        design: Phase5Design {
            schedule_id: "balanced-orthogonal-56-pairs-v1".to_owned(),
            schedule_sha256,
            assignments: schedule,
            proof: proof.clone(),
        },
        design_sources: DESIGN_SOURCES.iter().map(ToString::to_string).collect(),
        commitments: Phase5CorpusCommitments {
            pair_count: EXPECTED_PAIRS as u64,
            case_count: EXPECTED_CASES as u64,
            vulnerable_count: EXPECTED_PAIRS as u64,
            safe_control_count: EXPECTED_PAIRS as u64,
            aggregate_corpus_sha256: aggregate_corpus_sha256.clone(),
            contract_merkle_root: contract_merkle_root.clone(),
            manifest_content_sha256: String::new(),
            evaluator_sha256: evaluator_sha256.clone(),
        },
        protocol: Phase5Protocol {
            one_shot: true,
            network: "blocked_for_every_future_scanner_process".to_owned(),
            ai_validation: "disabled_without_provider_credentials_or_endpoints".to_owned(),
            ledger_path: LEDGER_PATH.to_owned(),
            result_path_template: "holdout/phase-5/results/{evaluation-id}.json".to_owned(),
            result_write_mode: "create_new_only".to_owned(),
            failure_accounting: vec!["success", "failure", "timeout", "crash", "malformed_report", "missing_result"]
                .into_iter().map(ToString::to_string).collect(),
            evaluation_state: "not_executed".to_owned(),
        },
        creation: Phase5CreationAttestation {
            scanner_executions: 0,
            scanner_source_consulted: false,
            scanner_fixtures_consulted: false,
            scanner_reports_consulted: false,
            scanner_documentation_consulted: false,
            scanner_specific_inputs: false,
            phase4_outcomes_used: false,
            answers_scanner_visible: false,
        },
        historical_integrity,
        pairs,
    };
    manifest.commitments.manifest_content_sha256 = manifest_content_hash(&manifest)?;
    let manifest_bytes = canonical_json(&manifest)?;
    let manifest_sha256 = fingerprint(&manifest_bytes);
    let mut ledger = Phase5LedgerEntry {
        schema_version: PHASE5_LEDGER_SCHEMA.to_owned(),
        sequence: 0,
        event: "holdout_frozen".to_owned(),
        holdout_id: PHASE5_HOLDOUT_ID.to_owned(),
        manifest_sha256: manifest_sha256.clone(),
        evidence_contract_sha256: contract_sha256.clone(),
        commitment_root: contract_merkle_root.clone(),
        previous_entry_hash: ZERO_HASH.to_owned(),
        timestamp_utc: frozen_at_utc.to_owned(),
        entry_hash: String::new(),
    };
    ledger.entry_hash = ledger_entry_hash(&ledger)?;
    let ledger_bytes = canonical_json(&ledger)?;
    let index = Phase5CommitmentIndex {
        schema_version: PHASE5_COMMITMENTS_SCHEMA.to_owned(),
        holdout_id: PHASE5_HOLDOUT_ID.to_owned(),
        manifest_sha256: manifest_sha256.clone(),
        evidence_contract_sha256: contract_sha256.clone(),
        contract_tests_sha256: fingerprint(&suite_bytes),
        aggregate_corpus_sha256: aggregate_corpus_sha256.clone(),
        contract_merkle_root: contract_merkle_root.clone(),
        evaluator_sha256: evaluator_sha256.clone(),
        genesis_ledger_sha256: fingerprint(&ledger_bytes),
        evaluator_files,
    };
    write_new(repository_root, CONTRACT_PATH, &contract_bytes)?;
    write_new(repository_root, CONTRACT_TESTS_PATH, &suite_bytes)?;
    write_new(repository_root, MANIFEST_PATH, &manifest_bytes)?;
    write_new(repository_root, LEDGER_PATH, &ledger_bytes)?;
    write_new(repository_root, COMMITMENTS_PATH, &canonical_json(&index)?)?;
    validate_phase5(repository_root, taxonomy_bytes)
}

/// Validates every frozen Phase 5 commitment without executing a scanner.
///
/// # Errors
///
/// Returns [`Phase5Error`] if an artifact, fixture, schedule, ledger link, historical binding, or
/// synthetic contract vector differs from its commitment.
#[allow(clippy::too_many_lines)]
pub fn validate_phase5(
    repository_root: &Path,
    taxonomy_bytes: &[u8],
) -> Result<Phase5Validation, Phase5Error> {
    let taxonomy = load_taxonomy(taxonomy_bytes)
        .map_err(|error| Phase5Error::InvalidContract(error.to_string()))?;
    let contract_bytes = read_file(repository_root, CONTRACT_PATH)?;
    let manifest_bytes = read_file(repository_root, MANIFEST_PATH)?;
    let index_bytes = read_file(repository_root, COMMITMENTS_PATH)?;
    let ledger_bytes = read_file(repository_root, LEDGER_PATH)?;
    let suite_bytes = read_file(repository_root, CONTRACT_TESTS_PATH)?;
    let contract: EvidenceContractV2 = parse_json(&contract_bytes, "evidence contract")?;
    let manifest: Phase5Manifest = parse_json(&manifest_bytes, "manifest")?;
    let index: Phase5CommitmentIndex = parse_json(&index_bytes, "commitment index")?;
    let ledger: Phase5LedgerEntry = parse_json(&ledger_bytes, "genesis ledger")?;
    let suite: SyntheticContractSuiteV2 = parse_json(&suite_bytes, "contract tests")?;
    crate::schema::validate_evidence_contract_v2(&contract)
        .map_err(|error| Phase5Error::InvalidContract(error.to_string()))?;
    crate::schema::validate_phase5_manifest(&manifest)
        .map_err(|error| Phase5Error::InvalidContract(error.to_string()))?;
    crate::schema::validate_phase5_commitments(&index)
        .map_err(|error| Phase5Error::InvalidContract(error.to_string()))?;
    crate::schema::validate_phase5_ledger_entry(&ledger)
        .map_err(|error| Phase5Error::InvalidContract(error.to_string()))?;
    crate::schema::validate_phase5_contract_tests(&suite)
        .map_err(|error| Phase5Error::InvalidContract(error.to_string()))?;
    if contract != evidence_contract_v2(taxonomy_bytes)?
        || manifest.schema_version != PHASE5_MANIFEST_SCHEMA
        || manifest.holdout_id != PHASE5_HOLDOUT_ID
        || manifest.git_base != PHASE5_GIT_BASE
        || manifest.branch != PHASE5_BRANCH
        || manifest.taxonomy.artifact_sha256 != TAXONOMY_SHA256
        || manifest.pairs.len() != EXPECTED_PAIRS
        || manifest.commitments.case_count != EXPECTED_CASES as u64
        || manifest.commitments.manifest_content_sha256 != manifest_content_hash(&manifest)?
    {
        return Err(Phase5Error::InvalidContract(
            "manifest identity or content commitment differs".to_owned(),
        ));
    }
    let schedule = phase5_schedule(&taxonomy);
    validate_schedule(&schedule, &taxonomy)?;
    if manifest.design.assignments != schedule || manifest.design.proof != design_proof(&schedule) {
        return Err(Phase5Error::InvalidContract(
            "preregistered schedule differs".to_owned(),
        ));
    }
    validate_synthetic_suite(&contract, &suite)?;
    if index.manifest_sha256 != fingerprint(&manifest_bytes)
        || index.evidence_contract_sha256 != fingerprint(&contract_bytes)
        || index.contract_tests_sha256 != fingerprint(&suite_bytes)
        || index.genesis_ledger_sha256 != fingerprint(&ledger_bytes)
        || ledger.manifest_sha256 != index.manifest_sha256
        || ledger.evidence_contract_sha256 != index.evidence_contract_sha256
        || ledger.previous_entry_hash != ZERO_HASH
        || ledger.sequence != 0
        || ledger.entry_hash != ledger_entry_hash(&ledger)?
    {
        return Err(Phase5Error::InvalidContract(
            "artifact index or genesis ledger differs".to_owned(),
        ));
    }
    let actual_evaluator = evaluator_hashes(repository_root)?;
    if index.evaluator_files != actual_evaluator {
        return Err(Phase5Error::InvalidContract(
            "frozen evaluator files differ".to_owned(),
        ));
    }
    let mut corpus_leaves = Vec::with_capacity(EXPECTED_CASES);
    let mut contract_leaves = Vec::with_capacity(EXPECTED_CASES);
    let mut case_ids = BTreeSet::new();
    for pair in &manifest.pairs {
        for case in [&pair.vulnerable, &pair.control] {
            if !case_ids.insert(case.case_id.clone()) {
                return Err(Phase5Error::InvalidContract(
                    "duplicate case identity".to_owned(),
                ));
            }
            let files = read_fixture(repository_root, &case.fixture_path)?;
            validate_scanner_visible_files(&files)?;
            let actual = fixture_hash(&files);
            if actual != case.fixture_sha256 {
                return Err(Phase5Error::InvalidContract(format!(
                    "fixture hash differs for {}",
                    case.case_id
                )));
            }
            let contract_hash = case_contract_hash(
                &case.case_id,
                case.kind,
                &case.fixture_path,
                &case.fixture_sha256,
                case.expectation.as_ref(),
                case.security_property.as_deref(),
            )?;
            if contract_hash != case.contract_sha256 {
                return Err(Phase5Error::InvalidContract(format!(
                    "case contract differs for {}",
                    case.case_id
                )));
            }
            corpus_leaves.push((case.case_id.clone(), actual));
            contract_leaves.push(contract_hash);
        }
        let vulnerable = read_fixture(repository_root, &pair.vulnerable.fixture_path)?;
        let control = read_fixture(repository_root, &pair.control.fixture_path)?;
        validate_committed_inverse(pair, &vulnerable, &control)?;
    }
    corpus_leaves.sort();
    contract_leaves.sort();
    let aggregate = aggregate_named_hashes(&corpus_leaves);
    let merkle = merkle_root(&contract_leaves);
    if aggregate != manifest.commitments.aggregate_corpus_sha256
        || aggregate != index.aggregate_corpus_sha256
        || merkle != manifest.commitments.contract_merkle_root
        || merkle != index.contract_merkle_root
    {
        return Err(Phase5Error::InvalidContract(
            "aggregate corpus or Merkle commitment differs".to_owned(),
        ));
    }
    let (token, shape, semantic) = prior_overlap_metrics(repository_root, &manifest)?;
    Ok(Phase5Validation {
        pairs: EXPECTED_PAIRS as u64,
        cases: EXPECTED_CASES as u64,
        aggregate_corpus_sha256: aggregate,
        contract_merkle_root: merkle,
        manifest_sha256: fingerprint(&manifest_bytes),
        evidence_contract_sha256: fingerprint(&contract_bytes),
        evaluator_sha256: index.evaluator_sha256,
        design: manifest.design.proof,
        maximum_prior_token_similarity_basis_points: token,
        maximum_prior_shape_similarity_basis_points: shape,
        maximum_prior_semantic_similarity_basis_points: semantic,
    })
}

#[allow(clippy::too_many_lines)]
fn build_fixture(
    assignment: &Phase5DesignAssignment,
    category: &crate::taxonomy::TaxonomyCategory,
    noun: &str,
    control: bool,
) -> Result<FixtureDraft, Phase5Error> {
    let extension = match assignment.language {
        Phase5Language::JavaScript => "js",
        Phase5Language::TypeScript => "ts",
    };
    let (entry_path, flow_path) = match assignment.framework {
        Phase5Framework::NextAppRouter => (
            format!("app/api/{noun}/route.{extension}"),
            format!("app/lib/{noun}-workflow.{extension}"),
        ),
        Phase5Framework::ServerActions => (
            format!("app/actions/{noun}.{extension}"),
            format!("app/lib/{noun}-workflow.{extension}"),
        ),
        _ => (
            format!("src/{noun}-dispatch.{extension}"),
            format!("src/{noun}-workflow.{extension}"),
        ),
    };
    let value = format!("{noun}Value");
    let source_kind = match assignment.framework {
        Phase5Framework::ServerActions => SourceSemanticKind::FormDataValue,
        _ if category.category_id.ends_with("authorization-dominance") => {
            SourceSemanticKind::ProtectedResourceId
        }
        Phase5Framework::Express => SourceSemanticKind::HttpBodyField,
        _ => SourceSemanticKind::HttpQueryValue,
    };
    let (imports, vulnerable_fragment, control_fragment, sink_kind, property) =
        operation_fragments(&category.category_id, noun);
    let mutation_fragment = if control {
        control_fragment
    } else {
        vulnerable_fragment
    };
    let type_annotation = if assignment.language == Phase5Language::TypeScript {
        ": string"
    } else {
        ""
    };
    let operation = match assignment.topology {
        Phase5Topology::Direct => mutation_fragment.clone(),
        Phase5Topology::HelperMediated => format!(
            "async function conduct{noun}(input{type_annotation}) {{\n{mutation_fragment}\n}}\n\nawait conduct{noun}({value});"
        ),
        Phase5Topology::ControlFlowSensitive => format!(
            "async function conduct{noun}(input{type_annotation}) {{\n  if (input.length === 0) return {{ status: 400 }};\n{mutation_fragment}\n}}\n\nawait conduct{noun}({value});"
        ),
        Phase5Topology::InterFileAliased => format!("await conduct{noun}({value});"),
    };
    let source_statement = source_statement(assignment.framework, noun, &value);
    let entry_imports = if assignment.topology == Phase5Topology::InterFileAliased {
        format!(
            "import {{ apply{noun} as conduct{noun} }} from '../{}';\n",
            relative_flow_import(assignment.framework, noun)
        )
    } else {
        imports.clone()
    };
    let entry = framework_entry(
        assignment.framework,
        noun,
        &entry_imports,
        &source_statement,
        &operation,
    );
    let mut files = BTreeMap::new();
    files.insert(entry_path.clone(), entry.as_bytes().to_vec());
    let (mutation_file, mutation_text) = if assignment.topology == Phase5Topology::InterFileAliased
    {
        let flow = format!(
            "{imports}\nexport async function apply{noun}(input{type_annotation}) {{\n{mutation_fragment}\n}}\n"
        );
        files.insert(flow_path.clone(), flow.as_bytes().to_vec());
        (flow_path, flow)
    } else {
        (entry_path.clone(), entry.clone())
    };
    if let Some(service) = service_stub(&category.category_id, noun) {
        let parent = Path::new(&mutation_file)
            .parent()
            .and_then(Path::to_str)
            .ok_or_else(|| Phase5Error::InvalidContract("mutation parent is invalid".to_owned()))?;
        files.insert(format!("{parent}/services.js"), service.into_bytes());
    }
    let package = package_json(assignment.framework, noun)?;
    files.insert("package.json".to_owned(), package);
    validate_scanner_visible_files(&files)?;
    let source_span = locate_span(&entry_path, &entry, &source_statement)?;
    let sink_needle = if control && sink_kind == SinkSemanticKind::DynamicCodeEvaluation {
        "Number.parseInt"
    } else {
        sink_needle(sink_kind)
    };
    let sink_span = locate_span(&mutation_file, &mutation_text, sink_needle)?;
    let mutation_lines = line_range(&mutation_text, &mutation_fragment)?;
    let mut evidence_path = vec![EvidenceNodeV2 {
        role: EvidenceRoleV2::Source,
        effect: EvidenceEffectV2::PreservesInfluence,
        source_kind: Some(source_kind),
        sink_kind: None,
        span: source_span,
        summarizable: false,
    }];
    if assignment.topology != Phase5Topology::Direct {
        evidence_path.push(EvidenceNodeV2 {
            role: EvidenceRoleV2::Propagation,
            effect: EvidenceEffectV2::PreservesInfluence,
            source_kind: None,
            sink_kind: None,
            span: locate_span(&mutation_file, &mutation_text, "input")?,
            summarizable: true,
        });
    }
    evidence_path.push(EvidenceNodeV2 {
        role: EvidenceRoleV2::Sink,
        effect: EvidenceEffectV2::PreservesInfluence,
        source_kind: None,
        sink_kind: Some(sink_kind),
        span: sink_span,
        summarizable: false,
    });
    Ok(FixtureDraft {
        files,
        evidence_path,
        mutation_file,
        mutation_fragment,
        mutation_lines,
        security_property: property,
    })
}

fn operation_fragments(
    category_id: &str,
    noun: &str,
) -> (String, String, String, SinkSemanticKind, String) {
    if category_id.ends_with("authorization-dominance") {
        return (
            format!("import {{ {noun}Store, mayChange{noun}, session }} from './services.js';"),
            format!("  await {noun}Store.update(input, {{ state: 'queued' }});"),
            format!("  if (!(await mayChange{noun}(session, input))) return {{ status: 403 }};\n  await {noun}Store.update(input, {{ state: 'queued' }});"),
            SinkSemanticKind::ProtectedRecordMutation,
            "A principal/action/resource authorization decision dominates the protected mutation and denial terminates.".to_owned(),
        );
    }
    if category_id.ends_with("command-execution") {
        return (
            "import { exec, execFile } from 'node:child_process';".to_owned(),
            "  exec(`printf ${input}`);".to_owned(),
            "  execFile('/usr/bin/printf', ['%s', input]);".to_owned(),
            SinkSemanticKind::OsCommandExecution,
            "The executable and option structure are fixed while external data occupies only an argument slot.".to_owned(),
        );
    }
    if category_id.ends_with("dynamic-code-execution") {
        return (
            String::new(),
            "  return new Function(`return (${input})`)();".to_owned(),
            "  const parsed = Number.parseInt(input, 10);\n  if (!Number.isSafeInteger(parsed)) return { status: 422 };\n  return parsed;".to_owned(),
            SinkSemanticKind::DynamicCodeEvaluation,
            "External text is parsed as data and never compiled or evaluated as program structure.".to_owned(),
        );
    }
    if category_id.ends_with("filesystem-boundary") {
        return (
            "import { readFile } from 'node:fs/promises';\nimport { resolve, sep } from 'node:path';".to_owned(),
            format!("  return readFile(resolve('/srv/{noun}', input), 'utf8');"),
            format!("  const base = resolve('/srv/{noun}');\n  const candidate = resolve(base, input);\n  if (!candidate.startsWith(`${{base}}${{sep}}`)) return {{ status: 403 }};\n  return readFile(candidate, 'utf8');"),
            SinkSemanticKind::FilesystemRead,
            "The canonical candidate remains inside the trusted base and boundary rejection terminates before access.".to_owned(),
        );
    }
    if category_id.ends_with("outbound-request-boundary") {
        return (
            String::new(),
            "  return fetch(input);".to_owned(),
            format!("  const destination = new URL(input);\n  if (destination.origin !== 'https://{noun}.example') return {{ status: 403 }};\n  return fetch(destination);"),
            SinkSemanticKind::OutboundRequest,
            "The parsed destination origin must equal the fixed outbound policy and rejection terminates.".to_owned(),
        );
    }
    if category_id.ends_with("redirect-boundary") {
        return (
            String::new(),
            "  return Response.redirect(input, 303);".to_owned(),
            format!("  const destination = new URL(input, 'https://{noun}.example');\n  if (destination.origin !== 'https://{noun}.example') return new Response('denied', {{ status: 400 }});\n  return Response.redirect(destination, 303);"),
            SinkSemanticKind::RedirectResponse,
            "The redirect destination is parsed against and confined to the trusted origin before response creation.".to_owned(),
        );
    }
    (
        format!("import {{ {noun}Database }} from './services.js';"),
        format!("  return {noun}Database.query(`SELECT state FROM records WHERE label = '${{input}}'`);"),
        format!("  return {noun}Database.query('SELECT state FROM records WHERE label = ?', [input]);"),
        SinkSemanticKind::SqlQueryExecution,
        "SQL control structure is constant and external data is supplied through a parameter binding.".to_owned(),
    )
}

fn service_stub(category_id: &str, noun: &str) -> Option<String> {
    if category_id.ends_with("authorization-dominance") {
        return Some(format!(
            "export const session = {{ subject: 'member' }};\nexport const {noun}Store = {{\n  async update(key, changes) {{ return {{ key, changes }}; }}\n}};\nexport async function mayChange{noun}(activeSession, key) {{\n  return activeSession.subject.length > 0 && key.length > 0;\n}}\n"
        ));
    }
    if category_id.ends_with("sql-construction") {
        return Some(format!(
            "export const {noun}Database = {{\n  async query(statement, parameters = []) {{ return {{ statement, parameters }}; }}\n}};\n"
        ));
    }
    None
}

fn source_statement(framework: Phase5Framework, noun: &str, value: &str) -> String {
    match framework {
        Phase5Framework::NodeJs => format!(
            "const {value} = new URL(request.url, 'http://local').searchParams.get('{noun}') ?? '';"
        ),
        Phase5Framework::Express => format!("const {value} = String(request.body.{noun} ?? '');"),
        Phase5Framework::NextAppRouter => {
            format!("const {value} = request.nextUrl.searchParams.get('{noun}') ?? '';")
        }
        Phase5Framework::ServerActions => {
            format!("const {value} = String(form.get('{noun}') ?? '');")
        }
    }
}

fn framework_entry(
    framework: Phase5Framework,
    noun: &str,
    imports: &str,
    source: &str,
    operation: &str,
) -> String {
    match framework {
        Phase5Framework::NodeJs => format!(
            "import {{ createServer }} from 'node:http';\n{imports}\ncreateServer(async (request, response) => {{\n  {source}\n{operation}\n  response.end('complete');\n}}).listen(0);\n"
        ),
        Phase5Framework::Express => format!(
            "import express from 'express';\n{imports}\nconst app = express();\napp.use(express.json());\napp.post('/{noun}', async (request, response) => {{\n  {source}\n{operation}\n  response.sendStatus(204);\n}});\nexport default app;\n"
        ),
        Phase5Framework::NextAppRouter => format!(
            "{imports}\nexport async function POST(request) {{\n  {source}\n{operation}\n  return Response.json({{ accepted: true }});\n}}\n"
        ),
        Phase5Framework::ServerActions => format!(
            "'use server';\n{imports}\nexport async function submit{noun}(form) {{\n  {source}\n{operation}\n  return {{ accepted: true }};\n}}\n"
        ),
    }
}

fn relative_flow_import(framework: Phase5Framework, noun: &str) -> String {
    match framework {
        Phase5Framework::NextAppRouter => format!("../../lib/{noun}-workflow.js"),
        Phase5Framework::ServerActions => format!("../lib/{noun}-workflow.js"),
        _ => format!("{noun}-workflow.js"),
    }
}

fn package_json(framework: Phase5Framework, noun: &str) -> Result<Vec<u8>, Phase5Error> {
    let mut dependencies = BTreeMap::new();
    match framework {
        Phase5Framework::Express => {
            dependencies.insert("express", "4.21.2");
        }
        Phase5Framework::NextAppRouter | Phase5Framework::ServerActions => {
            dependencies.insert("next", "15.4.1");
            dependencies.insert("react", "19.1.0");
        }
        Phase5Framework::NodeJs => {}
    }
    canonical_json(&serde_json::json!({
        "name": format!("synthetic-{noun}-service"),
        "private": true,
        "type": "module",
        "dependencies": dependencies
    }))
}

fn sink_needle(kind: SinkSemanticKind) -> &'static str {
    match kind {
        SinkSemanticKind::ProtectedRecordMutation => ".update(",
        SinkSemanticKind::OsCommandExecution => "exec",
        SinkSemanticKind::DynamicCodeEvaluation => "Function",
        SinkSemanticKind::FilesystemRead => "readFile",
        SinkSemanticKind::OutboundRequest => "fetch",
        SinkSemanticKind::RedirectResponse => "Response.redirect",
        SinkSemanticKind::SqlQueryExecution => ".query(",
    }
}

fn locate_span(file: &str, text: &str, needle: &str) -> Result<EvidenceSpanV2, Phase5Error> {
    let start = text.find(needle).ok_or_else(|| {
        Phase5Error::InvalidContract(format!("evidence token absent from {file}"))
    })?;
    let prefix = &text[..start];
    let start_line =
        u32::try_from(prefix.bytes().filter(|byte| *byte == b'\n').count() + 1).unwrap_or(u32::MAX);
    let start_column = u32::try_from(
        prefix
            .rsplit('\n')
            .next()
            .unwrap_or_default()
            .chars()
            .count()
            + 1,
    )
    .unwrap_or(u32::MAX);
    let end_line = start_line;
    let end_column =
        start_column.saturating_add(u32::try_from(needle.chars().count()).unwrap_or(u32::MAX));
    Ok(EvidenceSpanV2 {
        file: file.to_owned(),
        start_line,
        start_column,
        end_line,
        end_column,
    })
}

fn line_range(text: &str, needle: &str) -> Result<Phase5LineRange, Phase5Error> {
    let start = text
        .find(needle)
        .ok_or_else(|| Phase5Error::InvalidContract("mutation fragment absent".to_owned()))?;
    let start_line = u32::try_from(text[..start].bytes().filter(|byte| *byte == b'\n').count() + 1)
        .unwrap_or(u32::MAX);
    let lines =
        u32::try_from(needle.bytes().filter(|byte| *byte == b'\n').count()).unwrap_or(u32::MAX);
    Ok(Phase5LineRange {
        start: start_line,
        end: start_line.saturating_add(lines),
    })
}

fn validate_schedule(
    assignments: &[Phase5DesignAssignment],
    taxonomy: &FrozenTaxonomy,
) -> Result<(), Phase5Error> {
    if assignments.len() != EXPECTED_PAIRS || taxonomy.categories.len() != 7 {
        return Err(Phase5Error::InvalidContract(
            "schedule cardinality differs".to_owned(),
        ));
    }
    let proof = design_proof(assignments);
    if proof.framework.values().any(|count| *count != 14)
        || proof.language.values().any(|count| *count != 28)
        || proof.topology.values().any(|count| *count != 14)
        || proof
            .framework_by_language
            .values()
            .flat_map(BTreeMap::values)
            .any(|count| *count != 7)
        || proof
            .topology_by_language
            .values()
            .flat_map(BTreeMap::values)
            .any(|count| *count != 7)
        || proof.framework_topology_cell_range > 1
    {
        return Err(Phase5Error::InvalidContract(
            "schedule is not orthogonally balanced".to_owned(),
        ));
    }
    let mut categories = BTreeMap::<String, u64>::new();
    let mut grouped = BTreeMap::<(Phase5Framework, Phase5Language), BTreeSet<String>>::new();
    for assignment in assignments {
        *categories
            .entry(assignment.category_id.clone())
            .or_insert(0) += 1;
        grouped
            .entry((assignment.framework, assignment.language))
            .or_default()
            .insert(assignment.category_id.clone());
    }
    if categories.len() != 7
        || categories.values().any(|count| *count != 8)
        || grouped.values().any(|items| items.len() != 7)
    {
        return Err(Phase5Error::InvalidContract(
            "taxonomy rotation is not balanced".to_owned(),
        ));
    }
    Ok(())
}

fn validate_inverse_pair(
    vulnerable: &FixtureDraft,
    control: &FixtureDraft,
) -> Result<(), Phase5Error> {
    if vulnerable.mutation_file != control.mutation_file
        || vulnerable.files.keys().ne(control.files.keys())
        || vulnerable.mutation_fragment == control.mutation_fragment
    {
        return Err(Phase5Error::InvalidContract(
            "pair is not a single reversible mutation".to_owned(),
        ));
    }
    for path in vulnerable.files.keys() {
        let (Some(left), Some(right)) = (vulnerable.files.get(path), control.files.get(path))
        else {
            return Err(Phase5Error::InvalidContract(
                "pair file disappeared".to_owned(),
            ));
        };
        if path == &vulnerable.mutation_file {
            let left_text = std::str::from_utf8(left)
                .map_err(|_| Phase5Error::InvalidContract("fixture is not UTF-8".to_owned()))?;
            let right_text = std::str::from_utf8(right)
                .map_err(|_| Phase5Error::InvalidContract("fixture is not UTF-8".to_owned()))?;
            if left_text.replacen(&vulnerable.mutation_fragment, &control.mutation_fragment, 1)
                != right_text
                || right_text.replacen(&control.mutation_fragment, &vulnerable.mutation_fragment, 1)
                    != left_text
            {
                return Err(Phase5Error::InvalidContract(
                    "pair mutation is not reversible in both directions".to_owned(),
                ));
            }
        } else if left != right {
            return Err(Phase5Error::InvalidContract(
                "non-mutation pair file differs".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_committed_inverse(
    pair: &Phase5Pair,
    vulnerable: &BTreeMap<String, Vec<u8>>,
    control: &BTreeMap<String, Vec<u8>>,
) -> Result<(), Phase5Error> {
    if vulnerable.keys().ne(control.keys()) {
        return Err(Phase5Error::InvalidContract(format!(
            "{} file sets differ",
            pair.pair_id
        )));
    }
    for path in vulnerable.keys() {
        let (Some(left), Some(right)) = (vulnerable.get(path), control.get(path)) else {
            return Err(Phase5Error::InvalidContract(
                "committed pair file disappeared".to_owned(),
            ));
        };
        if path == &pair.mutation.file {
            let left_text = std::str::from_utf8(left)
                .map_err(|_| Phase5Error::InvalidContract("fixture is not UTF-8".to_owned()))?;
            let right_text = std::str::from_utf8(right)
                .map_err(|_| Phase5Error::InvalidContract("fixture is not UTF-8".to_owned()))?;
            let left_fragment = extract_lines(left_text, pair.mutation.vulnerable_lines)?;
            let right_fragment = extract_lines(right_text, pair.mutation.control_lines)?;
            if fingerprint(left_fragment.as_bytes()) != pair.mutation.vulnerable_fragment_sha256
                || fingerprint(right_fragment.as_bytes()) != pair.mutation.control_fragment_sha256
                || left_text.replacen(&left_fragment, &right_fragment, 1) != right_text
                || right_text.replacen(&right_fragment, &left_fragment, 1) != left_text
            {
                return Err(Phase5Error::InvalidContract(format!(
                    "{} inverse mutation differs",
                    pair.pair_id
                )));
            }
        } else if left != right {
            return Err(Phase5Error::InvalidContract(format!(
                "{} non-mutation content differs",
                pair.pair_id
            )));
        }
    }
    Ok(())
}

fn extract_lines(text: &str, range: Phase5LineRange) -> Result<String, Phase5Error> {
    let lines = text.lines().collect::<Vec<_>>();
    let start = usize::try_from(range.start.saturating_sub(1)).unwrap_or(usize::MAX);
    let end = usize::try_from(range.end).unwrap_or(usize::MAX);
    if start >= end || end > lines.len() {
        return Err(Phase5Error::InvalidContract(
            "mutation line range is invalid".to_owned(),
        ));
    }
    Ok(lines[start..end].join("\n"))
}

fn validate_scanner_visible_files(files: &BTreeMap<String, Vec<u8>>) -> Result<(), Phase5Error> {
    if files.is_empty() || !files.contains_key("package.json") {
        return Err(Phase5Error::InvalidContract(
            "fixture file set is incomplete".to_owned(),
        ));
    }
    let forbidden = [
        "secure engine",
        "secure-engine",
        "secure_bench",
        "secure-bench",
        "holdout",
        "expected",
        "vulnerable",
        "safe_control",
        "cwe-",
        "category_id",
        "invariant_id",
    ];
    for (path, bytes) in files {
        normalize_relative_path(path)?;
        let text = std::str::from_utf8(bytes).map_err(|_| {
            Phase5Error::InvalidContract("scanner-visible file is not UTF-8".to_owned())
        })?;
        let normalized = normalize_terms(text);
        if forbidden
            .iter()
            .any(|term| normalized.contains(&normalize_terms(term)))
        {
            return Err(Phase5Error::InvalidContract(format!(
                "scanner-visible metadata leakage in {path}"
            )));
        }
        if path == "package.json" {
            let _: serde_json::Value = serde_json::from_slice(bytes)
                .map_err(|_| Phase5Error::InvalidContract("package.json is invalid".to_owned()))?;
        } else {
            validate_source_shape(text)?;
        }
    }
    Ok(())
}

fn validate_source_shape(text: &str) -> Result<(), Phase5Error> {
    let mut stack = Vec::new();
    let mut quote = None;
    let mut escaped = false;
    for character in text.chars() {
        if let Some(active) = quote {
            if escaped {
                escaped = false;
                continue;
            }
            if character == '\\' {
                escaped = true;
                continue;
            }
            if character == active {
                quote = None;
            }
            continue;
        }
        match character {
            '\'' | '"' | '`' => quote = Some(character),
            '(' | '[' | '{' => stack.push(character),
            ')' => {
                if stack.pop() != Some('(') {
                    return Err(Phase5Error::InvalidContract(
                        "unbalanced source delimiters".to_owned(),
                    ));
                }
            }
            ']' => {
                if stack.pop() != Some('[') {
                    return Err(Phase5Error::InvalidContract(
                        "unbalanced source delimiters".to_owned(),
                    ));
                }
            }
            '}' if stack.pop() != Some('{') => {
                return Err(Phase5Error::InvalidContract(
                    "unbalanced source delimiters".to_owned(),
                ));
            }
            _ => {}
        }
    }
    if quote.is_some() || !stack.is_empty() {
        return Err(Phase5Error::InvalidContract(
            "unterminated source construct".to_owned(),
        ));
    }
    Ok(())
}

fn normalize_terms(text: &str) -> String {
    text.chars()
        .filter(char::is_ascii_alphanumeric)
        .flat_map(char::to_lowercase)
        .collect()
}

#[allow(clippy::too_many_lines)]
fn synthetic_contract_suite(
    contract: &EvidenceContractV2,
    taxonomy: &FrozenTaxonomy,
) -> Result<SyntheticContractSuiteV2, Phase5Error> {
    let category = taxonomy
        .categories
        .first()
        .ok_or_else(|| Phase5Error::InvalidContract("taxonomy is empty".to_owned()))?;
    let source = EvidenceNodeV2 {
        role: EvidenceRoleV2::Source,
        effect: EvidenceEffectV2::PreservesInfluence,
        source_kind: Some(SourceSemanticKind::HttpBodyField),
        sink_kind: None,
        span: EvidenceSpanV2 {
            file: "src/synthetic.ts".to_owned(),
            start_line: 10,
            start_column: 3,
            end_line: 10,
            end_column: 18,
        },
        summarizable: false,
    };
    let propagation = EvidenceNodeV2 {
        role: EvidenceRoleV2::Propagation,
        effect: EvidenceEffectV2::PreservesInfluence,
        source_kind: None,
        sink_kind: None,
        span: EvidenceSpanV2 {
            file: "src/synthetic.ts".to_owned(),
            start_line: 12,
            start_column: 3,
            end_line: 12,
            end_column: 16,
        },
        summarizable: true,
    };
    let sink = EvidenceNodeV2 {
        role: EvidenceRoleV2::Sink,
        effect: EvidenceEffectV2::PreservesInfluence,
        source_kind: None,
        sink_kind: Some(SinkSemanticKind::ProtectedRecordMutation),
        span: EvidenceSpanV2 {
            file: "src/synthetic.ts".to_owned(),
            start_line: 14,
            start_column: 3,
            end_line: 14,
            end_column: 20,
        },
        summarizable: false,
    };
    let expectation = EvidenceExpectationV2 {
        expectation_id: "synthetic-expectation".to_owned(),
        taxonomy_version: taxonomy.taxonomy_version.clone(),
        category_id: category.category_id.clone(),
        invariant_id: category.invariant_id.clone(),
        primary_cwe: category.primary_cwe.id.clone(),
        path: vec![source.clone(), propagation.clone(), sink.clone()],
    };
    let canonical = CanonicalFindingV2 {
        taxonomy_version: taxonomy.taxonomy_version.clone(),
        category_id: category.category_id.clone(),
        invariant_id: category.invariant_id.clone(),
        path: vec![source.clone(), propagation, sink.clone()],
        connected_edges: vec![true, true],
        effective_barriers: vec![],
        unresolved_call: false,
        uncertain: false,
        rule_id: Some("ignored-rule".to_owned()),
        tool_identity: Some("synthetic-tool".to_owned()),
        prose: Some("ignored prose".to_owned()),
    };
    let mut vectors = Vec::new();
    let mut add = |id: &str, finding: CanonicalFindingV2, expected: EvidenceMatchV2| {
        vectors.push(SyntheticContractTestV2 {
            test_id: id.to_owned(),
            expectation: expectation.clone(),
            finding,
            expected,
        });
    };
    add("canonical", canonical.clone(), EvidenceMatchV2::Exact);
    let mut equivalent = canonical.clone();
    equivalent.path[0].span.start_column += 1;
    equivalent.path[0].span.end_column -= 1;
    add(
        "equivalent-contained-span",
        equivalent,
        EvidenceMatchV2::Exact,
    );
    let mut compressed = canonical.clone();
    compressed.path.remove(1);
    compressed.connected_edges = vec![true];
    add(
        "permitted-compressed-path",
        compressed,
        EvidenceMatchV2::Exact,
    );
    let mut wrong_source = canonical.clone();
    wrong_source.path[0].source_kind = Some(SourceSemanticKind::HttpQueryValue);
    add("wrong-source", wrong_source, EvidenceMatchV2::NoMatch);
    let mut wrong_sink = canonical.clone();
    if let Some(sink) = wrong_sink.path.last_mut() {
        sink.sink_kind = Some(SinkSemanticKind::SqlQueryExecution);
    }
    add("wrong-sink", wrong_sink, EvidenceMatchV2::NoMatch);
    let mut unordered = canonical.clone();
    unordered.path.swap(0, 2);
    add("wrong-order", unordered, EvidenceMatchV2::NoMatch);
    let mut disconnected = canonical.clone();
    disconnected.connected_edges[0] = false;
    add("disconnected-path", disconnected, EvidenceMatchV2::NoMatch);
    let mut taxonomy_mismatch = canonical.clone();
    taxonomy_mismatch.category_id.push_str(".different");
    add(
        "taxonomy-mismatch",
        taxonomy_mismatch,
        EvidenceMatchV2::NoMatch,
    );
    let mut unresolved = canonical.clone();
    unresolved.unresolved_call = true;
    add("unresolved-call", unresolved, EvidenceMatchV2::Partial);
    let mut uncertain = canonical.clone();
    uncertain.uncertain = true;
    add("declared-uncertainty", uncertain, EvidenceMatchV2::Partial);
    let mut barrier = canonical.clone();
    barrier
        .effective_barriers
        .push(EvidenceEffectV2::RejectsAndTerminates);
    add("effective-barrier", barrier, EvidenceMatchV2::NoMatch);
    let _ = contract;
    Ok(SyntheticContractSuiteV2 {
        schema_version: "secure-bench-phase5-contract-tests-v1".to_owned(),
        contract_version: EVIDENCE_CONTRACT_V2_VERSION.to_owned(),
        synthetic_reports_only: true,
        tests: vectors,
    })
}

fn validate_synthetic_suite(
    contract: &EvidenceContractV2,
    suite: &SyntheticContractSuiteV2,
) -> Result<(), Phase5Error> {
    if !suite.synthetic_reports_only || suite.tests.len() < 11 {
        return Err(Phase5Error::InvalidContract(
            "synthetic contract suite is incomplete".to_owned(),
        ));
    }
    let mut ids = BTreeSet::new();
    for test in &suite.tests {
        if !ids.insert(&test.test_id)
            || match_evidence_v2(contract, &test.expectation, &test.finding) != test.expected
        {
            return Err(Phase5Error::InvalidContract(format!(
                "contract vector failed: {}",
                test.test_id
            )));
        }
    }
    let first = &suite.tests[0].finding;
    let mut renamed = first.clone();
    renamed.rule_id = Some("another-rule".to_owned());
    renamed.tool_identity = Some("another-tool".to_owned());
    renamed.prose = Some("different words".to_owned());
    if evidence_fingerprint_v2(first)? != evidence_fingerprint_v2(&renamed)? {
        return Err(Phase5Error::InvalidContract(
            "non-scoring fields changed fingerprint".to_owned(),
        ));
    }
    Ok(())
}

fn write_fixture(
    root: &Path,
    relative: &str,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<(), Phase5Error> {
    for (path, bytes) in files {
        write_new(root, &format!("{relative}/{path}"), bytes)?;
    }
    Ok(())
}

fn write_new(root: &Path, relative: &str, bytes: &[u8]) -> Result<(), Phase5Error> {
    normalize_relative_path(relative)?;
    let path = root.join(relative);
    if path.exists() {
        return Err(Phase5Error::InvalidContract(format!(
            "refusing to replace {relative}"
        )));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| io_error(relative, error))?;
    }
    fs::write(&path, bytes).map_err(|error| io_error(relative, error))
}

fn read_file(root: &Path, relative: &str) -> Result<Vec<u8>, Phase5Error> {
    normalize_relative_path(relative)?;
    fs::read(root.join(relative)).map_err(|error| io_error(relative, error))
}

fn parse_json<T: for<'de> Deserialize<'de>>(bytes: &[u8], label: &str) -> Result<T, Phase5Error> {
    serde_json::from_slice(bytes)
        .map_err(|_| Phase5Error::InvalidContract(format!("{label} JSON is invalid")))
}

fn read_fixture(root: &Path, relative: &str) -> Result<BTreeMap<String, Vec<u8>>, Phase5Error> {
    normalize_relative_path(relative)?;
    let base = root.join(relative);
    let mut files = BTreeMap::new();
    collect_files(&base, &base, &mut files)?;
    Ok(files)
}

fn collect_files(
    base: &Path,
    current: &Path,
    output: &mut BTreeMap<String, Vec<u8>>,
) -> Result<(), Phase5Error> {
    let mut entries = fs::read_dir(current)
        .map_err(|error| io_error(&current.display().to_string(), error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| io_error(&current.display().to_string(), error))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let file_type = entry
            .file_type()
            .map_err(|error| io_error(&entry.path().display().to_string(), error))?;
        if file_type.is_symlink() {
            return Err(Phase5Error::InvalidContract(
                "fixture symlink is forbidden".to_owned(),
            ));
        }
        if file_type.is_dir() {
            collect_files(base, &entry.path(), output)?;
        } else if file_type.is_file() {
            let relative = entry
                .path()
                .strip_prefix(base)
                .map_err(|_| Phase5Error::InvalidContract("fixture path escaped".to_owned()))?
                .to_str()
                .ok_or_else(|| {
                    Phase5Error::InvalidContract("fixture path is not UTF-8".to_owned())
                })?
                .replace('\\', "/");
            let bytes = fs::read(entry.path()).map_err(|error| io_error(&relative, error))?;
            output.insert(relative, bytes);
        } else {
            return Err(Phase5Error::InvalidContract(
                "special fixture file is forbidden".to_owned(),
            ));
        }
    }
    Ok(())
}

fn fixture_hash(files: &BTreeMap<String, Vec<u8>>) -> String {
    let mut digest = Sha256::new();
    for (path, bytes) in files {
        digest.update((path.len() as u64).to_be_bytes());
        digest.update(path.as_bytes());
        digest.update((bytes.len() as u64).to_be_bytes());
        digest.update(bytes);
    }
    hex_digest(&digest.finalize())
}

fn case_contract_hash(
    id: &str,
    kind: Phase5CaseKind,
    path: &str,
    fixture_sha256: &str,
    expectation: Option<&EvidenceExpectationV2>,
    security_property: Option<&str>,
) -> Result<String, Phase5Error> {
    let bytes = serde_json::to_vec(&(
        id,
        kind,
        path,
        fixture_sha256,
        expectation,
        security_property,
    ))
    .map_err(|_| Phase5Error::Serialization)?;
    Ok(fingerprint(&bytes))
}

fn aggregate_named_hashes(items: &[(String, String)]) -> String {
    let mut digest = Sha256::new();
    for (name, hash) in items {
        digest.update((name.len() as u64).to_be_bytes());
        digest.update(name.as_bytes());
        digest.update(hash.as_bytes());
    }
    hex_digest(&digest.finalize())
}

fn merkle_root(leaves: &[String]) -> String {
    if leaves.is_empty() {
        return ZERO_HASH.to_owned();
    }
    let mut level = leaves
        .iter()
        .map(|leaf| Sha256::digest(leaf.as_bytes()).to_vec())
        .collect::<Vec<_>>();
    while level.len() > 1 {
        if level.len() % 2 == 1
            && let Some(last) = level.last().cloned()
        {
            level.push(last);
        }
        level = level
            .chunks(2)
            .map(|pair| {
                let mut digest = Sha256::new();
                digest.update(&pair[0]);
                digest.update(&pair[1]);
                digest.finalize().to_vec()
            })
            .collect();
    }
    hex_digest(&level[0])
}

fn evaluator_hashes(root: &Path) -> Result<BTreeMap<String, String>, Phase5Error> {
    EVALUATOR_FILES
        .iter()
        .map(|relative| {
            let bytes = read_file(root, relative)?;
            Ok(((*relative).to_owned(), fingerprint(&bytes)))
        })
        .collect()
}

fn manifest_content_hash(manifest: &Phase5Manifest) -> Result<String, Phase5Error> {
    let mut copy = manifest.clone();
    copy.commitments.manifest_content_sha256.clear();
    Ok(fingerprint(
        &serde_json::to_vec(&copy).map_err(|_| Phase5Error::Serialization)?,
    ))
}

fn ledger_entry_hash(entry: &Phase5LedgerEntry) -> Result<String, Phase5Error> {
    let mut copy = entry.clone();
    copy.entry_hash.clear();
    Ok(fingerprint(
        &serde_json::to_vec(&copy).map_err(|_| Phase5Error::Serialization)?,
    ))
}

fn validate_timestamp(value: &str) -> Result<(), Phase5Error> {
    if value.len() != 20 || !value.ends_with('Z') || value.as_bytes().get(10) != Some(&b'T') {
        return Err(Phase5Error::InvalidContract(
            "freeze time must be UTC YYYY-MM-DDTHH:MM:SSZ".to_owned(),
        ));
    }
    Ok(())
}

fn prior_overlap_metrics(
    root: &Path,
    manifest: &Phase5Manifest,
) -> Result<(u32, u32, u32), Phase5Error> {
    let mut current = Vec::new();
    for pair in &manifest.pairs {
        current.push(read_fixture(root, &pair.vulnerable.fixture_path)?);
        current.push(read_fixture(root, &pair.control.fixture_path)?);
    }
    let mut prior = Vec::new();
    for prior_root in ["fixtures", "holdout/phase-3/cases"] {
        let path = root.join(prior_root);
        if path.exists() {
            collect_source_documents(&path, &mut prior)?;
        }
    }
    let current_docs = current.iter().map(combined_source).collect::<Vec<_>>();
    let mut max_token = 0;
    let mut max_shape = 0;
    let mut max_semantic = 0;
    for document in &current_docs {
        for other in &prior {
            max_token = max_token.max(jaccard_basis_points(
                &token_shingles(document),
                &token_shingles(other),
            ));
            max_shape = max_shape.max(jaccard_basis_points(
                &shape_tokens(document),
                &shape_tokens(other),
            ));
            max_semantic = max_semantic.max(jaccard_basis_points(
                &semantic_tokens(document),
                &semantic_tokens(other),
            ));
        }
    }
    if max_token >= 9_500 || max_shape >= 9_800 {
        return Err(Phase5Error::InvalidContract(
            "near-duplicate prior fixture detected".to_owned(),
        ));
    }
    Ok((max_token, max_shape, max_semantic))
}

fn collect_source_documents(path: &Path, output: &mut Vec<String>) -> Result<(), Phase5Error> {
    let mut entries = fs::read_dir(path)
        .map_err(|error| io_error("prior corpus", error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| io_error("prior corpus", error))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let kind = entry
            .file_type()
            .map_err(|error| io_error("prior corpus", error))?;
        if kind.is_dir() {
            collect_source_documents(&entry.path(), output)?;
        } else if kind.is_file() {
            let entry_path = entry.path();
            let extension = entry_path
                .extension()
                .and_then(std::ffi::OsStr::to_str)
                .unwrap_or_default();
            if ["js", "jsx", "ts", "tsx"].contains(&extension)
                && let Ok(text) = fs::read_to_string(entry.path())
            {
                output.push(text);
            }
        }
    }
    Ok(())
}

fn combined_source(files: &BTreeMap<String, Vec<u8>>) -> String {
    files
        .iter()
        .filter(|(path, _)| *path != "package.json")
        .filter_map(|(_, bytes)| std::str::from_utf8(bytes).ok())
        .collect::<Vec<_>>()
        .join("\n")
}

fn lexical_tokens(text: &str) -> Vec<String> {
    text.split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|token| token.len() > 1)
        .map(str::to_ascii_lowercase)
        .collect()
}

fn token_shingles(text: &str) -> BTreeSet<String> {
    lexical_tokens(text)
        .windows(5)
        .map(|window| window.join("|"))
        .collect()
}

fn shape_tokens(text: &str) -> BTreeSet<String> {
    let shapes = lexical_tokens(text)
        .into_iter()
        .map(|token| {
            if [
                "if", "return", "import", "export", "function", "await", "new", "const",
            ]
            .contains(&token.as_str())
            {
                token
            } else if token.chars().all(|character| character.is_ascii_digit()) {
                "number".to_owned()
            } else {
                "identifier".to_owned()
            }
        })
        .collect::<Vec<_>>();
    shapes.windows(8).map(|window| window.join("|")).collect()
}

fn semantic_tokens(text: &str) -> BTreeSet<String> {
    [
        "createServer",
        "express",
        "nextUrl",
        "form",
        "execFile",
        "Function",
        "readFile",
        "fetch",
        "redirect",
        "query",
        "startsWith",
        "origin",
    ]
    .into_iter()
    .filter(|token| text.contains(token))
    .map(ToString::to_string)
    .collect()
}

fn jaccard_basis_points(left: &BTreeSet<String>, right: &BTreeSet<String>) -> u32 {
    let union = left.union(right).count();
    if union == 0 {
        return 0;
    }
    u32::try_from(left.intersection(right).count() * 10_000 / union).unwrap_or(10_000)
}

fn case_noun(index: usize) -> &'static str {
    const NOUNS: [&str; 56] = [
        "alder",
        "beacon",
        "cinder",
        "delta",
        "elm",
        "flint",
        "grove",
        "harbor",
        "islet",
        "juniper",
        "keystone",
        "lagoon",
        "meadow",
        "nectar",
        "orchard",
        "prairie",
        "quartz",
        "ridge",
        "summit",
        "thicket",
        "upland",
        "valley",
        "willow",
        "xenon",
        "yarrow",
        "zephyr",
        "amber",
        "birch",
        "coral",
        "drift",
        "ember",
        "fern",
        "glade",
        "heath",
        "indigo",
        "jasmine",
        "kestrel",
        "linden",
        "marsh",
        "northstar",
        "opal",
        "pebble",
        "quill",
        "rivulet",
        "spruce",
        "tundra",
        "umber",
        "violet",
        "wren",
        "xylem",
        "yucca",
        "zenith",
        "acorn",
        "brook",
        "clover",
        "dune",
    ];
    NOUNS[index]
}

#[allow(clippy::needless_pass_by_value)]
fn io_error(path: &str, error: std::io::Error) -> Phase5Error {
    Phase5Error::Io {
        path: path.to_owned(),
        detail: error.to_string(),
    }
}

fn normalize_relative_path(path: &str) -> Result<String, Phase5Error> {
    let path = Path::new(path);
    if path.is_absolute() {
        return Err(Phase5Error::InvalidContract(
            "absolute evidence path".to_owned(),
        ));
    }
    let mut segments = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(segment) => segments.push(
                segment
                    .to_str()
                    .ok_or_else(|| Phase5Error::InvalidContract("non-UTF-8 path".to_owned()))?,
            ),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(Phase5Error::InvalidContract(
                    "unsafe evidence path".to_owned(),
                ));
            }
        }
    }
    if segments.is_empty() {
        return Err(Phase5Error::InvalidContract(
            "empty evidence path".to_owned(),
        ));
    }
    Ok(segments.join("/"))
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, Phase5Error> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|_| Phase5Error::Serialization)?;
    bytes.push(b'\n');
    Ok(bytes)
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

#[cfg(test)]
mod tests {
    use super::*;

    const TAXONOMY: &[u8] = include_bytes!("../../../taxonomy/secure-bench-taxonomy-v1.json");

    #[test]
    fn schedule_is_balanced_and_rotates_every_taxonomy_family() -> Result<(), Phase5Error> {
        let taxonomy = load_taxonomy(TAXONOMY)
            .map_err(|error| Phase5Error::InvalidContract(error.to_string()))?;
        let schedule = phase5_schedule(&taxonomy);
        validate_schedule(&schedule, &taxonomy)?;
        let proof = design_proof(&schedule);
        assert_eq!(proof.framework_topology_cell_range, 1);
        assert_eq!(proof.framework_language_association.chi_square_milli, 0);
        assert_eq!(proof.topology_language_association.chi_square_milli, 0);
        Ok(())
    }

    #[test]
    fn all_generated_pair_drafts_are_inverse_and_scanner_neutral() -> Result<(), Phase5Error> {
        let taxonomy = load_taxonomy(TAXONOMY)
            .map_err(|error| Phase5Error::InvalidContract(error.to_string()))?;
        for assignment in phase5_schedule(&taxonomy) {
            let category = taxonomy
                .categories
                .iter()
                .find(|category| category.category_id == assignment.category_id)
                .ok_or_else(|| Phase5Error::InvalidContract("missing category".to_owned()))?;
            let noun = case_noun(usize::try_from(assignment.ordinal - 1).unwrap_or_default());
            let vulnerable = build_fixture(&assignment, category, noun, false)?;
            let control = build_fixture(&assignment, category, noun, true)?;
            validate_inverse_pair(&vulnerable, &control)?;
            validate_scanner_visible_files(&vulnerable.files)?;
            validate_scanner_visible_files(&control.files)?;
        }
        Ok(())
    }

    #[test]
    fn synthetic_contract_vectors_are_adversarial() -> Result<(), Phase5Error> {
        let taxonomy = load_taxonomy(TAXONOMY)
            .map_err(|error| Phase5Error::InvalidContract(error.to_string()))?;
        let contract = evidence_contract_v2(TAXONOMY)?;
        let suite = synthetic_contract_suite(&contract, &taxonomy)?;
        validate_synthetic_suite(&contract, &suite)?;
        assert!(
            suite
                .tests
                .iter()
                .any(|test| test.expected == EvidenceMatchV2::Exact)
        );
        assert!(
            suite
                .tests
                .iter()
                .any(|test| test.expected == EvidenceMatchV2::Partial)
        );
        assert!(
            suite
                .tests
                .iter()
                .any(|test| test.expected == EvidenceMatchV2::NoMatch)
        );
        Ok(())
    }

    #[test]
    fn unsafe_paths_never_compare_as_equivalent() -> Result<(), Phase5Error> {
        let contract = evidence_contract_v2(TAXONOMY)?;
        let span = EvidenceSpanV2 {
            file: "../outside.ts".to_owned(),
            start_line: 1,
            start_column: 1,
            end_line: 1,
            end_column: 2,
        };
        assert!(!spans_equivalent(&contract.location_rules, &span, &span));
        Ok(())
    }
}
