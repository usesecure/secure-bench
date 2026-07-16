//! Frozen Phase 3 holdout contracts, commitments, mutation proofs, and ledger validation.

use crate::adapter::fingerprint;
use crate::model::{CaseKind, EvidenceConstraint, FixtureProvenance, LocationConstraint};
use crate::taxonomy::{FrozenTaxonomy, load_taxonomy};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

/// Phase 3 frozen holdout manifest schema identifier.
pub const HOLDOUT_SCHEMA_V1: &str = "secure-bench-holdout-v1";
/// Phase 3 append-only ledger entry schema identifier.
pub const HOLDOUT_LEDGER_SCHEMA_V1: &str = "secure-bench-holdout-ledger-entry-v1";
/// Stable identity of the first expanded holdout.
pub const PHASE_3_HOLDOUT_ID: &str = "phase-3-expanded-frozen-holdout";

const EXPECTED_PAIR_COUNT: usize = 28;
const EXPECTED_CASE_COUNT: u64 = 56;
const HOLDOUT_ROOT: &str = "holdout/phase-3/cases";
const LEDGER_PATH: &str = "holdout/phase-3/execution-ledger.jsonl";
const RESULT_PATH_TEMPLATE: &str = "holdout/phase-3/results/{commitment_root}/{run_id}.json";
const MAX_CASE_FILES: usize = 64;
const MAX_CASE_BYTES: u64 = 256 * 1024;
const MAX_FILE_BYTES: u64 = 128 * 1024;
const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Complete frozen Phase 3 holdout manifest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HoldoutManifest {
    /// Manifest schema identity.
    pub schema_version: String,
    /// Stable holdout identity.
    pub holdout_id: String,
    /// Human-readable title.
    pub title: String,
    /// Neutral scope and limitations.
    pub description: String,
    /// Published methodology revision.
    pub methodology_version: String,
    /// UTC time at which the examination was sealed.
    pub frozen_at_utc: String,
    /// Exact frozen taxonomy linkage.
    pub taxonomy: HoldoutTaxonomyBinding,
    /// Public sources permitted during case design.
    pub design_sources: Vec<String>,
    /// Corpus and contract commitments.
    pub commitment: HoldoutCommitment,
    /// Frozen scoring behavior.
    pub scoring: HoldoutScoring,
    /// One-shot future evaluation protocol.
    pub protocol: HoldoutProtocol,
    /// Creation-time neutrality attestation.
    pub creation: HoldoutCreationAttestation,
    /// Suite provenance.
    pub provenance: FixtureProvenance,
    /// Exactly 28 independently validated vulnerable/control pairs.
    pub pairs: Vec<HoldoutPair>,
}

/// Exact taxonomy artifact and semantic version linkage.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HoldoutTaxonomyBinding {
    /// Taxonomy schema identity.
    pub schema_version: String,
    /// Frozen semantic taxonomy version.
    pub taxonomy_version: String,
    /// SHA-256 of the taxonomy artifact bytes.
    pub artifact_sha256: String,
    /// Canonical taxonomy content hash.
    pub content_hash: String,
}

/// Aggregate content and contract commitments.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HoldoutCommitment {
    /// Number of paired designs.
    pub pair_count: u64,
    /// Total cases.
    pub case_count: u64,
    /// Vulnerable cases.
    pub vulnerable_count: u64,
    /// Safe controls.
    pub safe_control_count: u64,
    /// SHA-256 over sorted case identifiers and fixture hashes.
    pub aggregate_corpus_sha256: String,
    /// Domain-separated Merkle root over sorted case contract hashes.
    pub contract_merkle_root: String,
}

/// Frozen prospective scoring semantics.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct HoldoutScoring {
    /// Required dimensions for exact detection credit.
    pub exact_requires: Vec<String>,
    /// Partial observations do not count as detections.
    pub partial_detection_credit: bool,
    /// One finding cannot satisfy multiple expectations.
    pub one_to_one_matching: bool,
    /// Duplicate observations cannot add credit.
    pub duplicate_detection_credit: bool,
    /// Operational failures cannot appear as clean cases.
    pub failed_cases_are_clean: bool,
    /// Negative controls remain separately scored.
    pub safe_controls_scored_separately: bool,
    /// Early phases expose no aggregate leaderboard score.
    pub composite_score: bool,
}

/// One-shot execution and result-retention rules.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HoldoutProtocol {
    /// Only one execution reservation may ever appear in the ledger.
    pub one_shot: bool,
    /// Required append-only ledger path.
    pub ledger_path: String,
    /// Commitment-bound future result location.
    pub result_path_template: String,
    /// Results must be created exclusively and never replaced.
    pub result_write_mode: String,
    /// Scanner network policy.
    pub network: String,
    /// Current sealed state.
    pub evaluation_state: String,
}

/// Creation-time assertions that can be independently audited from repository history.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HoldoutCreationAttestation {
    /// Scanner processes launched while defining the examination.
    pub scanner_executions: u64,
    /// Whether scanner reports informed case design.
    pub scanner_reports_consulted: bool,
    /// Whether scanner-specific rule or alias data informed the contract.
    pub scanner_specific_inputs: bool,
    /// Whether answers are present in scanner-visible copies.
    pub answers_scanner_visible: bool,
}

/// One independently mutated vulnerable/control pair.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HoldoutPair {
    /// Stable pair identity.
    pub pair_id: String,
    /// Source language shared by both cases.
    pub language: HoldoutLanguage,
    /// Framework stratum shared by both cases.
    pub framework: HoldoutFramework,
    /// Required structural variation.
    pub variation: HoldoutVariation,
    /// Exact frozen taxonomy coordinates.
    pub taxonomy: HoldoutTaxonomyCoordinates,
    /// Primary public CWE association.
    pub primary_cwe: String,
    /// Neutral eligibility and security rationale.
    pub rationale: String,
    /// Exact guard-addition/removal projection.
    pub mutation: HoldoutMutation,
    /// Vulnerable member.
    pub vulnerable: HoldoutCase,
    /// Paired safe control.
    pub control: HoldoutCase,
}

/// Supported scanner-visible source language.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldoutLanguage {
    /// JavaScript.
    JavaScript,
    /// JavaScript with JSX syntax.
    Jsx,
    /// TypeScript.
    TypeScript,
    /// TypeScript with JSX syntax.
    Tsx,
}

/// Framework coverage strata.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldoutFramework {
    /// Node.js standard APIs.
    NodeJs,
    /// Express-style handlers.
    Express,
    /// Next.js App Router route handlers.
    NextAppRouter,
    /// Next.js Server Actions.
    NextServerActions,
}

/// Data-flow and control-flow structure.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldoutVariation {
    /// Direct source-to-sink flow.
    Direct,
    /// Flow through a local helper.
    HelperMediated,
    /// Flow through an aliased inter-file import.
    InterFileAliased,
    /// Flow whose exploitability depends on branch dominance.
    ControlFlowSensitive,
}

/// Canonical taxonomy coordinates stored independently of scanner vocabulary.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HoldoutTaxonomyCoordinates {
    /// Frozen taxonomy version.
    pub taxonomy_version: String,
    /// Canonical category identifier.
    pub category_id: String,
    /// Canonical invariant identifier.
    pub invariant_id: String,
}

/// One frozen holdout case.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HoldoutCase {
    /// Stable case identity.
    pub case_id: String,
    /// Vulnerable or safe-control label.
    pub kind: CaseKind,
    /// Repository-relative fixture directory.
    pub fixture_path: String,
    /// SHA-256 commitment to scanner-visible bytes.
    pub fixture_sha256: String,
    /// SHA-256 commitment to all case contract fields.
    pub contract_sha256: String,
    /// Vulnerable expectation, absent for controls.
    pub expected: Option<HoldoutExpectation>,
    /// Security property preventing exploitation, present only for controls.
    pub security_property: Option<String>,
    /// Case-level authorship and license provenance.
    pub provenance: FixtureProvenance,
}

/// Exact vulnerable expectation frozen before execution.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HoldoutExpectation {
    /// Stable expectation identity.
    pub expectation_id: String,
    /// Precise source location.
    pub source: LocationConstraint,
    /// Precise sink location.
    pub sink: LocationConstraint,
    /// Required ordered evidence path.
    pub evidence: EvidenceConstraint,
    /// Why the flow violates the frozen invariant.
    pub rationale: String,
}

/// One exact reversible guard mutation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HoldoutMutation {
    /// Relative source file containing the only semantic pair delta.
    pub file: String,
    /// Lines replaced when introducing the guard.
    pub vulnerable_lines: HoldoutLineRange,
    /// Lines removed when deleting the guard.
    pub control_lines: HoldoutLineRange,
    /// SHA-256 of the vulnerable fragment including line endings.
    pub vulnerable_fragment_sha256: String,
    /// SHA-256 of the control fragment including line endings.
    pub control_fragment_sha256: String,
    /// Neutral description of the guard transformation.
    pub guard_property: String,
}

/// Inclusive one-based line range.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HoldoutLineRange {
    /// First included line.
    pub start: u32,
    /// Last included line.
    pub end: u32,
}

/// One append-only ledger entry.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HoldoutLedgerEntry {
    /// Ledger entry schema identity.
    pub schema_version: String,
    /// Zero-based append sequence.
    pub sequence: u64,
    /// State-transition event.
    pub event: HoldoutLedgerEvent,
    /// Bound holdout identity.
    pub holdout_id: String,
    /// Bound contract commitment root.
    pub commitment_root: String,
    /// Prior canonical entry hash, or all zeroes for genesis.
    pub previous_entry_hash: String,
    /// UTC event time.
    pub timestamp_utc: String,
    /// Future run identity.
    pub run_id: Option<String>,
    /// Future external binary fingerprint.
    pub binary_sha256: Option<String>,
    /// Future immutable result fingerprint.
    pub result_sha256: Option<String>,
    /// Stable non-sensitive terminal detail code.
    pub detail_code: Option<String>,
    /// SHA-256 over this entry excluding this field.
    pub entry_hash: String,
}

/// Allowed append-only ledger state transitions.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldoutLedgerEvent {
    /// Examination frozen; no scanner was run.
    HoldoutSealed,
    /// The sole evaluation slot was durably reserved before execution.
    ExecutionStarted,
    /// The sole execution produced an immutable result.
    ExecutionCompleted,
    /// The sole execution terminated without a replaceable result.
    ExecutionFailed,
}

/// Validated corpus coverage and commitments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HoldoutValidation {
    /// Total pairs.
    pub pairs: u64,
    /// Total cases.
    pub cases: u64,
    /// Vulnerable cases.
    pub vulnerable_cases: u64,
    /// Safe controls.
    pub safe_controls: u64,
    /// Pair counts by category ID.
    pub taxonomy_pairs: BTreeMap<String, u64>,
    /// Case counts by framework.
    pub framework_cases: BTreeMap<String, u64>,
    /// Recomputed corpus hash.
    pub aggregate_corpus_sha256: String,
    /// Recomputed contract Merkle root.
    pub contract_merkle_root: String,
}

/// Holdout contract, filesystem, privacy, mutation, or ledger error.
#[derive(Debug, Error)]
pub enum HoldoutError {
    /// Input JSON was malformed.
    #[error("invalid {contract} JSON at line {line}")]
    InvalidJson {
        /// Contract label.
        contract: &'static str,
        /// One-based parser line.
        line: usize,
    },
    /// Schema or semantic contract failure.
    #[error("invalid holdout contract: {0}")]
    InvalidContract(String),
    /// Privacy or answer-leakage failure.
    #[error("scanner-visible holdout leakage in `{path}`: {detail}")]
    Leakage {
        /// Repository-relative path.
        path: String,
        /// Sanitized reason.
        detail: String,
    },
    /// Filesystem failure without source contents.
    #[error("could not inspect holdout path `{path}`: {detail}")]
    Io {
        /// Repository-relative path.
        path: String,
        /// Sanitized error.
        detail: String,
    },
    /// Deterministic serialization failed.
    #[error("could not serialize deterministic holdout data")]
    Serialization,
}

#[derive(Serialize)]
struct CaseContractView<'a> {
    pair_id: &'a str,
    language: HoldoutLanguage,
    framework: HoldoutFramework,
    variation: HoldoutVariation,
    taxonomy: &'a HoldoutTaxonomyCoordinates,
    primary_cwe: &'a str,
    rationale: &'a str,
    mutation: &'a HoldoutMutation,
    case_id: &'a str,
    kind: CaseKind,
    fixture_path: &'a str,
    fixture_sha256: &'a str,
    expected: &'a Option<HoldoutExpectation>,
    security_property: &'a Option<String>,
    provenance: &'a FixtureProvenance,
}

#[derive(Serialize)]
struct LedgerHashView<'a> {
    schema_version: &'a str,
    sequence: u64,
    event: HoldoutLedgerEvent,
    holdout_id: &'a str,
    commitment_root: &'a str,
    previous_entry_hash: &'a str,
    timestamp_utc: &'a str,
    run_id: &'a Option<String>,
    binary_sha256: &'a Option<String>,
    result_sha256: &'a Option<String>,
    detail_code: &'a Option<String>,
}

/// Loads and fully validates the committed holdout manifest and fixture tree.
///
/// # Errors
///
/// Returns [`HoldoutError`] for malformed, schema-invalid, non-canonical, drifted, leaked,
/// duplicated, or semantically invalid data.
pub fn load_holdout_manifest(
    bytes: &[u8],
    repository_root: &Path,
    taxonomy_bytes: &[u8],
) -> Result<(HoldoutManifest, HoldoutValidation), HoldoutError> {
    let manifest: HoldoutManifest =
        serde_json::from_slice(bytes).map_err(|error| HoldoutError::InvalidJson {
            contract: "holdout manifest",
            line: error.line(),
        })?;
    crate::schema::validate_holdout_manifest(&manifest)
        .map_err(|error| HoldoutError::InvalidContract(error.to_string()))?;
    if canonical_holdout_json(&manifest)? != bytes {
        return Err(HoldoutError::InvalidContract(
            "holdout manifest must use canonical pretty JSON with one trailing newline".to_owned(),
        ));
    }
    let taxonomy = load_taxonomy(taxonomy_bytes)
        .map_err(|error| HoldoutError::InvalidContract(error.to_string()))?;
    let validation = validate_manifest(&manifest, repository_root, taxonomy_bytes, &taxonomy)?;
    Ok((manifest, validation))
}

/// Computes all fixture, case-contract, aggregate, and Merkle commitments for a draft manifest.
///
/// # Errors
///
/// Returns [`HoldoutError`] when fixture discovery or deterministic hashing fails.
pub fn seal_holdout_manifest(
    manifest: &mut HoldoutManifest,
    repository_root: &Path,
    taxonomy_bytes: &[u8],
) -> Result<HoldoutValidation, HoldoutError> {
    let taxonomy = load_taxonomy(taxonomy_bytes)
        .map_err(|error| HoldoutError::InvalidContract(error.to_string()))?;
    for pair in &mut manifest.pairs {
        pair.vulnerable.fixture_sha256 =
            fixture_fingerprint(repository_root, &pair.vulnerable.fixture_path)?;
        pair.control.fixture_sha256 =
            fixture_fingerprint(repository_root, &pair.control.fixture_path)?;
        pair.mutation.vulnerable_fragment_sha256 = mutation_fragment_hash(
            repository_root,
            &pair.vulnerable.fixture_path,
            &pair.mutation.file,
            pair.mutation.vulnerable_lines,
        )?;
        pair.mutation.control_fragment_sha256 = mutation_fragment_hash(
            repository_root,
            &pair.control.fixture_path,
            &pair.mutation.file,
            pair.mutation.control_lines,
        )?;
    }
    for index in 0..manifest.pairs.len() {
        let (vulnerable_hash, control_hash) = {
            let pair = &manifest.pairs[index];
            (
                case_contract_hash(pair, &pair.vulnerable)?,
                case_contract_hash(pair, &pair.control)?,
            )
        };
        manifest.pairs[index].vulnerable.contract_sha256 = vulnerable_hash;
        manifest.pairs[index].control.contract_sha256 = control_hash;
    }
    let (aggregate, merkle) = commitments(manifest)?;
    manifest.commitment = HoldoutCommitment {
        pair_count: manifest.pairs.len().try_into().unwrap_or(u64::MAX),
        case_count: manifest
            .pairs
            .len()
            .saturating_mul(2)
            .try_into()
            .unwrap_or(u64::MAX),
        vulnerable_count: manifest.pairs.len().try_into().unwrap_or(u64::MAX),
        safe_control_count: manifest.pairs.len().try_into().unwrap_or(u64::MAX),
        aggregate_corpus_sha256: aggregate,
        contract_merkle_root: merkle,
    };
    validate_manifest(manifest, repository_root, taxonomy_bytes, &taxonomy)
}

/// Returns canonical manifest bytes.
///
/// # Errors
///
/// Returns [`HoldoutError::Serialization`] if JSON serialization fails.
pub fn canonical_holdout_json(manifest: &HoldoutManifest) -> Result<Vec<u8>, HoldoutError> {
    let mut bytes = serde_json::to_vec_pretty(manifest).map_err(|_| HoldoutError::Serialization)?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Creates the sealed genesis ledger entry without reserving an evaluation.
///
/// # Errors
///
/// Returns [`HoldoutError`] if deterministic hashing fails.
pub fn genesis_ledger_entry(
    manifest: &HoldoutManifest,
) -> Result<HoldoutLedgerEntry, HoldoutError> {
    let mut entry = HoldoutLedgerEntry {
        schema_version: HOLDOUT_LEDGER_SCHEMA_V1.to_owned(),
        sequence: 0,
        event: HoldoutLedgerEvent::HoldoutSealed,
        holdout_id: manifest.holdout_id.clone(),
        commitment_root: manifest.commitment.contract_merkle_root.clone(),
        previous_entry_hash: ZERO_HASH.to_owned(),
        timestamp_utc: manifest.frozen_at_utc.clone(),
        run_id: None,
        binary_sha256: None,
        result_sha256: None,
        detail_code: None,
        entry_hash: ZERO_HASH.to_owned(),
    };
    entry.entry_hash = ledger_entry_hash(&entry)?;
    Ok(entry)
}

/// Returns canonical compact JSON Lines bytes for ledger entries.
///
/// # Errors
///
/// Returns [`HoldoutError::Serialization`] if JSON serialization fails.
pub fn canonical_ledger_jsonl(entries: &[HoldoutLedgerEntry]) -> Result<Vec<u8>, HoldoutError> {
    let mut bytes = Vec::new();
    for entry in entries {
        let line = serde_json::to_vec(entry).map_err(|_| HoldoutError::Serialization)?;
        bytes.extend_from_slice(&line);
        bytes.push(b'\n');
    }
    Ok(bytes)
}

/// Validates canonical append-only ledger bytes and one-shot state transitions.
///
/// # Errors
///
/// Returns [`HoldoutError`] for malformed entries, broken chains, replacement attempts, or
/// multiple execution reservations.
pub fn validate_holdout_ledger(
    bytes: &[u8],
    manifest: &HoldoutManifest,
) -> Result<Vec<HoldoutLedgerEntry>, HoldoutError> {
    let text = std::str::from_utf8(bytes).map_err(|_| {
        HoldoutError::InvalidContract("holdout ledger must be UTF-8 JSON Lines".to_owned())
    })?;
    let mut entries = Vec::new();
    for line in text.lines() {
        if line.is_empty() {
            return Err(HoldoutError::InvalidContract(
                "holdout ledger cannot contain empty lines".to_owned(),
            ));
        }
        let entry: HoldoutLedgerEntry =
            serde_json::from_str(line).map_err(|error| HoldoutError::InvalidJson {
                contract: "holdout ledger entry",
                line: error.line(),
            })?;
        crate::schema::validate_holdout_ledger_entry(&entry)
            .map_err(|error| HoldoutError::InvalidContract(error.to_string()))?;
        entries.push(entry);
    }
    if entries.is_empty() || canonical_ledger_jsonl(&entries)? != bytes {
        return Err(HoldoutError::InvalidContract(
            "holdout ledger must contain canonical append-only JSON Lines".to_owned(),
        ));
    }
    validate_ledger_semantics(&entries, manifest)?;
    Ok(entries)
}

/// Constructs the only permitted execution-reservation entry after validating the complete chain.
///
/// # Errors
///
/// Returns [`HoldoutError`] unless the ledger is in its genesis-only sealed state.
pub fn execution_started_ledger_entry(
    entries: &[HoldoutLedgerEntry],
    manifest: &HoldoutManifest,
    timestamp_utc: &str,
    run_id: &str,
    binary_sha256: &str,
) -> Result<HoldoutLedgerEntry, HoldoutError> {
    validate_ledger_semantics(entries, manifest)?;
    if entries.len() != 1 || entries[0].event != HoldoutLedgerEvent::HoldoutSealed {
        return Err(HoldoutError::InvalidContract(
            "the one-shot execution slot is not available".to_owned(),
        ));
    }
    next_ledger_entry(
        entries,
        manifest,
        timestamp_utc,
        HoldoutLedgerEvent::ExecutionStarted,
        Some(run_id.to_owned()),
        Some(binary_sha256.to_owned()),
        None,
        None,
    )
}

/// Constructs the immutable successful terminal entry for the reserved execution.
///
/// # Errors
///
/// Returns [`HoldoutError`] unless the chain contains exactly one matching reservation.
pub fn execution_completed_ledger_entry(
    entries: &[HoldoutLedgerEntry],
    manifest: &HoldoutManifest,
    timestamp_utc: &str,
    run_id: &str,
    result_sha256: &str,
) -> Result<HoldoutLedgerEntry, HoldoutError> {
    validate_ledger_semantics(entries, manifest)?;
    if entries.len() != 2
        || entries[1].event != HoldoutLedgerEvent::ExecutionStarted
        || entries[1].run_id.as_deref() != Some(run_id)
    {
        return Err(HoldoutError::InvalidContract(
            "the terminal entry does not match the sole reservation".to_owned(),
        ));
    }
    next_ledger_entry(
        entries,
        manifest,
        timestamp_utc,
        HoldoutLedgerEvent::ExecutionCompleted,
        Some(run_id.to_owned()),
        None,
        Some(result_sha256.to_owned()),
        None,
    )
}

/// Constructs the immutable failed terminal entry for the reserved execution.
///
/// # Errors
///
/// Returns [`HoldoutError`] unless the chain contains exactly one matching reservation.
pub fn execution_failed_ledger_entry(
    entries: &[HoldoutLedgerEntry],
    manifest: &HoldoutManifest,
    timestamp_utc: &str,
    run_id: &str,
    detail_code: &str,
) -> Result<HoldoutLedgerEntry, HoldoutError> {
    validate_ledger_semantics(entries, manifest)?;
    if entries.len() != 2
        || entries[1].event != HoldoutLedgerEvent::ExecutionStarted
        || entries[1].run_id.as_deref() != Some(run_id)
    {
        return Err(HoldoutError::InvalidContract(
            "the failed entry does not match the sole reservation".to_owned(),
        ));
    }
    next_ledger_entry(
        entries,
        manifest,
        timestamp_utc,
        HoldoutLedgerEvent::ExecutionFailed,
        Some(run_id.to_owned()),
        None,
        None,
        Some(detail_code.to_owned()),
    )
}

#[allow(clippy::too_many_arguments)]
fn next_ledger_entry(
    entries: &[HoldoutLedgerEntry],
    manifest: &HoldoutManifest,
    timestamp_utc: &str,
    event: HoldoutLedgerEvent,
    run_id: Option<String>,
    binary_sha256: Option<String>,
    result_sha256: Option<String>,
    detail_code: Option<String>,
) -> Result<HoldoutLedgerEntry, HoldoutError> {
    let previous = entries.last().ok_or_else(|| {
        HoldoutError::InvalidContract("cannot append to an empty ledger".to_owned())
    })?;
    let mut entry = HoldoutLedgerEntry {
        schema_version: HOLDOUT_LEDGER_SCHEMA_V1.to_owned(),
        sequence: entries.len().try_into().unwrap_or(u64::MAX),
        event,
        holdout_id: manifest.holdout_id.clone(),
        commitment_root: manifest.commitment.contract_merkle_root.clone(),
        previous_entry_hash: previous.entry_hash.clone(),
        timestamp_utc: timestamp_utc.to_owned(),
        run_id,
        binary_sha256,
        result_sha256,
        detail_code,
        entry_hash: ZERO_HASH.to_owned(),
    };
    entry.entry_hash = ledger_entry_hash(&entry)?;
    crate::schema::validate_holdout_ledger_entry(&entry)
        .map_err(|error| HoldoutError::InvalidContract(error.to_string()))?;
    let mut extended = entries.to_vec();
    extended.push(entry.clone());
    validate_ledger_semantics(&extended, manifest)?;
    Ok(entry)
}

fn validate_manifest(
    manifest: &HoldoutManifest,
    repository_root: &Path,
    taxonomy_bytes: &[u8],
    taxonomy: &FrozenTaxonomy,
) -> Result<HoldoutValidation, HoldoutError> {
    validate_top_level(manifest, taxonomy_bytes, taxonomy)?;
    let forbidden = forbidden_terms(manifest, taxonomy);
    let mut case_ids = BTreeSet::new();
    let mut fixture_paths = BTreeSet::new();
    let mut fixture_hashes = BTreeSet::new();
    let mut taxonomy_pairs = BTreeMap::new();
    let mut framework_cases = BTreeMap::new();
    let mut pair_ids = BTreeSet::new();
    let mut pair_texts = Vec::new();
    for pair in &manifest.pairs {
        validate_pair_taxonomy(pair, taxonomy)?;
        if !pair_ids.insert(pair.pair_id.as_str()) {
            return Err(HoldoutError::InvalidContract(format!(
                "duplicate pair identifier `{}`",
                pair.pair_id
            )));
        }
        *taxonomy_pairs
            .entry(pair.taxonomy.category_id.clone())
            .or_insert(0_u64) += 1;
        *framework_cases
            .entry(framework_name(pair.framework).to_owned())
            .or_insert(0_u64) += 2;
        validate_case(
            pair,
            &pair.vulnerable,
            repository_root,
            &forbidden,
            &mut case_ids,
            &mut fixture_paths,
            &mut fixture_hashes,
        )?;
        validate_case(
            pair,
            &pair.control,
            repository_root,
            &forbidden,
            &mut case_ids,
            &mut fixture_paths,
            &mut fixture_hashes,
        )?;
        validate_pair_mutation(pair, repository_root)?;
        pair_texts.push((
            pair.pair_id.as_str(),
            pair_source_text(pair, repository_root)?,
        ));
    }
    validate_coverage(manifest, &taxonomy_pairs, &framework_cases)?;
    validate_near_duplicates(&pair_texts)?;
    validate_phase1_non_reuse(manifest, repository_root, &pair_texts)?;
    let (aggregate, merkle) = commitments(manifest)?;
    if manifest.commitment.aggregate_corpus_sha256 != aggregate
        || manifest.commitment.contract_merkle_root != merkle
    {
        return Err(HoldoutError::InvalidContract(
            "aggregate corpus or contract Merkle commitment drifted".to_owned(),
        ));
    }
    Ok(HoldoutValidation {
        pairs: manifest.pairs.len().try_into().unwrap_or(u64::MAX),
        cases: EXPECTED_CASE_COUNT,
        vulnerable_cases: EXPECTED_CASE_COUNT / 2,
        safe_controls: EXPECTED_CASE_COUNT / 2,
        taxonomy_pairs,
        framework_cases,
        aggregate_corpus_sha256: aggregate,
        contract_merkle_root: merkle,
    })
}

fn validate_top_level(
    manifest: &HoldoutManifest,
    taxonomy_bytes: &[u8],
    taxonomy: &FrozenTaxonomy,
) -> Result<(), HoldoutError> {
    let expected_scoring = [
        "taxonomy_version",
        "category",
        "invariant",
        "primary_cwe",
        "source",
        "sink",
        "evidence_path",
    ];
    if manifest.schema_version != HOLDOUT_SCHEMA_V1
        || manifest.holdout_id != PHASE_3_HOLDOUT_ID
        || manifest.methodology_version != "phase-3.0"
        || manifest.taxonomy.schema_version != taxonomy.schema_version
        || manifest.taxonomy.taxonomy_version != taxonomy.taxonomy_version
        || manifest.taxonomy.artifact_sha256 != fingerprint(taxonomy_bytes)
        || manifest.taxonomy.content_hash != taxonomy.content_hash
        || manifest.pairs.len() != EXPECTED_PAIR_COUNT
    {
        return Err(HoldoutError::InvalidContract(
            "holdout does not link exactly to Phase 3 and frozen taxonomy 1.0.0".to_owned(),
        ));
    }
    if manifest.scoring.exact_requires != expected_scoring.map(str::to_owned)
        || manifest.scoring.partial_detection_credit
        || !manifest.scoring.one_to_one_matching
        || manifest.scoring.duplicate_detection_credit
        || manifest.scoring.failed_cases_are_clean
        || !manifest.scoring.safe_controls_scored_separately
        || manifest.scoring.composite_score
    {
        return Err(HoldoutError::InvalidContract(
            "holdout scoring contract is not the frozen neutral policy".to_owned(),
        ));
    }
    if !manifest.protocol.one_shot
        || manifest.protocol.ledger_path != LEDGER_PATH
        || manifest.protocol.result_path_template != RESULT_PATH_TEMPLATE
        || manifest.protocol.result_write_mode != "create-new"
        || manifest.protocol.network != "disabled"
        || manifest.protocol.evaluation_state != "sealed-not-executed"
        || manifest.creation.scanner_executions != 0
        || manifest.creation.scanner_reports_consulted
        || manifest.creation.scanner_specific_inputs
        || manifest.creation.answers_scanner_visible
    {
        return Err(HoldoutError::InvalidContract(
            "holdout creation or one-shot protocol is not sealed and scanner-neutral".to_owned(),
        ));
    }
    if manifest.commitment.pair_count != EXPECTED_PAIR_COUNT as u64
        || manifest.commitment.case_count != EXPECTED_CASE_COUNT
        || manifest.commitment.vulnerable_count != EXPECTED_CASE_COUNT / 2
        || manifest.commitment.safe_control_count != EXPECTED_CASE_COUNT / 2
    {
        return Err(HoldoutError::InvalidContract(
            "holdout commitment counts must be 28 pairs and 56 cases".to_owned(),
        ));
    }
    if !manifest
        .pairs
        .windows(2)
        .all(|window| window[0].pair_id < window[1].pair_id)
        || !manifest
            .design_sources
            .windows(2)
            .all(|window| window[0] < window[1])
    {
        return Err(HoldoutError::InvalidContract(
            "pairs and design sources must be strictly sorted and unique".to_owned(),
        ));
    }
    Ok(())
}

fn validate_pair_taxonomy(
    pair: &HoldoutPair,
    taxonomy: &FrozenTaxonomy,
) -> Result<(), HoldoutError> {
    let category = taxonomy.categories.iter().find(|category| {
        category.category_id == pair.taxonomy.category_id
            && category.invariant_id == pair.taxonomy.invariant_id
    });
    if pair.taxonomy.taxonomy_version != taxonomy.taxonomy_version
        || category.is_none_or(|category| category.primary_cwe.id != pair.primary_cwe)
    {
        return Err(HoldoutError::InvalidContract(format!(
            "pair `{}` does not name one exact taxonomy/CWE contract",
            pair.pair_id
        )));
    }
    if pair.rationale.trim().is_empty() || pair.mutation.guard_property.trim().is_empty() {
        return Err(HoldoutError::InvalidContract(format!(
            "pair `{}` lacks rationale or guard property",
            pair.pair_id
        )));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_case<'a>(
    pair: &HoldoutPair,
    case: &'a HoldoutCase,
    repository_root: &Path,
    forbidden: &BTreeSet<String>,
    case_ids: &mut BTreeSet<&'a str>,
    fixture_paths: &mut BTreeSet<&'a str>,
    fixture_hashes: &mut BTreeSet<&'a str>,
) -> Result<(), HoldoutError> {
    if !case_ids.insert(case.case_id.as_str())
        || !fixture_paths.insert(case.fixture_path.as_str())
        || !fixture_hashes.insert(case.fixture_sha256.as_str())
    {
        return Err(HoldoutError::InvalidContract(format!(
            "case `{}` duplicates an identifier, fixture path, or exact fixture",
            case.case_id
        )));
    }
    if !case.fixture_path.starts_with(&format!("{HOLDOUT_ROOT}/"))
        || case.fixture_path.contains("phase1")
        || case.case_id.starts_with("phase1-")
        || case.provenance.authors.is_empty()
    {
        return Err(HoldoutError::InvalidContract(format!(
            "case `{}` has unsafe identity, path, or provenance",
            case.case_id
        )));
    }
    match case.kind {
        CaseKind::Vulnerable if case.expected.is_none() || case.security_property.is_some() => {
            return Err(HoldoutError::InvalidContract(format!(
                "vulnerable case `{}` must have one expectation and no control property",
                case.case_id
            )));
        }
        CaseKind::SafeControl
            if case.expected.is_some()
                || case.security_property.as_deref().is_none_or(str::is_empty) =>
        {
            return Err(HoldoutError::InvalidContract(format!(
                "control `{}` must have a security property and no expectation",
                case.case_id
            )));
        }
        CaseKind::Vulnerable | CaseKind::SafeControl => {}
    }
    let computed = fixture_fingerprint(repository_root, &case.fixture_path)?;
    if computed != case.fixture_sha256 {
        return Err(HoldoutError::InvalidContract(format!(
            "fixture fingerprint drift for case `{}`",
            case.case_id
        )));
    }
    let computed_contract = case_contract_hash(pair, case)?;
    if computed_contract != case.contract_sha256 {
        return Err(HoldoutError::InvalidContract(format!(
            "contract fingerprint drift for case `{}`",
            case.case_id
        )));
    }
    validate_scanner_visible_tree(repository_root, case, forbidden)?;
    if let Some(expected) = &case.expected {
        validate_expectation(case, expected, repository_root)?;
    }
    Ok(())
}

fn validate_expectation(
    case: &HoldoutCase,
    expected: &HoldoutExpectation,
    repository_root: &Path,
) -> Result<(), HoldoutError> {
    if expected.expectation_id.starts_with("phase1-")
        || expected.rationale.trim().is_empty()
        || expected.evidence.minimum_hops < 2
        || expected.evidence.required_kinds.first().map(String::as_str) != Some("source")
        || expected.evidence.required_kinds.last().map(String::as_str) != Some("sink")
    {
        return Err(HoldoutError::InvalidContract(format!(
            "case `{}` has an invalid frozen expectation",
            case.case_id
        )));
    }
    for location in [&expected.source, &expected.sink] {
        validate_relative_path(&location.path)?;
        let path = safe_join(repository_root, &case.fixture_path)?.join(&location.path);
        let text = fs::read_to_string(&path).map_err(|error| HoldoutError::Io {
            path: format!("{}/{}", case.fixture_path, location.path),
            detail: error.to_string(),
        })?;
        let line = location.line.ok_or_else(|| {
            HoldoutError::InvalidContract(format!(
                "case `{}` expectation locations require exact lines",
                case.case_id
            ))
        })?;
        let selected = text.lines().nth(line.saturating_sub(1) as usize);
        if selected.is_none_or(|value| value.trim().is_empty()) || !location.alternatives.is_empty()
        {
            return Err(HoldoutError::InvalidContract(format!(
                "case `{}` expectation line is absent, blank, or ambiguous",
                case.case_id
            )));
        }
    }
    Ok(())
}

fn validate_pair_mutation(pair: &HoldoutPair, repository_root: &Path) -> Result<(), HoldoutError> {
    validate_relative_path(&pair.mutation.file)?;
    let vulnerable_root = safe_join(repository_root, &pair.vulnerable.fixture_path)?;
    let control_root = safe_join(repository_root, &pair.control.fixture_path)?;
    let vulnerable_files = collect_relative_files(&vulnerable_root, &pair.vulnerable.fixture_path)?;
    let control_files = collect_relative_files(&control_root, &pair.control.fixture_path)?;
    let vulnerable_sources = vulnerable_files
        .iter()
        .filter(|path| path.as_str() != "package.json")
        .collect::<BTreeSet<_>>();
    let control_sources = control_files
        .iter()
        .filter(|path| path.as_str() != "package.json")
        .collect::<BTreeSet<_>>();
    if vulnerable_sources != control_sources || !vulnerable_sources.contains(&pair.mutation.file) {
        return Err(HoldoutError::InvalidContract(format!(
            "pair `{}` mutation source trees do not align",
            pair.pair_id
        )));
    }
    for path in &vulnerable_sources {
        if path.as_str() != pair.mutation.file {
            let vulnerable = fs::read(vulnerable_root.join(path.as_str())).map_err(|error| {
                HoldoutError::Io {
                    path: format!("{}/{}", pair.vulnerable.fixture_path, path),
                    detail: error.to_string(),
                }
            })?;
            let control =
                fs::read(control_root.join(path.as_str())).map_err(|error| HoldoutError::Io {
                    path: format!("{}/{}", pair.control.fixture_path, path),
                    detail: error.to_string(),
                })?;
            if vulnerable != control {
                return Err(HoldoutError::InvalidContract(format!(
                    "pair `{}` differs outside its declared mutation file",
                    pair.pair_id
                )));
            }
        }
    }
    let vulnerable = read_utf8(
        &vulnerable_root.join(&pair.mutation.file),
        &pair.mutation.file,
    )?;
    let control = read_utf8(&control_root.join(&pair.mutation.file), &pair.mutation.file)?;
    let vulnerable_fragment = select_lines(&vulnerable, pair.mutation.vulnerable_lines)?;
    let control_fragment = select_lines(&control, pair.mutation.control_lines)?;
    if fingerprint(vulnerable_fragment.as_bytes()) != pair.mutation.vulnerable_fragment_sha256
        || fingerprint(control_fragment.as_bytes()) != pair.mutation.control_fragment_sha256
        || replace_lines(
            &vulnerable,
            pair.mutation.vulnerable_lines,
            &control_fragment,
        )? != control
        || replace_lines(&control, pair.mutation.control_lines, &vulnerable_fragment)? != vulnerable
    {
        return Err(HoldoutError::InvalidContract(format!(
            "pair `{}` does not prove reversible guard introduction and removal",
            pair.pair_id
        )));
    }
    Ok(())
}

fn validate_coverage(
    manifest: &HoldoutManifest,
    taxonomy_pairs: &BTreeMap<String, u64>,
    framework_cases: &BTreeMap<String, u64>,
) -> Result<(), HoldoutError> {
    if taxonomy_pairs.len() != 7 || taxonomy_pairs.values().any(|count| *count != 4) {
        return Err(HoldoutError::InvalidContract(
            "each of seven taxonomy families must contain exactly four pairs".to_owned(),
        ));
    }
    let framework_counts = manifest
        .pairs
        .iter()
        .fold(BTreeMap::new(), |mut counts, pair| {
            *counts.entry(pair.framework).or_insert(0_u64) += 1;
            counts
        });
    let language_counts = manifest
        .pairs
        .iter()
        .fold(BTreeMap::new(), |mut counts, pair| {
            *counts.entry(pair.language).or_insert(0_u64) += 1;
            counts
        });
    let variation_counts = manifest
        .pairs
        .iter()
        .fold(BTreeMap::new(), |mut counts, pair| {
            *counts.entry(pair.variation).or_insert(0_u64) += 1;
            counts
        });
    if framework_counts.len() != 4
        || framework_counts.values().any(|count| *count != 7)
        || language_counts.len() != 4
        || language_counts.values().any(|count| *count != 7)
        || variation_counts.len() != 4
        || variation_counts.values().any(|count| *count != 7)
        || framework_cases.values().any(|count| *count != 14)
    {
        return Err(HoldoutError::InvalidContract(
            "framework, language, and variation strata must each contain seven pairs".to_owned(),
        ));
    }
    Ok(())
}

fn validate_near_duplicates(pair_texts: &[(&str, String)]) -> Result<(), HoldoutError> {
    for (index, (left_id, left)) in pair_texts.iter().enumerate() {
        let left_shingles = shingles(left, 7);
        for (right_id, right) in &pair_texts[index + 1..] {
            let right_shingles = shingles(right, 7);
            let denominator = left_shingles.len().min(right_shingles.len());
            if denominator > 0 {
                let intersection = left_shingles.intersection(&right_shingles).count();
                if intersection.saturating_mul(100) >= denominator.saturating_mul(85) {
                    return Err(HoldoutError::InvalidContract(format!(
                        "pairs `{left_id}` and `{right_id}` are near-duplicates"
                    )));
                }
            }
        }
    }
    Ok(())
}

fn validate_phase1_non_reuse(
    manifest: &HoldoutManifest,
    repository_root: &Path,
    pair_texts: &[(&str, String)],
) -> Result<(), HoldoutError> {
    let phase1_root = repository_root.join("fixtures/corpus");
    let phase1_text = tree_source_text(&phase1_root, "fixtures/corpus")?;
    let phase1_declarations = declarations(&phase1_text);
    let phase1_literals = quoted_literals(&phase1_text);
    let exemptions = BTreeSet::from([
        "get", "post", "string", "number", "error", "response", "request",
    ]);
    for pair in &manifest.pairs {
        for case in [&pair.vulnerable, &pair.control] {
            let root = safe_join(repository_root, &case.fixture_path)?;
            for path in collect_relative_files(&root, &case.fixture_path)? {
                let lowered = path.to_ascii_lowercase();
                if lowered.contains("entry.")
                    || lowered.ends_with("actions.tsx")
                    || ["/items/", "/session/", "/calculate/", "/profile/"]
                        .iter()
                        .any(|segment| format!("/{lowered}/").contains(segment))
                {
                    return Err(HoldoutError::InvalidContract(format!(
                        "case `{}` reuses a Phase 1 filename or route segment",
                        case.case_id
                    )));
                }
            }
        }
    }
    for (pair_id, text) in pair_texts {
        let declared = declarations(text);
        let repeated = declared
            .intersection(&phase1_declarations)
            .find(|name| name.len() >= 5 && !exemptions.contains(name.as_str()));
        if let Some(name) = repeated {
            return Err(HoldoutError::InvalidContract(format!(
                "pair `{pair_id}` reuses Phase 1 declaration `{name}`"
            )));
        }
        let literal_exemptions = BTreeSet::from([
            "use server",
            "node:child_process",
            "node:fs/promises",
            "node:path",
            "https:",
        ]);
        if let Some(literal) = quoted_literals(text)
            .intersection(&phase1_literals)
            .find(|literal| literal.len() >= 6 && !literal_exemptions.contains(literal.as_str()))
        {
            return Err(HoldoutError::InvalidContract(format!(
                "pair `{pair_id}` reuses Phase 1 literal `{literal}`"
            )));
        }
        let old_shingles = shingles(&phase1_text, 9);
        let new_shingles = shingles(text, 9);
        let denominator = old_shingles.len().min(new_shingles.len());
        let intersection = old_shingles.intersection(&new_shingles).count();
        if denominator > 0 && intersection.saturating_mul(100) >= denominator.saturating_mul(70) {
            return Err(HoldoutError::InvalidContract(format!(
                "pair `{pair_id}` reuses a Phase 1 implementation shape"
            )));
        }
    }
    Ok(())
}

fn validate_scanner_visible_tree(
    repository_root: &Path,
    case: &HoldoutCase,
    forbidden: &BTreeSet<String>,
) -> Result<(), HoldoutError> {
    let root = safe_join(repository_root, &case.fixture_path)?;
    let metadata = fs::symlink_metadata(&root).map_err(|error| HoldoutError::Io {
        path: case.fixture_path.clone(),
        detail: error.to_string(),
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(HoldoutError::InvalidContract(format!(
            "fixture `{}` must be a regular directory",
            case.fixture_path
        )));
    }
    for relative in collect_relative_files(&root, &case.fixture_path)? {
        let extension = Path::new(&relative)
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or("");
        if !["js", "jsx", "json", "ts", "tsx"].contains(&extension) {
            return Err(HoldoutError::Leakage {
                path: format!("{}/{}", case.fixture_path, relative),
                detail: "unsupported scanner-visible file type".to_owned(),
            });
        }
        let display = format!("{}/{}", case.fixture_path, relative);
        let text = read_utf8(&root.join(&relative), &display)?;
        if text.contains("/home/")
            || text.contains("/Users/")
            || text.contains("danielcastrillon")
            || text.contains("secure-engine")
        {
            return Err(HoldoutError::Leakage {
                path: display,
                detail: "host-specific or scanner-specific data".to_owned(),
            });
        }
        for line in text.lines() {
            let trimmed = line.trim_start();
            if (trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*'))
                && contains_forbidden(trimmed, forbidden)
            {
                return Err(HoldoutError::Leakage {
                    path: display.clone(),
                    detail: "comment contains holdout answer metadata".to_owned(),
                });
            }
            for declaration in declarations(line) {
                if contains_forbidden(&declaration, forbidden) {
                    return Err(HoldoutError::Leakage {
                        path: display.clone(),
                        detail: "declaration contains holdout answer metadata".to_owned(),
                    });
                }
            }
        }
        if relative == "package.json" {
            let value: serde_json::Value = serde_json::from_str(&text).map_err(|_| {
                HoldoutError::InvalidContract(format!("invalid package metadata `{display}`"))
            })?;
            let package_name = value
                .get("name")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    HoldoutError::InvalidContract(format!(
                        "package metadata `{display}` has no name"
                    ))
                })?;
            if contains_forbidden(package_name, forbidden) {
                return Err(HoldoutError::Leakage {
                    path: display,
                    detail: "package name contains holdout answer metadata".to_owned(),
                });
            }
        }
    }
    Ok(())
}

fn forbidden_terms(manifest: &HoldoutManifest, taxonomy: &FrozenTaxonomy) -> BTreeSet<String> {
    let mut terms = [
        "vulnerable",
        "safe-control",
        "safe_control",
        "expectation",
        "expected-outcome",
        "taxonomy",
        "holdout",
        "cwe-",
    ]
    .into_iter()
    .map(normalize)
    .collect::<BTreeSet<_>>();
    for pair in &manifest.pairs {
        terms.insert(normalize(&pair.pair_id));
        terms.insert(normalize(&pair.vulnerable.case_id));
        terms.insert(normalize(&pair.control.case_id));
        if let Some(expected) = &pair.vulnerable.expected {
            terms.insert(normalize(&expected.expectation_id));
        }
    }
    for category in &taxonomy.categories {
        terms.insert(normalize(&category.category_id));
        terms.insert(normalize(&category.invariant_id));
        terms.insert(normalize(&category.title));
    }
    terms
}

fn contains_forbidden(value: &str, forbidden: &BTreeSet<String>) -> bool {
    let normalized = normalize(value);
    forbidden
        .iter()
        .any(|term| !term.is_empty() && normalized.contains(term))
}

fn normalize(value: &str) -> String {
    value
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .flat_map(char::to_lowercase)
        .collect()
}

fn declarations(text: &str) -> BTreeSet<String> {
    let words = text
        .split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>();
    let mut declarations = BTreeSet::new();
    for (index, word) in words.iter().enumerate() {
        if matches!(*word, "const" | "let" | "var" | "function" | "class")
            && let Some(name) = words.get(index + 1)
        {
            declarations.insert(name.to_ascii_lowercase());
        }
    }
    declarations
}

fn quoted_literals(text: &str) -> BTreeSet<String> {
    let mut literals = BTreeSet::new();
    for quote in ['\'', '"', '`'] {
        let mut parts = text.split(quote);
        while parts.next().is_some() {
            if let Some(value) = parts.next()
                && !value.contains('\n')
            {
                literals.insert(value.to_owned());
            }
        }
    }
    literals
}

fn commitments(manifest: &HoldoutManifest) -> Result<(String, String), HoldoutError> {
    let mut fixture_hashes = BTreeMap::new();
    let mut contract_hashes = BTreeMap::new();
    for pair in &manifest.pairs {
        for case in [&pair.vulnerable, &pair.control] {
            fixture_hashes.insert(case.case_id.as_str(), case.fixture_sha256.as_str());
            contract_hashes.insert(case.case_id.as_str(), case.contract_sha256.as_str());
        }
    }
    let mut aggregate_bytes = Vec::new();
    for (case_id, digest) in fixture_hashes {
        aggregate_bytes.extend_from_slice(case_id.as_bytes());
        aggregate_bytes.push(0);
        aggregate_bytes.extend_from_slice(digest.as_bytes());
        aggregate_bytes.push(0);
    }
    let aggregate = fingerprint(&aggregate_bytes);
    let mut nodes = contract_hashes
        .into_iter()
        .map(|(case_id, digest)| {
            let mut bytes = b"secure-bench-holdout-leaf-v1\0".to_vec();
            bytes.extend_from_slice(case_id.as_bytes());
            bytes.push(0);
            bytes.extend_from_slice(digest.as_bytes());
            Sha256::digest(bytes).to_vec()
        })
        .collect::<Vec<_>>();
    if nodes.is_empty() {
        return Err(HoldoutError::InvalidContract(
            "cannot commit an empty holdout".to_owned(),
        ));
    }
    while nodes.len() > 1 {
        if nodes.len() % 2 == 1 {
            let last = nodes.last().cloned().ok_or_else(|| {
                HoldoutError::InvalidContract("Merkle level was unexpectedly empty".to_owned())
            })?;
            nodes.push(last);
        }
        nodes = nodes
            .chunks_exact(2)
            .map(|pair| {
                let mut bytes = b"secure-bench-holdout-node-v1\0".to_vec();
                bytes.extend_from_slice(&pair[0]);
                bytes.extend_from_slice(&pair[1]);
                Sha256::digest(bytes).to_vec()
            })
            .collect();
    }
    Ok((aggregate, hex_digest(&nodes[0])))
}

fn case_contract_hash(pair: &HoldoutPair, case: &HoldoutCase) -> Result<String, HoldoutError> {
    let view = CaseContractView {
        pair_id: &pair.pair_id,
        language: pair.language,
        framework: pair.framework,
        variation: pair.variation,
        taxonomy: &pair.taxonomy,
        primary_cwe: &pair.primary_cwe,
        rationale: &pair.rationale,
        mutation: &pair.mutation,
        case_id: &case.case_id,
        kind: case.kind,
        fixture_path: &case.fixture_path,
        fixture_sha256: &case.fixture_sha256,
        expected: &case.expected,
        security_property: &case.security_property,
        provenance: &case.provenance,
    };
    let bytes = serde_json::to_vec(&view).map_err(|_| HoldoutError::Serialization)?;
    Ok(fingerprint(&bytes))
}

fn ledger_entry_hash(entry: &HoldoutLedgerEntry) -> Result<String, HoldoutError> {
    let view = LedgerHashView {
        schema_version: &entry.schema_version,
        sequence: entry.sequence,
        event: entry.event,
        holdout_id: &entry.holdout_id,
        commitment_root: &entry.commitment_root,
        previous_entry_hash: &entry.previous_entry_hash,
        timestamp_utc: &entry.timestamp_utc,
        run_id: &entry.run_id,
        binary_sha256: &entry.binary_sha256,
        result_sha256: &entry.result_sha256,
        detail_code: &entry.detail_code,
    };
    let bytes = serde_json::to_vec(&view).map_err(|_| HoldoutError::Serialization)?;
    Ok(fingerprint(&bytes))
}

fn validate_ledger_semantics(
    entries: &[HoldoutLedgerEntry],
    manifest: &HoldoutManifest,
) -> Result<(), HoldoutError> {
    let mut started_run: Option<&str> = None;
    let mut terminal = false;
    for (index, entry) in entries.iter().enumerate() {
        if entry.sequence != index as u64
            || entry.holdout_id != manifest.holdout_id
            || entry.commitment_root != manifest.commitment.contract_merkle_root
            || entry.entry_hash != ledger_entry_hash(entry)?
            || (index == 0 && entry.previous_entry_hash != ZERO_HASH)
            || (index > 0 && entry.previous_entry_hash != entries[index - 1].entry_hash)
            || terminal
        {
            return Err(HoldoutError::InvalidContract(
                "holdout ledger sequence, chain, commitment, or terminal state is invalid"
                    .to_owned(),
            ));
        }
        match entry.event {
            HoldoutLedgerEvent::HoldoutSealed => {
                if index != 0
                    || entry.run_id.is_some()
                    || entry.binary_sha256.is_some()
                    || entry.result_sha256.is_some()
                    || entry.detail_code.is_some()
                {
                    return Err(HoldoutError::InvalidContract(
                        "ledger seal must be the metadata-free genesis entry".to_owned(),
                    ));
                }
            }
            HoldoutLedgerEvent::ExecutionStarted => {
                if started_run.is_some()
                    || entry.run_id.as_deref().is_none_or(str::is_empty)
                    || entry
                        .binary_sha256
                        .as_deref()
                        .is_none_or(|value| !is_sha256(value))
                    || entry.result_sha256.is_some()
                    || entry.detail_code.is_some()
                {
                    return Err(HoldoutError::InvalidContract(
                        "ledger permits exactly one fully identified execution reservation"
                            .to_owned(),
                    ));
                }
                started_run = entry.run_id.as_deref();
            }
            HoldoutLedgerEvent::ExecutionCompleted => {
                if started_run != entry.run_id.as_deref()
                    || entry.binary_sha256.is_some()
                    || entry
                        .result_sha256
                        .as_deref()
                        .is_none_or(|value| !is_sha256(value))
                    || entry.detail_code.is_some()
                {
                    return Err(HoldoutError::InvalidContract(
                        "completed ledger entry does not close the reserved run immutably"
                            .to_owned(),
                    ));
                }
                terminal = true;
            }
            HoldoutLedgerEvent::ExecutionFailed => {
                if started_run != entry.run_id.as_deref()
                    || entry.binary_sha256.is_some()
                    || entry.result_sha256.is_some()
                    || entry.detail_code.as_deref().is_none_or(str::is_empty)
                {
                    return Err(HoldoutError::InvalidContract(
                        "failed ledger entry does not close the reserved run explicitly".to_owned(),
                    ));
                }
                terminal = true;
            }
        }
    }
    Ok(())
}

fn fixture_fingerprint(repository_root: &Path, relative: &str) -> Result<String, HoldoutError> {
    let root = safe_join(repository_root, relative)?;
    let files = collect_relative_files(&root, relative)?;
    let mut hasher = Sha256::new();
    for path in files {
        let file = root.join(&path);
        let metadata = fs::metadata(&file).map_err(|error| HoldoutError::Io {
            path: format!("{relative}/{path}"),
            detail: error.to_string(),
        })?;
        hasher.update(u64::try_from(path.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(path.as_bytes());
        hasher.update(metadata.len().to_be_bytes());
        let mut handle = fs::File::open(&file).map_err(|error| HoldoutError::Io {
            path: format!("{relative}/{path}"),
            detail: error.to_string(),
        })?;
        let mut buffer = [0_u8; 8192];
        loop {
            let read = handle.read(&mut buffer).map_err(|error| HoldoutError::Io {
                path: format!("{relative}/{path}"),
                detail: error.to_string(),
            })?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
    }
    Ok(hex_digest(&hasher.finalize()))
}

fn collect_relative_files(root: &Path, display: &str) -> Result<Vec<String>, HoldoutError> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    let mut total_bytes = 0_u64;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).map_err(|error| HoldoutError::Io {
            path: display.to_owned(),
            detail: error.to_string(),
        })? {
            let entry = entry.map_err(|error| HoldoutError::Io {
                path: display.to_owned(),
                detail: error.to_string(),
            })?;
            let metadata =
                fs::symlink_metadata(entry.path()).map_err(|error| HoldoutError::Io {
                    path: display.to_owned(),
                    detail: error.to_string(),
                })?;
            if metadata.file_type().is_symlink() || (!metadata.is_dir() && !metadata.is_file()) {
                return Err(HoldoutError::InvalidContract(format!(
                    "fixture `{display}` contains a non-regular entry"
                )));
            }
            if metadata.is_dir() {
                pending.push(entry.path());
            } else {
                if metadata.len() > MAX_FILE_BYTES {
                    return Err(HoldoutError::InvalidContract(format!(
                        "fixture `{display}` contains an oversized file"
                    )));
                }
                total_bytes = total_bytes.saturating_add(metadata.len());
                let relative = entry
                    .path()
                    .strip_prefix(root)
                    .map_err(|_| {
                        HoldoutError::InvalidContract(format!(
                            "fixture `{display}` escaped its root"
                        ))
                    })?
                    .components()
                    .filter_map(|component| match component {
                        Component::Normal(value) => Some(value.to_string_lossy()),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
                    .join("/");
                files.push(relative);
            }
        }
    }
    if files.is_empty() || files.len() > MAX_CASE_FILES || total_bytes > MAX_CASE_BYTES {
        return Err(HoldoutError::InvalidContract(format!(
            "fixture `{display}` exceeds bounded file or byte counts"
        )));
    }
    files.sort();
    Ok(files)
}

fn pair_source_text(pair: &HoldoutPair, repository_root: &Path) -> Result<String, HoldoutError> {
    let root = safe_join(repository_root, &pair.vulnerable.fixture_path)?;
    tree_source_text(&root, &pair.vulnerable.fixture_path)
}

fn tree_source_text(root: &Path, display: &str) -> Result<String, HoldoutError> {
    let mut text = String::new();
    for path in collect_relative_files(root, display)? {
        if path != "package.json" {
            text.push_str(&path);
            text.push('\n');
            text.push_str(&read_utf8(&root.join(&path), &format!("{display}/{path}"))?);
            text.push('\n');
        }
    }
    Ok(text)
}

fn shingles(text: &str, size: usize) -> BTreeSet<String> {
    let tokens = text
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>();
    tokens
        .windows(size)
        .map(|window| window.join("\0"))
        .collect()
}

fn mutation_fragment_hash(
    repository_root: &Path,
    fixture_path: &str,
    relative_file: &str,
    range: HoldoutLineRange,
) -> Result<String, HoldoutError> {
    let path = safe_join(repository_root, fixture_path)?.join(relative_file);
    let text = read_utf8(&path, &format!("{fixture_path}/{relative_file}"))?;
    Ok(fingerprint(select_lines(&text, range)?.as_bytes()))
}

fn select_lines(text: &str, range: HoldoutLineRange) -> Result<String, HoldoutError> {
    if range.start == 0 || range.end < range.start {
        return Err(HoldoutError::InvalidContract(
            "mutation line range is invalid".to_owned(),
        ));
    }
    let lines = text.split_inclusive('\n').collect::<Vec<_>>();
    let start = range.start.saturating_sub(1) as usize;
    let end = range.end as usize;
    if end > lines.len() {
        return Err(HoldoutError::InvalidContract(
            "mutation line range exceeds its file".to_owned(),
        ));
    }
    Ok(lines[start..end].concat())
}

fn replace_lines(
    text: &str,
    range: HoldoutLineRange,
    replacement: &str,
) -> Result<String, HoldoutError> {
    let lines = text.split_inclusive('\n').collect::<Vec<_>>();
    let start = range.start.saturating_sub(1) as usize;
    let end = range.end as usize;
    if range.start == 0 || end < range.start as usize || end > lines.len() {
        return Err(HoldoutError::InvalidContract(
            "mutation replacement range is invalid".to_owned(),
        ));
    }
    let mut output = lines[..start].concat();
    output.push_str(replacement);
    output.push_str(&lines[end..].concat());
    Ok(output)
}

fn read_utf8(path: &Path, display: &str) -> Result<String, HoldoutError> {
    let bytes = fs::read(path).map_err(|error| HoldoutError::Io {
        path: display.to_owned(),
        detail: error.to_string(),
    })?;
    String::from_utf8(bytes).map_err(|_| HoldoutError::Leakage {
        path: display.to_owned(),
        detail: "scanner-visible source must be UTF-8".to_owned(),
    })
}

fn validate_relative_path(relative: &str) -> Result<(), HoldoutError> {
    let path = Path::new(relative);
    if relative.is_empty()
        || path.is_absolute()
        || relative.contains(['\\', ':', '%'])
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(HoldoutError::InvalidContract(
            "holdout paths must be private, portable, repository-relative paths".to_owned(),
        ));
    }
    Ok(())
}

fn safe_join(root: &Path, relative: &str) -> Result<PathBuf, HoldoutError> {
    validate_relative_path(relative)?;
    Ok(root.join(relative))
}

fn framework_name(framework: HoldoutFramework) -> &'static str {
    match framework {
        HoldoutFramework::NodeJs => "Node.js",
        HoldoutFramework::Express => "Express",
        HoldoutFramework::NextAppRouter => "Next.js App Router",
        HoldoutFramework::NextServerActions => "Next.js Server Actions",
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reversible_line_projection_is_exact() -> Result<(), HoldoutError> {
        let vulnerable = "before\nunsafe\nafter\n";
        let control = "before\nguard\nsafe\nafter\n";
        assert_eq!(
            replace_lines(
                vulnerable,
                HoldoutLineRange { start: 2, end: 2 },
                "guard\nsafe\n",
            )?,
            control
        );
        assert_eq!(
            replace_lines(control, HoldoutLineRange { start: 2, end: 3 }, "unsafe\n",)?,
            vulnerable
        );
        Ok(())
    }

    #[test]
    fn near_duplicate_pairs_are_rejected() {
        let left = "alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu nu xi omicron pi rho sigma tau upsilon";
        let right = "alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu nu xi omicron pi rho sigma tau omega";
        assert!(
            validate_near_duplicates(&[("left", left.into()), ("right", right.into())]).is_err()
        );
    }
}
