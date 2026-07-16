//! Frozen neutral taxonomy validation and prospective taxonomy-aware matching.

use crate::model::{
    EvidenceConstraint, ExpectedFinding, NormalizedFinding, ReportedTaxonomyMetadata,
    SourceLocation, TaxonomyCoordinates,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use thiserror::Error;

/// Schema identifier for the first frozen neutral taxonomy.
pub const TAXONOMY_SCHEMA_V1: &str = "secure-bench-taxonomy-v1";
/// Semantic version of the first frozen neutral taxonomy.
pub const TAXONOMY_VERSION_V1: &str = "1.0.0";
/// Publication date of the first frozen neutral taxonomy.
pub const TAXONOMY_PUBLICATION_DATE_V1: &str = "2026-07-16";
/// Official upstream source release recorded by the frozen taxonomy.
pub const TAXONOMY_SOURCE_VERSION_V1: &str = "CWE 4.20";

const MAX_TAXONOMY_BYTES: usize = 1024 * 1024;
const CATEGORY_PREFIX: &str = "secure-bench.category.";
const INVARIANT_PREFIX: &str = "secure-bench.invariant.";

/// One frozen, versioned taxonomy document.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenTaxonomy {
    /// JSON Schema contract identifier.
    pub schema_version: String,
    /// Public semantic taxonomy version.
    pub taxonomy_version: String,
    /// Publication date in RFC 3339 full-date form.
    pub publication_date: String,
    /// Version label reported by the official upstream source.
    pub source_version: String,
    /// Complete sorted set of official source URLs.
    pub source_urls: Vec<String>,
    /// SHA-256 of canonical taxonomy content excluding this field.
    pub content_hash: String,
    /// Sorted neutral category and invariant definitions.
    pub categories: Vec<TaxonomyCategory>,
}

/// One neutral category, invariant, and public weakness association.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaxonomyCategory {
    /// Stable neutral category identifier used for matching.
    pub category_id: String,
    /// Stable neutral security invariant identifier used for matching.
    pub invariant_id: String,
    /// Primary official CWE association.
    pub primary_cwe: CweReference,
    /// Optional additional public references; never matching aliases.
    pub secondary_references: Vec<CweReference>,
    /// Display-only human-readable title.
    pub title: String,
    /// Display-only human-readable description.
    pub description: String,
}

/// An official CWE identifier and canonical MITRE definition URL.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CweReference {
    /// Public identifier in `CWE-N` form.
    pub id: String,
    /// Official MITRE definition URL.
    pub url: String,
}

/// Explicit result of resolving scanner-reported taxonomy metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum TaxonomyResolution {
    /// All reported coordinates map to one frozen category and invariant pair.
    Mapped {
        /// Validated canonical coordinates.
        coordinates: TaxonomyCoordinates,
    },
    /// Metadata cannot be mapped without guessing.
    Unmapped {
        /// Stable reason for withholding taxonomy credit.
        reason: UnmappedReason,
    },
}

/// Stable reasons that reported metadata remains unmapped.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnmappedReason {
    /// The report did not provide taxonomy metadata.
    MissingMetadata,
    /// The metadata object omitted one or more required coordinates.
    MissingFields,
    /// The report referenced a different taxonomy version.
    VersionMismatch,
    /// The category identifier is absent from the frozen taxonomy.
    UnknownCategory,
    /// The invariant identifier is absent from the frozen taxonomy.
    UnknownInvariant,
    /// Both identifiers exist but are not the same frozen pair.
    ConflictingIdentifiers,
}

/// Prospective taxonomy matching outcome.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaxonomyMatchOutcome {
    /// Canonical identifiers and every required evidence constraint match.
    Matched,
    /// Metadata mapped, but identifiers or evidence constraints differ.
    NotMatched,
    /// Reported metadata remained explicitly unmapped.
    Unmapped,
}

/// Atomic criteria for a prospective taxonomy-aware decision.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::struct_excessive_bools)]
#[serde(deny_unknown_fields)]
pub struct TaxonomyMatchCriteria {
    /// Canonical category identifier equality.
    pub category_id: bool,
    /// Canonical invariant identifier equality.
    pub invariant_id: bool,
    /// Source constraint satisfaction.
    pub source: bool,
    /// Sink constraint satisfaction.
    pub sink: bool,
    /// Evidence-path constraint satisfaction.
    pub evidence_path: bool,
}

/// Inspectable prospective match decision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaxonomyMatchDecision {
    /// Overall prospective outcome.
    pub outcome: TaxonomyMatchOutcome,
    /// Explicit metadata resolution.
    pub resolution: TaxonomyResolution,
    /// Atomic identifier and evidence decisions.
    pub criteria: TaxonomyMatchCriteria,
}

/// Taxonomy parsing, schema, semantic, fingerprint, or expectation error.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TaxonomyError {
    /// Input exceeds its fixed parser bound.
    #[error("taxonomy exceeds the 1 MiB input limit")]
    TooLarge,
    /// Input is not valid typed JSON.
    #[error("taxonomy JSON syntax or shape error at line {0}")]
    InvalidJson(usize),
    /// Input violates the committed JSON Schema.
    #[error("taxonomy schema validation failed: {0}")]
    InvalidSchema(String),
    /// Input violates a frozen semantic invariant.
    #[error("taxonomy semantic validation failed: {0}")]
    InvalidSemantics(String),
    /// Declared and computed canonical content hashes differ.
    #[error("taxonomy content hash does not match canonical content")]
    ContentHashMismatch,
    /// Serialization of a validated typed contract failed.
    #[error("taxonomy canonical serialization failed")]
    Serialization,
    /// A prospective expectation does not name one frozen pair.
    #[error("taxonomy-aware expectation is invalid or unmapped")]
    InvalidExpectation,
}

#[derive(Serialize)]
struct TaxonomyContent<'a> {
    schema_version: &'a str,
    taxonomy_version: &'a str,
    publication_date: &'a str,
    source_version: &'a str,
    source_urls: &'a [String],
    categories: &'a [TaxonomyCategory],
}

/// Parses and validates schema and semantics without accepting the declared content hash.
///
/// This is intended for deterministic inspection and contract authoring. Evaluators must call
/// [`load_taxonomy`] before matching.
///
/// # Errors
///
/// Returns [`TaxonomyError`] for bounded parsing, schema, or semantic failures.
pub fn inspect_taxonomy(bytes: &[u8]) -> Result<FrozenTaxonomy, TaxonomyError> {
    if bytes.len() > MAX_TAXONOMY_BYTES {
        return Err(TaxonomyError::TooLarge);
    }
    let taxonomy: FrozenTaxonomy =
        serde_json::from_slice(bytes).map_err(|error| TaxonomyError::InvalidJson(error.line()))?;
    crate::schema::validate_taxonomy(&taxonomy)
        .map_err(|error| TaxonomyError::InvalidSchema(error.to_string()))?;
    validate_semantics(&taxonomy)?;
    Ok(taxonomy)
}

/// Loads a complete frozen taxonomy and verifies its canonical content hash.
///
/// # Errors
///
/// Returns [`TaxonomyError`] when parsing, schema validation, semantics, or the hash fails.
pub fn load_taxonomy(bytes: &[u8]) -> Result<FrozenTaxonomy, TaxonomyError> {
    let taxonomy = inspect_taxonomy(bytes)?;
    if taxonomy.content_hash != taxonomy_content_hash(&taxonomy)? {
        return Err(TaxonomyError::ContentHashMismatch);
    }
    Ok(taxonomy)
}

/// Returns deterministic pretty JSON with a single trailing newline.
///
/// # Errors
///
/// Returns [`TaxonomyError::Serialization`] if typed serialization fails.
pub fn canonical_taxonomy_json(taxonomy: &FrozenTaxonomy) -> Result<Vec<u8>, TaxonomyError> {
    let mut bytes =
        serde_json::to_vec_pretty(taxonomy).map_err(|_| TaxonomyError::Serialization)?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Computes the canonical payload SHA-256, excluding the document's `content_hash` field.
///
/// # Errors
///
/// Returns [`TaxonomyError::Serialization`] if typed serialization fails.
pub fn taxonomy_content_hash(taxonomy: &FrozenTaxonomy) -> Result<String, TaxonomyError> {
    let content = TaxonomyContent {
        schema_version: &taxonomy.schema_version,
        taxonomy_version: &taxonomy.taxonomy_version,
        publication_date: &taxonomy.publication_date,
        source_version: &taxonomy.source_version,
        source_urls: &taxonomy.source_urls,
        categories: &taxonomy.categories,
    };
    let bytes = serde_json::to_vec(&content).map_err(|_| TaxonomyError::Serialization)?;
    Ok(hex_digest(&Sha256::digest(bytes)))
}

/// Resolves optional reported metadata without aliases, prose comparison, or guesses.
#[must_use]
pub fn resolve_reported_taxonomy(
    taxonomy: &FrozenTaxonomy,
    reported: Option<&ReportedTaxonomyMetadata>,
) -> TaxonomyResolution {
    let Some(reported) = reported else {
        return TaxonomyResolution::Unmapped {
            reason: UnmappedReason::MissingMetadata,
        };
    };
    let (Some(version), Some(category_id), Some(invariant_id)) = (
        reported.taxonomy_version.as_deref(),
        reported.category_id.as_deref(),
        reported.invariant_id.as_deref(),
    ) else {
        return TaxonomyResolution::Unmapped {
            reason: UnmappedReason::MissingFields,
        };
    };
    if version != taxonomy.taxonomy_version {
        return TaxonomyResolution::Unmapped {
            reason: UnmappedReason::VersionMismatch,
        };
    }
    let Some(category) = taxonomy
        .categories
        .iter()
        .find(|category| category.category_id == category_id)
    else {
        return TaxonomyResolution::Unmapped {
            reason: UnmappedReason::UnknownCategory,
        };
    };
    if !taxonomy
        .categories
        .iter()
        .any(|category| category.invariant_id == invariant_id)
    {
        return TaxonomyResolution::Unmapped {
            reason: UnmappedReason::UnknownInvariant,
        };
    }
    if category.invariant_id != invariant_id {
        return TaxonomyResolution::Unmapped {
            reason: UnmappedReason::ConflictingIdentifiers,
        };
    }
    TaxonomyResolution::Mapped {
        coordinates: TaxonomyCoordinates {
            taxonomy_version: version.to_owned(),
            category_id: category_id.to_owned(),
            invariant_id: invariant_id.to_owned(),
        },
    }
}

/// Matches prospective canonical taxonomy metadata together with required evidence constraints.
///
/// Human-readable category and invariant prose is deliberately ignored. Existing Phase 0 and
/// Phase 1 evaluation entry points do not call this function.
///
/// # Errors
///
/// Returns [`TaxonomyError::InvalidExpectation`] when the expectation omits or conflicts with the
/// frozen taxonomy contract.
pub fn match_taxonomy_finding(
    taxonomy: &FrozenTaxonomy,
    expected: &ExpectedFinding,
    finding: &NormalizedFinding,
) -> Result<TaxonomyMatchDecision, TaxonomyError> {
    let expected_coordinates = expected
        .taxonomy
        .as_ref()
        .ok_or(TaxonomyError::InvalidExpectation)?;
    let expected_reported = ReportedTaxonomyMetadata {
        taxonomy_version: Some(expected_coordinates.taxonomy_version.clone()),
        category_id: Some(expected_coordinates.category_id.clone()),
        invariant_id: Some(expected_coordinates.invariant_id.clone()),
    };
    if !matches!(
        resolve_reported_taxonomy(taxonomy, Some(&expected_reported)),
        TaxonomyResolution::Mapped { .. }
    ) {
        return Err(TaxonomyError::InvalidExpectation);
    }

    let resolution = resolve_reported_taxonomy(taxonomy, finding.taxonomy.as_ref());
    let (category_id, invariant_id) = match &resolution {
        TaxonomyResolution::Mapped { coordinates } => (
            coordinates.category_id == expected_coordinates.category_id,
            coordinates.invariant_id == expected_coordinates.invariant_id,
        ),
        TaxonomyResolution::Unmapped { .. } => (false, false),
    };
    let criteria = TaxonomyMatchCriteria {
        category_id,
        invariant_id,
        source: location_matches(&expected.source.path, expected.source.line, &finding.source)
            || expected
                .source
                .alternatives
                .iter()
                .any(|variant| location_matches(&variant.path, variant.line, &finding.source)),
        sink: location_matches(&expected.sink.path, expected.sink.line, &finding.sink)
            || expected
                .sink
                .alternatives
                .iter()
                .any(|variant| location_matches(&variant.path, variant.line, &finding.sink)),
        evidence_path: evidence_matches(&expected.evidence, finding),
    };
    let outcome = if matches!(resolution, TaxonomyResolution::Unmapped { .. }) {
        TaxonomyMatchOutcome::Unmapped
    } else if criteria.category_id
        && criteria.invariant_id
        && criteria.source
        && criteria.sink
        && criteria.evidence_path
    {
        TaxonomyMatchOutcome::Matched
    } else {
        TaxonomyMatchOutcome::NotMatched
    };
    Ok(TaxonomyMatchDecision {
        outcome,
        resolution,
        criteria,
    })
}

fn validate_semantics(taxonomy: &FrozenTaxonomy) -> Result<(), TaxonomyError> {
    if taxonomy.schema_version != TAXONOMY_SCHEMA_V1
        || taxonomy.taxonomy_version != TAXONOMY_VERSION_V1
        || taxonomy.publication_date != TAXONOMY_PUBLICATION_DATE_V1
        || taxonomy.source_version != TAXONOMY_SOURCE_VERSION_V1
    {
        return Err(TaxonomyError::InvalidSemantics(
            "version, publication date, or source release differs from the frozen v1 contract"
                .to_owned(),
        ));
    }
    if !is_sha256(&taxonomy.content_hash) {
        return Err(TaxonomyError::InvalidSemantics(
            "content_hash must be lowercase SHA-256".to_owned(),
        ));
    }
    if taxonomy.categories.len() != 7 {
        return Err(TaxonomyError::InvalidSemantics(
            "the frozen v1 contract requires exactly seven categories".to_owned(),
        ));
    }
    if !strictly_sorted_unique(&taxonomy.source_urls) {
        return Err(TaxonomyError::InvalidSemantics(
            "source_urls must be sorted and unique".to_owned(),
        ));
    }

    let mut category_ids = BTreeSet::new();
    let mut invariant_ids = BTreeSet::new();
    let mut primary_cwes = BTreeSet::new();
    let mut referenced_urls = BTreeSet::new();
    let mut previous_category = None;
    for category in &taxonomy.categories {
        if previous_category.is_some_and(|previous| previous >= category.category_id.as_str()) {
            return Err(TaxonomyError::InvalidSemantics(
                "categories must be sorted by unique category_id".to_owned(),
            ));
        }
        previous_category = Some(category.category_id.as_str());
        if !valid_namespaced_id(&category.category_id, CATEGORY_PREFIX)
            || !valid_namespaced_id(&category.invariant_id, INVARIANT_PREFIX)
            || !category_ids.insert(&category.category_id)
            || !invariant_ids.insert(&category.invariant_id)
        {
            return Err(TaxonomyError::InvalidSemantics(
                "category and invariant identifiers must be unique frozen neutral identifiers"
                    .to_owned(),
            ));
        }
        if category.title.trim().is_empty()
            || category.title.len() > 200
            || category.description.trim().is_empty()
            || category.description.len() > 1000
        {
            return Err(TaxonomyError::InvalidSemantics(
                "display prose must be non-empty and bounded".to_owned(),
            ));
        }
        validate_cwe(&category.primary_cwe)?;
        if !primary_cwes.insert(&category.primary_cwe.id) {
            return Err(TaxonomyError::InvalidSemantics(
                "primary CWE identifiers must be unique".to_owned(),
            ));
        }
        referenced_urls.insert(category.primary_cwe.url.clone());
        if !category
            .secondary_references
            .windows(2)
            .all(|window| window[0] < window[1])
        {
            return Err(TaxonomyError::InvalidSemantics(
                "secondary references must be sorted and unique".to_owned(),
            ));
        }
        for reference in &category.secondary_references {
            validate_cwe(reference)?;
            if reference.id == category.primary_cwe.id {
                return Err(TaxonomyError::InvalidSemantics(
                    "a secondary reference cannot repeat the primary CWE".to_owned(),
                ));
            }
            referenced_urls.insert(reference.url.clone());
        }
    }
    if taxonomy
        .source_urls
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        != referenced_urls
    {
        return Err(TaxonomyError::InvalidSemantics(
            "source_urls must equal the complete official reference URL set".to_owned(),
        ));
    }
    Ok(())
}

fn validate_cwe(reference: &CweReference) -> Result<(), TaxonomyError> {
    let Some(number) = reference.id.strip_prefix("CWE-") else {
        return Err(TaxonomyError::InvalidSemantics(
            "CWE identifiers must use CWE-N form".to_owned(),
        ));
    };
    if number.is_empty()
        || number.starts_with('0')
        || !number.bytes().all(|byte| byte.is_ascii_digit())
        || reference.url != format!("https://cwe.mitre.org/data/definitions/{number}.html")
    {
        return Err(TaxonomyError::InvalidSemantics(
            "CWE identifiers and official MITRE URLs must agree".to_owned(),
        ));
    }
    Ok(())
}

fn valid_namespaced_id(value: &str, prefix: &str) -> bool {
    let Some(suffix) = value.strip_prefix(prefix) else {
        return false;
    };
    !suffix.is_empty()
        && suffix.split('-').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
}

fn strictly_sorted_unique(values: &[String]) -> bool {
    values.windows(2).all(|window| window[0] < window[1])
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn location_matches(path: &str, line: Option<u32>, actual: &SourceLocation) -> bool {
    path == actual.path && line.is_none_or(|expected_line| expected_line == actual.line)
}

fn evidence_matches(expected: &EvidenceConstraint, finding: &NormalizedFinding) -> bool {
    let Ok(actual_hops) = u32::try_from(finding.evidence_path.len()) else {
        return false;
    };
    if actual_hops < expected.minimum_hops {
        return false;
    }
    let actual = finding
        .evidence_path
        .iter()
        .map(|hop| hop.kind.as_str())
        .collect::<Vec<_>>();
    let mut next = 0;
    for required in &expected.required_kinds {
        let required = canonical_token(required);
        let Some(relative) = actual[next..].iter().position(|kind| *kind == required) else {
            return false;
        };
        next += relative + 1;
    }
    true
}

fn canonical_token(value: &str) -> String {
    value
        .trim()
        .to_ascii_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
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
