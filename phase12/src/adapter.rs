//! Prospective Evidence Contract v2 adapter with explicit compatibility routing.

use crate::{Phase12Error, sha256};
use secure_bench_core::phase5::{
    CanonicalFindingV2, EvidenceContractV2, EvidenceEffectV2, EvidenceNodeV2, EvidenceRoleV2,
    EvidenceSpanV2, SinkSemanticKind, SourceSemanticKind,
};
use secure_bench_core::taxonomy::FrozenTaxonomy;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Explicit adapter route requested by the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdapterRoute {
    /// Require a declared authoritative Evidence Contract v2 projection.
    EvidenceContractV2,
    /// Permit the separately versioned legacy compatibility projection when v2 is absent.
    ExplicitLegacyCompatibility,
}

/// Projection selected as the scoring input.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionSource {
    /// Complete declared Evidence Contract v2 projection.
    AuthoritativeEvidenceContractV2,
    /// Explicit, separately identified compatibility projection.
    LegacyCompatibilityV1,
}

/// Inspectable adapter provenance attached to every accepted finding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterProvenance {
    /// Adapter semantic version.
    pub adapter_version: String,
    /// Projection that supplied every scoring field.
    pub projection_source: ProjectionSource,
    /// Evidence contract version when v2 was selected.
    pub evidence_contract_version: Option<String>,
    /// Whether an explicit legacy projection was also present.
    pub legacy_projection_present: bool,
    /// Whether both declared projections were compared for equality.
    pub legacy_consistency_checked: bool,
    /// Canonical projection fingerprint calculated by Secure Bench.
    pub projection_sha256: String,
}

/// Canonical prospective finding and its non-scoring traceability fields.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdaptedFindingV2 {
    /// Evidence Contract v2 canonical finding used by the matcher.
    pub canonical: CanonicalFindingV2,
    /// Exact reported primary CWE.
    pub primary_cwe: String,
    /// Declared finding fingerprint, retained without scoring meaning.
    pub declared_fingerprint: String,
    /// Declared duplicate fingerprint, retained for deterministic duplicate handling.
    pub duplicate_fingerprint: String,
    /// Adapter decision provenance.
    pub provenance: AdapterProvenance,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TaxonomyCoordinates {
    taxonomy_version: String,
    category_id: String,
    invariant_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DeclaredProjectionV2 {
    contract_version: String,
    #[serde(default)]
    semantics_version: Option<String>,
    path: Vec<DeclaredNode>,
    connected_edges: Vec<bool>,
    #[serde(default)]
    effective_barriers: Vec<EvidenceEffectV2>,
    unresolved_call: bool,
    uncertain: bool,
    fingerprint: String,
    duplicate_fingerprint: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DeclaredNode {
    role: EvidenceRoleV2,
    effect: EvidenceEffectV2,
    #[serde(default)]
    source_kind: Option<SourceSemanticKind>,
    #[serde(default)]
    sink_kind: Option<SinkSemanticKind>,
    span: DeclaredSpan,
    summarizable: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
enum DeclaredSpan {
    Located(LocatedSpan),
    Canonical(EvidenceSpanV2),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LocatedSpan {
    path: String,
    span: LineSpan,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LineSpan {
    #[serde(default)]
    start_byte: Option<u64>,
    #[serde(default)]
    end_byte: Option<u64>,
    start_line: u32,
    start_column: u32,
    end_line: u32,
    end_column: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LegacyProjectionV1 {
    projection_version: String,
    taxonomy: TaxonomyCoordinates,
    primary_cwe: String,
    canonical: CanonicalFindingV2,
    fingerprint: String,
    duplicate_fingerprint: String,
}

fn invalid(detail: impl Into<String>) -> Phase12Error {
    Phase12Error::Adapter(detail.into())
}

fn parse_required<T: for<'de> Deserialize<'de>>(
    value: Option<&Value>,
    label: &str,
) -> Result<T, Phase12Error> {
    serde_json::from_value(
        value
            .cloned()
            .ok_or_else(|| invalid(format!("missing {label}")))?,
    )
    .map_err(|error| invalid(format!("malformed {label}: {error}")))
}

fn primary_cwe(value: Option<&Value>) -> Result<String, Phase12Error> {
    let value = value.ok_or_else(|| invalid("missing primary_cwe"))?;
    let cwe = value
        .as_str()
        .or_else(|| value.get("id").and_then(Value::as_str))
        .ok_or_else(|| invalid("primary_cwe must be a string or an object with an id"))?;
    if !cwe.starts_with("CWE-") || cwe[4..].parse::<u32>().is_err() {
        return Err(invalid("primary_cwe is not a canonical CWE identifier"));
    }
    Ok(cwe.to_owned())
}

fn safe_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.contains('\\')
        && path.split('/').all(|part| !matches!(part, "" | "." | ".."))
}

fn canonical_span(span: DeclaredSpan) -> Result<EvidenceSpanV2, Phase12Error> {
    let result = match span {
        DeclaredSpan::Located(value) => EvidenceSpanV2 {
            file: value.path,
            start_line: value.span.start_line,
            start_column: value.span.start_column,
            end_line: value.span.end_line,
            end_column: value.span.end_column,
        },
        DeclaredSpan::Canonical(value) => value,
    };
    if !safe_path(&result.file)
        || result.start_line == 0
        || result.start_column == 0
        || result.end_line < result.start_line
        || (result.end_line == result.start_line && result.end_column <= result.start_column)
    {
        return Err(invalid(
            "projection contains an invalid or non-portable span",
        ));
    }
    Ok(result)
}

fn validate_fingerprint(value: &str, label: &str) -> Result<(), Phase12Error> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid(format!(
            "{label} must be a 64-character hexadecimal SHA-256"
        )));
    }
    Ok(())
}

fn validate_taxonomy(
    taxonomy: &FrozenTaxonomy,
    coordinates: &TaxonomyCoordinates,
    cwe: &str,
) -> Result<(), Phase12Error> {
    if coordinates.taxonomy_version != taxonomy.taxonomy_version {
        return Err(invalid(
            "taxonomy version does not match the frozen canonical taxonomy",
        ));
    }
    let category = taxonomy
        .categories
        .iter()
        .find(|category| category.category_id == coordinates.category_id)
        .ok_or_else(|| invalid("category is absent from the frozen canonical taxonomy"))?;
    if category.invariant_id != coordinates.invariant_id {
        return Err(invalid(
            "category and invariant do not form a canonical taxonomy pair",
        ));
    }
    if category.primary_cwe.id != cwe {
        return Err(invalid(
            "primary CWE does not match the canonical taxonomy pair",
        ));
    }
    Ok(())
}

fn validate_canonical(
    contract: &EvidenceContractV2,
    canonical: &CanonicalFindingV2,
) -> Result<(), Phase12Error> {
    if canonical.path.len() < 2
        || canonical.connected_edges.len() != canonical.path.len().saturating_sub(1)
    {
        return Err(invalid(
            "projection path or connected-edge cardinality is incomplete",
        ));
    }
    if canonical.path.first().map(|node| node.role) != Some(EvidenceRoleV2::Source)
        || canonical.path.last().map(|node| node.role) != Some(EvidenceRoleV2::Sink)
    {
        return Err(invalid(
            "projection must begin at a source and end at a sink",
        ));
    }
    if canonical.path[0].source_kind.is_none()
        || canonical
            .path
            .last()
            .and_then(|node| node.sink_kind)
            .is_none()
    {
        return Err(invalid(
            "projection source or sink semantic identity is missing",
        ));
    }
    if canonical.path.iter().any(|node| {
        !safe_path(&node.span.file)
            || node.span.start_line == 0
            || node.span.start_column == 0
            || node.span.end_line < node.span.start_line
    }) {
        return Err(invalid("projection contains an invalid source span"));
    }
    if canonical.taxonomy_version != contract.taxonomy.taxonomy_version {
        return Err(invalid(
            "projection taxonomy version conflicts with Evidence Contract v2",
        ));
    }
    Ok(())
}

fn canonical_from_v2(
    coordinates: &TaxonomyCoordinates,
    projection: DeclaredProjectionV2,
    contract: &EvidenceContractV2,
) -> Result<(CanonicalFindingV2, String, String), Phase12Error> {
    if projection.contract_version != contract.contract_version
        || projection.contract_version != "2.0.0"
    {
        return Err(invalid(
            "authoritative projection declares an unsupported contract version",
        ));
    }
    if projection
        .semantics_version
        .as_deref()
        .is_some_and(|version| version != "secure-evidence-semantics-v2")
    {
        return Err(invalid(
            "authoritative projection declares an unsupported semantics version",
        ));
    }
    validate_fingerprint(&projection.fingerprint, "finding fingerprint")?;
    validate_fingerprint(&projection.duplicate_fingerprint, "duplicate fingerprint")?;
    let canonical = CanonicalFindingV2 {
        taxonomy_version: coordinates.taxonomy_version.clone(),
        category_id: coordinates.category_id.clone(),
        invariant_id: coordinates.invariant_id.clone(),
        path: projection
            .path
            .into_iter()
            .map(|node| {
                Ok(EvidenceNodeV2 {
                    role: node.role,
                    effect: node.effect,
                    source_kind: node.source_kind,
                    sink_kind: node.sink_kind,
                    span: canonical_span(node.span)?,
                    summarizable: node.summarizable,
                })
            })
            .collect::<Result<Vec<_>, Phase12Error>>()?,
        connected_edges: projection.connected_edges,
        effective_barriers: projection.effective_barriers,
        unresolved_call: projection.unresolved_call,
        uncertain: projection.uncertain,
        rule_id: None,
        tool_identity: None,
        prose: None,
    };
    validate_canonical(contract, &canonical)?;
    Ok((
        canonical,
        projection.fingerprint,
        projection.duplicate_fingerprint,
    ))
}

fn projection_hash(canonical: &CanonicalFindingV2, cwe: &str) -> Result<String, Phase12Error> {
    serde_json::to_vec(&(canonical, cwe))
        .map(|bytes| sha256(&bytes))
        .map_err(|error| Phase12Error::Serialization(error.to_string()))
}

/// Adapts one report finding under the prospective 0.2.0 precedence policy.
///
/// Generic legacy report fields are deliberately ignored. A malformed declared v2 object fails
/// closed even if a valid legacy compatibility object is present.
///
/// # Errors
///
/// Returns [`Phase12Error::Adapter`] for missing, malformed, incomplete, conflicting, unknown, or
/// version-mismatched projections.
pub fn adapt_finding(
    value: &Value,
    route: AdapterRoute,
    contract: &EvidenceContractV2,
    taxonomy: &FrozenTaxonomy,
) -> Result<AdaptedFindingV2, Phase12Error> {
    if contract.contract_version != "2.0.0" {
        return Err(invalid(
            "benchmark Evidence Contract v2 version is unsupported",
        ));
    }
    let coordinates: TaxonomyCoordinates = parse_required(value.get("taxonomy"), "taxonomy")?;
    let cwe = primary_cwe(value.get("primary_cwe"))?;
    validate_taxonomy(taxonomy, &coordinates, &cwe)?;

    let legacy_value = value.get("declared_legacy_projection");
    if let Some(v2_value) = value.get("evidence_contract_v2") {
        let projection: DeclaredProjectionV2 =
            serde_json::from_value(v2_value.clone()).map_err(|error| {
                invalid(format!(
                    "malformed authoritative evidence_contract_v2: {error}"
                ))
            })?;
        let (canonical, fingerprint, duplicate_fingerprint) =
            canonical_from_v2(&coordinates, projection, contract)?;
        let mut checked = false;
        if let Some(legacy_value) = legacy_value {
            let legacy: LegacyProjectionV1 =
                serde_json::from_value(legacy_value.clone()).map_err(|error| {
                    invalid(format!("malformed declared legacy projection: {error}"))
                })?;
            if legacy.projection_version != "legacy-compat-v1"
                || legacy.taxonomy != coordinates
                || legacy.primary_cwe != cwe
                || legacy.canonical != canonical
                || legacy.fingerprint != fingerprint
                || legacy.duplicate_fingerprint != duplicate_fingerprint
            {
                return Err(invalid("declared v2 and legacy projections conflict"));
            }
            checked = true;
        }
        return Ok(AdaptedFindingV2 {
            provenance: AdapterProvenance {
                adapter_version: "secure-bench-adapter-0.2.0".to_owned(),
                projection_source: ProjectionSource::AuthoritativeEvidenceContractV2,
                evidence_contract_version: Some(contract.contract_version.clone()),
                legacy_projection_present: legacy_value.is_some(),
                legacy_consistency_checked: checked,
                projection_sha256: projection_hash(&canonical, &cwe)?,
            },
            canonical,
            primary_cwe: cwe,
            declared_fingerprint: fingerprint,
            duplicate_fingerprint,
        });
    }

    if route != AdapterRoute::ExplicitLegacyCompatibility {
        return Err(invalid(
            "authoritative evidence_contract_v2 projection is missing",
        ));
    }
    let legacy: LegacyProjectionV1 = parse_required(legacy_value, "declared legacy projection")?;
    if legacy.projection_version != "legacy-compat-v1" {
        return Err(invalid("legacy projection version is unsupported"));
    }
    if legacy.taxonomy != coordinates || legacy.primary_cwe != cwe {
        return Err(invalid(
            "legacy projection conflicts with report taxonomy or CWE",
        ));
    }
    validate_fingerprint(&legacy.fingerprint, "finding fingerprint")?;
    validate_fingerprint(&legacy.duplicate_fingerprint, "duplicate fingerprint")?;
    validate_canonical(contract, &legacy.canonical)?;
    if legacy.canonical.taxonomy_version != coordinates.taxonomy_version
        || legacy.canonical.category_id != coordinates.category_id
        || legacy.canonical.invariant_id != coordinates.invariant_id
    {
        return Err(invalid(
            "legacy canonical evidence conflicts with report taxonomy",
        ));
    }
    Ok(AdaptedFindingV2 {
        provenance: AdapterProvenance {
            adapter_version: "secure-bench-adapter-0.2.0".to_owned(),
            projection_source: ProjectionSource::LegacyCompatibilityV1,
            evidence_contract_version: None,
            legacy_projection_present: true,
            legacy_consistency_checked: true,
            projection_sha256: projection_hash(&legacy.canonical, &cwe)?,
        },
        canonical: legacy.canonical,
        primary_cwe: cwe,
        declared_fingerprint: legacy.fingerprint,
        duplicate_fingerprint: legacy.duplicate_fingerprint,
    })
}
