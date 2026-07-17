//! Public Evidence Contract v2 conformance-vector validation through the repaired adapter.

use crate::adapter::{AdapterRoute, ProjectionSource, adapt_finding};
use crate::{Phase12Error, sha256};
use secure_bench_core::phase5::{
    CanonicalFindingV2, EvidenceContractV2, EvidenceExpectationV2, EvidenceMatchV2,
    match_evidence_v2,
};
use secure_bench_core::taxonomy::FrozenTaxonomy;
use serde_json::{Value, json};

fn outcome_name(value: EvidenceMatchV2) -> &'static str {
    match value {
        EvidenceMatchV2::Exact => "exact",
        EvidenceMatchV2::Partial => "partial",
        EvidenceMatchV2::NoMatch => "no_match",
    }
}

fn report_from_vector(vector: &Value) -> Result<Value, Phase12Error> {
    let finding: CanonicalFindingV2 = serde_json::from_value(vector["finding"].clone())
        .map_err(|error| Phase12Error::InvalidConformance(error.to_string()))?;
    let vector_id = vector["vector_id"]
        .as_str()
        .ok_or_else(|| Phase12Error::InvalidConformance("vector id is missing".to_owned()))?;
    let digest = sha256(vector_id.as_bytes());
    Ok(json!({
        "taxonomy": {
            "taxonomy_version": finding.taxonomy_version,
            "category_id": finding.category_id,
            "invariant_id": finding.invariant_id,
        },
        "primary_cwe": vector["reported_primary_cwe"],
        "evidence_contract_v2": {
            "contract_version": "2.0.0",
            "semantics_version": "secure-evidence-semantics-v2",
            "path": finding.path,
            "connected_edges": finding.connected_edges,
            "effective_barriers": finding.effective_barriers,
            "unresolved_call": finding.unresolved_call,
            "uncertain": finding.uncertain,
            "fingerprint": digest,
            "duplicate_fingerprint": sha256(format!("duplicate:{vector_id}").as_bytes()),
        },
        "evidence_path": [{
            "kind": "generic-legacy-node",
            "semantic": {"identity": "deliberately-non-authoritative"}
        }],
        "rule_id": "non-scoring-public-vector",
    }))
}

/// Validates all public Phase 11 vectors through the prospective adapter and frozen matcher.
///
/// Adapter rejection is the required no-match outcome for malformed taxonomy or CWE tuples. The
/// exact vector also carries a deliberately unusable generic legacy path, reproducing the Phase 10
/// defect condition while proving that declared v2 evidence remains authoritative.
///
/// # Errors
///
/// Returns an error for a missing vector, altered expectation, adapter precedence failure, or
/// mismatch outcome drift.
pub fn validate_public_vectors(
    bytes: &[u8],
    contract: &EvidenceContractV2,
    taxonomy: &FrozenTaxonomy,
) -> Result<u64, Phase12Error> {
    let suite: Value = serde_json::from_slice(bytes)
        .map_err(|error| Phase12Error::InvalidConformance(error.to_string()))?;
    let vectors = suite["vectors"]
        .as_array()
        .ok_or_else(|| Phase12Error::InvalidConformance("public vectors are missing".to_owned()))?;
    if vectors.len() != 19 || suite["evidence_contract_version"] != "2.0.0" {
        return Err(Phase12Error::InvalidConformance(
            "public vector population or contract version differs".to_owned(),
        ));
    }
    for vector in vectors {
        let expectation: EvidenceExpectationV2 =
            serde_json::from_value(vector["expectation"].clone())
                .map_err(|error| Phase12Error::InvalidConformance(error.to_string()))?;
        let report = report_from_vector(vector)?;
        let duplicate = vector["semantic_duplicate"].as_bool().unwrap_or(false);
        let result = adapt_finding(
            &report,
            AdapterRoute::EvidenceContractV2,
            contract,
            taxonomy,
        );
        let outcome = match result {
            Ok(adapted) => {
                if adapted.provenance.projection_source
                    != ProjectionSource::AuthoritativeEvidenceContractV2
                {
                    return Err(Phase12Error::InvalidConformance(
                        "authoritative vector used a compatibility projection".to_owned(),
                    ));
                }
                if duplicate {
                    "duplicate_rejected"
                } else if adapted.primary_cwe != expectation.primary_cwe {
                    "no_match"
                } else {
                    outcome_name(match_evidence_v2(
                        contract,
                        &expectation,
                        &adapted.canonical,
                    ))
                }
            }
            Err(_) => "no_match",
        };
        let expected = vector["expected_outcome"].as_str().ok_or_else(|| {
            Phase12Error::InvalidConformance("expected outcome is missing".to_owned())
        })?;
        if outcome != expected {
            return Err(Phase12Error::InvalidConformance(format!(
                "{} produced {outcome}, expected {expected}",
                vector["vector_id"].as_str().unwrap_or("unknown-vector")
            )));
        }
    }
    u64::try_from(vectors.len())
        .map_err(|_| Phase12Error::InvalidConformance("vector count overflow".to_owned()))
}
