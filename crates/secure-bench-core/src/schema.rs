//! Versioned JSON Schema validation for suite, run, and result projections.

use crate::model::{
    BenchmarkResult, BenchmarkSuite, RESULT_SCHEMA_V1, RESULT_SCHEMA_V2, RecordedRun,
    SUITE_SCHEMA_V1, SUITE_SCHEMA_V2,
};
use crate::phase2::{NetworkIsolationAttestation, Phase2Result, TaxonomyProfile};
use crate::runner::LiveRun;
use crate::taxonomy::FrozenTaxonomy;
use serde_json::Value;
use thiserror::Error;

const SUITE_SCHEMA: &str = include_str!("../../../schemas/suite-v1.schema.json");
const SUITE_SCHEMA_V2_JSON: &str = include_str!("../../../schemas/suite-v2.schema.json");
const RUN_SCHEMA: &str = include_str!("../../../schemas/run-v1.schema.json");
const LIVE_RUN_SCHEMA: &str = include_str!("../../../schemas/live-run-v1.schema.json");
const RESULT_SCHEMA: &str = include_str!("../../../schemas/result-v1.schema.json");
const RESULT_SCHEMA_V2_JSON: &str = include_str!("../../../schemas/result-v2.schema.json");
const TAXONOMY_SCHEMA: &str = include_str!("../../../schemas/taxonomy-v1.schema.json");
const TAXONOMY_PROFILE_SCHEMA: &str =
    include_str!("../../../schemas/taxonomy-profile-v1.schema.json");
const NETWORK_ISOLATION_SCHEMA: &str =
    include_str!("../../../schemas/network-isolation-v1.schema.json");
const PHASE2_RESULT_SCHEMA: &str = include_str!("../../../schemas/phase2-result-v1.schema.json");

/// Schema loading or validation failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SchemaError {
    /// A committed schema could not be parsed or compiled.
    #[error("committed {contract} schema is invalid: {detail}")]
    InvalidCommittedSchema {
        /// Contract name.
        contract: &'static str,
        /// Parser or compiler detail.
        detail: String,
    },
    /// An instance did not satisfy its versioned schema.
    #[error("{contract} does not satisfy its versioned schema: {detail}")]
    InvalidInstance {
        /// Contract name.
        contract: &'static str,
        /// Validation detail.
        detail: String,
    },
    /// A typed model could not be projected to JSON.
    #[error("could not project {contract} to JSON: {detail}")]
    Projection {
        /// Contract name.
        contract: &'static str,
        /// Serialization detail.
        detail: String,
    },
}

/// Validates the JSON projection of a suite contract.
///
/// # Errors
///
/// Returns [`SchemaError`] for invalid committed schemas, projections, or instances.
pub fn validate_suite(suite: &BenchmarkSuite) -> Result<(), SchemaError> {
    let schema = match suite.schema_version.as_str() {
        SUITE_SCHEMA_V1 => SUITE_SCHEMA,
        SUITE_SCHEMA_V2 => SUITE_SCHEMA_V2_JSON,
        version => {
            return Err(SchemaError::InvalidInstance {
                contract: "suite",
                detail: format!("unsupported schema version `{version}`"),
            });
        }
    };
    validate_typed("suite", schema, suite)
}

/// Validates a recorded-run contract.
///
/// # Errors
///
/// Returns [`SchemaError`] for invalid committed schemas, projections, or instances.
pub fn validate_run(run: &RecordedRun) -> Result<(), SchemaError> {
    validate_typed("run", RUN_SCHEMA, run)
}

/// Validates a Phase 1 live-run contract.
///
/// # Errors
///
/// Returns [`SchemaError`] for invalid committed schemas, projections, or instances.
pub fn validate_live_run(run: &LiveRun) -> Result<(), SchemaError> {
    validate_typed("live run", LIVE_RUN_SCHEMA, run)
}

/// Validates a machine-readable benchmark result.
///
/// # Errors
///
/// Returns [`SchemaError`] for invalid committed schemas, projections, or instances.
pub fn validate_result(result: &BenchmarkResult) -> Result<(), SchemaError> {
    let schema = match result.schema_version.as_str() {
        RESULT_SCHEMA_V1 => RESULT_SCHEMA,
        RESULT_SCHEMA_V2 => RESULT_SCHEMA_V2_JSON,
        version => {
            return Err(SchemaError::InvalidInstance {
                contract: "result",
                detail: format!("unsupported schema version `{version}`"),
            });
        }
    };
    validate_typed("result", schema, result)
}

/// Validates the JSON projection of the frozen neutral taxonomy.
///
/// # Errors
///
/// Returns [`SchemaError`] for invalid committed schemas, projections, or instances.
pub fn validate_taxonomy(taxonomy: &FrozenTaxonomy) -> Result<(), SchemaError> {
    validate_typed("taxonomy", TAXONOMY_SCHEMA, taxonomy)
}

/// Validates the prospective expectation taxonomy profile.
///
/// # Errors
///
/// Returns [`SchemaError`] for invalid committed schemas, projections, or instances.
pub fn validate_taxonomy_profile(profile: &TaxonomyProfile) -> Result<(), SchemaError> {
    validate_typed("taxonomy profile", TAXONOMY_PROFILE_SCHEMA, profile)
}

/// Validates a network-isolation attestation.
///
/// # Errors
///
/// Returns [`SchemaError`] for invalid committed schemas, projections, or instances.
pub fn validate_network_attestation(
    attestation: &NetworkIsolationAttestation,
) -> Result<(), SchemaError> {
    validate_typed(
        "network isolation attestation",
        NETWORK_ISOLATION_SCHEMA,
        attestation,
    )
}

/// Validates a complete Phase 2 prospective result.
///
/// # Errors
///
/// Returns [`SchemaError`] for invalid committed schemas, projections, or instances.
pub fn validate_phase2_result(result: &Phase2Result) -> Result<(), SchemaError> {
    validate_typed("Phase 2 result", PHASE2_RESULT_SCHEMA, result)
}

fn validate_typed<T: serde::Serialize>(
    contract: &'static str,
    schema_text: &str,
    instance: &T,
) -> Result<(), SchemaError> {
    let schema: Value =
        serde_json::from_str(schema_text).map_err(|error| SchemaError::InvalidCommittedSchema {
            contract,
            detail: error.to_string(),
        })?;
    let validator = jsonschema::validator_for(&schema).map_err(|error| {
        SchemaError::InvalidCommittedSchema {
            contract,
            detail: error.to_string(),
        }
    })?;
    let instance = serde_json::to_value(instance).map_err(|error| SchemaError::Projection {
        contract,
        detail: error.to_string(),
    })?;
    validator
        .validate(&instance)
        .map_err(|error| SchemaError::InvalidInstance {
            contract,
            detail: error.to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committed_schemas_compile() -> Result<(), Box<dyn std::error::Error>> {
        for (name, schema) in [
            ("suite", SUITE_SCHEMA),
            ("suite v2", SUITE_SCHEMA_V2_JSON),
            ("run", RUN_SCHEMA),
            ("live run", LIVE_RUN_SCHEMA),
            ("result", RESULT_SCHEMA),
            ("result v2", RESULT_SCHEMA_V2_JSON),
            ("taxonomy", TAXONOMY_SCHEMA),
            ("taxonomy profile", TAXONOMY_PROFILE_SCHEMA),
            ("network isolation", NETWORK_ISOLATION_SCHEMA),
            ("Phase 2 result", PHASE2_RESULT_SCHEMA),
        ] {
            let value: Value = serde_json::from_str(schema)?;
            jsonschema::validator_for(&value)
                .map_err(|error| format!("{name} schema must compile: {error}"))?;
        }
        Ok(())
    }

    #[test]
    fn suite_schema_rejects_an_invalid_version() -> Result<(), Box<dyn std::error::Error>> {
        let bytes = include_bytes!("../../../fixtures/suite.toml");
        let mut suite = crate::load_suite(bytes)?;
        validate_suite(&suite)?;
        suite.schema_version = "secure-bench-suite-v999".to_owned();
        assert!(matches!(
            validate_suite(&suite),
            Err(SchemaError::InvalidInstance { .. })
        ));
        Ok(())
    }
}
