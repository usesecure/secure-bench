//! Versioned JSON Schema validation for suite, run, and result projections.

use crate::model::{BenchmarkResult, BenchmarkSuite, RecordedRun};
use serde_json::Value;
use thiserror::Error;

const SUITE_SCHEMA: &str = include_str!("../../../schemas/suite-v1.schema.json");
const RUN_SCHEMA: &str = include_str!("../../../schemas/run-v1.schema.json");
const RESULT_SCHEMA: &str = include_str!("../../../schemas/result-v1.schema.json");

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
    validate_typed("suite", SUITE_SCHEMA, suite)
}

/// Validates a recorded-run contract.
///
/// # Errors
///
/// Returns [`SchemaError`] for invalid committed schemas, projections, or instances.
pub fn validate_run(run: &RecordedRun) -> Result<(), SchemaError> {
    validate_typed("run", RUN_SCHEMA, run)
}

/// Validates a machine-readable benchmark result.
///
/// # Errors
///
/// Returns [`SchemaError`] for invalid committed schemas, projections, or instances.
pub fn validate_result(result: &BenchmarkResult) -> Result<(), SchemaError> {
    validate_typed("result", RESULT_SCHEMA, result)
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
            ("run", RUN_SCHEMA),
            ("result", RESULT_SCHEMA),
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
