//! Versioned JSON Schema validation for suite, run, and result projections.

use crate::holdout::{HoldoutLedgerEntry, HoldoutManifest};
use crate::model::{
    BenchmarkResult, BenchmarkSuite, RESULT_SCHEMA_V1, RESULT_SCHEMA_V2, RecordedRun,
    SUITE_SCHEMA_V1, SUITE_SCHEMA_V2,
};
use crate::phase2::{NetworkIsolationAttestation, Phase2Result, TaxonomyProfile};
use crate::phase4::{Phase4Artifacts, Phase4PreExecutionContract, Phase4Result, Phase4Run};
use crate::phase5::{
    EvidenceContractV2, Phase5CommitmentIndex, Phase5LedgerEntry, Phase5Manifest,
    SyntheticContractSuiteV2,
};
use crate::phase6::{RetiredHoldoutDiagnosticPack, RetiredRegressionManifest};
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
const HOLDOUT_SCHEMA: &str = include_str!("../../../schemas/holdout-v1.schema.json");
const HOLDOUT_LEDGER_ENTRY_SCHEMA: &str =
    include_str!("../../../schemas/holdout-ledger-entry-v1.schema.json");
const PHASE4_PRE_EXECUTION_SCHEMA: &str =
    include_str!("../../../schemas/phase4-pre-execution-v1.schema.json");
const PHASE4_RUN_SCHEMA: &str = include_str!("../../../schemas/phase4-run-v1.schema.json");
const PHASE4_RESULT_SCHEMA: &str = include_str!("../../../schemas/phase4-result-v1.schema.json");
const PHASE4_ARTIFACTS_SCHEMA: &str =
    include_str!("../../../schemas/phase4-artifacts-v1.schema.json");
const EVIDENCE_CONTRACT_V2_SCHEMA: &str =
    include_str!("../../../schemas/evidence-contract-v2.schema.json");
const PHASE5_HOLDOUT_SCHEMA: &str = include_str!("../../../schemas/phase5-holdout-v2.schema.json");
const PHASE5_COMMITMENTS_SCHEMA: &str =
    include_str!("../../../schemas/phase5-commitments-v1.schema.json");
const PHASE5_LEDGER_SCHEMA: &str =
    include_str!("../../../schemas/phase5-ledger-entry-v1.schema.json");
const PHASE5_CONTRACT_TESTS_SCHEMA: &str =
    include_str!("../../../schemas/phase5-contract-tests-v1.schema.json");
const PHASE6_DIAGNOSTIC_SCHEMA: &str =
    include_str!("../../../schemas/phase6-retired-diagnostic-v1.schema.json");
const PHASE6_REGRESSION_SCHEMA: &str =
    include_str!("../../../schemas/phase6-regression-manifest-v1.schema.json");

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

/// Validates a frozen Phase 3 holdout manifest.
///
/// # Errors
///
/// Returns [`SchemaError`] for invalid committed schemas, projections, or instances.
pub fn validate_holdout_manifest(manifest: &HoldoutManifest) -> Result<(), SchemaError> {
    validate_typed("holdout manifest", HOLDOUT_SCHEMA, manifest)
}

/// Validates one append-only Phase 3 holdout ledger entry.
///
/// # Errors
///
/// Returns [`SchemaError`] for invalid committed schemas, projections, or instances.
pub fn validate_holdout_ledger_entry(entry: &HoldoutLedgerEntry) -> Result<(), SchemaError> {
    validate_typed("holdout ledger entry", HOLDOUT_LEDGER_ENTRY_SCHEMA, entry)
}

/// Validates a frozen Phase 4 pre-execution contract.
///
/// # Errors
///
/// Returns [`SchemaError`] if the committed schema, projection, or instance is invalid.
pub fn validate_phase4_pre_execution(
    contract: &Phase4PreExecutionContract,
) -> Result<(), SchemaError> {
    validate_typed(
        "Phase 4 pre-execution contract",
        PHASE4_PRE_EXECUTION_SCHEMA,
        contract,
    )
}

/// Validates a retained Phase 4 run.
///
/// # Errors
///
/// Returns [`SchemaError`] if the committed schema, projection, or instance is invalid.
pub fn validate_phase4_run(run: &Phase4Run) -> Result<(), SchemaError> {
    validate_typed("Phase 4 run", PHASE4_RUN_SCHEMA, run)
}

/// Validates a deterministic Phase 4 result.
///
/// # Errors
///
/// Returns [`SchemaError`] if the committed schema, projection, or instance is invalid.
pub fn validate_phase4_result(result: &Phase4Result) -> Result<(), SchemaError> {
    validate_typed("Phase 4 result", PHASE4_RESULT_SCHEMA, result)
}

/// Validates a Phase 4 final artifact index.
///
/// # Errors
///
/// Returns [`SchemaError`] if the committed schema, projection, or instance is invalid.
pub fn validate_phase4_artifacts(artifacts: &Phase4Artifacts) -> Result<(), SchemaError> {
    validate_typed("Phase 4 artifact index", PHASE4_ARTIFACTS_SCHEMA, artifacts)
}

/// Validates the tool-neutral evidence contract v2.
///
/// # Errors
///
/// Returns [`SchemaError`] if the committed schema, projection, or instance is invalid.
pub fn validate_evidence_contract_v2(contract: &EvidenceContractV2) -> Result<(), SchemaError> {
    validate_typed(
        "evidence contract v2",
        EVIDENCE_CONTRACT_V2_SCHEMA,
        contract,
    )
}

/// Validates the frozen Phase 5 manifest.
///
/// # Errors
///
/// Returns [`SchemaError`] if the committed schema, projection, or instance is invalid.
pub fn validate_phase5_manifest(manifest: &Phase5Manifest) -> Result<(), SchemaError> {
    validate_typed("Phase 5 manifest", PHASE5_HOLDOUT_SCHEMA, manifest)
}

/// Validates the Phase 5 commitment index.
///
/// # Errors
///
/// Returns [`SchemaError`] if the committed schema, projection, or instance is invalid.
pub fn validate_phase5_commitments(index: &Phase5CommitmentIndex) -> Result<(), SchemaError> {
    validate_typed("Phase 5 commitment index", PHASE5_COMMITMENTS_SCHEMA, index)
}

/// Validates one Phase 5 append-only ledger entry.
///
/// # Errors
///
/// Returns [`SchemaError`] if the committed schema, projection, or instance is invalid.
pub fn validate_phase5_ledger_entry(entry: &Phase5LedgerEntry) -> Result<(), SchemaError> {
    validate_typed("Phase 5 ledger entry", PHASE5_LEDGER_SCHEMA, entry)
}

/// Validates the synthetic evidence-contract conformance suite.
///
/// # Errors
///
/// Returns [`SchemaError`] if the committed schema, projection, or instance is invalid.
pub fn validate_phase5_contract_tests(suite: &SyntheticContractSuiteV2) -> Result<(), SchemaError> {
    validate_typed(
        "Phase 5 contract tests",
        PHASE5_CONTRACT_TESTS_SCHEMA,
        suite,
    )
}

/// Validates the public retired-holdout diagnostic package.
///
/// # Errors
///
/// Returns [`SchemaError`] if the committed schema, projection, or instance is invalid.
pub fn validate_phase6_diagnostic(
    package: &RetiredHoldoutDiagnosticPack,
) -> Result<(), SchemaError> {
    validate_typed(
        "Phase 6 retired diagnostic",
        PHASE6_DIAGNOSTIC_SCHEMA,
        package,
    )
}

/// Validates the engine-consumable retired regression manifest.
///
/// # Errors
///
/// Returns [`SchemaError`] if the committed schema, projection, or instance is invalid.
pub fn validate_phase6_regression(manifest: &RetiredRegressionManifest) -> Result<(), SchemaError> {
    validate_typed(
        "Phase 6 regression manifest",
        PHASE6_REGRESSION_SCHEMA,
        manifest,
    )
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
            ("holdout manifest", HOLDOUT_SCHEMA),
            ("holdout ledger entry", HOLDOUT_LEDGER_ENTRY_SCHEMA),
            ("Phase 4 pre-execution", PHASE4_PRE_EXECUTION_SCHEMA),
            ("Phase 4 run", PHASE4_RUN_SCHEMA),
            ("Phase 4 result", PHASE4_RESULT_SCHEMA),
            ("Phase 4 artifact index", PHASE4_ARTIFACTS_SCHEMA),
            ("evidence contract v2", EVIDENCE_CONTRACT_V2_SCHEMA),
            ("Phase 5 holdout", PHASE5_HOLDOUT_SCHEMA),
            ("Phase 5 commitments", PHASE5_COMMITMENTS_SCHEMA),
            ("Phase 5 ledger", PHASE5_LEDGER_SCHEMA),
            ("Phase 5 contract tests", PHASE5_CONTRACT_TESTS_SCHEMA),
            ("Phase 6 retired diagnostic", PHASE6_DIAGNOSTIC_SCHEMA),
            ("Phase 6 regression manifest", PHASE6_REGRESSION_SCHEMA),
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
