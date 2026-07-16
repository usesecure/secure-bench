//! Contract validation and mock-only evaluation orchestration.

use crate::adapter::{AdapterError, AdapterRegistry, fingerprint};
use crate::matcher::match_findings;
use crate::model::{
    BenchmarkError, BenchmarkResult, BenchmarkSuite, CaseExecution, CaseKind, ErrorStage,
    ExecutionStatus, NetworkPolicy, RESULT_SCHEMA_V1, RUN_SCHEMA_V1, RecordedRun, ResultProvenance,
    SUITE_SCHEMA_V1,
};
use crate::score::score;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};
use thiserror::Error;

/// Raw committed inputs for one Phase 0 evaluation.
#[derive(Clone, Copy, Debug)]
pub struct EvaluationInput<'a> {
    /// Human-authored TOML suite manifest.
    pub suite: &'a [u8],
    /// JSON recorded-run manifest.
    pub run_manifest: &'a [u8],
    /// JSON native or SARIF report.
    pub report: &'a [u8],
}

/// Contract errors stop evaluation before a misleading result can be emitted.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ContractError {
    /// Suite TOML is invalid.
    #[error("suite contract is invalid: {0}")]
    InvalidSuite(String),
    /// Recorded-run JSON is invalid.
    #[error("recorded run contract is invalid: {0}")]
    InvalidRun(String),
    /// The implementation produced output that violates its committed schema.
    #[error("generated result contract is invalid: {0}")]
    InvalidResult(String),
}

/// Parses a suite without evaluating scanner output.
///
/// # Errors
///
/// Returns a sanitized error when the TOML shape is invalid.
pub fn load_suite(bytes: &[u8]) -> Result<BenchmarkSuite, ContractError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| ContractError::InvalidSuite("manifest is not UTF-8".to_owned()))?;
    toml::from_str(text).map_err(|error| {
        ContractError::InvalidSuite(format!("TOML syntax or shape error: {error}"))
    })
}

/// Parses a recorded mock run without executing its recorded command.
///
/// # Errors
///
/// Returns a sanitized error when the JSON shape is invalid.
pub fn load_run_manifest(bytes: &[u8]) -> Result<RecordedRun, ContractError> {
    serde_json::from_slice(bytes).map_err(|error| {
        ContractError::InvalidRun(format!(
            "JSON syntax or shape error at line {}",
            error.line()
        ))
    })
}

/// Evaluates one committed report through the neutral Phase 0 pipeline.
///
/// Adapter failures are returned inside a valid result and scored as parse or unsupported
/// failures. Contract violations return an error because denominators would be ambiguous.
///
/// # Errors
///
/// Returns [`ContractError`] when suite or run metadata is invalid or inconsistent.
pub fn evaluate(input: EvaluationInput<'_>) -> Result<BenchmarkResult, ContractError> {
    let suite = load_suite(input.suite)?;
    let run = load_run_manifest(input.run_manifest)?;
    validate_suite(&suite)?;
    validate_run(&suite, &run)?;
    crate::schema::validate_suite(&suite)
        .map_err(|error| ContractError::InvalidSuite(error.to_string()))?;
    crate::schema::validate_run(&run)
        .map_err(|error| ContractError::InvalidRun(error.to_string()))?;

    let mut executions = canonical_executions(&suite, &run);
    let report_fingerprint = fingerprint(input.report);
    let adapter_result = AdapterRegistry::adapter(run.adapter)
        .and_then(|adapter| adapter.normalize(input.report, &report_fingerprint));
    let (mut findings, errors) = match adapter_result {
        Ok(findings) => (findings, Vec::new()),
        Err(error) => {
            let is_unsupported = matches!(
                error,
                AdapterError::UnsupportedFormat | AdapterError::UnsupportedVersion(_)
            );
            for execution in &mut executions {
                if execution.status == ExecutionStatus::Success {
                    execution.status = if is_unsupported {
                        ExecutionStatus::Unsupported
                    } else {
                        ExecutionStatus::ParseFailure
                    };
                }
            }
            (
                Vec::new(),
                vec![BenchmarkError {
                    code: adapter_error_code(&error).to_owned(),
                    stage: ErrorStage::Adapter,
                    message: error.to_string(),
                }],
            )
        }
    };
    findings.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));

    let matching = match_findings(&suite, &findings, &executions);
    let score = score(&suite, &findings, &matching, &executions);
    let schemas = BTreeMap::from([
        ("result".to_owned(), RESULT_SCHEMA_V1.to_owned()),
        ("run".to_owned(), RUN_SCHEMA_V1.to_owned()),
        ("suite".to_owned(), SUITE_SCHEMA_V1.to_owned()),
        ("tool_report".to_owned(), run.tool.report_schema.clone()),
    ]);

    let result = BenchmarkResult {
        schema_version: RESULT_SCHEMA_V1.to_owned(),
        suite_id: suite.suite_id,
        run_id: run.run_id,
        normalized_findings: findings,
        matching,
        score,
        errors,
        provenance: ResultProvenance {
            suite_fingerprint: fingerprint(input.suite),
            run_manifest_fingerprint: fingerprint(input.run_manifest),
            report_fingerprint,
            tool: run.tool,
            host: run.host,
            schemas,
        },
    };
    crate::schema::validate_result(&result)
        .map_err(|error| ContractError::InvalidResult(error.to_string()))?;
    Ok(result)
}

// Keeping the cross-field checks together makes the suite contract auditable as one gate.
#[allow(clippy::too_many_lines)]
fn validate_suite(suite: &BenchmarkSuite) -> Result<(), ContractError> {
    if suite.schema_version != SUITE_SCHEMA_V1 {
        return Err(ContractError::InvalidSuite(format!(
            "unsupported schema version `{}`",
            suite.schema_version
        )));
    }
    validate_identifier(&suite.suite_id)
        .map_err(|message| ContractError::InvalidSuite(format!("suite_id {message}")))?;
    if suite.title.trim().is_empty()
        || suite.description.trim().is_empty()
        || suite.methodology_version.trim().is_empty()
        || suite.cases.is_empty()
    {
        return Err(ContractError::InvalidSuite(
            "title, description, methodology version, and cases are required".to_owned(),
        ));
    }
    validate_provenance(
        &suite.provenance.origin,
        &suite.provenance.license,
        &suite.provenance.revision,
    )?;

    let mut case_ids = BTreeSet::new();
    let mut expectation_ids = BTreeSet::new();
    for case in &suite.cases {
        validate_identifier(&case.case_id)
            .map_err(|message| ContractError::InvalidSuite(format!("case_id {message}")))?;
        if !case_ids.insert(case.case_id.as_str()) {
            return Err(ContractError::InvalidSuite(format!(
                "duplicate case identifier `{}`",
                case.case_id
            )));
        }
        validate_relative_path(&case.fixture_path)?;
        validate_provenance(
            &case.provenance.origin,
            &case.provenance.license,
            &case.provenance.revision,
        )?;
        if case.language.trim().is_empty()
            || case.category.trim().is_empty()
            || case.eligibility.supported_report_formats.is_empty()
        {
            return Err(ContractError::InvalidSuite(format!(
                "case `{}` is missing language, category, or report eligibility",
                case.case_id
            )));
        }
        if case.resource_budget.timeout_ms == 0
            || case.resource_budget.memory_bytes == 0
            || case.resource_budget.output_bytes == 0
        {
            return Err(ContractError::InvalidSuite(format!(
                "case `{}` has a zero resource budget",
                case.case_id
            )));
        }
        if case.resource_budget.network != NetworkPolicy::Disabled {
            return Err(ContractError::InvalidSuite(format!(
                "case `{}` must disable network access in Phase 0",
                case.case_id
            )));
        }
        match case.kind {
            CaseKind::Vulnerable => {
                if case.invariant.as_deref().is_none_or(str::is_empty)
                    || case.expected_findings.is_empty()
                {
                    return Err(ContractError::InvalidSuite(format!(
                        "vulnerable case `{}` requires an invariant and expectation",
                        case.case_id
                    )));
                }
            }
            CaseKind::SafeControl => {
                if case.invariant.is_some() || !case.expected_findings.is_empty() {
                    return Err(ContractError::InvalidSuite(format!(
                        "safe control `{}` cannot declare a violated invariant or expected finding",
                        case.case_id
                    )));
                }
            }
        }
        for expected in &case.expected_findings {
            validate_identifier(&expected.expectation_id).map_err(|message| {
                ContractError::InvalidSuite(format!("expectation_id {message}"))
            })?;
            if !expectation_ids.insert(expected.expectation_id.as_str()) {
                return Err(ContractError::InvalidSuite(format!(
                    "duplicate expectation identifier `{}`",
                    expected.expectation_id
                )));
            }
            if expected.category.trim().is_empty()
                || expected.invariant.trim().is_empty()
                || expected.evidence.minimum_hops < 2
            {
                return Err(ContractError::InvalidSuite(format!(
                    "expectation `{}` has incomplete matching constraints",
                    expected.expectation_id
                )));
            }
            validate_location_constraint(&expected.source)?;
            validate_location_constraint(&expected.sink)?;
        }
    }
    Ok(())
}

fn validate_run(suite: &BenchmarkSuite, run: &RecordedRun) -> Result<(), ContractError> {
    if run.schema_version != RUN_SCHEMA_V1 {
        return Err(ContractError::InvalidRun(format!(
            "unsupported schema version `{}`",
            run.schema_version
        )));
    }
    validate_identifier(&run.run_id)
        .map_err(|message| ContractError::InvalidRun(format!("run_id {message}")))?;
    validate_report_reference(&run.report_path)?;
    if run.tool.name.trim().is_empty()
        || run.tool.version.trim().is_empty()
        || run.tool.command.is_empty()
        || run.tool.command.iter().any(|part| part.trim().is_empty())
        || run.tool.report_schema.trim().is_empty()
    {
        return Err(ContractError::InvalidRun(
            "tool name, version, command, and report schema are required".to_owned(),
        ));
    }
    if !is_sha256(&run.tool.configuration_fingerprint) {
        return Err(ContractError::InvalidRun(
            "configuration_fingerprint must be a lowercase SHA-256 value".to_owned(),
        ));
    }
    if run.host.os.trim().is_empty() || run.host.architecture.trim().is_empty() {
        return Err(ContractError::InvalidRun(
            "sanitized host OS and architecture are required".to_owned(),
        ));
    }

    let suite_ids = suite
        .cases
        .iter()
        .map(|case| case.case_id.as_str())
        .collect::<BTreeSet<_>>();
    let mut execution_ids = BTreeSet::new();
    for execution in &run.case_executions {
        if !execution_ids.insert(execution.case_id.as_str()) {
            return Err(ContractError::InvalidRun(format!(
                "duplicate case execution `{}`",
                execution.case_id
            )));
        }
        if !suite_ids.contains(execution.case_id.as_str()) {
            return Err(ContractError::InvalidRun(format!(
                "case execution `{}` is not declared by the suite",
                execution.case_id
            )));
        }
        validate_measurements(execution)?;
    }
    Ok(())
}

fn canonical_executions(suite: &BenchmarkSuite, run: &RecordedRun) -> Vec<CaseExecution> {
    let by_case = run
        .case_executions
        .iter()
        .map(|execution| (execution.case_id.as_str(), execution))
        .collect::<BTreeMap<_, _>>();
    let mut executions = suite
        .cases
        .iter()
        .map(|case| {
            by_case.get(case.case_id.as_str()).map_or_else(
                || CaseExecution {
                    case_id: case.case_id.clone(),
                    status: ExecutionStatus::Missing,
                    cold_duration_ms: None,
                    warm_duration_ms: None,
                    peak_memory_bytes: None,
                    output_bytes: None,
                },
                |execution| (*execution).clone(),
            )
        })
        .collect::<Vec<_>>();
    executions.sort_by(|left, right| left.case_id.cmp(&right.case_id));
    executions
}

fn validate_location_constraint(
    location: &crate::model::LocationConstraint,
) -> Result<(), ContractError> {
    validate_relative_path(&location.path)?;
    if location.line == Some(0) {
        return Err(ContractError::InvalidSuite(
            "expected line numbers must be one-based".to_owned(),
        ));
    }
    for alternative in &location.alternatives {
        validate_relative_path(&alternative.path)?;
        if alternative.line == Some(0) {
            return Err(ContractError::InvalidSuite(
                "alternative line numbers must be one-based".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_relative_path(path: &str) -> Result<(), ContractError> {
    if path.is_empty()
        || path.contains('\0')
        || path.contains('\\')
        || path.contains(':')
        || path.contains('%')
        || Path::new(path).is_absolute()
        || Path::new(path).components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        Err(ContractError::InvalidSuite(
            "all fixture and source paths must be privacy-safe repository-relative paths"
                .to_owned(),
        ))
    } else {
        Ok(())
    }
}

fn validate_report_reference(path: &str) -> Result<(), ContractError> {
    if path.is_empty()
        || path.contains('\0')
        || path.contains('\\')
        || path.contains(':')
        || path.contains('%')
        || Path::new(path).is_absolute()
        || !Path::new(path)
            .components()
            .any(|component| matches!(component, Component::Normal(_)))
    {
        Err(ContractError::InvalidRun(
            "report_path must be a relative mock artifact reference".to_owned(),
        ))
    } else {
        Ok(())
    }
}

fn validate_identifier(identifier: &str) -> Result<(), &'static str> {
    if identifier.is_empty()
        || !identifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        Err("must use ASCII letters, digits, dots, dashes, or underscores")
    } else {
        Ok(())
    }
}

fn validate_provenance(origin: &str, license: &str, revision: &str) -> Result<(), ContractError> {
    if origin.trim().is_empty() || license.trim().is_empty() || revision.trim().is_empty() {
        Err(ContractError::InvalidSuite(
            "fixture origin, license, and revision are required".to_owned(),
        ))
    } else {
        Ok(())
    }
}

fn validate_measurements(execution: &CaseExecution) -> Result<(), ContractError> {
    let has_measurement = execution.cold_duration_ms.is_some()
        || execution.warm_duration_ms.is_some()
        || execution.peak_memory_bytes.is_some()
        || execution.output_bytes.is_some();
    if execution.status != ExecutionStatus::Success && has_measurement {
        return Err(ContractError::InvalidRun(format!(
            "failed case `{}` cannot claim successful performance measurements",
            execution.case_id
        )));
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn adapter_error_code(error: &AdapterError) -> &'static str {
    match error {
        AdapterError::ReportTooLarge => "adapter.report_too_large",
        AdapterError::InvalidReport { .. } => "adapter.parse_failure",
        AdapterError::UnsupportedVersion(_) => "adapter.unsupported_version",
        AdapterError::UnsafePath => "adapter.unsafe_path",
        AdapterError::UnsupportedFormat => "adapter.unsupported_format",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_validation_is_strict() {
        assert!(is_sha256(&"a".repeat(64)));
        assert!(!is_sha256(&"A".repeat(64)));
        assert!(!is_sha256(&"a".repeat(63)));
    }
}
