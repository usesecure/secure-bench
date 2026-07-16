//! Contract validation and deterministic recorded or live evaluation orchestration.

use crate::adapter::{AdapterError, AdapterInput, AdapterRegistry, fingerprint};
use crate::matcher::match_findings;
use crate::model::{
    BenchmarkError, BenchmarkResult, BenchmarkSuite, CaseExecution, CaseKind, ErrorStage,
    ExecutionStatus, NetworkPolicy, RESULT_SCHEMA_V1, RESULT_SCHEMA_V2, RUN_SCHEMA_V1, RecordedRun,
    ReportFormat, ResultProvenance, SUITE_SCHEMA_V1, SUITE_SCHEMA_V2, ToolProvenance,
};
use crate::runner::{
    LIVE_RUN_SCHEMA_V1, LiveCaseStatus, LiveRun, aggregate_status, load_live_run, render_arguments,
    valid_report_path, validate_argument_template,
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

/// Raw committed inputs for one Phase 1 live-run evaluation.
#[derive(Debug)]
pub struct LiveEvaluationInput<'a> {
    /// Human-authored Phase 1 TOML suite manifest.
    pub suite: &'a [u8],
    /// JSON live-run bundle manifest.
    pub run_manifest: &'a [u8],
    /// Bundle-relative raw reports keyed by their manifest paths.
    pub reports: &'a BTreeMap<String, Vec<u8>>,
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
    validate_suite_contract(&suite)?;
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

/// Evaluates a Phase 1 live-run bundle through the existing scoring-blind adapter and matcher.
///
/// # Errors
///
/// Returns [`ContractError`] when suite, run, report linkage, or generated result contracts are
/// inconsistent. Process and adapter failures remain explicit inside a valid result.
#[allow(clippy::too_many_lines)]
pub fn evaluate_live_run(
    input: &LiveEvaluationInput<'_>,
) -> Result<BenchmarkResult, ContractError> {
    let suite = load_suite(input.suite)?;
    validate_suite_contract(&suite)?;
    if suite.schema_version != SUITE_SCHEMA_V2 {
        return Err(ContractError::InvalidSuite(format!(
            "live evaluation requires `{SUITE_SCHEMA_V2}`"
        )));
    }
    crate::schema::validate_suite(&suite)
        .map_err(|error| ContractError::InvalidSuite(error.to_string()))?;
    let run = load_live_run(input.run_manifest)
        .map_err(|error| ContractError::InvalidRun(error.to_string()))?;
    validate_live_run_contract(&suite, &run, input.reports)?;
    crate::schema::validate_live_run(&run)
        .map_err(|error| ContractError::InvalidRun(error.to_string()))?;

    let case_by_id = suite
        .cases
        .iter()
        .map(|case| (case.case_id.as_str(), case))
        .collect::<BTreeMap<_, _>>();
    let mut findings = Vec::new();
    let mut executions = Vec::new();
    let mut errors = Vec::new();
    for case_run in &run.cases {
        let case = case_by_id.get(case_run.case_id.as_str()).ok_or_else(|| {
            ContractError::InvalidRun(format!("run contains unknown case `{}`", case_run.case_id))
        })?;
        let mut execution_status = live_execution_status(case_run.status);
        if case_run.status.is_success() {
            let report_path = case_run.report_path.as_deref().ok_or_else(|| {
                ContractError::InvalidRun(format!(
                    "successful case `{}` has no report path",
                    case_run.case_id
                ))
            })?;
            let report = input.reports.get(report_path).ok_or_else(|| {
                ContractError::InvalidRun(format!(
                    "bundle omitted report for case `{}`",
                    case_run.case_id
                ))
            })?;
            let report_fingerprint = fingerprint(report);
            let adapter = AdapterRegistry::adapter(ReportFormat::SecureJsonV1)
                .map_err(|error| ContractError::InvalidRun(error.to_string()))?;
            match adapter.normalize_scoped(AdapterInput {
                report,
                report_fingerprint: &report_fingerprint,
                case_id: Some(&case_run.case_id),
                path_prefix: Some(&case.fixture_path),
            }) {
                Ok(mut normalized) => {
                    let status_matches = matches!(
                        (case_run.status, normalized.is_empty()),
                        (LiveCaseStatus::Success, true) | (LiveCaseStatus::Findings, false)
                    );
                    if !status_matches {
                        return Err(ContractError::InvalidRun(format!(
                            "reported outcome differs from report contents for case `{}`",
                            case_run.case_id
                        )));
                    }
                    findings.append(&mut normalized);
                }
                Err(error) => {
                    let unsupported = matches!(
                        error,
                        AdapterError::UnsupportedVersion(_) | AdapterError::UnsupportedFormat
                    );
                    execution_status = if unsupported {
                        ExecutionStatus::Unsupported
                    } else {
                        ExecutionStatus::InvalidOutput
                    };
                    errors.push(BenchmarkError {
                        code: adapter_error_code(&error).to_owned(),
                        stage: ErrorStage::Adapter,
                        message: error.to_string(),
                    });
                }
            }
        } else {
            errors.push(BenchmarkError {
                code: case_run
                    .error_code
                    .clone()
                    .unwrap_or_else(|| "runner.unspecified_failure".to_owned()),
                stage: ErrorStage::Runner,
                message: format!(
                    "case `{}` did not produce an eligible successful scan ({:?})",
                    case_run.case_id, case_run.status
                ),
            });
        }
        executions.push(CaseExecution {
            case_id: case_run.case_id.clone(),
            status: execution_status,
            cold_duration_ms: Some(case_run.duration_ms),
            warm_duration_ms: None,
            peak_memory_bytes: case_run.peak_memory_bytes,
            output_bytes: case_run.output_bytes,
        });
    }
    findings.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
    errors.sort_by(|left, right| (&left.code, &left.message).cmp(&(&right.code, &right.message)));
    executions.sort_by(|left, right| left.case_id.cmp(&right.case_id));
    let matching = match_findings(&suite, &findings, &executions);
    let score = score(&suite, &findings, &matching, &executions);
    let aggregate_report_fingerprint = aggregate_report_fingerprint(&run);
    let schemas = BTreeMap::from([
        ("result".to_owned(), RESULT_SCHEMA_V2.to_owned()),
        ("run".to_owned(), LIVE_RUN_SCHEMA_V1.to_owned()),
        ("suite".to_owned(), SUITE_SCHEMA_V2.to_owned()),
        ("tool_report".to_owned(), run.tool.report_schema.clone()),
    ]);
    let result = BenchmarkResult {
        schema_version: RESULT_SCHEMA_V2.to_owned(),
        suite_id: suite.suite_id,
        run_id: run.run_id,
        normalized_findings: findings,
        matching,
        score,
        errors,
        provenance: ResultProvenance {
            suite_fingerprint: fingerprint(input.suite),
            run_manifest_fingerprint: fingerprint(input.run_manifest),
            report_fingerprint: aggregate_report_fingerprint,
            tool: ToolProvenance {
                name: run.tool.name,
                version: run.tool.reported_version,
                command: run.tool.argument_template,
                configuration_fingerprint: run.tool.configuration_fingerprint,
                report_schema: run.tool.report_schema,
                binary_fingerprint: Some(run.tool.binary_fingerprint),
            },
            host: run.host,
            schemas,
        },
    };
    crate::schema::validate_result(&result)
        .map_err(|error| ContractError::InvalidResult(error.to_string()))?;
    Ok(result)
}

// Keeping manifest/report cross-field checks together makes the live contract auditable.
#[allow(clippy::too_many_lines)]
fn validate_live_run_contract(
    suite: &BenchmarkSuite,
    run: &LiveRun,
    reports: &BTreeMap<String, Vec<u8>>,
) -> Result<(), ContractError> {
    if run.schema_version != LIVE_RUN_SCHEMA_V1 {
        return Err(ContractError::InvalidRun(format!(
            "unsupported live-run schema `{}`",
            run.schema_version
        )));
    }
    if run.finished_unix_ms < run.started_unix_ms || aggregate_status(&run.cases) != run.status {
        return Err(ContractError::InvalidRun(
            "live-run timestamps or aggregate status are inconsistent".to_owned(),
        ));
    }
    if run.suite_id != suite.suite_id
        || Some(run.corpus_fingerprint.as_str()) != suite.corpus_fingerprint.as_deref()
    {
        return Err(ContractError::InvalidRun(
            "suite identity or corpus fingerprint does not match the run".to_owned(),
        ));
    }
    if !is_sha256(&run.tool.binary_fingerprint)
        || !is_sha256(&run.tool.configuration_fingerprint)
        || run.tool.report_schema != "secure-json-v1"
    {
        return Err(ContractError::InvalidRun(
            "live tool fingerprints or report schema are invalid".to_owned(),
        ));
    }
    validate_argument_template(&run.tool.argument_template).map_err(ContractError::InvalidRun)?;
    let configuration_placeholders = run
        .tool
        .argument_template
        .iter()
        .filter(|argument| argument.as_str() == "{configuration}")
        .count();
    let empty_configuration = fingerprint(&[]);
    if (run.tool.configuration_fingerprint == empty_configuration
        && configuration_placeholders != 0)
        || (run.tool.configuration_fingerprint != empty_configuration
            && configuration_placeholders != 1)
    {
        return Err(ContractError::InvalidRun(
            "configuration fingerprint and argument template are inconsistent".to_owned(),
        ));
    }
    let suite_cases = suite
        .cases
        .iter()
        .map(|case| (case.case_id.as_str(), case))
        .collect::<BTreeMap<_, _>>();
    let mut seen = BTreeSet::new();
    let mut referenced_reports = BTreeSet::new();
    let expected_arguments = render_arguments(&run.tool.argument_template);
    for case_run in &run.cases {
        if !seen.insert(case_run.case_id.as_str()) {
            return Err(ContractError::InvalidRun(format!(
                "duplicate live case `{}`",
                case_run.case_id
            )));
        }
        let case = suite_cases.get(case_run.case_id.as_str()).ok_or_else(|| {
            ContractError::InvalidRun(format!("unknown live case `{}`", case_run.case_id))
        })?;
        if case.content_fingerprint.as_deref() != Some(case_run.fixture_fingerprint.as_str()) {
            return Err(ContractError::InvalidRun(format!(
                "fixture fingerprint differs for case `{}`",
                case_run.case_id
            )));
        }
        if case_run.arguments != expected_arguments
            || case_run.finished_unix_ms < case_run.started_unix_ms
            || case_run.started_unix_ms < run.started_unix_ms
            || case_run.finished_unix_ms > run.finished_unix_ms
            || (case_run.status.is_success() && case_run.error_code.is_some())
            || (!case_run.status.is_success() && case_run.error_code.is_none())
        {
            return Err(ContractError::InvalidRun(format!(
                "execution provenance is inconsistent for case `{}`",
                case_run.case_id
            )));
        }
        if let Some(path) = &case_run.report_path {
            let expected_path = format!("reports/{}.json", case_run.case_id);
            if path != &expected_path
                || !valid_report_path(path)
                || !referenced_reports.insert(path.as_str())
            {
                return Err(ContractError::InvalidRun(format!(
                    "case `{}` has an unsafe or duplicate report path",
                    case_run.case_id
                )));
            }
            let report = reports.get(path).ok_or_else(|| {
                ContractError::InvalidRun(format!("report `{path}` is not present in the bundle"))
            })?;
            let report_size = u64::try_from(report.len()).unwrap_or(u64::MAX);
            let report_fingerprint = fingerprint(report);
            if report_size > case.resource_budget.output_bytes
                || case_run.output_bytes != Some(report_size)
                || case_run.report_fingerprint.as_deref() != Some(report_fingerprint.as_str())
            {
                return Err(ContractError::InvalidRun(format!(
                    "report fingerprint or size differs for case `{}`",
                    case_run.case_id
                )));
            }
        } else if case_run.report_fingerprint.is_some() || case_run.status.is_success() {
            return Err(ContractError::InvalidRun(format!(
                "case `{}` has inconsistent report metadata",
                case_run.case_id
            )));
        }
    }
    if seen.len() != suite_cases.len()
        || reports
            .keys()
            .any(|path| !referenced_reports.contains(path.as_str()))
    {
        return Err(ContractError::InvalidRun(
            "live run and report bundle must account for every case and no unrelated reports"
                .to_owned(),
        ));
    }
    Ok(())
}

const fn live_execution_status(status: LiveCaseStatus) -> ExecutionStatus {
    match status {
        LiveCaseStatus::Success | LiveCaseStatus::Findings => ExecutionStatus::Success,
        LiveCaseStatus::Crash => ExecutionStatus::Crash,
        LiveCaseStatus::Timeout => ExecutionStatus::Timeout,
        LiveCaseStatus::InvalidOutput => ExecutionStatus::InvalidOutput,
        LiveCaseStatus::UnsupportedSchema => ExecutionStatus::Unsupported,
        LiveCaseStatus::ExecutionFailure => ExecutionStatus::ExecutionFailure,
        LiveCaseStatus::Cancelled => ExecutionStatus::Cancelled,
    }
}

fn aggregate_report_fingerprint(run: &LiveRun) -> String {
    let mut bytes = Vec::new();
    for case in &run.cases {
        if let Some(digest) = &case.report_fingerprint {
            bytes.extend_from_slice(case.case_id.as_bytes());
            bytes.push(0);
            bytes.extend_from_slice(digest.as_bytes());
            bytes.push(0);
        }
    }
    fingerprint(&bytes)
}

// Keeping the cross-field checks together makes the suite contract auditable as one gate.
#[allow(clippy::too_many_lines)]
pub(crate) fn validate_suite_contract(suite: &BenchmarkSuite) -> Result<(), ContractError> {
    if !matches!(
        suite.schema_version.as_str(),
        SUITE_SCHEMA_V1 | SUITE_SCHEMA_V2
    ) {
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
                "case `{}` must declare disabled network access",
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
