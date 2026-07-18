//! Conservative OpenGrep JSON adapter for disclosed Phase 17 conformance fixtures.
//!
//! The adapter has no process-launching API. It captures raw bytes before parsing, rejects unsafe
//! paths and incomplete output, preserves supported OpenGrep fields, and marks unsupported
//! Evidence Contract v2 dimensions unavailable.

#![allow(
    clippy::doc_markdown,
    clippy::module_name_repetitions,
    clippy::naive_bytecount,
    clippy::struct_excessive_bools,
    clippy::too_many_lines
)]

use secure_bench_scanner_protocol::{
    Availability, FindingIdentityKey, ProcessDecision, ProcessTermination, RawArtifact,
    ReportAssessment, RuleMetadata, ScannerManifest, SourceSpan, adjudicate_process,
    assign_finding_ids, portable_relative, sha256,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Component, Path};
use thiserror::Error;

/// Raw OpenGrep JSON profile accepted by this adapter.
pub const RAW_FORMAT: &str = "opengrep-json-v1";
/// Stable adapter identity.
pub const ADAPTER_ID: &str = "secure-bench-opengrep-json";
/// Adapter semantic version.
pub const ADAPTER_VERSION: &str = "1.0.0";
/// Stable explanation for Evidence Contract v2 fields absent from OpenGrep JSON.
pub const UNSUPPORTED_EVIDENCE_REASON: &str =
    "unavailable: opengrep-json-v1 does not declare this Evidence Contract v2 field";

/// Adapter or offline verification failure.
#[derive(Debug, Error)]
pub enum AdapterError {
    /// Manifest does not select this exact adapter profile.
    #[error("manifest/adapter mismatch: {0}")]
    Manifest(String),
    /// Raw bytes exceed the manifest boundary.
    #[error("raw OpenGrep output exceeds the declared byte limit")]
    ReportTooLarge,
    /// JSON syntax or required OpenGrep envelope fields are malformed.
    #[error("malformed OpenGrep report: {0}")]
    Malformed(String),
    /// OpenGrep declared scan errors, skipped rules, or partial completion.
    #[error("OpenGrep report is internally errored or partial")]
    InternallyErrored,
    /// A result refers to a rule outside the pinned ruleset.
    #[error("unknown OpenGrep rule `{0}`")]
    UnknownRule(String),
    /// A result path is absolute, traversing, ambiguous, or a symlink.
    #[error("unsafe OpenGrep result path `{0}`")]
    UnsafePath(String),
    /// A result points to a missing or non-regular disclosed fixture file.
    #[error("OpenGrep result path is not a regular fixture file: `{0}`")]
    MissingSource(String),
    /// A reported source span is empty, reversed, zero-based, or outside the file.
    #[error("invalid OpenGrep span for `{0}`")]
    InvalidSpan(String),
    /// Scanner-neutral protocol validation failed.
    #[error("scanner protocol rejected OpenGrep output: {0}")]
    Protocol(String),
    /// Repository fixture, schema, or provenance input failed.
    #[error("Phase 17 verification failed: {0}")]
    Verification(String),
    /// Filesystem operation failed.
    #[error("Phase 17 filesystem operation failed for `{path}`: {detail}")]
    Io {
        /// Portable path context.
        path: String,
        /// Sanitized detail.
        detail: String,
    },
}

#[derive(Debug, Deserialize)]
struct RawReport {
    version: String,
    results: Vec<RawResult>,
    errors: Vec<Value>,
    #[serde(default)]
    skipped_rules: Vec<Value>,
}

#[derive(Debug, Deserialize)]
struct RawResult {
    check_id: String,
    path: String,
    start: RawPosition,
    end: RawPosition,
    extra: RawExtra,
}

#[derive(Clone, Copy, Debug, Deserialize)]
struct RawPosition {
    line: u32,
    col: u32,
    #[serde(default)]
    offset: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct RawExtra {
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    metadata: BTreeMap<String, Value>,
    #[serde(default)]
    fingerprint: Option<String>,
}

/// Explicit availability of Evidence Contract v2 dimensions.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceAvailability {
    /// Semantic source identity.
    pub source_identity: Availability<String>,
    /// Semantic sink identity.
    pub sink_identity: Availability<String>,
    /// Ordered connected evidence path.
    pub evidence_path: Availability<Vec<Value>>,
    /// Dominating guards or barriers.
    pub guards: Availability<Vec<Value>>,
    /// CWE mapping.
    pub cwe: Availability<String>,
    /// Secure Bench taxonomy coordinates.
    pub taxonomy: Availability<Value>,
    /// Confidence.
    pub confidence: Availability<String>,
}

impl EvidenceAvailability {
    fn unsupported() -> Self {
        Self {
            source_identity: Availability::unavailable(UNSUPPORTED_EVIDENCE_REASON),
            sink_identity: Availability::unavailable(UNSUPPORTED_EVIDENCE_REASON),
            evidence_path: Availability::unavailable(UNSUPPORTED_EVIDENCE_REASON),
            guards: Availability::unavailable(UNSUPPORTED_EVIDENCE_REASON),
            cwe: Availability::unavailable(UNSUPPORTED_EVIDENCE_REASON),
            taxonomy: Availability::unavailable(UNSUPPORTED_EVIDENCE_REASON),
            confidence: Availability::unavailable(UNSUPPORTED_EVIDENCE_REASON),
        }
    }

    /// Returns true only when every unsupported v2 dimension stayed unavailable.
    #[must_use]
    pub const fn all_unavailable(&self) -> bool {
        self.source_identity.is_unavailable()
            && self.sink_identity.is_unavailable()
            && self.evidence_path.is_unavailable()
            && self.guards.is_unavailable()
            && self.cwe.is_unavailable()
            && self.taxonomy.is_unavailable()
            && self.confidence.is_unavailable()
    }
}

/// One finding containing only fields supported by OpenGrep JSON.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdaptedFinding {
    /// Stable ID assigned after neutral projection.
    pub finding_id: String,
    /// Fingerprint of the generic projected identity key.
    pub projection_fingerprint: String,
    /// First ID with the same projected key, if this is a duplicate.
    pub duplicate_of: Option<String>,
    /// Exact OpenGrep rule ID.
    pub rule_id: String,
    /// Validated primary location.
    pub primary_location: SourceSpan,
    /// Scanner message, only if supplied and nonempty.
    pub message: Availability<String>,
    /// Scanner severity, only if supplied and nonempty.
    pub severity: Availability<String>,
    /// Scanner fingerprint, only if supplied and nonempty.
    pub scanner_fingerprint: Availability<String>,
    /// Uninterpreted rule metadata. No metadata key grants taxonomy or evidence identity.
    pub rule_metadata: RuleMetadata,
    /// Explicitly unavailable Evidence Contract v2 dimensions.
    pub evidence: EvidenceAvailability,
}

/// Complete adapter-valid report plus its untouched raw artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdaptedReport {
    /// Raw OpenGrep version string.
    pub scanner_version: String,
    /// Exact adapter version.
    pub adapter_version: String,
    /// Raw bytes retained before parsing.
    pub raw_artifact: RawArtifact,
    /// Findings in raw report order.
    pub findings: Vec<AdaptedFinding>,
}

/// Serializable public projection that intentionally excludes raw bytes and source text.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicProjection {
    /// Projection schema.
    pub schema_version: String,
    /// Scanner version.
    pub scanner_version: String,
    /// Adapter version.
    pub adapter_version: String,
    /// SHA-256 of separately retained raw bytes.
    pub raw_sha256: String,
    /// Raw byte count.
    pub raw_size_bytes: u64,
    /// Conservative findings.
    pub findings: Vec<AdaptedFinding>,
}

impl AdaptedReport {
    /// Produces the privacy-minimized projection while raw bytes remain separate and untouched.
    #[must_use]
    pub fn public_projection(&self) -> PublicProjection {
        PublicProjection {
            schema_version: "secure-bench-adapted-report-v1".to_owned(),
            scanner_version: self.scanner_version.clone(),
            adapter_version: self.adapter_version.clone(),
            raw_sha256: self.raw_artifact.digest().to_owned(),
            raw_size_bytes: u64::try_from(self.raw_artifact.bytes().len()).unwrap_or(u64::MAX),
            findings: self.findings.clone(),
        }
    }
}

fn nonempty(value: Option<String>, field: &str) -> Availability<String> {
    value.map_or_else(
        || Availability::unavailable(format!("unavailable: OpenGrep omitted {field}")),
        |candidate| {
            if candidate.trim().is_empty() {
                Availability::unavailable(format!("unavailable: OpenGrep emitted empty {field}"))
            } else {
                Availability::available(candidate)
            }
        },
    )
}

fn validate_manifest(manifest: &ScannerManifest) -> Result<(), AdapterError> {
    manifest
        .validate()
        .map_err(|error| AdapterError::Manifest(error.to_string()))?;
    if manifest.adapter.adapter_id != ADAPTER_ID
        || manifest.adapter.adapter_version != ADAPTER_VERSION
        || manifest.adapter.raw_output_format != RAW_FORMAT
        || manifest.scanner.id != "opengrep"
    {
        return Err(AdapterError::Manifest(
            "manifest does not select the pinned OpenGrep JSON adapter".to_owned(),
        ));
    }
    Ok(())
}

fn validate_path(root: &Path, value: &str) -> Result<(String, Vec<u8>), AdapterError> {
    let relative =
        portable_relative(value).map_err(|_| AdapterError::UnsafePath(value.to_owned()))?;
    let canonical_root = root.canonicalize().map_err(|error| AdapterError::Io {
        path: root.display().to_string(),
        detail: error.to_string(),
    })?;
    let mut cursor = canonical_root.clone();
    for component in Path::new(&relative).components() {
        let Component::Normal(part) = component else {
            return Err(AdapterError::UnsafePath(value.to_owned()));
        };
        cursor.push(part);
        let metadata = fs::symlink_metadata(&cursor)
            .map_err(|_| AdapterError::MissingSource(relative.clone()))?;
        if metadata.file_type().is_symlink() {
            return Err(AdapterError::UnsafePath(relative));
        }
    }
    let canonical = cursor
        .canonicalize()
        .map_err(|_| AdapterError::MissingSource(relative.clone()))?;
    if !canonical.starts_with(&canonical_root) || !canonical.is_file() {
        return Err(AdapterError::UnsafePath(relative));
    }
    let bytes = fs::read(&canonical).map_err(|error| AdapterError::Io {
        path: relative.clone(),
        detail: error.to_string(),
    })?;
    Ok((relative, bytes))
}

fn validate_span(
    path: String,
    file: &[u8],
    start: RawPosition,
    end: RawPosition,
) -> Result<SourceSpan, AdapterError> {
    if start.line == 0
        || start.col == 0
        || end.line == 0
        || end.col == 0
        || (start.line, start.col) >= (end.line, end.col)
    {
        return Err(AdapterError::InvalidSpan(path));
    }
    let line_count = file.iter().filter(|byte| **byte == b'\n').count() + 1;
    let end_line =
        usize::try_from(end.line).map_err(|_| AdapterError::InvalidSpan(path.clone()))?;
    if end_line > line_count {
        return Err(AdapterError::InvalidSpan(path));
    }
    match (start.offset, end.offset) {
        (Some(start_offset), Some(end_offset)) => {
            let file_len = u64::try_from(file.len()).unwrap_or(u64::MAX);
            if start_offset >= end_offset || end_offset > file_len {
                return Err(AdapterError::InvalidSpan(path));
            }
        }
        (None, None) => {}
        _ => return Err(AdapterError::InvalidSpan(path)),
    }
    Ok(SourceSpan {
        path,
        start_line: start.line,
        start_column: start.col,
        end_line: end.line,
        end_column: end.col,
        start_offset: start.offset.map_or_else(
            || Availability::unavailable("unavailable: OpenGrep omitted start offset"),
            Availability::available,
        ),
        end_offset: end.offset.map_or_else(
            || Availability::unavailable("unavailable: OpenGrep omitted end offset"),
            Availability::available,
        ),
    })
}

/// Adapts one complete OpenGrep JSON report without consulting expectations or score data.
///
/// # Errors
///
/// Fails closed for malformed or partial output, unknown rules, unsafe paths, symlinks, invalid
/// spans, manifest drift, oversized reports, or generic ID failures.
pub fn adapt_report(
    case_scope: &str,
    raw_bytes: &[u8],
    fixture_root: &Path,
    manifest: &ScannerManifest,
) -> Result<AdaptedReport, AdapterError> {
    validate_manifest(manifest)?;
    if u64::try_from(raw_bytes.len()).unwrap_or(u64::MAX) > manifest.resources.max_output_bytes {
        return Err(AdapterError::ReportTooLarge);
    }
    let raw_artifact = RawArtifact::capture(raw_bytes);
    let raw: RawReport = serde_json::from_slice(raw_bytes).map_err(|error| {
        AdapterError::Malformed(format!(
            "JSON syntax or shape error at line {}",
            error.line()
        ))
    })?;
    if raw.version != manifest.scanner.version {
        return Err(AdapterError::Malformed(
            "report version differs from the pinned scanner".to_owned(),
        ));
    }
    if !raw.errors.is_empty() || !raw.skipped_rules.is_empty() {
        return Err(AdapterError::InternallyErrored);
    }
    let mut pending = Vec::with_capacity(raw.results.len());
    let mut keys = Vec::with_capacity(raw.results.len());
    for result in raw.results {
        if !manifest.ruleset.rule_ids.contains(&result.check_id) {
            return Err(AdapterError::UnknownRule(result.check_id));
        }
        let (path, file) = validate_path(fixture_root, &result.path)?;
        let primary_location = validate_span(path, &file, result.start, result.end)?;
        keys.push(FindingIdentityKey {
            rule_id: result.check_id.clone(),
            primary_location: primary_location.clone(),
        });
        pending.push((result, primary_location));
    }
    let ids = assign_finding_ids(case_scope, &keys)
        .map_err(|error| AdapterError::Protocol(error.to_string()))?;
    let findings = pending
        .into_iter()
        .zip(ids)
        .map(|((result, primary_location), assigned)| AdaptedFinding {
            finding_id: assigned.finding_id,
            projection_fingerprint: assigned.projection_fingerprint,
            duplicate_of: assigned.duplicate_of,
            rule_id: result.check_id,
            primary_location,
            message: nonempty(result.extra.message, "message"),
            severity: nonempty(result.extra.severity, "severity"),
            scanner_fingerprint: nonempty(result.extra.fingerprint, "fingerprint"),
            rule_metadata: result.extra.metadata,
            evidence: EvidenceAvailability::unsupported(),
        })
        .collect();
    Ok(AdaptedReport {
        scanner_version: raw.version,
        adapter_version: ADAPTER_VERSION.to_owned(),
        raw_artifact,
        findings,
    })
}

/// Converts adapter success/failure to neutral process-policy input without reading exit status.
#[must_use]
pub fn report_assessment(result: &Result<AdaptedReport, AdapterError>) -> ReportAssessment {
    match result {
        Ok(report) => ReportAssessment::Valid {
            findings: u64::try_from(report.findings.len()).unwrap_or(u64::MAX),
        },
        Err(AdapterError::InternallyErrored) => ReportAssessment::InternallyErrored,
        Err(_) => ReportAssessment::Malformed,
    }
}

/// Offline conformance totals.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationSummary {
    /// Adapter-valid reports.
    pub valid_reports: u64,
    /// Adapter-valid findings.
    pub valid_findings: u64,
    /// Explicit malformed/unsafe/unknown-rule rejections.
    pub malformed_rejections: u64,
    /// Explicit partial report rejections.
    pub partial_rejections: u64,
    /// Deterministic repeat projections.
    pub deterministic_repeats: u64,
    /// Raw byte integrity comparisons.
    pub raw_integrity_checks: u64,
    /// Unsupported-evidence availability checks.
    pub unavailable_evidence_checks: u64,
    /// Separate timeout/nonzero/clean process-policy vectors.
    pub process_policy_checks: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureIndex {
    schema_version: String,
    cases: Vec<FixtureCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureCase {
    id: String,
    report: String,
    report_sha256: String,
    expected: String,
    expected_findings: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessIndex {
    schema_version: String,
    cases: Vec<ProcessCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessCase {
    id: String,
    report: String,
    termination: String,
    #[serde(default)]
    exit_code: Option<i32>,
    expected: ProcessDecision,
}

fn read(root: &Path, relative: &str) -> Result<Vec<u8>, AdapterError> {
    fs::read(root.join(relative)).map_err(|error| AdapterError::Io {
        path: relative.to_owned(),
        detail: error.to_string(),
    })
}

fn parse<T: for<'de> Deserialize<'de>>(bytes: &[u8], label: &str) -> Result<T, AdapterError> {
    serde_json::from_slice(bytes)
        .map_err(|error| AdapterError::Verification(format!("{label}: {error}")))
}

/// Validates all committed Phase 17 schemas, provenance, and disclosed conformance vectors.
///
/// # Errors
///
/// Returns an error for any schema, hash, projection, privacy, or determinism drift.
pub fn verify_repository(root: &Path) -> Result<VerificationSummary, AdapterError> {
    let manifest_bytes = read(root, "phase17/manifests/opengrep-v1.22.0-conformance.json")?;
    let manifest_value: Value = parse(&manifest_bytes, "scanner manifest JSON")?;
    let schema: Value = parse(
        &read(root, "phase17/schemas/scanner-manifest-v1.schema.json")?,
        "scanner manifest schema",
    )?;
    jsonschema::validator_for(&schema)
        .map_err(|error| AdapterError::Verification(error.to_string()))?
        .validate(&manifest_value)
        .map_err(|error| AdapterError::Verification(error.to_string()))?;
    let manifest: ScannerManifest = serde_json::from_value(manifest_value)
        .map_err(|error| AdapterError::Verification(error.to_string()))?;
    validate_manifest(&manifest)?;
    let projection_schema: Value = parse(
        &read(root, "phase17/schemas/adapted-report-v1.schema.json")?,
        "adapted report schema",
    )?;
    let projection_validator = jsonschema::validator_for(&projection_schema)
        .map_err(|error| AdapterError::Verification(error.to_string()))?;
    let rules = read(root, "phase17/rules/opengrep-conformance-v1.yml")?;
    if sha256(&rules) != manifest.ruleset.sha256 {
        return Err(AdapterError::Verification(
            "conformance ruleset hash drift".to_owned(),
        ));
    }
    let provenance: Value = parse(
        &read(root, "phase17/provenance/opengrep-v1.22.0.json")?,
        "OpenGrep provenance",
    )?;
    if provenance
        .pointer("/artifact/sha256")
        .and_then(Value::as_str)
        != Some(manifest.artifact.sha256.as_str())
        || provenance
            .pointer("/signature/certificate_identity")
            .and_then(Value::as_str)
            != Some(manifest.artifact.verification.certificate_identity.as_str())
    {
        return Err(AdapterError::Verification(
            "OpenGrep provenance does not bind the manifest".to_owned(),
        ));
    }
    let index: FixtureIndex = parse(
        &read(root, "phase17/fixtures/conformance/index.json")?,
        "fixture index",
    )?;
    if index.schema_version != "secure-bench-phase17-conformance-index-v1" {
        return Err(AdapterError::Verification(
            "unsupported fixture index".to_owned(),
        ));
    }
    let fixture_root = root.join("phase17/fixtures/conformance/workspace");
    let mut summary = VerificationSummary {
        valid_reports: 0,
        valid_findings: 0,
        malformed_rejections: 0,
        partial_rejections: 0,
        deterministic_repeats: 0,
        raw_integrity_checks: 0,
        unavailable_evidence_checks: 0,
        process_policy_checks: 0,
    };
    for case in index.cases {
        let raw = read(root, &case.report)?;
        if sha256(&raw) != case.report_sha256 {
            return Err(AdapterError::Verification(format!(
                "raw fixture hash drift for {}",
                case.id
            )));
        }
        summary.raw_integrity_checks += 1;
        let first = adapt_report(&case.id, &raw, &fixture_root, &manifest);
        let second = adapt_report(&case.id, &raw, &fixture_root, &manifest);
        match case.expected.as_str() {
            "valid" => {
                let first = first
                    .map_err(|error| AdapterError::Verification(format!("{}: {error}", case.id)))?;
                let second = second
                    .map_err(|error| AdapterError::Verification(format!("{}: {error}", case.id)))?;
                if first != second
                    || first.raw_artifact.bytes() != raw
                    || u64::try_from(first.findings.len()).unwrap_or(u64::MAX)
                        != case.expected_findings
                {
                    return Err(AdapterError::Verification(format!(
                        "determinism or raw preservation failed for {}",
                        case.id
                    )));
                }
                summary.valid_reports += 1;
                summary.valid_findings += case.expected_findings;
                summary.deterministic_repeats += 1;
                summary.unavailable_evidence_checks += first
                    .findings
                    .iter()
                    .filter(|finding| finding.evidence.all_unavailable())
                    .count() as u64;
                let projection = first.public_projection();
                let projection_value = serde_json::to_value(&projection)
                    .map_err(|_| AdapterError::Verification("serialization failed".to_owned()))?;
                projection_validator
                    .validate(&projection_value)
                    .map_err(|error| AdapterError::Verification(error.to_string()))?;
                let public = serde_json::to_string(&projection)
                    .map_err(|_| AdapterError::Verification("serialization failed".to_owned()))?;
                if public.contains("SECRET_CONFORMANCE_SOURCE_TEXT") {
                    return Err(AdapterError::Verification(
                        "source text escaped the raw artifact".to_owned(),
                    ));
                }
            }
            "partial" => {
                if !matches!(first, Err(AdapterError::InternallyErrored)) {
                    return Err(AdapterError::Verification(format!(
                        "{} did not fail as partial",
                        case.id
                    )));
                }
                summary.partial_rejections += 1;
            }
            "malformed" => {
                if first.is_ok() || matches!(first, Err(AdapterError::InternallyErrored)) {
                    return Err(AdapterError::Verification(format!(
                        "{} did not fail closed",
                        case.id
                    )));
                }
                summary.malformed_rejections += 1;
            }
            _ => {
                return Err(AdapterError::Verification(format!(
                    "unknown expected state for {}",
                    case.id
                )));
            }
        }
    }
    let process_index: ProcessIndex = parse(
        &read(root, "phase17/fixtures/conformance/process-cases.json")?,
        "process conformance index",
    )?;
    if process_index.schema_version != "secure-bench-phase17-process-conformance-v1" {
        return Err(AdapterError::Verification(
            "unsupported process fixture index".to_owned(),
        ));
    }
    for case in process_index.cases {
        let raw = read(root, &case.report)?;
        let adapted = adapt_report(&case.id, &raw, &fixture_root, &manifest);
        let termination = match case.termination.as_str() {
            "exited" => ProcessTermination::Exited(case.exit_code.ok_or_else(|| {
                AdapterError::Verification(format!("{} has no exit code", case.id))
            })?),
            "timeout" if case.exit_code.is_none() => ProcessTermination::Timeout,
            _ => {
                return Err(AdapterError::Verification(format!(
                    "{} has invalid termination evidence",
                    case.id
                )));
            }
        };
        let actual = adjudicate_process(
            termination,
            report_assessment(&adapted),
            &manifest.exit_semantics,
        );
        if actual != case.expected {
            return Err(AdapterError::Verification(format!(
                "{} process decision drifted",
                case.id
            )));
        }
        summary.process_policy_checks += 1;
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::{AdapterError, adapt_report, report_assessment, verify_repository};
    use secure_bench_scanner_protocol::{
        Availability, ProcessDecision, ProcessTermination, ReportAssessment, ScannerManifest,
        adjudicate_process,
    };
    use std::fs;
    use std::path::{Path, PathBuf};

    fn root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap_or_else(|_| PathBuf::from("../.."))
    }

    fn manifest(root: &Path) -> Result<ScannerManifest, AdapterError> {
        let bytes = fs::read(root.join("phase17/manifests/opengrep-v1.22.0-conformance.json"))
            .map_err(|error| AdapterError::Verification(error.to_string()))?;
        serde_json::from_slice(&bytes)
            .map_err(|error| AdapterError::Verification(error.to_string()))
    }

    #[test]
    fn disclosed_repository_vectors_verify_offline() -> Result<(), AdapterError> {
        let summary = verify_repository(&root())?;
        assert_eq!(summary.valid_reports, 3);
        assert_eq!(summary.valid_findings, 3);
        assert_eq!(summary.malformed_rejections, 6);
        assert_eq!(summary.partial_rejections, 1);
        assert_eq!(summary.deterministic_repeats, 3);
        assert_eq!(summary.raw_integrity_checks, 10);
        assert_eq!(summary.unavailable_evidence_checks, 3);
        assert_eq!(summary.process_policy_checks, 3);
        Ok(())
    }

    #[test]
    fn supported_fields_are_exact_and_evidence_stays_unavailable() -> Result<(), AdapterError> {
        let repository = root();
        let manifest = manifest(&repository)?;
        let raw = fs::read(repository.join("phase17/fixtures/conformance/reports/finding.json"))
            .map_err(|error| AdapterError::Verification(error.to_string()))?;
        let report = adapt_report(
            "finding-fields",
            &raw,
            &repository.join("phase17/fixtures/conformance/workspace"),
            &manifest,
        )?;
        assert_eq!(report.raw_artifact.bytes(), raw);
        let finding = &report.findings[0];
        assert_eq!(finding.rule_id, "secure-bench.phase17.eval-call");
        assert_eq!(finding.primary_location.path, "src/app.js");
        assert_eq!(
            (
                finding.primary_location.start_line,
                finding.primary_location.start_column,
                finding.primary_location.end_line,
                finding.primary_location.end_column,
            ),
            (1, 1, 1, 12)
        );
        assert!(matches!(
            &finding.scanner_fingerprint,
            Availability::Available { value } if value == "opengrep-conformance-fingerprint"
        ));
        assert_eq!(
            finding.rule_metadata.get("cwe"),
            Some(&serde_json::Value::String("CWE-95".to_owned()))
        );
        assert!(finding.evidence.all_unavailable());
        Ok(())
    }

    #[test]
    fn duplicate_projection_is_retained_and_linked() -> Result<(), AdapterError> {
        let repository = root();
        let manifest = manifest(&repository)?;
        let raw = fs::read(repository.join("phase17/fixtures/conformance/reports/duplicate.json"))
            .map_err(|error| AdapterError::Verification(error.to_string()))?;
        let report = adapt_report(
            "duplicate-fields",
            &raw,
            &repository.join("phase17/fixtures/conformance/workspace"),
            &manifest,
        )?;
        assert_eq!(report.findings.len(), 2);
        assert_eq!(
            report.findings[1].duplicate_of.as_deref(),
            Some(report.findings[0].finding_id.as_str())
        );
        assert_eq!(
            report.findings[0].projection_fingerprint,
            report.findings[1].projection_fingerprint
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn symlink_sources_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;

        let repository = root();
        let manifest = manifest(&repository)?;
        let temp = tempfile::tempdir()?;
        fs::write(temp.path().join("real.js"), b"eval(input);\n")?;
        symlink(temp.path().join("real.js"), temp.path().join("link.js"))?;
        let raw = br#"{"version":"1.22.0","results":[{"check_id":"secure-bench.phase17.eval-call","path":"link.js","start":{"line":1,"col":1,"offset":0},"end":{"line":1,"col":12,"offset":11},"extra":{"message":"x","severity":"ERROR","metadata":{},"fingerprint":"x"}}],"errors":[]}"#;
        assert!(adapt_report("symlink", raw, temp.path(), &manifest).is_err());
        Ok(())
    }

    #[test]
    fn nonzero_timeout_and_partial_process_cases_remain_separate() -> Result<(), AdapterError> {
        let repository = root();
        let manifest = manifest(&repository)?;
        let raw = fs::read(repository.join("phase17/fixtures/conformance/reports/finding.json"))
            .map_err(|error| AdapterError::Verification(error.to_string()))?;
        let adapted = adapt_report(
            "finding",
            &raw,
            &repository.join("phase17/fixtures/conformance/workspace"),
            &manifest,
        );
        assert_eq!(
            report_assessment(&adapted),
            ReportAssessment::Valid { findings: 1 }
        );
        assert_eq!(
            adjudicate_process(
                ProcessTermination::Exited(7),
                report_assessment(&adapted),
                &manifest.exit_semantics,
            ),
            ProcessDecision::PolicyExitWithValidFindingsReport
        );
        assert_eq!(
            adjudicate_process(
                ProcessTermination::Timeout,
                report_assessment(&adapted),
                &manifest.exit_semantics,
            ),
            ProcessDecision::Timeout
        );
        Ok(())
    }
}
