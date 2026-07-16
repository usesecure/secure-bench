//! Strict, scoring-blind adapters for committed mock reports.

use crate::model::{
    Confidence, EvidenceHop, FindingProvenance, NormalizedFinding, ReportFormat,
    ReportedTaxonomyMetadata, Severity, SourceLocation,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::{Component, Path};
use thiserror::Error;

const MAX_REPORT_BYTES: usize = 10 * 1024 * 1024;

/// A report adapter may parse and normalize, but it never receives expectations or scores.
pub trait Adapter: Send + Sync {
    /// Stable public adapter identifier.
    fn id(&self) -> &'static str;

    /// Converts an untrusted report into the neutral finding model.
    ///
    /// # Errors
    ///
    /// Returns a bounded, sanitized error for malformed, unsupported, or privacy-unsafe input.
    fn normalize(
        &self,
        report: &[u8],
        report_fingerprint: &str,
    ) -> Result<Vec<NormalizedFinding>, AdapterError> {
        self.normalize_scoped(AdapterInput {
            report,
            report_fingerprint,
            case_id: None,
            path_prefix: None,
        })
    }

    /// Converts a report produced for one neutral case scope.
    ///
    /// Scope supplies case identity and a repository-relative path prefix, but never expected
    /// findings, categories, invariants, or scoring data.
    ///
    /// # Errors
    ///
    /// Returns a bounded, sanitized error for malformed, unsupported, or inconsistent input.
    fn normalize_scoped(
        &self,
        input: AdapterInput<'_>,
    ) -> Result<Vec<NormalizedFinding>, AdapterError>;
}

/// Neutral execution scope for a report produced from one isolated case.
#[derive(Clone, Copy, Debug)]
pub struct AdapterInput<'a> {
    /// Untrusted report bytes.
    pub report: &'a [u8],
    /// SHA-256 of the raw report.
    pub report_fingerprint: &'a str,
    /// Case identifier assigned before scanner execution.
    pub case_id: Option<&'a str>,
    /// Repository-relative prefix for paths emitted relative to the isolated case.
    pub path_prefix: Option<&'a str>,
}

/// Adapter failures are kept distinct from successful empty reports.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AdapterError {
    /// Report exceeds the adapter input bound.
    #[error("report exceeds the 10 MiB adapter input limit")]
    ReportTooLarge,
    /// Input is not valid for the selected format.
    #[error("report is not valid {format}: {detail}")]
    InvalidReport {
        /// Selected format.
        format: &'static str,
        /// Sanitized parser detail.
        detail: String,
    },
    /// Version is valid JSON but not a supported contract version.
    #[error("unsupported report schema version: {0}")]
    UnsupportedVersion(String),
    /// Location would disclose a host path or escape the fixture root.
    #[error("report contains an unsafe or non-relative source path")]
    UnsafePath,
    /// The registry deliberately has no adapter for this format.
    #[error("the selected report format is unsupported")]
    UnsupportedFormat,
}

/// Neutral registry with no tool-name dispatch or tool-specific matching behavior.
#[derive(Clone, Copy, Debug, Default)]
pub struct AdapterRegistry;

impl AdapterRegistry {
    /// Selects an adapter solely from the declared public report format.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterError::UnsupportedFormat`] for unsupported formats.
    pub fn adapter(format: ReportFormat) -> Result<Box<dyn Adapter>, AdapterError> {
        match format {
            ReportFormat::SecureJsonV1 => Ok(Box::new(SecureJsonAdapter)),
            ReportFormat::Sarif210 => Ok(Box::new(SarifAdapter)),
            ReportFormat::Unsupported => Err(AdapterError::UnsupportedFormat),
        }
    }
}

/// Adapter for the public `secure-json-v1` mock contract.
#[derive(Clone, Copy, Debug, Default)]
pub struct SecureJsonAdapter;

impl Adapter for SecureJsonAdapter {
    fn id(&self) -> &'static str {
        "secure-json-v1"
    }

    fn normalize_scoped(
        &self,
        input: AdapterInput<'_>,
    ) -> Result<Vec<NormalizedFinding>, AdapterError> {
        check_size(input.report)?;
        let native: NativeReport =
            serde_json::from_slice(input.report).map_err(|error| AdapterError::InvalidReport {
                format: self.id(),
                detail: parser_detail(&error),
            })?;
        if native.schema_version != "secure-json-v1" {
            return Err(AdapterError::UnsupportedVersion(sanitized_label(
                &native.schema_version,
            )));
        }
        if native.scan.as_ref().is_some_and(|scan| !scan.complete) || !native.errors.is_empty() {
            return Err(AdapterError::InvalidReport {
                format: self.id(),
                detail: "report declares an incomplete scan or scanner errors".to_owned(),
            });
        }

        let prefix = input.path_prefix.map(normalize_path).transpose()?;
        native
            .findings
            .into_iter()
            .enumerate()
            .map(|(index, finding)| {
                let source = normalize_native_location(&finding.source)?;
                let sink = normalize_native_location(&finding.sink)?;
                let evidence_path = finding
                    .evidence_path
                    .into_iter()
                    .map(|hop| {
                        Ok(EvidenceHop {
                            kind: canonical_token(&hop.kind),
                            location: normalize_native_location(&hop.location)?,
                        })
                    })
                    .collect::<Result<Vec<_>, AdapterError>>()?;
                let case_id = scoped_case_id(finding.case_id.as_deref(), input.case_id)?;
                let mut parts = FindingParts {
                    case_id,
                    native_rule_id: finding.rule_id,
                    taxonomy: finding.taxonomy,
                    category: finding.category,
                    invariant: finding.invariant,
                    severity: finding.severity,
                    confidence: finding.confidence,
                    source,
                    sink,
                    evidence_path,
                };
                apply_path_prefix(&mut parts, prefix.as_deref());
                build_finding(parts, self.id(), input.report_fingerprint, index)
            })
            .collect()
    }
}

/// Adapter for the SARIF 2.1.0 mock contract.
#[derive(Clone, Copy, Debug, Default)]
pub struct SarifAdapter;

impl Adapter for SarifAdapter {
    fn id(&self) -> &'static str {
        "sarif-2.1.0"
    }

    fn normalize_scoped(
        &self,
        input: AdapterInput<'_>,
    ) -> Result<Vec<NormalizedFinding>, AdapterError> {
        check_size(input.report)?;
        let sarif: SarifLog =
            serde_json::from_slice(input.report).map_err(|error| AdapterError::InvalidReport {
                format: self.id(),
                detail: parser_detail(&error),
            })?;
        if sarif.version != "2.1.0" {
            return Err(AdapterError::UnsupportedVersion(sanitized_label(
                &sarif.version,
            )));
        }

        let prefix = input.path_prefix.map(normalize_path).transpose()?;
        let mut normalized = Vec::new();
        for run in sarif.runs {
            for result in run.results {
                let raw_index = normalized.len();
                let finding = normalize_sarif_result(
                    result,
                    self.id(),
                    input.report_fingerprint,
                    raw_index,
                    input.case_id,
                    prefix.as_deref(),
                )?;
                normalized.push(finding);
            }
        }
        Ok(normalized)
    }
}

#[derive(Debug, Deserialize)]
struct NativeReport {
    schema_version: String,
    findings: Vec<NativeFinding>,
    #[serde(default)]
    scan: Option<NativeScan>,
    #[serde(default)]
    errors: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct NativeFinding {
    #[serde(default)]
    case_id: Option<String>,
    rule_id: String,
    #[serde(default)]
    taxonomy: Option<ReportedTaxonomyMetadata>,
    category: String,
    invariant: String,
    severity: Severity,
    confidence: Confidence,
    source: NativeLocation,
    sink: NativeLocation,
    evidence_path: Vec<NativeHop>,
    #[allow(dead_code)]
    message: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NativeLocation {
    path: String,
    #[serde(default)]
    line: Option<u32>,
    #[serde(default)]
    column: Option<u32>,
    #[serde(default)]
    span: Option<NativeSpan>,
}

#[derive(Debug, Deserialize)]
struct NativeHop {
    kind: String,
    location: NativeLocation,
}

#[derive(Debug, Deserialize)]
struct NativeSpan {
    start_line: u32,
    #[serde(default)]
    start_column: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct NativeScan {
    complete: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SarifLog {
    version: String,
    runs: Vec<SarifRun>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SarifRun {
    #[serde(default)]
    results: Vec<SarifResult>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SarifResult {
    rule_id: String,
    #[serde(default)]
    level: Option<String>,
    #[serde(default)]
    locations: Vec<SarifLocation>,
    #[serde(default)]
    code_flows: Vec<SarifCodeFlow>,
    properties: SarifProperties,
}

#[derive(Debug, Deserialize)]
struct SarifProperties {
    #[serde(default)]
    case_id: Option<String>,
    #[serde(default)]
    taxonomy: Option<ReportedTaxonomyMetadata>,
    category: String,
    invariant: String,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    confidence: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SarifLocation {
    physical_location: SarifPhysicalLocation,
    #[serde(default)]
    properties: SarifLocationProperties,
}

#[derive(Debug, Default, Deserialize)]
struct SarifLocationProperties {
    #[serde(default = "default_hop_kind")]
    kind: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SarifPhysicalLocation {
    artifact_location: SarifArtifactLocation,
    region: SarifRegion,
}

#[derive(Debug, Deserialize)]
struct SarifArtifactLocation {
    uri: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SarifRegion {
    start_line: u32,
    #[serde(default)]
    start_column: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SarifCodeFlow {
    #[serde(default)]
    thread_flows: Vec<SarifThreadFlow>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SarifThreadFlow {
    #[serde(default)]
    locations: Vec<SarifThreadFlowLocation>,
}

#[derive(Debug, Deserialize)]
struct SarifThreadFlowLocation {
    location: SarifLocation,
}

fn default_hop_kind() -> String {
    "intermediate".to_owned()
}

fn normalize_sarif_result(
    result: SarifResult,
    adapter: &str,
    report_fingerprint: &str,
    raw_index: usize,
    scoped_case: Option<&str>,
    path_prefix: Option<&str>,
) -> Result<NormalizedFinding, AdapterError> {
    let mut evidence_path = result
        .code_flows
        .into_iter()
        .flat_map(|flow| flow.thread_flows)
        .flat_map(|flow| flow.locations)
        .map(|hop| {
            Ok(EvidenceHop {
                kind: canonical_token(&hop.location.properties.kind),
                location: normalize_sarif_location(&hop.location)?,
            })
        })
        .collect::<Result<Vec<_>, AdapterError>>()?;

    let fallback_locations = result
        .locations
        .into_iter()
        .map(|location| normalize_sarif_location(&location))
        .collect::<Result<Vec<_>, AdapterError>>()?;
    if evidence_path.is_empty() {
        evidence_path = fallback_locations
            .iter()
            .cloned()
            .enumerate()
            .map(|(index, location)| EvidenceHop {
                kind: if index == 0 {
                    "source".to_owned()
                } else {
                    "sink".to_owned()
                },
                location,
            })
            .collect();
    }

    let source = evidence_path
        .first()
        .map(|hop| hop.location.clone())
        .or_else(|| fallback_locations.first().cloned())
        .ok_or_else(|| AdapterError::InvalidReport {
            format: "sarif-2.1.0",
            detail: "result has no source location".to_owned(),
        })?;
    let sink = evidence_path
        .last()
        .map(|hop| hop.location.clone())
        .or_else(|| fallback_locations.last().cloned())
        .ok_or_else(|| AdapterError::InvalidReport {
            format: "sarif-2.1.0",
            detail: "result has no sink location".to_owned(),
        })?;

    let severity = parse_severity(
        result
            .properties
            .severity
            .as_deref()
            .or(result.level.as_deref())
            .unwrap_or("medium"),
    )?;
    let confidence = parse_confidence(result.properties.confidence.as_deref().unwrap_or("medium"))?;

    let mut parts = FindingParts {
        case_id: scoped_case_id(result.properties.case_id.as_deref(), scoped_case)?,
        native_rule_id: result.rule_id,
        taxonomy: result.properties.taxonomy,
        category: result.properties.category,
        invariant: result.properties.invariant,
        severity,
        confidence,
        source,
        sink,
        evidence_path,
    };
    apply_path_prefix(&mut parts, path_prefix);
    build_finding(parts, adapter, report_fingerprint, raw_index)
}

fn scoped_case_id(reported: Option<&str>, scoped: Option<&str>) -> Result<String, AdapterError> {
    match (reported, scoped) {
        (_, Some(scoped)) => canonical_identifier(scoped),
        (Some(reported), None) => canonical_identifier(reported),
        (None, None) => Err(AdapterError::InvalidReport {
            format: "normalized finding",
            detail: "finding has no case identifier or neutral execution scope".to_owned(),
        }),
    }
}

fn apply_path_prefix(finding: &mut FindingParts, prefix: Option<&str>) {
    let Some(prefix) = prefix else {
        return;
    };
    finding.source.path = format!("{prefix}/{}", finding.source.path);
    finding.sink.path = format!("{prefix}/{}", finding.sink.path);
    for hop in &mut finding.evidence_path {
        hop.location.path = format!("{prefix}/{}", hop.location.path);
    }
}

struct FindingParts {
    case_id: String,
    native_rule_id: String,
    taxonomy: Option<ReportedTaxonomyMetadata>,
    category: String,
    invariant: String,
    severity: Severity,
    confidence: Confidence,
    source: SourceLocation,
    sink: SourceLocation,
    evidence_path: Vec<EvidenceHop>,
}

fn build_finding(
    mut parts: FindingParts,
    adapter: &str,
    report_fingerprint: &str,
    raw_index: usize,
) -> Result<NormalizedFinding, AdapterError> {
    parts.case_id = canonical_identifier(&parts.case_id)?;
    parts.category = canonical_token(&parts.category);
    parts.invariant = canonical_token(&parts.invariant);
    if parts.category.is_empty() || parts.invariant.is_empty() {
        return Err(AdapterError::InvalidReport {
            format: "normalized finding",
            detail: "category and invariant must not be empty".to_owned(),
        });
    }

    let mut hasher = Sha256::new();
    hasher.update(parts.case_id.as_bytes());
    hasher.update([0]);
    hasher.update(parts.category.as_bytes());
    hasher.update([0]);
    hasher.update(parts.invariant.as_bytes());
    hasher.update([0]);
    if let Some(taxonomy) = &parts.taxonomy {
        hasher.update([1]);
        for value in [
            taxonomy.taxonomy_version.as_deref(),
            taxonomy.category_id.as_deref(),
            taxonomy.invariant_id.as_deref(),
        ] {
            if let Some(value) = value {
                hasher.update([1]);
                hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
                hasher.update(value.as_bytes());
            } else {
                hasher.update([0]);
            }
        }
    }
    hasher.update(parts.source.path.as_bytes());
    hasher.update(parts.source.line.to_be_bytes());
    hasher.update(parts.sink.path.as_bytes());
    hasher.update(parts.sink.line.to_be_bytes());
    for hop in &parts.evidence_path {
        hasher.update(hop.kind.as_bytes());
        hasher.update(hop.location.path.as_bytes());
        hasher.update(hop.location.line.to_be_bytes());
    }
    let digest = hex_digest(&hasher.finalize());
    let finding_id = format!("finding-{}-{raw_index:04}", &digest[..16]);

    Ok(NormalizedFinding {
        finding_id,
        case_id: parts.case_id,
        native_rule_id: sanitized_rule_id(&parts.native_rule_id),
        taxonomy: parts.taxonomy,
        category: parts.category,
        invariant: parts.invariant,
        severity: parts.severity,
        confidence: parts.confidence,
        source: parts.source,
        sink: parts.sink,
        evidence_path: parts.evidence_path,
        provenance: FindingProvenance {
            adapter: adapter.to_owned(),
            report_fingerprint: report_fingerprint.to_owned(),
            raw_index: u64::try_from(raw_index).unwrap_or(u64::MAX),
        },
    })
}

fn normalize_native_location(location: &NativeLocation) -> Result<SourceLocation, AdapterError> {
    let span_line = location.span.as_ref().map(|span| span.start_line);
    let span_column = location.span.as_ref().and_then(|span| span.start_column);
    if location
        .line
        .zip(span_line)
        .is_some_and(|(line, span_line)| line != span_line)
        || location
            .column
            .zip(span_column)
            .is_some_and(|(column, span_column)| column != span_column)
    {
        return Err(AdapterError::InvalidReport {
            format: "secure-json-v1",
            detail: "location and span start coordinates disagree".to_owned(),
        });
    }
    let line = location
        .line
        .or(span_line)
        .ok_or_else(|| AdapterError::InvalidReport {
            format: "secure-json-v1",
            detail: "location has no one-based start line".to_owned(),
        })?;
    Ok(SourceLocation {
        path: normalize_path(&location.path)?,
        line: validate_line(line)?,
        column: validate_column(location.column.or(span_column))?,
    })
}

fn normalize_sarif_location(location: &SarifLocation) -> Result<SourceLocation, AdapterError> {
    Ok(SourceLocation {
        path: normalize_path(&location.physical_location.artifact_location.uri)?,
        line: validate_line(location.physical_location.region.start_line)?,
        column: validate_column(location.physical_location.region.start_column)?,
    })
}

fn normalize_path(raw: &str) -> Result<String, AdapterError> {
    if raw.is_empty()
        || raw.contains('\0')
        || raw.contains('\\')
        || raw.contains(':')
        || raw.contains('%')
        || Path::new(raw).is_absolute()
    {
        return Err(AdapterError::UnsafePath);
    }
    let mut segments = Vec::new();
    for component in Path::new(raw).components() {
        match component {
            Component::Normal(segment) => segments.push(segment.to_string_lossy().into_owned()),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(AdapterError::UnsafePath);
            }
        }
    }
    if segments.is_empty() {
        return Err(AdapterError::UnsafePath);
    }
    Ok(segments.join("/"))
}

fn validate_line(line: u32) -> Result<u32, AdapterError> {
    if line == 0 {
        Err(AdapterError::InvalidReport {
            format: "normalized finding",
            detail: "line numbers must be one-based".to_owned(),
        })
    } else {
        Ok(line)
    }
}

fn validate_column(column: Option<u32>) -> Result<Option<u32>, AdapterError> {
    if column == Some(0) {
        Err(AdapterError::InvalidReport {
            format: "normalized finding",
            detail: "column numbers must be one-based".to_owned(),
        })
    } else {
        Ok(column)
    }
}

fn canonical_identifier(value: &str) -> Result<String, AdapterError> {
    let value = value.trim();
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(AdapterError::InvalidReport {
            format: "normalized finding",
            detail: "case identifiers must use ASCII letters, digits, dots, dashes, or underscores"
                .to_owned(),
        });
    }
    Ok(value.to_owned())
}

fn canonical_token(value: &str) -> String {
    value
        .trim()
        .to_ascii_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn sanitized_label(value: &str) -> String {
    let trimmed = value.trim();
    if !trimmed.is_empty()
        && trimmed.len() <= 64
        && trimmed
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        trimmed.to_owned()
    } else {
        "unrecognized".to_owned()
    }
}

fn sanitized_rule_id(value: &str) -> String {
    let trimmed = value.trim();
    if !trimmed.is_empty()
        && trimmed.len() <= 128
        && trimmed
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'/'))
    {
        trimmed.to_owned()
    } else {
        format!("rule-{}", &fingerprint(trimmed.as_bytes())[..16])
    }
}

fn parse_severity(value: &str) -> Result<Severity, AdapterError> {
    match canonical_token(value).as_str() {
        "note" | "none" | "info" | "informational" => Ok(Severity::Info),
        "low" => Ok(Severity::Low),
        "warning" | "medium" => Ok(Severity::Medium),
        "error" | "high" => Ok(Severity::High),
        "critical" => Ok(Severity::Critical),
        _ => Err(AdapterError::InvalidReport {
            format: "normalized finding",
            detail: "severity is not recognized".to_owned(),
        }),
    }
}

fn parse_confidence(value: &str) -> Result<Confidence, AdapterError> {
    match canonical_token(value).as_str() {
        "low" => Ok(Confidence::Low),
        "medium" => Ok(Confidence::Medium),
        "high" => Ok(Confidence::High),
        _ => Err(AdapterError::InvalidReport {
            format: "normalized finding",
            detail: "confidence is not recognized".to_owned(),
        }),
    }
}

fn check_size(report: &[u8]) -> Result<(), AdapterError> {
    if report.len() > MAX_REPORT_BYTES {
        Err(AdapterError::ReportTooLarge)
    } else {
        Ok(())
    }
}

fn parser_detail(error: &serde_json::Error) -> String {
    format!("JSON syntax or shape error at line {}", error.line())
}

/// Computes a lowercase SHA-256 fingerprint without retaining artifact contents.
#[must_use]
pub fn fingerprint(bytes: &[u8]) -> String {
    hex_digest(&Sha256::digest(bytes))
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
    fn rejects_absolute_and_traversal_paths() {
        assert_eq!(
            normalize_path("/home/user/project/app.ts"),
            Err(AdapterError::UnsafePath)
        );
        assert_eq!(
            normalize_path("src/../secret"),
            Err(AdapterError::UnsafePath)
        );
        assert_eq!(
            normalize_path("C:\\repo\\app.ts"),
            Err(AdapterError::UnsafePath)
        );
    }

    #[test]
    fn canonicalizes_safe_relative_paths() {
        assert_eq!(normalize_path("./src/app.ts"), Ok("src/app.ts".to_owned()));
    }

    #[test]
    fn hashes_rule_identifiers_that_could_embed_report_content() {
        let sanitized = sanitized_rule_id("source code: process.env.SECRET");
        assert!(sanitized.starts_with("rule-"));
        assert!(!sanitized.contains("SECRET"));
    }

    #[test]
    fn live_execution_scope_is_authoritative_for_case_identity() {
        assert_eq!(
            scoped_case_id(Some("native-project-label"), Some("phase1-001")),
            Ok("phase1-001".to_owned())
        );
    }

    #[test]
    fn accepts_public_span_locations_and_ignores_non_scoring_metadata() {
        let report = serde_json::to_vec(&serde_json::json!({
            "schema_version": "secure-json-v1",
            "document_type": "scan-report",
            "scan": {"complete": true},
            "errors": [],
            "inventory": {"files": 2},
            "findings": [{
                "rule_id": "PUBLIC1001",
                "title": "Public report finding",
                "category": "command-injection",
                "invariant": "command arguments must not be untrusted",
                "severity": "high",
                "confidence": "high",
                "source": {
                    "path": "src/entry.js",
                    "span": {"start_line": 4, "start_column": 16}
                },
                "sink": {
                    "path": "src/entry.js",
                    "span": {"start_line": 5, "start_column": 10}
                },
                "evidence_path": [{
                    "node_id": "node-1",
                    "kind": "source",
                    "location": {
                        "path": "src/entry.js",
                        "span": {"start_line": 4, "start_column": 16}
                    }
                }, {
                    "node_id": "node-2",
                    "kind": "sink",
                    "location": {
                        "path": "src/entry.js",
                        "span": {"start_line": 5, "start_column": 10}
                    }
                }]
            }]
        }))
        .unwrap_or_default();
        let findings = SecureJsonAdapter
            .normalize_scoped(AdapterInput {
                report: &report,
                report_fingerprint: &fingerprint(&report),
                case_id: Some("phase1-001"),
                path_prefix: Some("fixtures/corpus/case-001"),
            })
            .unwrap_or_default();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].source.line, 4);
        assert_eq!(findings[0].source.column, Some(16));
        assert_eq!(findings[0].sink.line, 5);
        assert_eq!(findings[0].case_id, "phase1-001");
    }

    #[test]
    fn rejects_public_reports_that_declare_incomplete_scans() {
        let report = br#"{
            "schema_version":"secure-json-v1",
            "scan":{"complete":false},
            "errors":[],
            "findings":[]
        }"#;
        assert!(
            SecureJsonAdapter
                .normalize(report, &fingerprint(report))
                .is_err()
        );
    }
}
