//! Conservative Semgrep CE JSON adapter for disclosed Phase 18 conformance fixtures.
//!
//! The adapter has no process-launching API. It captures raw bytes before parsing, rejects unsafe
//! paths and incomplete output, preserves supported Semgrep CE fields, and marks unsupported
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
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::{Component, Path};
use thiserror::Error;

/// Raw Semgrep CE JSON profile accepted by this adapter.
pub const RAW_FORMAT: &str = "semgrep-json-v1";
/// Stable adapter identity.
pub const ADAPTER_ID: &str = "secure-bench-semgrep-json";
/// Adapter semantic version.
pub const ADAPTER_VERSION: &str = "1.0.0";
/// Stable explanation for Evidence Contract v2 fields absent from Semgrep CE JSON.
pub const UNSUPPORTED_EVIDENCE_REASON: &str =
    "unavailable: semgrep-json-v1 does not declare this Evidence Contract v2 field";

/// Adapter or offline verification failure.
#[derive(Debug, Error)]
pub enum AdapterError {
    /// Manifest does not select this exact adapter profile.
    #[error("manifest/adapter mismatch: {0}")]
    Manifest(String),
    /// Raw bytes exceed the manifest boundary.
    #[error("raw Semgrep CE output exceeds the declared byte limit")]
    ReportTooLarge,
    /// JSON syntax or required Semgrep CE envelope fields are malformed.
    #[error("malformed Semgrep CE report: {0}")]
    Malformed(String),
    /// Semgrep CE declared scan errors, skipped rules, or partial completion.
    #[error("Semgrep CE report is internally errored or partial")]
    InternallyErrored,
    /// Output requested or used an engine outside Semgrep CE.
    #[error("Semgrep output is not Community Edition OSS output")]
    UnsupportedEngine,
    /// A result refers to a rule outside the pinned ruleset.
    #[error("unknown Semgrep CE rule `{0}`")]
    UnknownRule(String),
    /// A result path is absolute, traversing, ambiguous, or a symlink.
    #[error("unsafe Semgrep CE result path `{0}`")]
    UnsafePath(String),
    /// A result points to a missing or non-regular disclosed fixture file.
    #[error("Semgrep CE result path is not a regular fixture file: `{0}`")]
    MissingSource(String),
    /// A reported source span is empty, reversed, zero-based, or outside the file.
    #[error("invalid Semgrep CE span for `{0}`")]
    InvalidSpan(String),
    /// Scanner-neutral protocol validation failed.
    #[error("scanner protocol rejected Semgrep CE output: {0}")]
    Protocol(String),
    /// Repository fixture, schema, or provenance input failed.
    #[error("Phase 18 verification failed: {0}")]
    Verification(String),
    /// Filesystem operation failed.
    #[error("Phase 18 filesystem operation failed for `{path}`: {detail}")]
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
    skipped_rules: Vec<Value>,
    paths: RawPaths,
    engine_requested: String,
}

#[derive(Debug, Deserialize)]
struct RawPaths {
    scanned: Vec<String>,
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
    engine_kind: String,
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

    /// Semgrep CE JSON has no generic-protocol sanitizer slot or trustworthy sanitizer evidence.
    #[must_use]
    pub const fn sanitizers_unavailable(&self) -> bool {
        true
    }
}

/// One finding containing only fields supported by Semgrep CE JSON.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdaptedFinding {
    /// Stable ID assigned after neutral projection.
    pub finding_id: String,
    /// Fingerprint of the generic projected identity key.
    pub projection_fingerprint: String,
    /// First ID with the same projected key, if this is a duplicate.
    pub duplicate_of: Option<String>,
    /// Exact Semgrep CE rule ID.
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
    /// Raw Semgrep CE version string.
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
        || Availability::unavailable(format!("unavailable: Semgrep CE omitted {field}")),
        |candidate| {
            if candidate.trim().is_empty() {
                Availability::unavailable(format!("unavailable: Semgrep CE emitted empty {field}"))
            } else {
                Availability::available(candidate)
            }
        },
    )
}

fn fingerprint(value: Option<String>) -> Availability<String> {
    match value {
        Some(candidate) if candidate == "requires login" => Availability::unavailable(
            "unavailable: Semgrep CE emitted the login-gated fingerprint placeholder",
        ),
        candidate => nonempty(candidate, "fingerprint"),
    }
}

fn validate_manifest(manifest: &ScannerManifest) -> Result<(), AdapterError> {
    manifest
        .validate()
        .map_err(|error| AdapterError::Manifest(error.to_string()))?;
    if manifest.adapter.adapter_id != ADAPTER_ID
        || manifest.adapter.adapter_version != ADAPTER_VERSION
        || manifest.adapter.raw_output_format != RAW_FORMAT
        || manifest.scanner.id != "semgrep"
    {
        return Err(AdapterError::Manifest(
            "manifest does not select the pinned Semgrep CE JSON adapter".to_owned(),
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
    let coordinate_offset = |position: RawPosition| -> Option<u64> {
        let target_line = usize::try_from(position.line).ok()?;
        let target_column = usize::try_from(position.col).ok()?;
        let mut line = 1_usize;
        let mut line_start = 0_usize;
        for (index, byte) in file.iter().enumerate() {
            if line == target_line {
                let line_end = file[line_start..]
                    .iter()
                    .position(|candidate| *candidate == b'\n')
                    .map_or(file.len(), |relative| line_start + relative);
                let offset = line_start.checked_add(target_column.checked_sub(1)?)?;
                return (offset <= line_end)
                    .then(|| u64::try_from(offset).ok())
                    .flatten();
            }
            if *byte == b'\n' {
                line += 1;
                line_start = index + 1;
            }
        }
        if line == target_line {
            let offset = line_start.checked_add(target_column.checked_sub(1)?)?;
            return (offset <= file.len())
                .then(|| u64::try_from(offset).ok())
                .flatten();
        }
        None
    };
    let expected_start =
        coordinate_offset(start).ok_or_else(|| AdapterError::InvalidSpan(path.clone()))?;
    let expected_end =
        coordinate_offset(end).ok_or_else(|| AdapterError::InvalidSpan(path.clone()))?;
    match (start.offset, end.offset) {
        (Some(start_offset), Some(end_offset)) => {
            if start_offset >= end_offset
                || start_offset != expected_start
                || end_offset != expected_end
            {
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
            || Availability::unavailable("unavailable: Semgrep CE omitted start offset"),
            Availability::available,
        ),
        end_offset: end.offset.map_or_else(
            || Availability::unavailable("unavailable: Semgrep CE omitted end offset"),
            Availability::available,
        ),
    })
}

/// Adapts one complete Semgrep CE JSON report without consulting expectations or score data.
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
    if raw.engine_requested != "OSS"
        || raw
            .results
            .iter()
            .any(|result| result.extra.engine_kind != "OSS")
    {
        return Err(AdapterError::UnsupportedEngine);
    }
    if !raw.errors.is_empty() || !raw.skipped_rules.is_empty() {
        return Err(AdapterError::InternallyErrored);
    }
    let mut scanned = BTreeSet::new();
    for path in raw.paths.scanned {
        let (relative, _) = validate_path(fixture_root, &path)?;
        if !scanned.insert(relative) {
            return Err(AdapterError::Malformed(
                "duplicate scanned-path evidence".to_owned(),
            ));
        }
    }
    let mut pending = Vec::with_capacity(raw.results.len());
    let mut keys = Vec::with_capacity(raw.results.len());
    for result in raw.results {
        if !manifest.ruleset.rule_ids.contains(&result.check_id) {
            return Err(AdapterError::UnknownRule(result.check_id));
        }
        let (path, file) = validate_path(fixture_root, &result.path)?;
        if !scanned.contains(&path) {
            return Err(AdapterError::Malformed(
                "result path was absent from paths.scanned".to_owned(),
            ));
        }
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
            scanner_fingerprint: fingerprint(result.extra.fingerprint),
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

/// Validates all committed Phase 18 schemas, provenance, and disclosed conformance vectors.
///
/// # Errors
///
/// Returns an error for any schema, hash, projection, privacy, or determinism drift.
pub fn verify_repository(root: &Path) -> Result<VerificationSummary, AdapterError> {
    let manifest_bytes = read(root, "phase18/manifests/semgrep-v1.170.0-conformance.json")?;
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
        &read(root, "phase18/provenance/semgrep-v1.170.0.json")?,
        "Semgrep CE provenance",
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
            "Semgrep CE provenance does not bind the manifest".to_owned(),
        ));
    }
    let lock: Value = parse(
        &read(
            root,
            "phase18/provenance/semgrep-python314-linux-x86_64-lock.json",
        )?,
        "Semgrep wheel lock",
    )?;
    let packages = lock
        .get("packages")
        .and_then(Value::as_array)
        .ok_or_else(|| AdapterError::Verification("wheel lock has no package array".to_owned()))?;
    if lock.get("package_count").and_then(Value::as_u64)
        != Some(u64::try_from(packages.len()).unwrap_or(u64::MAX))
        || packages.len() != 66
    {
        return Err(AdapterError::Verification(
            "wheel lock package count drift".to_owned(),
        ));
    }
    let mut closure = String::new();
    let mut semgrep_bound = false;
    for package in packages {
        let field = |name: &str| {
            package.get(name).and_then(Value::as_str).ok_or_else(|| {
                AdapterError::Verification(format!("wheel lock package omits {name}"))
            })
        };
        let name = field("name")?;
        let version = field("version")?;
        let digest = field("sha256")?;
        let filename = field("filename")?;
        for required in [
            "artifact_url",
            "index_url",
            "source_url",
            "license_declared",
        ] {
            if field(required)?.trim().is_empty() {
                return Err(AdapterError::Verification(format!(
                    "wheel lock package has empty {required}"
                )));
            }
        }
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(AdapterError::Verification(
                "wheel lock contains an invalid SHA-256".to_owned(),
            ));
        }
        writeln!(&mut closure, "{name}=={version} {digest} {filename}").map_err(|_| {
            AdapterError::Verification("wheel closure serialization failed".to_owned())
        })?;
        if name.eq_ignore_ascii_case("semgrep") {
            semgrep_bound = version == manifest.scanner.version
                && digest == manifest.artifact.sha256
                && package.get("attestation_url").and_then(Value::as_str)
                    == Some(manifest.artifact.verification.signature_url.as_str());
        }
    }
    if !semgrep_bound
        || lock.get("closure_sha256").and_then(Value::as_str)
            != Some(sha256(closure.trim_end().as_bytes()).as_str())
    {
        return Err(AdapterError::Verification(
            "wheel closure digest or Semgrep binding drift".to_owned(),
        ));
    }
    let execution_policy: Value = parse(
        &read(root, "phase18/policies/execution-boundary-v1.json")?,
        "execution boundary",
    )?;
    let required_arguments = execution_policy
        .get("required_cli_arguments")
        .and_then(Value::as_array)
        .ok_or_else(|| AdapterError::Verification("execution policy has no CLI list".to_owned()))?;
    if required_arguments.iter().any(|argument| {
        argument
            .as_str()
            .is_none_or(|value| !manifest.command_template.iter().any(|item| item == value))
    }) {
        return Err(AdapterError::Verification(
            "manifest omits a required offline/metrics CLI control".to_owned(),
        ));
    }
    let forbidden_arguments = execution_policy
        .get("forbidden_arguments")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            AdapterError::Verification("execution policy has no forbidden CLI list".to_owned())
        })?;
    if forbidden_arguments.iter().any(|argument| {
        argument
            .as_str()
            .is_some_and(|value| manifest.command_template.iter().any(|item| item == value))
    }) {
        return Err(AdapterError::Verification(
            "manifest selects forbidden network or proprietary functionality".to_owned(),
        ));
    }
    let index: FixtureIndex = parse(
        &read(root, "phase18/fixtures/conformance/index.json")?,
        "fixture index",
    )?;
    if index.schema_version != "secure-bench-phase18-conformance-index-v1" {
        return Err(AdapterError::Verification(
            "unsupported fixture index".to_owned(),
        ));
    }
    let fixture_root = root.join("phase18/fixtures/conformance/workspace");
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
                if public.contains("DISCLOSED_PHASE18_CONFORMANCE_SOURCE") {
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
        &read(root, "phase18/fixtures/conformance/process-cases.json")?,
        "process conformance index",
    )?;
    if process_index.schema_version != "secure-bench-phase18-process-conformance-v1" {
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
        ProcessDecision, ProcessTermination, ReportAssessment, ScannerManifest, adjudicate_process,
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
        let bytes = fs::read(root.join("phase18/manifests/semgrep-v1.170.0-conformance.json"))
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
        assert_eq!(summary.process_policy_checks, 4);
        Ok(())
    }

    #[test]
    fn supported_fields_are_exact_and_evidence_stays_unavailable() -> Result<(), AdapterError> {
        let repository = root();
        let manifest = manifest(&repository)?;
        let raw = fs::read(repository.join("phase18/fixtures/conformance/reports/finding.json"))
            .map_err(|error| AdapterError::Verification(error.to_string()))?;
        let report = adapt_report(
            "finding-fields",
            &raw,
            &repository.join("phase18/fixtures/conformance/workspace"),
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
        assert!(finding.scanner_fingerprint.is_unavailable());
        assert_eq!(
            finding.rule_metadata.get("purpose"),
            Some(&serde_json::Value::String(
                "adapter-conformance-only".to_owned()
            ))
        );
        assert!(finding.evidence.all_unavailable());
        assert!(finding.evidence.sanitizers_unavailable());
        Ok(())
    }

    #[test]
    fn duplicate_projection_is_retained_and_linked() -> Result<(), AdapterError> {
        let repository = root();
        let manifest = manifest(&repository)?;
        let raw = fs::read(repository.join("phase18/fixtures/conformance/reports/duplicate.json"))
            .map_err(|error| AdapterError::Verification(error.to_string()))?;
        let report = adapt_report(
            "duplicate-fields",
            &raw,
            &repository.join("phase18/fixtures/conformance/workspace"),
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
        let raw = br#"{"version":"1.170.0","results":[{"check_id":"secure-bench.phase17.eval-call","path":"link.js","start":{"line":1,"col":1,"offset":0},"end":{"line":1,"col":12,"offset":11},"extra":{"message":"x","severity":"ERROR","metadata":{},"fingerprint":"x","engine_kind":"OSS"}}],"errors":[],"paths":{"scanned":["link.js"]},"engine_requested":"OSS","skipped_rules":[]}"#;
        assert!(adapt_report("symlink", raw, temp.path(), &manifest).is_err());
        Ok(())
    }

    #[test]
    fn nonzero_timeout_and_partial_process_cases_remain_separate() -> Result<(), AdapterError> {
        let repository = root();
        let manifest = manifest(&repository)?;
        let raw = fs::read(repository.join("phase18/fixtures/conformance/reports/finding.json"))
            .map_err(|error| AdapterError::Verification(error.to_string()))?;
        let adapted = adapt_report(
            "finding",
            &raw,
            &repository.join("phase18/fixtures/conformance/workspace"),
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
