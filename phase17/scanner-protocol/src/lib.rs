//! Scanner-neutral, versioned protocol shared by Secure Bench adapters.
//!
//! This crate deliberately has no process-launching or scanner-specific code. Adapters project
//! only fields present in their raw format, then pass neutral identity keys to the shared ID
//! derivation. Process observations are adjudicated independently from finding adaptation.

#![allow(clippy::module_name_repetitions, clippy::struct_excessive_bools)]

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

/// Scanner manifest schema identifier.
pub const SCANNER_MANIFEST_SCHEMA: &str = "secure-bench-scanner-manifest-v1";
/// Scanner-neutral protocol version.
pub const PROTOCOL_VERSION: &str = "1.0.0";
/// Stable finding-ID algorithm version.
pub const FINDING_ID_VERSION: &str = "secure-bench-projected-finding-v1";

/// Protocol validation or projection error.
#[derive(Debug, Error)]
pub enum ProtocolError {
    /// A manifest is incomplete, inconsistent, or unsafe.
    #[error("invalid scanner manifest: {0}")]
    InvalidManifest(String),
    /// A caller supplied a non-portable scope or source path.
    #[error("unsafe portable path: {0}")]
    UnsafePath(String),
    /// Identity serialization failed.
    #[error("finding identity serialization failed")]
    Serialization,
}

/// A value is either explicitly supported or explicitly unavailable.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "availability", rename_all = "snake_case")]
pub enum Availability<T> {
    /// The adapter received and validated the value from raw output.
    Available {
        /// Preserved value.
        value: T,
    },
    /// The raw format did not support a trustworthy projection.
    Unavailable {
        /// Stable explanation; never a guessed replacement.
        reason: String,
    },
}

impl<T> Availability<T> {
    /// Constructs an available value.
    pub const fn available(value: T) -> Self {
        Self::Available { value }
    }

    /// Constructs an unavailable value.
    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self::Unavailable {
            reason: reason.into(),
        }
    }

    /// Returns whether the value is explicitly unavailable.
    #[must_use]
    pub const fn is_unavailable(&self) -> bool {
        matches!(self, Self::Unavailable { .. })
    }
}

/// Upstream scanner identity and licensing.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScannerIdentity {
    /// Stable lowercase scanner ID.
    pub id: String,
    /// Exact upstream version.
    pub version: String,
    /// Canonical public upstream repository.
    pub upstream_repository: String,
    /// SPDX license expression declared upstream.
    pub license: String,
}

/// One pinned executable or archive.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactIdentity {
    /// Official immutable download URL.
    pub url: String,
    /// Asset name.
    pub name: String,
    /// Target operating system.
    pub operating_system: String,
    /// Target architecture.
    pub architecture: String,
    /// Byte length published upstream.
    pub size_bytes: u64,
    /// Lowercase SHA-256 of downloaded bytes.
    pub sha256: String,
    /// Signature and provenance verification.
    pub verification: SignatureVerification,
}

/// Detached-signature and certificate provenance.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureVerification {
    /// Verification scheme.
    pub scheme: String,
    /// Official detached-signature URL.
    pub signature_url: String,
    /// SHA-256 of the encoded signature asset.
    pub signature_sha256: String,
    /// Official certificate URL.
    pub certificate_url: String,
    /// SHA-256 of the encoded certificate asset.
    pub certificate_sha256: String,
    /// OIDC certificate issuer.
    pub certificate_issuer: String,
    /// Exact certificate workflow identity.
    pub certificate_identity: String,
    /// Source revision bound into the certificate.
    pub source_revision: String,
    /// Human-auditable verification command template.
    pub verification_command: Vec<String>,
}

/// Exact ruleset identity used by one declared lane or conformance profile.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RulesetIdentity {
    /// Stable ruleset ID.
    pub id: String,
    /// Exact semantic version or immutable revision.
    pub version: String,
    /// Public origin or repository-relative disclosed origin.
    pub origin: String,
    /// SPDX license expression.
    pub license: String,
    /// SHA-256 of the exact rules bytes.
    pub sha256: String,
    /// Rules allowed in adapter output for this manifest.
    pub rule_ids: BTreeSet<String>,
}

/// Declared scanner capabilities; these are provenance claims, not observed scores.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredCapabilities {
    /// Declared languages.
    pub languages: BTreeSet<String>,
    /// Declared frameworks or generic framework capability.
    pub frameworks: BTreeSet<String>,
    /// Declared ability to connect findings across files.
    pub inter_file: bool,
    /// Declared interprocedural analysis.
    pub interprocedural: bool,
    /// Declared taint analysis.
    pub taint: bool,
    /// Scope note preventing capability claims from becoming benchmark results.
    pub qualification: String,
}

/// Fixed timeout and resource boundary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourcePolicy {
    /// Wall-clock timeout in milliseconds.
    pub timeout_ms: u64,
    /// Maximum accepted raw output bytes.
    pub max_output_bytes: u64,
    /// Maximum address-space declaration in MiB.
    pub memory_limit_mib: u64,
    /// Maximum process count.
    pub process_limit: u32,
    /// Whether network access is permitted during execution.
    pub network_allowed: bool,
    /// Whether execution uses a fresh copied fixture workspace.
    pub isolated_fixture_copy: bool,
}

/// Expected normal exit semantics for the exact command template.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExitSemantics {
    /// Normal exit codes representing a complete clean report.
    pub clean: BTreeSet<i32>,
    /// Normal exit codes representing a complete findings report.
    pub findings: BTreeSet<i32>,
    /// Everything else is a process failure unless timeout/signal evidence is stronger.
    pub all_other: String,
}

/// Raw format and adapter identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterIdentity {
    /// Raw report format.
    pub raw_output_format: String,
    /// Stable adapter ID.
    pub adapter_id: String,
    /// Exact adapter version.
    pub adapter_version: String,
}

/// Complete versioned scanner manifest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScannerManifest {
    /// JSON Schema identity.
    pub schema_version: String,
    /// Protocol semantic version.
    pub protocol_version: String,
    /// Scanner identity.
    pub scanner: ScannerIdentity,
    /// Exact binary/archive identity.
    pub artifact: ArtifactIdentity,
    /// Exact ruleset identity.
    pub ruleset: RulesetIdentity,
    /// Upstream-declared capabilities.
    pub capabilities: DeclaredCapabilities,
    /// Argument vector template; no shell expansion is permitted.
    pub command_template: Vec<String>,
    /// Resource policy.
    pub resources: ResourcePolicy,
    /// Process exit policy declaration.
    pub exit_semantics: ExitSemantics,
    /// Output and adapter versions.
    pub adapter: AdapterIdentity,
}

impl ScannerManifest {
    /// Performs scanner-neutral semantic validation after JSON Schema validation.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::InvalidManifest`] for an incomplete or unsafe declaration.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.schema_version != SCANNER_MANIFEST_SCHEMA
            || self.protocol_version != PROTOCOL_VERSION
        {
            return Err(ProtocolError::InvalidManifest(
                "unsupported schema or protocol version".to_owned(),
            ));
        }
        if self.scanner.id.is_empty()
            || !self
                .scanner
                .id
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            || self.scanner.version.is_empty()
        {
            return Err(ProtocolError::InvalidManifest(
                "scanner identity is not stable and portable".to_owned(),
            ));
        }
        for digest in [
            &self.artifact.sha256,
            &self.artifact.verification.signature_sha256,
            &self.artifact.verification.certificate_sha256,
            &self.ruleset.sha256,
        ] {
            validate_sha256(digest)?;
        }
        if self.ruleset.rule_ids.is_empty()
            || self.command_template.is_empty()
            || self.resources.timeout_ms == 0
            || self.resources.max_output_bytes == 0
            || self.resources.memory_limit_mib == 0
            || self.resources.process_limit == 0
            || self.resources.network_allowed
            || !self.resources.isolated_fixture_copy
        {
            return Err(ProtocolError::InvalidManifest(
                "rules, command, or fail-closed resource policy is incomplete".to_owned(),
            ));
        }
        let required = ["{binary}", "{ruleset}", "{fixture_root}", "{raw_output}"];
        if required.iter().any(|placeholder| {
            !self
                .command_template
                .iter()
                .any(|argument| argument.contains(placeholder))
        }) {
            return Err(ProtocolError::InvalidManifest(
                "command template omits a required placeholder".to_owned(),
            ));
        }
        if !self
            .exit_semantics
            .clean
            .is_disjoint(&self.exit_semantics.findings)
        {
            return Err(ProtocolError::InvalidManifest(
                "clean and findings exit codes overlap".to_owned(),
            ));
        }
        Ok(())
    }
}

fn validate_sha256(value: &str) -> Result<(), ProtocolError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(ProtocolError::InvalidManifest(
            "a SHA-256 value is not lowercase hexadecimal".to_owned(),
        ))
    }
}

/// One one-based, repository-relative source span.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceSpan {
    /// Portable relative path.
    pub path: String,
    /// Inclusive start line.
    pub start_line: u32,
    /// Inclusive start column.
    pub start_column: u32,
    /// Exclusive end line as emitted by the scanner.
    pub end_line: u32,
    /// Exclusive end column as emitted by the scanner.
    pub end_column: u32,
    /// Start byte offset when supplied by the scanner.
    pub start_offset: Availability<u64>,
    /// End byte offset when supplied by the scanner.
    pub end_offset: Availability<u64>,
}

/// Generic key supplied to the shared post-projection ID algorithm.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FindingIdentityKey {
    /// Adapter-supported rule identity.
    pub rule_id: String,
    /// Adapter-supported primary location.
    pub primary_location: SourceSpan,
}

/// IDs and duplicate relationship assigned by the generic protocol.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssignedFindingId {
    /// Stable per-occurrence finding ID.
    pub finding_id: String,
    /// Stable projected-key fingerprint.
    pub projection_fingerprint: String,
    /// First finding ID with the same projected key.
    pub duplicate_of: Option<String>,
}

/// Assigns deterministic IDs after projection, with no scanner-specific branches.
///
/// # Errors
///
/// Returns an error for a non-portable case scope or serialization failure.
pub fn assign_finding_ids(
    case_scope: &str,
    keys: &[FindingIdentityKey],
) -> Result<Vec<AssignedFindingId>, ProtocolError> {
    validate_scope(case_scope)?;
    let mut counts = BTreeMap::<String, u64>::new();
    let mut first_ids = BTreeMap::<String, String>::new();
    let mut assigned = Vec::with_capacity(keys.len());
    for key in keys {
        let canonical = serde_json::to_vec(key).map_err(|_| ProtocolError::Serialization)?;
        let projection_fingerprint = sha256(&canonical);
        let occurrence = counts.entry(projection_fingerprint.clone()).or_insert(0);
        let finding_id = sha256(
            format!("{FINDING_ID_VERSION}\0{case_scope}\0{projection_fingerprint}\0{occurrence}")
                .as_bytes(),
        );
        let duplicate_of = first_ids.get(&projection_fingerprint).cloned();
        first_ids
            .entry(projection_fingerprint.clone())
            .or_insert_with(|| finding_id.clone());
        *occurrence += 1;
        assigned.push(AssignedFindingId {
            finding_id,
            projection_fingerprint,
            duplicate_of,
        });
    }
    Ok(assigned)
}

fn validate_scope(value: &str) -> Result<(), ProtocolError> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ProtocolError::UnsafePath(
            "case scope is not a portable identifier".to_owned(),
        ));
    }
    Ok(())
}

/// Lexically normalizes a portable relative path and rejects traversal or platform ambiguity.
///
/// # Errors
///
/// Returns an error for absolute paths, traversal, prefixes, colons, or backslashes.
pub fn portable_relative(value: &str) -> Result<String, ProtocolError> {
    if value.is_empty() || value.contains(['\\', ':']) {
        return Err(ProtocolError::UnsafePath(value.to_owned()));
    }
    let mut normalized = PathBuf::new();
    for component in Path::new(value).components() {
        match component {
            Component::Normal(part) => normalized.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(ProtocolError::UnsafePath(value.to_owned()));
            }
        }
    }
    if normalized.as_os_str().is_empty() {
        return Err(ProtocolError::UnsafePath(value.to_owned()));
    }
    Ok(normalized.to_string_lossy().replace('\\', "/"))
}

/// SHA-256 helper shared by manifests, raw artifacts, and projected identities.
#[must_use]
pub fn sha256(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

/// Immutable raw scanner output retained byte-for-byte.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawArtifact {
    bytes: Vec<u8>,
    sha256: String,
}

impl RawArtifact {
    /// Captures raw output without decoding, rewriting, or canonicalization.
    #[must_use]
    pub fn capture(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
            sha256: sha256(bytes),
        }
    }

    /// Returns the untouched bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the digest of the untouched bytes.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.sha256
    }
}

/// Scanner adapter assessment consumed by the separate process policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReportAssessment {
    /// No output was produced.
    Missing,
    /// JSON, schema, path, span, rule, or adapter validation failed.
    Malformed,
    /// The scanner declared errors or a partial report.
    InternallyErrored,
    /// Complete adapter-valid output.
    Valid {
        /// Number of preserved normalized findings.
        findings: u64,
    },
}

/// Process termination evidence; finding adapters never manufacture this state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessTermination {
    /// Normal process exit.
    Exited(i32),
    /// Signal termination.
    Signaled,
    /// Wall-clock deadline termination.
    Timeout,
    /// Spawn, observation, or containment failure.
    ExecutionFailure,
}

/// Scanner-neutral process outcome.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessDecision {
    /// Complete empty report with a declared clean exit.
    CleanSuccessfulReport,
    /// Complete nonempty report with a declared findings exit.
    SuccessfulFindingsReport,
    /// Complete nonempty report with a non-clean normal exit.
    PolicyExitWithValidFindingsReport,
    /// Signal, execution failure, or invalid clean/report exit combination.
    GenuineCrash,
    /// Timeout dominates any partial bytes.
    Timeout,
    /// Missing report.
    MissingReport,
    /// Malformed adapter output.
    MalformedReport,
    /// Scanner-declared internal errors or partial report.
    InternallyErroredReport,
}

/// Adjudicates process state after, and independently from, adaptation.
#[must_use]
pub fn adjudicate_process(
    termination: ProcessTermination,
    assessment: ReportAssessment,
    semantics: &ExitSemantics,
) -> ProcessDecision {
    match termination {
        ProcessTermination::Timeout => ProcessDecision::Timeout,
        ProcessTermination::Signaled | ProcessTermination::ExecutionFailure => {
            ProcessDecision::GenuineCrash
        }
        ProcessTermination::Exited(code) => match assessment {
            ReportAssessment::Missing => ProcessDecision::MissingReport,
            ReportAssessment::Malformed => ProcessDecision::MalformedReport,
            ReportAssessment::InternallyErrored => ProcessDecision::InternallyErroredReport,
            ReportAssessment::Valid { findings: 0 } => {
                if semantics.clean.contains(&code) {
                    ProcessDecision::CleanSuccessfulReport
                } else {
                    ProcessDecision::GenuineCrash
                }
            }
            ReportAssessment::Valid { findings: _ } => {
                if semantics.findings.contains(&code) || semantics.clean.contains(&code) {
                    ProcessDecision::SuccessfulFindingsReport
                } else {
                    ProcessDecision::PolicyExitWithValidFindingsReport
                }
            }
        },
    }
}

/// Generic scanner metadata retained without interpreting vocabulary as benchmark truth.
pub type RuleMetadata = BTreeMap<String, Value>;

#[cfg(test)]
mod tests {
    use super::{
        Availability, ExitSemantics, FindingIdentityKey, ProcessDecision, ProcessTermination,
        ReportAssessment, SourceSpan, adjudicate_process, assign_finding_ids, portable_relative,
    };
    use std::collections::BTreeSet;

    fn key() -> FindingIdentityKey {
        FindingIdentityKey {
            rule_id: "public.rule".to_owned(),
            primary_location: SourceSpan {
                path: "src/app.js".to_owned(),
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 5,
                start_offset: Availability::available(0),
                end_offset: Availability::available(4),
            },
        }
    }

    #[test]
    fn shared_ids_are_stable_and_mark_duplicates() -> Result<(), Box<dyn std::error::Error>> {
        let ids = assign_finding_ids("case-1", &[key(), key()])?;
        assert_ne!(ids[0].finding_id, ids[1].finding_id);
        assert_eq!(ids[0].projection_fingerprint, ids[1].projection_fingerprint);
        assert_eq!(
            ids[1].duplicate_of.as_deref(),
            Some(ids[0].finding_id.as_str())
        );
        assert_eq!(ids, assign_finding_ids("case-1", &[key(), key()])?);
        Ok(())
    }

    #[test]
    fn portable_paths_fail_closed() {
        assert!(matches!(
            portable_relative("./src/app.js").as_deref(),
            Ok("src/app.js")
        ));
        for path in ["", "../app.js", "/tmp/app.js", "C:/app.js", "src\\app.js"] {
            assert!(portable_relative(path).is_err(), "accepted {path}");
        }
    }

    #[test]
    fn process_policy_is_independent_and_timeout_dominates() {
        let semantics = ExitSemantics {
            clean: BTreeSet::from([0]),
            findings: BTreeSet::from([1]),
            all_other: "failure".to_owned(),
        };
        assert_eq!(
            adjudicate_process(
                ProcessTermination::Exited(1),
                ReportAssessment::Valid { findings: 1 },
                &semantics,
            ),
            ProcessDecision::SuccessfulFindingsReport
        );
        assert_eq!(
            adjudicate_process(
                ProcessTermination::Exited(7),
                ReportAssessment::Valid { findings: 1 },
                &semantics,
            ),
            ProcessDecision::PolicyExitWithValidFindingsReport
        );
        assert_eq!(
            adjudicate_process(
                ProcessTermination::Timeout,
                ReportAssessment::Valid { findings: 1 },
                &semantics,
            ),
            ProcessDecision::Timeout
        );
    }
}
