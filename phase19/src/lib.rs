//! Immutable Secure Engine artifact binding for Secure Bench Phase 19.
//!
//! Validation is deliberately scanner-free: it parses committed metadata, validates the exact
//! constants, and can hash already-downloaded RPM and extracted binary bytes. It never launches,
//! installs, or rebuilds Secure Engine.

#![allow(clippy::struct_excessive_bools)]

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Deterministic scanner-free Phase 19 holdout authoring and validation.
pub mod holdout;

/// Binding schema identity.
pub const SCHEMA_VERSION: &str = "secure-bench-phase19-secure-engine-binding-v1";
/// Frozen phase number.
pub const PHASE: u8 = 19;
/// Frozen public release URL.
pub const RELEASE_URL: &str = "https://github.com/usesecure/secure-engine/releases/tag/v0.1.6";
/// Frozen release tag.
pub const RELEASE_TAG: &str = "v0.1.6";
/// Frozen release commit.
pub const RELEASE_COMMIT: &str = "a921b9b0b737fa04af66903eeff43c1fd9ce6bcf";
/// Frozen signed annotated-tag object.
pub const SIGNED_TAG_OBJECT: &str = "542d10b70987e6b5fe81af9d9f4a534703f18f25";
/// Frozen official RPM filename.
pub const RPM_FILENAME: &str = "secure-engine-0.1.6-1.fc44.x86_64.rpm";
/// Frozen official RPM SHA-256.
pub const RPM_SHA256: &str = "0f336a262d1c1cac51a73c625a7398c392feb9f3ecad2aa81f62cbc128a62a64";
/// Frozen path of the Secure Engine CLI inside the RPM payload.
pub const SECURE_PATH: &str = "/usr/bin/secure";
/// Frozen SHA-256 of the unmodified CLI bytes extracted from the RPM payload.
pub const SECURE_SHA256: &str = "ad91499f3de9918963c9189bd236f5eb99b78cb99954e30f50bbc3098f18a5e0";

const BINDING_PATH: &str = "phase19/bindings/secure-engine-v0.1.6.json";
const SCHEMA_PATH: &str = "phase19/schemas/secure-engine-binding-v1.schema.json";
const PROVENANCE_PATH: &str = "phase19/provenance/secure-engine-v0.1.6.json";
const REPOSITORY: &str = "https://github.com/usesecure/secure-engine";
const RPM_URL: &str = "https://github.com/usesecure/secure-engine/releases/download/v0.1.6/secure-engine-0.1.6-1.fc44.x86_64.rpm";

/// Phase 19 binding validation failure.
#[derive(Debug, Error)]
pub enum BindingError {
    /// A required file could not be read.
    #[error("unable to read {path}: {detail}")]
    Io {
        /// Repository-relative or supplied path.
        path: String,
        /// Operating-system detail.
        detail: String,
    },
    /// JSON syntax or shape was invalid.
    #[error("invalid JSON in {0}: {1}")]
    Json(String, String),
    /// JSON Schema compilation or validation failed.
    #[error("binding schema validation failed: {0}")]
    Schema(String),
    /// A supposedly frozen field drifted.
    #[error("immutable binding drift: {0}")]
    Drift(String),
    /// Supplied artifact bytes do not match the binding.
    #[error("artifact digest mismatch for {artifact}: expected {expected}, got {actual}")]
    DigestMismatch {
        /// Artifact label.
        artifact: String,
        /// Frozen expected SHA-256.
        expected: String,
        /// Observed SHA-256.
        actual: String,
    },
}

/// Public release identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseBinding {
    /// Canonical upstream repository.
    pub repository: String,
    /// Exact versioned release page.
    pub url: String,
    /// Exact annotated tag.
    pub tag: String,
    /// Commit peeled from the annotated tag.
    pub commit: String,
    /// Signed annotated-tag object ID.
    pub signed_tag_object: String,
}

/// Official release RPM identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RpmBinding {
    /// Exact asset filename.
    pub filename: String,
    /// Exact versioned asset URL.
    pub url: String,
    /// SHA-256 of RPM bytes.
    pub sha256: String,
    /// Immutable source classification.
    pub source: String,
}

/// CLI bytes extracted without modification from the RPM payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BinaryBinding {
    /// Installed path declared by the RPM.
    pub path: String,
    /// SHA-256 of extracted bytes.
    pub sha256: String,
    /// Relationship between RPM and binary bytes.
    pub relationship: String,
}

/// Policies preventing the binding from becoming a moving or rebuilt target.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FreezePolicy {
    /// Release selection policy.
    pub selection: String,
    /// Moving latest references are forbidden.
    pub moving_latest_reference_allowed: bool,
    /// Future releases cannot silently replace this release.
    pub future_release_auto_upgrade_allowed: bool,
    /// Source rebuilds cannot replace official RPM bytes.
    pub rebuild_allowed: bool,
    /// Artifact mutation is forbidden.
    pub artifact_mutation_allowed: bool,
    /// Binding verification cannot execute the CLI.
    pub binary_execution_allowed_during_binding_verification: bool,
}

/// Complete immutable Phase 19 Secure Engine binding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecureEngineBinding {
    /// Schema identity.
    pub schema_version: String,
    /// Secure Bench phase.
    pub phase: u8,
    /// Stable binding identity.
    pub binding_id: String,
    /// Public release identity.
    pub release: ReleaseBinding,
    /// Official RPM identity.
    pub rpm: RpmBinding,
    /// Extracted CLI identity.
    pub extracted_binary: BinaryBinding,
    /// Freeze policies.
    pub policy: FreezePolicy,
}

impl SecureEngineBinding {
    /// Validates every frozen value and prohibition.
    ///
    /// # Errors
    ///
    /// Returns [`BindingError::Drift`] when any value differs from the Phase 19 contract.
    pub fn validate_exact(&self) -> Result<(), BindingError> {
        exact("schema_version", &self.schema_version, SCHEMA_VERSION)?;
        if self.phase != PHASE {
            return Err(BindingError::Drift("phase".to_owned()));
        }
        exact(
            "binding_id",
            &self.binding_id,
            "secure-engine-v0.1.6-fedora44-x86_64",
        )?;
        exact("release.repository", &self.release.repository, REPOSITORY)?;
        exact("release.url", &self.release.url, RELEASE_URL)?;
        exact("release.tag", &self.release.tag, RELEASE_TAG)?;
        exact("release.commit", &self.release.commit, RELEASE_COMMIT)?;
        exact(
            "release.signed_tag_object",
            &self.release.signed_tag_object,
            SIGNED_TAG_OBJECT,
        )?;
        exact("rpm.filename", &self.rpm.filename, RPM_FILENAME)?;
        exact("rpm.url", &self.rpm.url, RPM_URL)?;
        exact("rpm.sha256", &self.rpm.sha256, RPM_SHA256)?;
        exact(
            "rpm.source",
            &self.rpm.source,
            "official-github-release-asset",
        )?;
        exact(
            "extracted_binary.path",
            &self.extracted_binary.path,
            SECURE_PATH,
        )?;
        exact(
            "extracted_binary.sha256",
            &self.extracted_binary.sha256,
            SECURE_SHA256,
        )?;
        exact(
            "extracted_binary.relationship",
            &self.extracted_binary.relationship,
            "unmodified-rpm-payload",
        )?;
        exact(
            "policy.selection",
            &self.policy.selection,
            "explicit-immutable-release",
        )?;
        if self.policy.moving_latest_reference_allowed
            || self.policy.future_release_auto_upgrade_allowed
            || self.policy.rebuild_allowed
            || self.policy.artifact_mutation_allowed
            || self
                .policy
                .binary_execution_allowed_during_binding_verification
        {
            return Err(BindingError::Drift(
                "one or more freeze-policy prohibitions are disabled".to_owned(),
            ));
        }
        if self.release.url.contains("/latest") || self.rpm.url.contains("/latest") {
            return Err(BindingError::Drift(
                "moving latest URL is forbidden".to_owned(),
            ));
        }
        Ok(())
    }
}

fn exact(field: &str, actual: &str, expected: &str) -> Result<(), BindingError> {
    if actual == expected {
        Ok(())
    } else {
        Err(BindingError::Drift(field.to_owned()))
    }
}

fn read(path: &Path) -> Result<Vec<u8>, BindingError> {
    fs::read(path).map_err(|error| BindingError::Io {
        path: path.display().to_string(),
        detail: error.to_string(),
    })
}

fn parse_value(path: &Path) -> Result<Value, BindingError> {
    let bytes = read(path)?;
    serde_json::from_slice(&bytes)
        .map_err(|error| BindingError::Json(path.display().to_string(), error.to_string()))
}

fn parse_binding(path: &Path) -> Result<SecureEngineBinding, BindingError> {
    let bytes = read(path)?;
    serde_json::from_slice(&bytes)
        .map_err(|error| BindingError::Json(path.display().to_string(), error.to_string()))
}

/// Scanner-free repository verification summary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationSummary {
    /// Validated binding schema identity.
    pub schema_version: String,
    /// Bound release tag.
    pub release_tag: String,
    /// Bound release commit.
    pub release_commit: String,
    /// Bound signed tag object.
    pub signed_tag_object: String,
    /// Bound RPM SHA-256.
    pub rpm_sha256: String,
    /// Bound extracted CLI SHA-256.
    pub extracted_secure_sha256: String,
    /// Moving release references remain forbidden.
    pub moving_reference_forbidden: bool,
    /// Rebuilds remain forbidden.
    pub rebuild_forbidden: bool,
    /// Verification did not launch the bound binary.
    pub scanner_executed: bool,
}

/// Validates the committed schema, binding, and provenance cross-links.
///
/// # Errors
///
/// Returns an error for missing files, schema failure, value drift, or provenance drift.
pub fn verify_repository(root: &Path) -> Result<VerificationSummary, BindingError> {
    let binding_path = root.join(BINDING_PATH);
    let schema = parse_value(&root.join(SCHEMA_PATH))?;
    let binding_value = parse_value(&binding_path)?;
    jsonschema::validator_for(&schema)
        .map_err(|error| BindingError::Schema(error.to_string()))?
        .validate(&binding_value)
        .map_err(|error| BindingError::Schema(error.to_string()))?;
    let binding = parse_binding(&binding_path)?;
    binding.validate_exact()?;

    let provenance = parse_value(&root.join(PROVENANCE_PATH))?;
    provenance_exact(&provenance, "/release_evidence/tag_ref", SIGNED_TAG_OBJECT)?;
    provenance_exact(
        &provenance,
        "/release_evidence/peeled_commit",
        RELEASE_COMMIT,
    )?;
    provenance_exact(&provenance, "/artifact_evidence/rpm_sha256", RPM_SHA256)?;
    provenance_exact(
        &provenance,
        "/artifact_evidence/extracted_sha256",
        SECURE_SHA256,
    )?;

    Ok(VerificationSummary {
        schema_version: binding.schema_version,
        release_tag: binding.release.tag,
        release_commit: binding.release.commit,
        signed_tag_object: binding.release.signed_tag_object,
        rpm_sha256: binding.rpm.sha256,
        extracted_secure_sha256: binding.extracted_binary.sha256,
        moving_reference_forbidden: true,
        rebuild_forbidden: true,
        scanner_executed: false,
    })
}

fn provenance_exact(provenance: &Value, pointer: &str, expected: &str) -> Result<(), BindingError> {
    if provenance.pointer(pointer).and_then(Value::as_str) == Some(expected) {
        Ok(())
    } else {
        Err(BindingError::Drift(format!("provenance{pointer}")))
    }
}

/// Hash-verification summary for externally supplied official RPM and extracted CLI bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactVerificationSummary {
    /// Supplied RPM path.
    pub rpm_path: PathBuf,
    /// Verified RPM SHA-256.
    pub rpm_sha256: String,
    /// Supplied extracted CLI path.
    pub secure_path: PathBuf,
    /// Verified CLI SHA-256.
    pub secure_sha256: String,
    /// The verifier only read bytes and never launched the CLI.
    pub scanner_executed: bool,
    /// The verifier did not build replacement bytes.
    pub rebuilt: bool,
}

/// Verifies already-downloaded official RPM and extracted CLI bytes without executing either.
///
/// # Errors
///
/// Returns an error when a file is unreadable or its digest differs from the immutable binding.
pub fn verify_artifacts(
    rpm_path: &Path,
    secure_path: &Path,
) -> Result<ArtifactVerificationSummary, BindingError> {
    let rpm_sha256 = sha256(&read(rpm_path)?);
    if rpm_sha256 != RPM_SHA256 {
        return Err(BindingError::DigestMismatch {
            artifact: RPM_FILENAME.to_owned(),
            expected: RPM_SHA256.to_owned(),
            actual: rpm_sha256,
        });
    }
    let secure_sha256 = sha256(&read(secure_path)?);
    if secure_sha256 != SECURE_SHA256 {
        return Err(BindingError::DigestMismatch {
            artifact: SECURE_PATH.to_owned(),
            expected: SECURE_SHA256.to_owned(),
            actual: secure_sha256,
        });
    }
    Ok(ArtifactVerificationSummary {
        rpm_path: rpm_path.to_path_buf(),
        rpm_sha256,
        secure_path: secure_path.to_path_buf(),
        secure_sha256,
        scanner_executed: false,
        rebuilt: false,
    })
}

fn sha256(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::{
        RPM_SHA256, SECURE_SHA256, SecureEngineBinding, verify_artifacts, verify_repository,
    };
    use std::fs;
    use std::path::{Path, PathBuf};

    fn root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
    }

    #[test]
    fn committed_binding_is_exact_and_scanner_free() -> Result<(), Box<dyn std::error::Error>> {
        let summary = verify_repository(&root())?;
        assert_eq!(summary.rpm_sha256, RPM_SHA256);
        assert_eq!(summary.extracted_secure_sha256, SECURE_SHA256);
        assert!(summary.moving_reference_forbidden);
        assert!(summary.rebuild_forbidden);
        assert!(!summary.scanner_executed);
        Ok(())
    }

    #[test]
    fn moving_reference_and_rebuild_drift_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let bytes = fs::read(root().join("phase19/bindings/secure-engine-v0.1.6.json"))?;
        let mut binding: SecureEngineBinding = serde_json::from_slice(&bytes)?;
        binding.release.url =
            "https://github.com/usesecure/secure-engine/releases/latest".to_owned();
        assert!(binding.validate_exact().is_err());

        let mut binding: SecureEngineBinding = serde_json::from_slice(&bytes)?;
        binding.policy.rebuild_allowed = true;
        assert!(binding.validate_exact().is_err());
        Ok(())
    }

    #[test]
    fn wrong_artifact_bytes_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let rpm = directory.path().join("release.rpm");
        let secure = directory.path().join("secure");
        fs::write(&rpm, b"not the bound rpm")?;
        fs::write(&secure, b"not the bound secure binary")?;
        assert!(verify_artifacts(&rpm, &secure).is_err());
        Ok(())
    }
}
