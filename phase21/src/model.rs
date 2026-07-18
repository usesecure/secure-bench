use serde::{Deserialize, Serialize};

/// One persisted synthetic qualification observation.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    /// Contiguous canary sequence.
    pub sequence: u64,
    /// Stable scenario identifier.
    pub id: String,
    /// Scanner or mock identity.
    pub subject: String,
    /// Legacy or corrected sandbox profile.
    pub sandbox_profile: String,
    /// Scenario class.
    pub scenario: String,
    /// Whether this process is counted as a scanner attempt.
    pub scanner_process_attempt: bool,
    /// Full bubblewrap command and child argument vector.
    pub command: Vec<String>,
    /// Hash of the command vector.
    pub command_sha256: String,
    /// Exact cleared environment.
    pub environment: Vec<String>,
    /// Process exit status when available.
    pub exit_code: Option<i32>,
    /// Whether the scenario intentionally exercised timeout handling.
    pub timed_out: bool,
    /// Wall-clock duration.
    pub duration_ms: u64,
    /// Captured standard output path.
    pub stdout_path: String,
    /// Captured standard output hash.
    pub stdout_sha256: String,
    /// Captured standard error path.
    pub stderr_path: String,
    /// Captured standard error hash.
    pub stderr_sha256: String,
    /// Raw JSON path when emitted.
    pub raw_output_path: Option<String>,
    /// Raw output hash when emitted.
    pub raw_output_sha256: Option<String>,
    /// Adapter-valid finding count.
    pub finding_count: Option<u64>,
    /// Adapter decision.
    pub adapter_decision: String,
    /// Human-readable expectation.
    pub expectation: String,
    /// Whether all scenario assertions passed.
    pub passed: bool,
}

/// One append-only, hash-chained evidence ledger entry.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerEntry {
    /// Ledger schema identity.
    pub schema_version: String,
    /// Contiguous sequence.
    pub sequence: u64,
    /// Event class.
    pub event: String,
    /// Observation payload hash.
    pub payload_sha256: String,
    /// Previous complete entry hash.
    pub previous_entry_hash: String,
    /// Complete entry hash.
    pub entry_hash: String,
}
