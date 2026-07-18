use serde::{Deserialize, Serialize};

/// One declared synthetic diagnostic experiment.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Experiment {
    /// Contiguous execution sequence.
    pub sequence: u64,
    /// Stable experiment identity.
    pub id: String,
    /// Control experiment identity, when paired.
    pub control: Option<String>,
    /// Exactly one changed variable relative to the control.
    pub changed_variable: String,
    /// Number of synthetic JavaScript targets.
    pub target_count: u64,
    /// Explicit Semgrep job count, or automatic selection.
    pub jobs: Option<u64>,
    /// Address-space limit in bytes, or no explicit limit.
    pub address_space_bytes: Option<u64>,
    /// Process/thread limit, or no explicit limit.
    pub process_limit: Option<u64>,
    /// Open-file limit, or no explicit limit.
    pub open_files_limit: Option<u64>,
    /// Stack limit in bytes, or inherited default.
    pub stack_bytes: Option<u64>,
    /// Whether the corrected PID namespace and fresh procfs are used.
    pub pid_namespace: bool,
    /// Whether the full corrected filesystem profile is used.
    pub full_profile: bool,
}

/// Resource usage captured by GNU time.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceUsage {
    /// Maximum resident set size in KiB.
    pub maximum_resident_kib: Option<u64>,
    /// Minor page faults.
    pub minor_page_faults: Option<u64>,
    /// Major page faults.
    pub major_page_faults: Option<u64>,
    /// Voluntary context switches.
    pub voluntary_context_switches: Option<u64>,
    /// Involuntary context switches.
    pub involuntary_context_switches: Option<u64>,
}

/// Persisted evidence for one Semgrep diagnostic execution.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    /// Experiment declaration.
    pub experiment: Experiment,
    /// Exact complete command vector.
    pub command: Vec<String>,
    /// Hash of the canonical command vector.
    pub command_sha256: String,
    /// Exact cleared environment.
    pub environment: Vec<String>,
    /// Normal wrapper exit code when available.
    pub exit_code: Option<i32>,
    /// External watchdog result.
    pub timed_out: bool,
    /// Wall-clock duration in milliseconds.
    pub duration_ms: u64,
    /// Whether retained output proves a segmentation fault.
    pub segmentation_fault: bool,
    /// Stage reached before exit.
    pub terminal_stage: String,
    /// Standard output path.
    pub stdout_path: String,
    /// Standard output hash.
    pub stdout_sha256: String,
    /// Standard error path.
    pub stderr_path: String,
    /// Standard error hash.
    pub stderr_sha256: String,
    /// Raw JSON path, when produced.
    pub raw_output_path: Option<String>,
    /// Raw JSON hash, when produced.
    pub raw_output_sha256: Option<String>,
    /// GNU time evidence path.
    pub resource_path: String,
    /// GNU time evidence hash.
    pub resource_sha256: String,
    /// Parsed resource usage.
    pub resources: ResourceUsage,
}

/// One append-only hash-chained ledger entry.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerEntry {
    /// Ledger schema identity.
    pub schema_version: String,
    /// Contiguous sequence.
    pub sequence: u64,
    /// Event identity.
    pub event: String,
    /// Observation payload hash.
    pub payload_sha256: String,
    /// Previous complete entry hash.
    pub previous_entry_hash: String,
    /// Complete entry hash.
    pub entry_hash: String,
}
