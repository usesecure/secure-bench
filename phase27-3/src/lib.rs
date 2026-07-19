#![forbid(unsafe_code)]
//! Scanner-free constants for the Phase 27.3 dual-adapter closure certification.

/// Commit on which Phase 27.3 is based.
pub const BASE_COMMIT: &str = "467413eeb2a22017b5bc19f7f2052fdbc5d43d0d";

/// Historical Phase 17 `OpenGrep` closure commit.
pub const PHASE17_COMMIT: &str = "241600628315db6d8a77e62bbaf6e61ba5c628f1";

/// Historical Phase 18 `Semgrep` closure commit.
pub const PHASE18_COMMIT: &str = "aee2c7094983cfb8bdc16cf59b1962add82ca1db";

/// Common runner request schema identifier.
pub const RUNNER_REQUEST_SCHEMA: &str = "secure-bench-adapter-runner-request-v1";

/// Historical common normalized projection schema identifier.
pub const NORMALIZED_SCHEMA: &str = "secure-bench-adapted-report-v1";

/// Public scanner-neutral protocol version implemented by both closures.
pub const PROTOCOL_VERSION: &str = "1.0.0";
