#![forbid(unsafe_code)]
//! Scanner-free certification constants for the atomic Phase 17 Cargo closure.

/// Phase 27.1 base commit on which this successor overlay is defined.
pub const BASE_COMMIT: &str = "0f6fe9f06f1f88233e6d537b9c4e1d826575d0ee";

/// Historical Phase 17 commit containing the certified Cargo closure.
pub const PHASE17_COMMIT: &str = "241600628315db6d8a77e62bbaf6e61ba5c628f1";

/// Repository-relative path of the atomic successor overlay.
pub const BINDING_OVERLAY: &str = "phase27-2/binding-overlay.json";
