//! Tool-neutral Phase 0 contracts and deterministic evaluation for Secure Bench.
//!
//! This crate intentionally contains no scanner execution or installation logic.

pub mod adapter;
pub mod matcher;
pub mod model;
pub mod pipeline;
pub mod schema;
pub mod score;

pub use adapter::{Adapter, AdapterError, AdapterRegistry, SarifAdapter, SecureJsonAdapter};
pub use model::*;
pub use pipeline::{ContractError, EvaluationInput, evaluate, load_run_manifest, load_suite};
