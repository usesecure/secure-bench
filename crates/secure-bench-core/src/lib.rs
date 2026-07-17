//! Tool-neutral contracts, corpus validation, black-box execution, and evaluation for Secure Bench.
//!
//! External analyzers are invoked only through a public command-line and report boundary. This
//! crate contains no scanner installation, discovery, private API, or product-specific scoring.

pub mod adapter;
pub mod corpus;
pub mod holdout;
pub mod matcher;
pub mod model;
pub mod phase2;
pub mod phase4;
pub mod phase5;
pub mod phase6;
pub mod phase7;
pub mod pipeline;
pub mod runner;
pub mod schema;
pub mod score;
pub mod taxonomy;

pub use adapter::{
    Adapter, AdapterError, AdapterInput, AdapterRegistry, SarifAdapter, SecureJsonAdapter,
};
pub use model::*;
pub use pipeline::{
    ContractError, EvaluationInput, LiveEvaluationInput, evaluate, evaluate_live_run,
    load_run_manifest, load_suite,
};
