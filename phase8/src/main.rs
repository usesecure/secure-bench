//! Scanner-free command-line interface for Phase 8 adjudication.

use secure_bench_phase8::{
    Phase8Error, adjudicate_repository, generate_artifacts, verify_artifacts,
};
use std::env;
use std::path::Path;

fn usage() -> &'static str {
    "Usage: secure-bench-phase8 <generate|verify|summary> [repository-root]"
}

fn run() -> Result<(), Phase8Error> {
    let mut arguments = env::args().skip(1);
    let command = arguments
        .next()
        .ok_or_else(|| Phase8Error::InvalidRequest(usage().to_owned()))?;
    let root = arguments.next().unwrap_or_else(|| ".".to_owned());
    if arguments.next().is_some() {
        return Err(Phase8Error::InvalidRequest(usage().to_owned()));
    }
    match command.as_str() {
        "generate" => {
            let artifacts = generate_artifacts(Path::new(&root))?;
            println!(
                "Generated retrospective Phase 8 adjudication {} from 112 retained reports; no scanner process was started.",
                artifacts.adjudication_id
            );
        }
        "verify" => {
            let artifacts = verify_artifacts(Path::new(&root))?;
            println!(
                "Verified Phase 8 result {}, separate ledger {}, immutable Phase 7 evidence, and zero scanner execution.",
                artifacts.result_sha256, artifacts.ledger_sha256
            );
        }
        "summary" => {
            let rendered = adjudicate_repository(Path::new(&root))?;
            let metrics = &rendered.result.corrected_evaluation.metrics;
            let counts = &metrics.counts;
            println!(
                "Phase 8 retrospective aggregate: exact={}, partial={}, missed={}, out_of_scope={}, controls_flagged={}, controls_clean={}, failures={}, duplicates={}, precision={}/{}, recall={}/{}, f1={}/{}; no scanner process was started.",
                counts.exact_detections,
                counts.partial_matches,
                counts.misses,
                counts.out_of_scope,
                counts.safe_controls_flagged,
                counts.clean_safe_controls,
                rendered.result.corrected_evaluation.measurement.failures,
                counts.duplicate_findings,
                metrics.precision.numerator,
                metrics.precision.denominator,
                metrics.recall.numerator,
                metrics.recall.denominator,
                metrics.f1.numerator,
                metrics.f1.denominator,
            );
            println!(
                "Agreement: taxonomy={}/{}, category={}/{}, invariant={}/{}, cwe={}/{}, source={}/{}, sink={}/{}, evidence_path={}/{}; findings={}, distinct={}, unrelated={}.",
                metrics.taxonomy_agreement.numerator,
                metrics.taxonomy_agreement.denominator,
                metrics.category_agreement.numerator,
                metrics.category_agreement.denominator,
                metrics.invariant_agreement.numerator,
                metrics.invariant_agreement.denominator,
                metrics.cwe_agreement.numerator,
                metrics.cwe_agreement.denominator,
                metrics.source_agreement.numerator,
                metrics.source_agreement.denominator,
                metrics.sink_agreement.numerator,
                metrics.sink_agreement.denominator,
                metrics.evidence_path_agreement.numerator,
                metrics.evidence_path_agreement.denominator,
                counts.findings,
                counts.distinct_findings,
                counts.unrelated_findings,
            );
        }
        _ => return Err(Phase8Error::InvalidRequest(usage().to_owned())),
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
