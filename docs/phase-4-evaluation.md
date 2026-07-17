# Phase 4 One-Shot Holdout Evaluation

Phase 6 preserves this result unchanged and retires the executed Phase 3 cases as a public diagnostic corpus. Post-disclosure runs on those cases are development tests, not unbiased repetitions of Phase 4.

Phase 4 applies the frozen Secure Bench evaluator to the sealed 56-case Phase 3 holdout exactly once. It evaluates a user-supplied Secure Engine 0.1.2 executable strictly through its public command and `secure-json-v1` report boundary. Secure Engine remains an external black box: Secure Bench does not inspect, build, install, import, update, modify, or debug it.

This phase is an intentionally neutral research foundation. It is not a production benchmark, a scanner comparison, a public ranking, a complete security assessment, or evidence that Secure Engine or any other tool is superior. Results describe only this artifact, frozen corpus, command, environment, and evaluator contract.

## Frozen procedure

Before reservation, the Rust CLI verifies the immutable base commit, external binary and source RPM fingerprints, corpus aggregate, contract Merkle root, manifest, taxonomy, genesis ledger, release benchmark executable, schemas, evaluator sources, expected outcomes, resource policy, and sanitized environment provenance. The pre-execution contract records those bytes before any scanner process starts.

The complete runner is placed in a fresh `bwrap --unshare-net` namespace. The runner proves that only loopback is visible and that a fixed outbound connection fails with `NetworkUnreachable` before appending the `execution_started` entry. Every scanner process receives an empty environment and the same command template:

```text
scan {fixture} --format secure-json-v1 --output {report}
```

AI validation is disabled. No provider, credentials, endpoints, configuration, AI command, or network access is permitted. Each case receives its own copied fixture, process group, timeout, memory observation, output limit, and create-new report location. Every outcome is synchronously appended to a per-case journal. Reports are retained without repair, including malformed reports. The final result records explicit success, findings, crash, timeout, unsupported schema, malformed or missing output, execution failure, and cancellation states. No case is retried.

After execution, the evaluator deterministically normalizes retained reports, applies the frozen taxonomy and matching criteria, accounts separately for exact detections, partial evidence, misses, out-of-scope cases, operational failures, duplicate findings, and safe controls, and binds the result hash into the terminal ledger entry. Verification re-evaluates retained bytes without starting a scanner.

## Interpretation and limitations

Phase 1 and Phase 2 artifacts remain immutable. Phase 2 and Phase 4 scores must not be ranked directly because they use different corpora. Taxonomy alignment is not synonymous with vulnerability detection; partial evidence is not an exact detection; a clean report is not proof of absence; and an execution failure is never treated as a clean control or miss.

The holdout is small, synthetic, JavaScript/TypeScript-focused, and limited to seven frozen taxonomy families and four structural strata. Runtime and peak RSS are host- and sampling-dependent. A single artifact and one-shot execution cannot establish production readiness, general security coverage, low real-world false-positive rates, or comparative superiority.

Machine-readable artifacts under `artifacts/phase-4-secure-engine-0-1-2/` are authoritative. Completion summaries disclose aggregate results only and do not expose exact holdout source or matcher-side answers.
