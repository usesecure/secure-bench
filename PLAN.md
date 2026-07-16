# Secure Bench - Project Plan

## Identity

- Organization: **Secure**
- Product: **Secure Bench**
- Repository: `usesecure/secure-bench`
- Core implementation: Rust
- Tagline: **Reproducible, evidence-aware benchmarks for static security analyzers.**

## Mission

Build a transparent benchmark system that measures what security analyzers actually detect, what they miss, what noise they produce, and whether their evidence paths are correct. Results must be reproducible from public inputs and raw artifacts rather than reduced to one unexplained score.

Secure Bench exists independently from Secure Engine. Its methodology must remain useful when Secure Engine performs poorly, and its design must make favoritism visible and testable.

## Product boundaries

Secure Bench owns:

- benchmark suite, case, and expectation schemas;
- fixture provenance and license metadata;
- isolated scanner execution plans;
- adapters for versioned native JSON, SARIF, and documented external formats;
- neutral finding normalization;
- expectation matching and ambiguity reporting;
- scoring and confidence intervals where statistically justified;
- runtime, memory, timeout, crash, and unsupported-case accounting;
- raw artifact retention and reproducible reports;
- CLI and static report generation.

Secure Bench does not own:

- scanner implementation or vulnerability rules;
- automatic installation of proprietary tools;
- source upload or hosted scanning;
- private benchmark answers sent to scanners;
- unsupported claims that one aggregate score represents all security quality;
- modifications to Secure Engine or Secure Skill.

## Core principles

1. **Independent:** tools integrate only through public commands and report contracts.
2. **Reproducible:** inputs, versions, configuration, environment, and raw outputs are recorded.
3. **Adversarially fair:** crashes, skips, duplicates, and unsupported cases cannot improve scores.
4. **Evidence aware:** source-to-sink correctness matters separately from alert presence.
5. **Negative controls first:** safe cases are mandatory and scored independently.
6. **No hidden denominator:** every metric states eligible, attempted, unsupported, and failed cases.
7. **Local first:** cases run without network access unless a suite explicitly requires and records it.
8. **Extensible:** adapters normalize evidence but cannot alter the scorer.

## Rust workspace direction

```text
model        Versioned suites, cases, expectations, runs, findings, and scores
schema       JSON Schema loading and compatibility validation
adapter      Native JSON, SARIF, and external report normalization
matcher      Deterministic expected-to-observed matching with ambiguity records
score        Per-case and aggregate metrics with explicit denominators
runner       Sandboxed commands, limits, cancellation, and artifact capture
provenance   Tool, host, corpus, configuration, and license metadata
report       JSON, terminal, and static HTML projections
```

Use Rust for executable components. Fixture source code uses the language under evaluation. Prefer declarative TOML for human-authored suite manifests and JSON for machine reports.

## Neutral benchmark contract

Each case must define:

- stable case and suite identifiers;
- vulnerability or safe-control status;
- language, framework, category, and violated invariant;
- expected source and sink constraints where applicable;
- allowed equivalent locations or path variants;
- minimum evidence-path requirements;
- fixture provenance, license, and modification history;
- supported tool eligibility rules declared before execution;
- resource budget and deterministic setup instructions.

Expected data is consumed only by the matcher after scanner execution. It must never be included in scanner prompts, configuration, environment variables, source trees, or filenames.

## Metrics

Report separately:

- vulnerable-case recall;
- safe-control false-positive rate;
- precision only where the labeled corpus supports it;
- evidence-path accuracy;
- source and sink localization accuracy;
- duplicate rate;
- severity and confidence calibration;
- crashes, timeouts, parse failures, and unsupported cases;
- cold and warm duration;
- peak memory and output size;
- per-language, framework, category, and rule-family coverage.

Do not collapse these into one leaderboard score during early phases. A later composite score requires published weighting rationale and sensitivity analysis.

## Adapter policy

Initial formats:

1. Secure Engine `secure-json-v1`.
2. SARIF 2.1.0 for compatible tools such as CodeQL and Opengrep.
3. Tool-specific JSON only when SARIF loses evidence required by the benchmark.
4. Joern export through a documented JSON projection in a later phase.

Adapters may parse, validate, and normalize. They may not assign benchmark credit, inspect expected answers, discard inconvenient findings, or rewrite locations to force matches.

## Roadmap

### Phase 0 - Contracts and mocked scoring

- Create the Rust workspace and versioned schemas.
- Implement neutral adapter and matcher boundaries.
- Normalize committed native JSON and SARIF mock reports.
- Produce deterministic per-case scores and raw decisions.

Exit condition: equivalent mock findings score equivalently and failure modes cannot appear clean.

### Phase 1 - First-party corpus and Secure Engine adapter

- Build an original TypeScript/JavaScript corpus with paired vulnerable and safe controls.
- Cover the Phase 3 Secure Engine rule families without leaking expected answers.
- Execute a user-provided Secure Engine binary under strict limits.
- Publish corpus provenance, raw runs, and baseline measurements.

Exit condition: Secure Engine is evaluated end to end without internal crate access.

### Phase 2 - SARIF scanner comparison

- Add isolated runners for user-provided Opengrep and CodeQL installations.
- Normalize SARIF code flows and partial evidence consistently.
- Compare eligible cases with explicit unsupported and failure accounting.

Exit condition: cross-tool comparisons are reproducible from pinned commands and raw artifacts.

### Phase 3 - Reproducible execution isolation

- Add process groups, timeouts, CPU and memory limits, read-only fixture copies, and disabled network defaults.
- Record cold/warm execution and host provenance.
- Detect fixture mutation and leaked expected metadata.

Exit condition: a failed or hostile scanner cannot corrupt the corpus or benchmark state.

### Phase 4 - Reports and methodology publication

- Generate static HTML and JSON reports from the same typed result model.
- Add drill-down from metrics to raw findings and match decisions.
- Publish methodology, uncertainty, limitations, and reproducibility bundles.

Exit condition: every public claim is traceable to committed cases and captured outputs.

### Phase 5 - Corpus expansion

- Add externally sourced cases only with verified licenses and provenance.
- Expand to Rust, Python, and Go alongside Secure Engine support.
- Add framework- and invariant-focused suites for authorization, tenants, state transitions, webhooks, payments, storage, and AI processing.

Exit condition: coverage claims match the labeled corpus and remain reproducible.

## Security and integrity

- Treat scanner output, SARIF, fixture repositories, archives, and report metadata as untrusted input.
- Prevent path traversal, symlink escape, command injection, archive escape, and uncontrolled artifact growth.
- Invoke tools without a shell and with explicit argument arrays.
- Redact environment secrets and bound captured stdout/stderr.
- Use atomic writes and content fingerprints for all benchmark artifacts.
- Never load executable fixture code into the benchmark process.
- Do not auto-download or auto-install scanners.

## Initial success criteria

- Results are deterministic and schema-versioned.
- Safe controls and vulnerable cases are always reported separately.
- Failures cannot masquerade as successful clean scans.
- Equivalent native and SARIF evidence receives equivalent treatment.
- Raw outputs and matching decisions explain every metric.
- Secure Engine has no privileged integration path.
- The benchmark can be audited without running an AI model.
