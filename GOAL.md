# Secure Bench - Phase 0 Goal

Build the foundation of Secure Bench as an independent, local-first Rust benchmark harness for static security analyzers.

The first delivery must define a neutral benchmark contract, deterministic scoring model, adapter boundary, and CLI without installing or executing real third-party scanners. Use committed mock reports to prove that multiple tool formats can be normalized and scored fairly.

## Required workspace

```text
secure-bench/
|- Cargo.toml
|- crates/
|  `- secure-bench-core/    Contracts, normalization, matching, and scoring
|- apps/
|  `- secure-bench-cli/     Runner and report commands
|- schemas/                 Versioned benchmark and result schemas
|- fixtures/
|  |- vulnerable/           Cases with declared expected invariants
|  |- safe/                 Negative controls
|  `- reports/              Mock native, SARIF, and malformed reports
|- docs/                    Architecture and methodology
`- PLAN.md
```

## Phase 0 requirements

1. Inspect the Fedora and Rust environment and select current compatible dependencies.
2. Create the Rust workspace, strict linting, tests, dependency policy, and CI.
3. Define versioned models for benchmark suites, cases, expected findings, tool runs, normalized findings, matches, scores, errors, and provenance.
4. Define a neutral adapter trait that accepts a tool report and emits normalized findings without tool-specific scoring privileges.
5. Implement mock adapters for `secure-json-v1`, SARIF 2.1.0, and malformed/unsupported reports using committed fixtures only.
6. Implement deterministic matching between expected cases and normalized findings using invariant, category, source/sink locations, and evidence-path constraints.
7. Score vulnerable detection, safe-control false positives, evidence-path correctness, duplicates, unsupported cases, tool failures, duration, and memory separately.
8. Ensure missing scans, crashes, timeouts, parse failures, and unsupported languages cannot be counted as clean results.
9. Produce machine-readable JSON plus a concise terminal summary containing raw counts and explicit denominators.
10. Add tests proving adapter neutrality, deterministic scores, schema validation, path privacy, malformed-input handling, and resistance to benchmark gaming.

## Integrity requirements

- Expected results are never passed to scanners.
- A tool cannot receive credit for skipped, crashed, timed-out, or unsupported cases.
- Vulnerable fixtures and safe controls are scored separately.
- Rule count and raw finding count are not quality metrics.
- Every aggregate score links back to raw normalized findings and matching decisions.
- Repository paths are relative and source code is not embedded in exported benchmark results.
- Network access is disabled by default in future runner phases.
- Tool versions, commands, configuration fingerprints, schemas, host metadata, and timing provenance are recorded.
- Secure Engine receives no internal API access or custom matching exceptions.

## Non-goals

- Do not install or execute Secure Engine, CodeQL, Joern, Opengrep, Semgrep, or any external scanner.
- Do not clone external vulnerable projects.
- Do not build a desktop interface or hosted dashboard.
- Do not claim one scanner is better from mock data.
- Do not modify Secure Engine or Secure Skill.
- Do not create vulnerability fixtures beyond the minimal synthetic files required to test the benchmark contract.

## Definition of done

- The workspace passes formatting, strict Clippy, all tests, audit, and dependency policy checks.
- The same inputs produce byte-stable normalized results and scores apart from documented runtime fields.
- Native JSON and SARIF mock reports representing equivalent findings receive equivalent matches.
- False positives in safe controls reduce quality metrics and remain visible.
- Unsupported and failed runs are reported distinctly rather than treated as zero findings.
- Every score is reproducible from committed inputs and inspectable matching decisions.
- No scanner, skill, external corpus, or system package was installed or modified.
- The branch is clean and contains one focused signed Phase 0 commit.

Read [PLAN.md](./PLAN.md) fully before editing. Keep Phase 0 limited to contracts, mocked adapters, deterministic scoring, and verification.
