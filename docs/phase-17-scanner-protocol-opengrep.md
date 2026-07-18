# Secure Bench Phase 17 scanner protocol and OpenGrep adapter

Phase 17 is a prospective, additive adapter-conformance phase. It introduces scanner-neutral
manifest, raw-artifact, projection-availability, finding-identity, and process-adjudication
contracts, then implements one conservative OpenGrep JSON adapter. It does not change or rescore
any Phase 0–16 artifact or official result.

## Reproducible OpenGrep pin

The pin is OpenGrep `1.22.0`, the latest non-draft, non-prerelease upstream release verified on
2026-07-18. The self-contained Linux x86_64 asset `opengrep_manylinux_x86` is 40,750,411 bytes and
has SHA-256 `45bcd58440e397ed52c50e953ccf5948909ea77087c9186fc7d277216f62e319`.
OpenGrep declares `LGPL-2.1-only`.

The official release also supplies a detached Sigstore signature and certificate. Their encoded
SHA-256 values are respectively
`d44b03294ff6931458cfeac77b44e79fd41c2096b87c597884468d923c864dbd` and
`bd823447c6413716691a1f568b793aa1f561aa30829309159cc09cf3190ce4b5`.
The certificate binds the GitHub OIDC issuer, the official
`opengrep/opengrep/.github/workflows/rolling-release.yml@refs/heads/main` identity, and source
revision `f458d7f0d52cc58eae1ca3cf3d5caf101e637519`. An independent SHA-256 comparison and detached
ECDSA verification succeeded. Admission to an execution cache additionally requires the manifest
`cosign verify-blob` identity/issuer template so transparency-log verification is not silently
omitted.

No install script is used. Tools belong in an ignored deterministic cache outside the repository,
become executable only after hash and signature verification, and are never downloaded during
tests. No binary, signature, certificate, package, or generated tool environment is committed.

## Protocol and manifest

`secure-bench-scanner-manifest-v1` / protocol `1.0.0` records scanner and adapter versions,
upstream repository and license, binary SHA-256 and signature provenance, exact ruleset identity
and SHA-256, language/framework and inter-file/interprocedural/taint declarations, an argument
vector template, timeout and resource policy, exit semantics, raw format, and adapter version.
Shell expansion is not part of the command contract.

The committed manifest selects the disclosed CC0 adapter-conformance rule only. That rule is not a
native or capability-normalized comparison profile and cannot be used as one. The archived
`opengrep/opengrep-rules` repository is explicitly ineligible as an implicitly current ruleset.

## Adaptation and unavailable evidence

OpenGrep JSON `check_id`, relative path, start/end positions, message, severity, fingerprint, and
uninterpreted metadata are projected only when present and valid. Metadata keys that resemble CWE
or taxonomy coordinates remain uninterpreted metadata. Raw source-line text is confined to the
separately retained raw artifact and is excluded from the public projection.

OpenGrep JSON does not independently declare Evidence Contract v2 semantic source identity, sink
identity, connected evidence path, guards/barriers, CWE, Secure Bench taxonomy, or confidence.
Every one of those fields is therefore explicitly `unavailable`; rule names, messages, metadata,
severity, lane identity, and scanner documentation never fill them. Missing OpenGrep message,
severity, fingerprint, or offsets are also explicit availability states rather than defaults.

The generic post-projection identity uses case scope, exact rule ID, validated portable span, and
duplicate occurrence. It does not receive scanner identity and has no adapter-specific exception.
Exact duplicate projections are retained with distinct occurrence IDs and a `duplicate_of` link to
the first occurrence; a downstream evaluator must not award duplicate credit.

## Failure and process policy

Raw bytes are captured before any JSON parsing. The adapter rejects oversized or malformed JSON,
version drift, scanner-declared errors, skipped rules, unknown rules, traversal, absolute or
platform-prefixed paths, backslashes, symlinks, missing/non-regular files, zero/reversed spans,
half-present offsets, and offsets outside disclosed fixture bytes.

Finding adaptation never reads an exit code. A scanner-neutral process policy consumes only normal
exit/signal/timeout evidence, the manifest's declared exit semantics, and the adapter assessment.
Timeout and signal evidence dominate any partial bytes. A nonzero complete findings report is
preserved as either the declared findings exit or `policy_exit_with_valid_findings_report`; a
nonzero clean report is a genuine process failure. Malformed and internally errored reports remain
separate outcomes.

SARIF ingestion is intentionally absent. For this bounded adapter, OpenGrep JSON already supplies
the useful rule ID, location, metadata, fingerprint, message, and severity fields. SARIF would add
no independently useful Evidence Contract v2 evidence and would broaden the trust surface without
improving the conservative projection.

## Separately reported comparison lanes

Any future comparison must freeze two independent, separately reported lanes before execution:

1. The **native lane** uses a maintained public scanner-recommended ruleset with immutable origin,
   revision, license, and SHA-256.
2. The **capability-normalized lane** uses public scanner-specific rules authored from the same
   already-frozen public vulnerability families without viewing cases, answers, native output, or
   scanner internals.

The lanes never share a score, denominator, aggregate, ranking, or post-observation rule revision.
Each retains its own scanner manifest, exact rules bytes, raw reports, process audit, metrics, and
limitations. Adapter availability and matching semantics are identical between lanes.

## Disclosed conformance scope and limitations

Ten committed raw vectors cover clean output, one finding, duplicates, malformed JSON, partial
output, traversal, absolute paths, invalid spans, unknown rules, and missing files. A runtime-only
symlink vector avoids committing a symlink. Three separate process vectors cover a nonzero findings
report, timeout with report bytes, and a nonzero clean report. Repeated adaptation, raw-byte hashes,
rule metadata, scanner fingerprints, privacy projection, and unavailable evidence are checked
offline.

These synthetic vectors establish only adapter and protocol behavior. No Secure Engine, Semgrep,
Joern, private/frozen holdout, Phase 13/14 comparison case, or future comparison case was executed
or inspected. Phase 17 produces no comparative score, ranking, superiority claim, production
readiness claim, or coverage claim.
