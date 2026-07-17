# Phase 12.1: stable historical verification

Secure Bench 0.2.1 repairs only the prospective historical-verification mechanism introduced in
Phase 12. It does not alter the published Secure Bench 0.2.0 artifacts, Evidence Contract v2,
taxonomy 1.0.0, adapter precedence, public regression semantics, or any historical result.

## Root cause

The 0.2.0 verifier recomputed one aggregate from broad live repository roots, including `.github`
and all of `docs`. That made a legitimate workflow-only change part of the purported Phase 0–11
payload. Adding Phase 12 to the CI matrix therefore changed the aggregate even though no historical
evidence changed. The check confused a mutable repository surface with an immutable evidence
boundary.

## Historical boundary

The versioned baseline manifest is anchored to the last Phase 11 commit,
`86aa6f439c14eaa7e2fd7122687aca35f5aadc18`. Closed roots contain the historical executables,
evaluators, fixtures, commitments, retained reports, results, ledgers, schemas, policies, and
taxonomy. Their complete file sets are content-addressed, so additions, deletions, replacements,
and byte changes fail verification. Historical root workspace files and Phase 0–11 methodology
documents are protected individually.

Repository governance, version-control metadata, Phase 12 and later namespaces, newly introduced
root paths, and newly introduced documentation paths are outside the Phase 0–11 boundary. Existing
protected historical documentation remains immutable, while unrelated prospective documentation
and CI changes do not affect the baseline.

Every protected path must be portable and relative. The verifier rejects path traversal, duplicate
or overlapping coverage, malformed manifests, unsupported filesystem objects, and symlinks in any
protected path. Generated `target` directories are excluded from closed-root content because they
are build products rather than committed evidence.

## Compatibility

The 0.2.1 verifier reconstructs the manifest deterministically and requires byte-identical canonical
JSON. It separately reconstructs and verifies every published 0.2.0 Phase 12 output. The `v0.2.0`
tag and commit `359c723a360a51c974b6d11bc9044b4e2af71d2b` remain unchanged. No scanner execution, result
rescoring, new holdout, ranking, superiority claim, production-readiness claim, or Phase 13 material
is part of this repair.
