# Secure Bench Phase 16 authoritative Evidence Contract v2 adapter

Phase 16 introduces the prospective Secure Bench 0.2.2 adapter policy. It repairs benchmark
infrastructure only. It does not modify Secure Engine, execute a scanner, rerun a holdout, or
change the official Phase 14 result. Every Phase 0–15 diagnostic, retained report, result, ledger,
contract, schema, fixture, and provenance artifact remains byte-identical.

## Authoritative projection

The `authoritative_v2` route deserializes each declared `evidence_contract_v2` object directly.
Before projection it validates the fixed `2.0.0` contract version, the
`secure-evidence-semantics-v2` identity, the committed declared-projection JSON Schema, and the
frozen taxonomy 1.0.0 category/invariant/CWE tuple. It then validates portable spans, ordered
source-to-sink roles, connected value flow, semantic source and sink identities, and exact
agreement between effective barriers and barrier nodes.

The adapter preserves the original declared v2 object, declared semantic and duplicate
fingerprints, taxonomy, primary CWE, source and sink semantics, every span including byte offsets,
ordered nodes, connectivity, summarizability, uncertainty, unresolved calls, and effective
barriers. Its canonical scoring projection retains the line/column spans required by Evidence
Contract v2. Connected edges are the report-side evidence that the ordered nodes carry the same
value identity; an absent, length-mismatched, or false edge fails closed.

Finding IDs are derived only after successful projection from the adapter-policy version, neutral
case scope, computed canonical semantic fingerprint, and duplicate occurrence. Report hashes,
prose, tool identity, scanner rule wording, and legacy fields cannot change the ID.

## Precedence and failure behavior

Declared v2 is authoritative. Malformed, incomplete, unsupported, version-mismatched,
taxonomy-invalid, span-invalid, disconnected, identity-incomplete, or barrier-inconsistent v2 is
adapter-invalid. It never falls back to legacy evidence.

Legacy input is available only through the explicit
`secure-json-v1-legacy-canonical-v1` compatibility route and only when v2 is absent. Selecting that
route when v2 exists fails closed. When the authoritative route sees legacy fields alongside v2,
legacy is never used to fill, repair, or enrich v2. If the legacy fields independently form a
complete canonical projection, they must be semantically equal to v2 or the report is rejected as
conflicting. Generic legacy evidence that cannot be mapped without aliases or guesses is ignored
as non-authoritative; this is what permits the retained Phase 14 reports to use their valid v2
objects without reproducing the defective legacy reconstruction.

## Process separation

Projection produces only an adapter-valid or adapter-invalid report assessment. The unchanged,
tool-neutral process-status policy consumes that assessment separately. A normal exit code 1 with
a complete authoritative findings report remains `policy_exit_with_valid_findings_report`; there
is no scanner-specific exit-code exception. Missing, malformed, incomplete, internally errored,
or adapter-invalid reports remain distinct failure states.

## Migration

Prospective evaluators select `AdapterRoute::AuthoritativeV2` and declare adapter policy `2.0.0`.
Producers that declare v2 must emit the complete projection and frozen taxonomy coordinates.
Legacy-only producers must be configured explicitly for the versioned compatibility route; the
adapter never infers that route from report contents. Evidence Contract v2 and taxonomy 1.0.0 are
unchanged.

## Offline conformance evidence

The Phase 16 verifier executes all 8 Phase 15 precedence vectors and all 16 Evidence Contract v2
matching vectors. It then reads all 112 retained Phase 14 reports without modifying them and
projects all 96 findings through authoritative v2. The diagnostic vulnerable comparison is 10
exact, 0 partial, and 46 no-match; controls remain 40 flagged and 16 clean. All 96 exit-code-1
findings reports retain their policy status. These are adapter-conformance counterfactuals only,
not a Phase 14 rescore or retrospective credit.

## Limitations

The retained reports are retired, disclosed synthetic material. Their offline projection proves
adapter behavior against this bounded contract surface, not scanner quality, production fitness,
real-world prevalence, superiority, ranking, or complete vulnerability coverage. The explicit
legacy route supports only semantics it can map without aliases, guessing, or v2 enrichment.
