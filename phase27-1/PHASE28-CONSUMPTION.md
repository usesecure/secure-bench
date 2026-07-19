# Phase 28 consumption

Before any irreversible marker or attempt, Phase 28 must load `phase27-1/binding-overlay.json` after its frozen Phase 27 plan. The overlay has precedence only over scanner identity fields marked `verify-at-phase28-preflight`.

Phase 28 must run `python3 phase27-1/scripts/verify-bindings.py` from the repository root and stop fail-closed on any error. Consumption must not edit Phase 27 or change lanes, methodology, cases, scoring, commitments, ledger, order, or the 336-attempt plan. This certification does not itself authorize Phase 28 execution.
