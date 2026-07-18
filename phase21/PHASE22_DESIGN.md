# Phase 22 recovery-study draft

## Status

Draft only. Phase 22 has not been executed, no Phase 22 process has started,
and no Phase 22 attempt exists.

## Study label

If the same 112-case corpus is reused, the study must be titled a
**post-open scanner recovery study**. It must never be called the original
one-shot execution, a rerun of Phase 20, a neutral unopened-holdout comparison,
or a completion of Phase 20.

Phase 20's 336 attempts remain immutable. Its OpenGrep and Semgrep results stay
failed/unavailable, and its Secure Engine evidence may be referenced only as
historical Phase 20 evidence with an explicit cross-phase caveat.

## Entry gates

Before opening or mounting any case, Phase 22 should:

1. pin the accepted Phase 21 commit and verify its ED25519 signature and DCO;
2. run the Phase 21 scanner-free independent verifier;
3. verify `phase21/output/SHA256SUMS`;
4. run `verify-tools` to rehash bubblewrap, OpenGrep, Python, the Semgrep
   manifests, the primary Semgrep wheel, and all 66 wheels in the closure;
5. require the exact `phase21-null-device-v1` mount/environment contract;
6. rerun only scanner-free containment probes and fail closed on drift;
7. freeze a new Phase 22 execution plan, schema, ledger, timeouts, process
   policy, output limits, and zero-retry rule before any scanner process;
8. record zero Phase 22 scanner attempts at the end of preflight.

## Execution proposal

Run OpenGrep and Semgrep CE once per selected case in deterministic order under
the corrected profile. Each `(scanner, case)` key receives at most one Phase 22
attempt. Preserve process status separately from adapter status, retain every
raw stream, and hash-chain attempts immediately. Do not relabel or merge these
attempts into the Phase 20 ledger.

If all 224 proposed recovery attempts complete with adapter-valid reports,
publish scanner metrics as Phase 22 recovery results. Any comparison against
the historical Phase 20 Secure Engine lane must say that execution occurred in
different phases and after the holdout had already been opened. If a lane is
partial, do not compute a complete-lane metric or substitute zero for missing
cases.

The final report should include both an as-run attempt accounting and a clear
limitations section. A valid recovery result answers whether the corrected
sandbox enables the frozen scanners; it does not restore the neutrality or
one-shot comparability that Phase 20 lost.

