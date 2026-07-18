# Phase 21: sandbox remediation and scanner qualification

Phase 21 identifies `MS_NODEV` propagation from Phase 20's read-only root bind
as the exact cause of the OpenGrep and Semgrep `/dev/null` `EACCES` failures.
The minimal device correction is a fresh `/dev` plus a bubblewrap device bind
for `/dev/null` alone. The qualified profile further masks credential-bearing
host paths and replaces `/proc` without expanding host access.

The implementation, synthetic fixtures, root-cause evidence, sealed results,
independent verifier, and Phase 22 recovery-study draft are under `phase21/`.
Phase 20 commit `6c27c9bb26b96855228d1a8e6483483ff4174907` remains byte-identical and
its 336 attempts remain unchanged.

Both OpenGrep 1.22.0 and Semgrep CE 1.170.0 passed corrected-profile startup,
zero-finding, expected-finding, rule-error, and timeout canaries. Their legacy
canaries reproduced `/dev/null` errno 13. Malformed-output checks used mock
bytes and did not start scanners. The phase contains 12 scanner processes, two
sandbox probes, and two scanner-free adapter mocks; these are not Phase 20 or
Phase 22 attempts.

No Phase 19 holdout fixture was opened, read, copied, parsed, or used during
Phase 21 diagnosis or qualification. Synthetic qualification establishes
operability and containment, not scanner accuracy.

