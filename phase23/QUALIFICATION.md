# Phase 23 synthetic qualification

Semgrep CE 1.170.0 is qualified for the future Phase 24
capability-normalized recovery lane under the corrected Phase 23 environment.
This is not a benchmark result or a production-readiness claim.

The sealed plan executed 11 new synthetic scanner cases exactly once: startup,
clean, expected finding, multi-file findings, invalid rule, malformed source,
external timeout, two clean repeats, and two finding repeats. It also executed
one non-scanner confinement probe. Results: zero segmentation faults, zero
retries, valid JSON for completed scans, frozen adapter acceptance for ordinary
clean/finding/multi-file outputs, deterministic normalized repeats, and cleanup
at sandbox exit.

The invalid rule failed explicitly with exit 7. The intentionally malformed
JavaScript fragment was accepted by Semgrep's tolerant parser and returned
valid empty OSS JSON with exit 0. That initially contradicted the anticipated
parser-error outcome; the already-executed attempt was retained, sealed without
a retry, and reported as observed behavior.

The confinement probe confirms no network route, failed write outside the
writable evidence bind, functional `/dev/null`, fresh procfs, stack 8 MiB,
address space 4 GiB, nproc 64, and no credential variables.

No input belongs to Phase 22 or Phase 24, and no holdout path was accessed.
Machine-readable detail is in `output/qualification/qualification-report.json`.

