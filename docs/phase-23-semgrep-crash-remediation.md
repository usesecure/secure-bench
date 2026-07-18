# Phase 23 Semgrep CE crash remediation

Phase 23 is a synthetic-only infrastructure study. It proves that the frozen
Semgrep CE 1.170.0 Python launcher raises `semgrep-core` stack size to 1 GB per
worker when the hard stack limit is unlimited. Under the existing 4 GiB virtual
address-space cap, automatic worker creation fails and `semgrep-core` exits by
signal 11. Bounding both stack limits to 8 MiB prevents that mutation without
widening isolation or changing any frozen scanner input.

The corrected profile passed startup, clean, finding, multi-file, invalid-rule,
malformed-source, timeout, JSON, cleanup, confinement, frozen-adapter, and
deterministic-repeat checks on original disclosed Phase 23 fixtures. The study
does not read or execute the 112 cases, does not change Phase 22 evidence, and
does not run Phase 24.

This qualification is narrow: it establishes infrastructure stability for a
future post-open Semgrep normalized recovery lane. It is not a comparative
result, ranking, production-readiness assessment, or retroactive repair.

