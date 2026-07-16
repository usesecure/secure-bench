# Phase 1 Black-Box Runner

## Trust boundary

The runner accepts one explicit regular-file binary path. It never searches a source tree or `PATH` for Secure Engine and never downloads, installs, builds, updates, or modifies a scanner. The executable is invoked directly through a Rust argument array without a shell. Secure Bench imports no Secure Engine crate and has no access to its internal graph, rule registry, fixtures, cache, or APIs.

Each case runs against a fresh temporary scanner-visible directory containing only a copied project. The report target and optional configuration live in its temporary parent, outside the scanned tree. The child environment is cleared and rebuilt with only deterministic locale, timezone, color, and temporary-directory values. Standard input is closed. Expected answers and suite metadata are absent from arguments, environment variables, configuration contents, filenames, and the temporary project.

## Bounds and cleanup

The runner provides these Phase 1 controls:

- a direct child process group for descendant cleanup;
- per-case wall-clock timeout and cancellation;
- periodic peak-memory sampling with termination when the declared direct-process budget is exceeded;
- a per-case accepted-report byte limit and a fixed 10 MiB adapter ceiling;
- complete stdout and stderr draining with SHA-256 fingerprints, byte counts, and only a 4 KiB in-memory diagnostic prefix;
- regular-file and symlink checks for the binary, fixtures, reports, and retained artifacts;
- fresh temporary workspaces and removal on completion or error;
- atomic file writes and final bundle publication; and
- portable bounded argument templates with exactly one `{fixture}` and one `{report}` placeholder.

An optional UTF-8 public configuration is accepted only when the argument template contains one `{configuration}` placeholder. It is copied outside the scanned project, is not retained in the bundle, and is represented in provenance by SHA-256. Configuration text containing matcher-owned categories, invariants, or expectation identifiers is rejected before execution.

The suite declares network access disabled. Phase 1 clears proxy and credential-bearing environment state by clearing the entire environment, but the Rust runner does not itself claim kernel-enforced network or filesystem sandboxing. The recorded Phase 6 baseline adds an outer Linux network namespace with no host network interface and records that containment separately. Generalized runner-managed network and filesystem sandboxing remain Phase 3 work. Peak memory is sampled from Linux `/proc` for the direct process; very short peaks or descendant-only allocation may not be observed. These limitations must accompany baseline measurements.

## Status model

Every suite case receives exactly one status:

- `success`: a valid empty `secure-json-v1` report;
- `findings`: a valid report containing normalized findings;
- `crash`: a started process exited unsuccessfully;
- `timeout`: the wall-clock budget expired;
- `invalid_output`: output was absent, oversized, malformed, privacy-unsafe, or otherwise invalid;
- `unsupported_schema`: the public report declared an unsupported format or version;
- `execution_failure`: the process could not start or be monitored, or crossed its observed memory budget; or
- `cancelled`: cancellation stopped or skipped the case.

Only `success` and `findings` are attempted scans. Every other state is explicit failure accounting and cannot improve clean-control coverage or detection credit.

## Provenance and artifacts

`run.json` records the binary SHA-256, sanitized version probe, public report schema, exact portable argument template and rendered per-case arguments, configuration fingerprint, host metadata, corpus and case fingerprints, timestamps, duration, process exit code, observed peak memory, stream fingerprints, report sizes and hashes, and all statuses. A nonzero finding exit code is retained while a complete, internally error-free, adapter-valid public report remains a completed scan. It never records the executable path, repository root, temporary directory, raw stdout, raw stderr, environment values, or secrets.

Raw accepted reports are retained beneath `reports/`. Evaluation verifies the manifest, exact case accounting, aggregate status, arguments, timestamps, case and corpus fingerprints, report paths, report sizes, report fingerprints, and absence of unrelated report files before normalization.

## Adapter neutrality

The live runner requests the same public `secure-json-v1` contract used by recorded inputs. The adapter accepts the minimal Phase 0 location form and the public span-based location form while ignoring non-scoring report metadata. The adapter receives report bytes, a report fingerprint, the current neutral case scope, and a path prefix. It does not receive expected categories, invariants, source or sink constraints, evidence requirements, eligibility, score weights, or tool identity. The matcher introduces expectations only after normalization.
