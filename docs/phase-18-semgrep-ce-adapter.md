# Phase 18: Semgrep Community Edition adapter

Phase 18 pins the official PyPI Semgrep 1.170.0 Linux x86-64 wheel and the complete 66-wheel CPython 3.14 dependency closure. The repository records each selected filename, version, SHA-256, PyPI artifact URL, upstream source URL, declared license, upload time, and available PyPI attestation URL. Packages and the isolated virtual environment remain outside the repository.

The PyPI wheel is LGPL-2.1-or-later and hashes to `09a7e8eeff5e2549161124957184f3566f484370aa6127e425897cef725eb99b`. Its public PyPI Sigstore attestation binds that digest but identifies `semgrep/semgrep-proprietary/.github/workflows/pro-release.yml@refs/heads/develop` as publisher. This boundary is disclosed: no proprietary repository source was inspected, no Pro flag or token was used, and the adapter rejects any report not explicitly marked OSS.

Execution used only `phase18/fixtures/conformance/workspace` with the exact unchanged Phase 17 rule bytes (`a9b0c304d6f12c00f7efa6bb648fe97b9d4b64c49e97fffccc0287cf03f97a96`). The command forces `--metrics=off` and `--disable-version-check`; the environment also sets `SEMGREP_SEND_METRICS=off` and `SEMGREP_ENABLE_VERSION_CHECK=0`, unsets token/proxy variables, uses only a local `--config`, and runs under `bubblewrap --unshare-net`.

The adapter admits rule ID, validated primary location and offsets, nonempty raw message, raw severity, and uninterpreted rule metadata. It does not infer source or sink identities, connected paths, guards, sanitizers, CWE, taxonomy, confidence, absent severity, or a login-gated fingerprint. Those dimensions remain unavailable. Finding adaptation and process adjudication are separate; timeout and exit-code evidence never comes from JSON.

Ten disclosed JSON vectors cover clean, findings, duplicates, malformed syntax, partial errors, unknown rules, invalid spans, absolute paths, traversal, and non-CE engine output. Four independent process vectors cover normal findings exit, unexpected nonzero findings exit, timeout, and unexpected nonzero clean exit. Repeated adaptation, byte-for-byte raw preservation, raw hashes, JSON Schema, privacy, symlinks, provenance, package closure, and historical integrity are verified offline.

Native and capability-normalized lanes remain separate declarations and were not executed. Phase 18 produces no comparison, score, rank, or superiority claim and does not execute any private/frozen holdout or Phase 13/14 material.
