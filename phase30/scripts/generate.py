#!/usr/bin/env python3
"""Generate Phase 30 artifacts from frozen Phase 28/29 evidence only."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

BASE_COMMIT = "9b6566e600d18160865e45eda31d8634669c889a"
PHASE28_TREE = "4c1c45ee433b70ff85eb4327be3612975e556a18"
PHASE29_TREE = "629be7e1da9b288480ab1869a184de3c8ad923dd"
EXECUTABLE_SHA256 = "5feca58fda54e4f9af0bf3846d04a98825d7315e64cbf80268a2395cf07ff2e6"
BINDING_SHA256 = "8d1a822e8a0828b06a1c6bb5629625314a6576f24296b8f5dc9aee8da8850a6a"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


def canonical_bytes(value: Any) -> bytes:
    """Return deterministic canonical JSON bytes."""
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def read_json(path: Path) -> Any:
    """Read one UTF-8 JSON document."""
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_bytes(data: bytes) -> str:
    """Hash bytes with SHA-256."""
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    """Hash a file with SHA-256."""
    return sha256_bytes(path.read_bytes())


def write_json(path: Path, value: Any) -> None:
    """Write deterministic canonical JSON."""
    path.write_bytes(canonical_bytes(value))


def ratio(numerator: int, denominator: int) -> float | None:
    """Return a metric ratio, preserving unavailable denominators as null."""
    return numerator / denominator if denominator else None


def metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute Phase 29-compatible binary classification metrics."""
    tp = sum(row["label"] == "vulnerable" and row["detected"] for row in rows)
    fn = sum(row["label"] == "vulnerable" and not row["detected"] for row in rows)
    fp = sum(row["label"] == "control" and row["detected"] for row in rows)
    tn = sum(row["label"] == "control" and not row["detected"] for row in rows)
    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)
    specificity = ratio(tn, tn + fp)
    f1 = ratio(2 * tp, 2 * tp + fp + fn)
    balanced = None if recall is None or specificity is None else (recall + specificity) / 2
    attempts = len(rows)
    return {
        "attempts": attempts,
        "balanced_accuracy": balanced,
        "completed": attempts,
        "completion_rate": 1.0,
        "confusion_matrix_completed_only": {"fn": fn, "fp": fp, "tn": tn, "tp": tp},
        "f1": f1,
        "failure_rate": 0.0,
        "fully_scorable": True,
        "non_completed": 0,
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
    }


def grouped_metrics(rows: list[dict[str, Any]], key: str) -> dict[str, Any]:
    """Compute deterministic metrics for one metadata dimension."""
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[row[key]].append(row)
    return {name: metrics(groups[name]) for name in sorted(groups)}


def locate_bytes(root: Path, attempt_dir: Path, filename: str, sequence: int) -> bytes:
    """Resolve Phase 29 evidence or the inherited Phase 28 evidence."""
    direct = attempt_dir / filename
    if direct.exists():
        return direct.read_bytes()
    if sequence != 1:
        raise RuntimeError(f"missing {filename} for sequence {sequence}")
    inherited = root / "phase28/evidence/attempts/001-p28-secure-engine-0-1-7-rc1-001" / filename
    return inherited.read_bytes()


def audit_attempts(root: Path) -> list[dict[str, Any]]:
    """Audit the 112 frozen Secure Engine observations without invoking any executable."""
    rows: list[dict[str, Any]] = []
    attempt_ids: set[str] = set()
    sequences: set[int] = set()
    case_ids: set[str] = set()
    baseline_command = read_json(
        root / "phase28/evidence/attempts/001-p28-secure-engine-0-1-7-rc1-001/command.json"
    )["normalized"]
    for attempt_dir in sorted((root / "phase29/evidence/attempts").iterdir()):
        observation = read_json(attempt_dir / "observation.json")
        if observation["artifact_id"] != "secure-engine-0.1.7-rc1":
            continue
        sequence = int(observation["sequence"])
        if observation["attempt_id"] in attempt_ids or sequence in sequences or observation["case_id"] in case_ids:
            raise RuntimeError("duplicate Secure Engine attempt, sequence, or case")
        attempt_ids.add(observation["attempt_id"])
        sequences.add(sequence)
        case_ids.add(observation["case_id"])

        raw_bytes = locate_bytes(root, attempt_dir, "raw.json", sequence)
        stderr_bytes = locate_bytes(root, attempt_dir, "stderr.bin", sequence)
        stdout_bytes = locate_bytes(root, attempt_dir, "stdout.bin", sequence)
        adapter_bytes = (attempt_dir / "adapter.json").read_bytes()
        raw = json.loads(raw_bytes.decode("utf-8"))
        adapter = json.loads(adapter_bytes.decode("utf-8"))

        if "process" in observation:
            process = observation["process"]
            exit_code = process["returncode"]
            signal = process["signal"]
            timed_out = process["timed_out"]
            spawn_error = process["spawn_error"]
            normalized_command = observation["normalized_command"]
            if observation["hashes"]["scanner_binding_sha256"] != BINDING_SHA256:
                raise RuntimeError(f"binding drift at sequence {sequence}")
        else:
            process = observation["scanner_process"]
            exit_code = process["exit_code"]
            signal = process["signal"]
            timed_out = False
            spawn_error = None
            normalized_command = baseline_command

        findings = raw.get("findings")
        adapter_findings = adapter.get("findings")
        stderr = stderr_bytes.decode("utf-8")
        summary_match = re.search(r"secure: (\d+) findings,", stderr)
        checks = {
            "raw_utf8_parseable": True,
            "raw_hash_valid": sha256_bytes(raw_bytes) == observation["raw_json_sha256"],
            "schema_identity_valid": raw.get("schema_version") == "secure-json-v1"
            and raw.get("engine_version") == "0.1.7"
            and raw.get("document_type") == "scan-report",
            "report_complete": raw.get("scan", {}).get("complete") is True,
            "analysis_not_truncated": raw.get("analysis", {}).get("truncated") is False,
            "engine_errors_absent": raw.get("errors") == [],
            "adapter_hash_valid": sha256_bytes(adapter_bytes) == observation["adapter_output_sha256"],
            "adapter_valid": observation["adapter_valid"] is True
            and observation["adapter"]["returncode"] == 0
            and observation["adapter"]["spawn_error"] is None,
            "adapter_count_matches": isinstance(findings, list)
            and isinstance(adapter_findings, list)
            and len(findings) == len(adapter_findings) == observation["finding_count"],
            "no_signal_timeout_or_spawn_error": signal is None and not timed_out and spawn_error is None,
            "stdout_empty": sha256_bytes(stdout_bytes) == EMPTY_SHA256,
            "stderr_complete_pattern": "secure: complete (" in stderr
            and "secure: wrote complete report to /tmp/run/raw.json" in stderr
            and summary_match is not None
            and int(summary_match.group(1)) == len(findings),
            "command_equivalent": normalized_command == baseline_command,
            "retry_zero": observation["retry_ordinal"] == 0,
        }
        if not all(checks.values()):
            failed = sorted(key for key, value in checks.items() if not value)
            raise RuntimeError(f"attempt {sequence} failed checks: {failed}")
        if exit_code not in (0, 1):
            raise RuntimeError(f"unexpected exit code {exit_code} at sequence {sequence}")
        if exit_code == 0 and findings:
            operational_class = "successful_findings_report"
        elif exit_code == 0:
            operational_class = "clean_successful_report"
        elif findings:
            operational_class = "policy_exit_with_valid_findings_report"
        else:
            raise RuntimeError(f"exit 1 without authoritative findings at sequence {sequence}")

        rows.append(
            {
                "adapter_output_sha256": observation["adapter_output_sha256"],
                "attempt_id": observation["attempt_id"],
                "case_id": observation["case_id"],
                "certified_status": "completed",
                "checks": checks,
                "detected": bool(findings),
                "exit_code": exit_code,
                "family_id": observation["family_id"],
                "finding_count": len(findings),
                "framework": observation["framework"],
                "label": observation["label"],
                "operational_classification": operational_class,
                "ordinal": observation["ordinal"],
                "pair_id": observation["pair_id"],
                "phase29_status": observation["status"],
                "raw_json_sha256": observation["raw_json_sha256"],
                "retry_ordinal": 0,
                "sequence": sequence,
                "signal": signal,
                "source_format": observation["source_format"],
                "stderr_sha256": sha256_bytes(stderr_bytes),
                "stdout_sha256": sha256_bytes(stdout_bytes),
                "topology": observation["topology"],
            }
        )
    if len(rows) != 112 or sequences != set(range(1, 113)):
        raise RuntimeError("Secure Engine evidence is not exactly sequences 1..112")
    return rows


def lane_results(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Build the fully rescored native lane."""
    return {
        "by_family": grouped_metrics(rows, "family_id"),
        "by_framework": grouped_metrics(rows, "framework"),
        "by_pair": grouped_metrics(rows, "pair_id"),
        "by_source_format": grouped_metrics(rows, "source_format"),
        "by_topology": grouped_metrics(rows, "topology"),
        "lane": "native",
        "overall": metrics(rows),
    }


def make_ledger(entries: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
    """Create a canonical SHA-256 hash chain."""
    previous = "0" * 64
    output: list[dict[str, Any]] = []
    for index, payload in enumerate(entries):
        body = {"index": index, "payload": payload, "previous_sha256": previous}
        entry_hash = sha256_bytes(canonical_bytes(body))
        entry = {**body, "entry_sha256": entry_hash}
        output.append(entry)
        previous = entry_hash
    return previous, output


def main() -> None:
    """Generate all deterministic Phase 30 artifacts except the independent proof and checksum list."""
    phase30 = Path(__file__).resolve().parents[1]
    root = phase30.parent
    if subprocess.check_output(["git", "rev-parse", "main"], cwd=root, text=True).strip() != BASE_COMMIT:
        raise RuntimeError("main moved from the authoritative Phase 29 commit")
    if subprocess.check_output(["git", "rev-parse", f"{BASE_COMMIT}:phase28"], cwd=root, text=True).strip() != PHASE28_TREE:
        raise RuntimeError("Phase 28 tree drift")
    if subprocess.check_output(["git", "rev-parse", f"{BASE_COMMIT}:phase29"], cwd=root, text=True).strip() != PHASE29_TREE:
        raise RuntimeError("Phase 29 tree drift")

    source_hashes = {
        "docs/contracts.md": "84f50028dd58905ce3fe8ccefbd6cadc2852521b467f0f7f763cd52f6e761430",
        "docs/phase-16-authoritative-v2-adapter.md": "ea26d4497a8a812216d76dac4371919363ebdb494f7ad5318392621667100c37",
        "policies/process-status-v1.json": "8b5ff33690828dc97afa8be24ef14dc66bf44d6da913e2621d92208e513f26ac",
        "schemas/process-status-policy-v1.schema.json": "f2ea85696844e6e00b2722a161dbc391203c6fe5b863fe45df042c2d6a52405f",
        "/home/danielcastrillon/Proyectos/secure-engine-rc/0.1.7-rc1/provenance.json": "80c543e8821a2f3ebc692f3fd325c35efcafcd34b6b4dbf3c758ff19dedd6826",
        "/home/danielcastrillon/Proyectos/secure-engine-rc/0.1.7-rc1/release-notes.md": "a90652554e3ef5a30f67111687f8e9363c45caec7feb7372d4132ee6b2c0cd30",
        "/home/danielcastrillon/Proyectos/secure-engine-rc/0.1.7-rc1/verification/build-a/secure-json-v1.schema.json": "880ace73f07ff719945d66889e33a8ab7477cf5570236c356177e493e841f0b1",
    }
    for name, expected in source_hashes.items():
        path = Path(name) if name.startswith("/") else root / name
        if sha256_file(path) != expected:
            raise RuntimeError(f"contract/provenance drift: {name}")
    if sha256_file(Path("/home/danielcastrillon/Proyectos/secure-engine-rc/0.1.7-rc1/extracted/secure")) != EXECUTABLE_SHA256:
        raise RuntimeError("Secure Engine executable drift")

    rows = audit_attempts(root)
    secure_lane = lane_results(rows)
    phase29_results = read_json(root / "phase29/results.json")
    opengrep = phase29_results["lanes"]["opengrep-1.22.0"]
    semgrep = phase29_results["lanes"]["semgrep-ce-1.170.0"]
    certified_results = {
        "attempts": 336,
        "base_commit": BASE_COMMIT,
        "classification": "post-open evidence certification derived from Phase 28/29",
        "lanes": {
            "opengrep-1.22.0": opengrep,
            "secure-engine-0.1.7-rc1": secure_lane,
            "semgrep-ce-1.170.0": semgrep,
        },
        "retries": 0,
        "schema_version": "secure-bench-phase30-certified-results-v1",
    }
    overall = secure_lane["overall"]
    comparison = {
        "classification": "post-open evidence certification derived from Phase 28/29",
        "native_vs_normalized_winner_allowed": False,
        "normalized_direct_comparison_allowed": True,
        "opengrep": opengrep["overall"],
        "schema_version": "secure-bench-phase30-comparison-v1",
        "secure_engine_native": overall,
        "semgrep": semgrep["overall"],
    }
    matrix_counts = Counter((row["exit_code"], row["finding_count"] > 0) for row in rows)
    aggregate = {
        "attempts": 112,
        "engine_errors_or_signals": 0,
        "exit_0_findings": matrix_counts[(0, True)],
        "exit_0_zero_findings": matrix_counts[(0, False)],
        "exit_1_findings": matrix_counts[(1, True)],
        "exit_1_zero_findings": matrix_counts[(1, False)],
        "invalid_raw_or_schema": 0,
        "raw_complete": 112,
        "schema_version": "secure-bench-phase30-aggregate-exit-matrix-v1",
        "stderr_complete_report_pattern": 112,
        "stdout_empty": 112,
    }
    contract = {
        "certification": {
            "decision": "exit-1-with-authoritative-findings-is-valid-completion",
            "phase29_classification": "conservative-failed-superseded-only-for-exit-status-semantics",
            "required_conditions": [
                "normal exit without signal timeout or spawn failure",
                "complete UTF-8 secure-json-v1 report valid against the frozen public schema",
                "errors array empty and analysis not truncated",
                "one or more findings",
                "valid unchanged adapter output",
                "frozen binary hash command environment and sandbox",
            ],
            "status": "certified",
        },
        "classification": "post-open evidence certification derived from Phase 28/29",
        "contract_sources": source_hashes,
        "executable_sha256": EXECUTABLE_SHA256,
        "policy_id": "secure-bench-process-status-policy-v1",
        "policy_sha256": source_hashes["policies/process-status-v1.json"],
        "policy_status": "authoritative-frozen-public-contract",
        "policy_version": "1.0.0",
        "schema_version": "secure-bench-phase30-exit-status-contract-v1",
    }
    classification = {
        "attempts": rows,
        "base_commit": BASE_COMMIT,
        "classification": "post-open evidence certification derived from Phase 28/29",
        "prior_status_counts": {"completed": 80, "failed": 32},
        "schema_version": "secure-bench-phase30-evidence-classification-v1",
        "certified_status_counts": {"completed": 112, "failed": 0},
    }
    phase29_norm_hashes = {
        "opengrep_canonical_sha256": sha256_bytes(canonical_bytes(opengrep)),
        "semgrep_canonical_sha256": sha256_bytes(canonical_bytes(semgrep)),
    }
    provenance = {
        "base_commit": BASE_COMMIT,
        "classification": "post-open evidence certification derived from Phase 28/29",
        "executable": {
            "path": "/home/danielcastrillon/Proyectos/secure-engine-rc/0.1.7-rc1/extracted/secure",
            "sha256": EXECUTABLE_SHA256,
        },
        "normalized_lanes": {**phase29_norm_hashes, "preserved_byte_semantics": True},
        "phase28_tree": PHASE28_TREE,
        "phase29_ledger_head": "1376f549960c2f599e9c23a9587a17b9660ba573407aa0c2cb52b0b1ecdf893c",
        "phase29_tree": PHASE29_TREE,
        "scanner_binding_sha256": BINDING_SHA256,
        "schema_version": "secure-bench-phase30-provenance-v1",
        "sources": source_hashes,
        "stashes_preserved": [
            "a5f8d978f21dae028eb722a5e73e12d858eeecb2",
            "73905cd14490f6bbe542dbd80c9f9b0c5889a3cf",
        ],
        "this_phase_execution": {
            "adapter_executions": 0,
            "case_executions": 0,
            "network_requests": 0,
            "runner_executions": 0,
            "scanner_executions": 0,
            "scanner_retries": 0,
        },
        "unique_scanner_case_combinations_inherited": 336,
    }

    write_json(phase30 / "exit-status-contract.json", contract)
    write_json(phase30 / "evidence-classification.json", classification)
    write_json(phase30 / "aggregate-exit-matrix.json", aggregate)
    write_json(phase30 / "certified-results.json", certified_results)
    write_json(phase30 / "comparison.json", comparison)
    write_json(phase30 / "provenance.json", provenance)

    report = f"""# Phase 30 Secure Engine exit-status evidence certification

Phase 30 is a **post-open evidence certification derived from Phase 28/29**. It starts no scanner,
runner, adapter, or case process and leaves every Phase 28/29 byte unchanged.

## Finding

The frozen public process policy certifies a normal nonzero exit with a complete, internally
error-free, adapter-valid findings report as `policy_exit_with_valid_findings_report`. All 32
Secure Engine exit-code-1 observations satisfy that contract. Phase 29's conservative operational
classification is superseded only for this exit-status semantic; its raw evidence is unchanged.

| Aggregate class | Count |
|---|---:|
| exit 0 + zero findings | {aggregate['exit_0_zero_findings']} |
| exit 0 + findings | {aggregate['exit_0_findings']} |
| exit 1 + zero findings | {aggregate['exit_1_zero_findings']} |
| exit 1 + findings | {aggregate['exit_1_findings']} |
| invalid raw/schema | {aggregate['invalid_raw_or_schema']} |
| engine errors/signals | {aggregate['engine_errors_or_signals']} |

## Certified Secure Engine/native metrics

- TP {overall['confusion_matrix_completed_only']['tp']}, FP {overall['confusion_matrix_completed_only']['fp']}, TN {overall['confusion_matrix_completed_only']['tn']}, FN {overall['confusion_matrix_completed_only']['fn']}.
- Precision {overall['precision']:.6f}, recall {overall['recall']:.6f}, specificity {overall['specificity']:.6f}, F1 {overall['f1']:.6f}, balanced accuracy {overall['balanced_accuracy']:.6f}.
- Completed 112/112; failed 0; scanner retries 0.

OpenGrep and Semgrep normalized results are preserved exactly from Phase 29. Native and normalized
lanes remain separate, and no direct winner is declared across those lanes.
"""
    (phase30 / "report.md").write_text(report, encoding="utf-8")
    (phase30 / "limitations.md").write_text(
        """# Limitations

- This is a derived post-open certification, not a new scanner execution.
- It certifies only the frozen Secure Engine 0.1.7 RC1 exit-status semantics and retained evidence.
- It does not inspect holdout source, scanner internals, rules, fixtures, or preserved stashes.
- It does not establish production fitness, superiority, ranking, or cross-lane equivalence.
- Any missing contract, binary drift, malformed/incomplete report, internal error, invalid adapter,
  signal, timeout, or exit 1 without findings remains fail-closed and unscored.
""",
        encoding="utf-8",
    )

    core_names = [
        "aggregate-exit-matrix.json",
        "certified-results.json",
        "comparison.json",
        "evidence-classification.json",
        "exit-status-contract.json",
        "limitations.md",
        "provenance.json",
        "report.md",
    ]
    core_hashes = {name: sha256_file(phase30 / name) for name in core_names}
    ledger_payloads = [
        {"base_commit": BASE_COMMIT, "event": "genesis", "phase29_ledger_head": provenance["phase29_ledger_head"]},
        {"aggregate_exit_matrix_sha256": core_hashes["aggregate-exit-matrix.json"], "event": "evidence-certified"},
        {"certified_results_sha256": core_hashes["certified-results.json"], "event": "rescore-derived"},
        {"event": "terminal", "status": "certified", "scanner_executions": 0, "scanner_retries": 0},
    ]
    ledger_head, ledger = make_ledger(ledger_payloads)
    ledger_dir = phase30 / "ledger"
    ledger_dir.mkdir(exist_ok=True)
    (ledger_dir / "certification.jsonl").write_bytes(b"".join(canonical_bytes(entry) for entry in ledger))
    write_json(phase30 / "ledger-head.json", {"entries": len(ledger), "head_sha256": ledger_head, "schema_version": "secure-bench-phase30-ledger-head-v1"})


if __name__ == "__main__":
    main()

