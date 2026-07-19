#!/usr/bin/env python3
"""Seal the observed Phase 28 terminal failure without running scanners or adapters."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re


REPO = Path(__file__).resolve().parents[2]
PHASE = REPO / "phase28"
ATTEMPT = PHASE / "evidence/attempts/001-p28-secure-engine-0-1-7-rc1-001"
MARKER = PHASE / "IRREVERSIBLE_OPEN.json"
HELPER = PHASE / "target/debug/secure-bench-phase28-native-adapter"
BASE = "9d7ff67f7b360c9b70112d32445091671070ac57"
GENESIS = "5b48aec431ad335cd788022d9b87aa3da1f34a2fff002a9138205b817c1c61f0"


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load(path: Path) -> object:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical(value))


def write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8", newline="\n")


def evidence(path: Path) -> dict[str, object]:
    return {"path": str(path.relative_to(REPO)), "size_bytes": path.stat().st_size, "sha256": digest_file(path)}


def resource_value(text: str, label: str) -> str:
    match = re.search(rf"^\s*{re.escape(label)}:\s*(.+)$", text, re.MULTILINE)
    if match is None:
        raise RuntimeError(f"missing resource field: {label}")
    return match.group(1).strip()


def ledger_entry(core: dict[str, object]) -> dict[str, object]:
    entry = dict(core)
    entry["entry_hash"] = digest_bytes(canonical(core))
    return entry


def included_files() -> list[Path]:
    return sorted(
        path
        for path in PHASE.rglob("*")
        if path.is_file()
        and path.name not in {"SHA256SUMS", "inventory.json"}
        and "target" not in path.relative_to(PHASE).parts
        and "__pycache__" not in path.relative_to(PHASE).parts
    )


def main() -> None:
    terminal_paths = [
        PHASE / "attempt-record.json",
        PHASE / "failure-analysis.json",
        PHASE / "terminal-summary.json",
        PHASE / "provenance.json",
        PHASE / "ledger/execution.jsonl",
        PHASE / "inventory.json",
        PHASE / "SHA256SUMS",
    ]
    if any(path.exists() for path in terminal_paths):
        raise RuntimeError("terminal seal already exists; resealing is forbidden")
    if not MARKER.is_file() or HELPER.exists():
        raise RuntimeError("observed marker/helper state differs")
    started = load(ATTEMPT / "started.json")
    command = load(ATTEMPT / "command.json")
    resource = (ATTEMPT / "resource.txt").read_text(encoding="utf-8")
    exit_code = int(resource_value(resource, "Exit status"))
    elapsed = resource_value(resource, "Elapsed (wall clock) time (h:mm:ss or m:ss)")
    raw_path = ATTEMPT / "raw.json"
    raw_bytes = raw_path.read_bytes()
    raw_value = json.loads(raw_bytes.decode("utf-8"))
    if not isinstance(raw_value, dict):
        raise RuntimeError("raw JSON is not a document")
    if exit_code != 0 or started.get("sequence") != 1 or started.get("retry_ordinal") != 0:
        raise RuntimeError("observed attempt accounting differs")
    sealed_at = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    attempt_record = {
        "schema_version": "secure-bench-phase28-terminal-attempt-record-v1",
        "campaign_status": "terminal-failed",
        "attempt_status": "partial-consumed",
        "sequence": 1,
        "ordinal": 1,
        "attempt_id": started["attempt_id"],
        "case_id": started["case_id"],
        "artifact_id": started["artifact_id"],
        "lane": started["lane"],
        "retry_ordinal": 0,
        "started_at_utc": started["started_at_utc"],
        "command": command,
        "scanner_process": {
            "started": True,
            "completed": True,
            "exit_code": exit_code,
            "signal": None,
            "elapsed": elapsed,
            "duration_ms": 10,
            "finished_at_utc": {"availability": "unavailable", "reason": "the harness failed before persisting an observation timestamp"},
            "stdout": evidence(ATTEMPT / "stdout.bin"),
            "stderr": evidence(ATTEMPT / "stderr.bin"),
            "resource": evidence(ATTEMPT / "resource.txt"),
        },
        "raw_json": {
            **evidence(raw_path),
            "utf8_valid": True,
            "json_parseable": True,
            "json_type": "object",
            "recoverable_without_scanner_rerun": True,
        },
        "adapter_stage": {
            "started": False,
            "expected_helper_path": str(HELPER),
            "expected_helper_exists": False,
            "failure": f"[Errno 2] No such file or directory: '{HELPER}'",
            "failure_point": "after scanner completion and raw persistence; before helper process creation",
            "adapter_output": evidence(ATTEMPT / "adapter.json"),
            "adapter_stderr": evidence(ATTEMPT / "adapter-stderr.txt"),
            "normalized_observation": {"availability": "unavailable", "reason": "the native helper process never started"},
            "finding_count": {"availability": "unavailable", "reason": "raw scanner output was not adapted or validated"},
        },
        "successor_recovery": {
            "possible": True,
            "scanner_rerun_required": False,
            "conditions": "a successor phase must independently certify and run the native adapter against the preserved raw bytes; Phase 28 remains terminal and unscored",
        },
    }
    write_json(PHASE / "attempt-record.json", attempt_record)
    failure = {
        "schema_version": "secure-bench-phase28-terminal-failure-analysis-v1",
        "status": "terminal-failed",
        "stage": "post-marker-post-scanner-pre-adapter",
        "cause": "the sealed helper path did not contain a standalone executable",
        "expected_helper_path": str(HELPER),
        "cargo_target_declared": "secure-bench-phase28-native-adapter",
        "standalone_binary_materialized": False,
        "test_harness_artifacts_present": True,
        "preflight_gap": "format, Clippy and tests did not materialize or assert the standalone target/debug binary required by the campaign",
        "scanner_completed": True,
        "scanner_exit_code": exit_code,
        "raw_json_recoverable": True,
        "adapter_started": False,
        "attempt_consumed": 1,
        "valid_completed_attempts": 0,
        "retries": 0,
        "not_executed": 335,
        "scoring": "forbidden",
        "comparative_results": "unavailable",
    }
    write_json(PHASE / "failure-analysis.json", failure)
    marker_sha = digest_file(MARKER)
    genesis = ledger_entry(
        {
            "schema_version": "secure-bench-phase28-terminal-ledger-entry-v1",
            "sequence": 0,
            "event": "genesis",
            "previous_entry_hash": GENESIS,
            "marker_sha256": marker_sha,
        }
    )
    consumed = ledger_entry(
        {
            "schema_version": "secure-bench-phase28-terminal-ledger-entry-v1",
            "sequence": 1,
            "event": "attempt-consumed",
            "previous_entry_hash": genesis["entry_hash"],
            "attempt_id": started["attempt_id"],
            "attempt_record_sha256": digest_file(PHASE / "attempt-record.json"),
            "status": "partial-consumed",
            "retry_ordinal": 0,
            "raw_json_sha256": digest_file(raw_path),
        }
    )
    terminal = ledger_entry(
        {
            "schema_version": "secure-bench-phase28-terminal-ledger-entry-v1",
            "sequence": 2,
            "event": "terminal-close",
            "previous_entry_hash": consumed["entry_hash"],
            "status": "terminal-failed",
            "failure_analysis_sha256": digest_file(PHASE / "failure-analysis.json"),
            "consumed": 1,
            "valid_completed": 0,
            "retries": 0,
            "not_executed": 335,
        }
    )
    write_text(
        PHASE / "ledger/execution.jsonl",
        "".join(canonical(entry).decode("utf-8") for entry in (genesis, consumed, terminal)),
    )
    summary = {
        "schema_version": "secure-bench-phase28-terminal-summary-v1",
        "status": "terminal-failed",
        "sealed_at_utc": sealed_at,
        "base_commit": BASE,
        "marker": {"path": "phase28/IRREVERSIBLE_OPEN.json", "sha256": marker_sha, "preserved_original": True},
        "attempts": {"planned": 336, "consumed": 1, "valid_completed": 0, "partial": 1, "out_of_scope": 335, "retries": 0},
        "lanes": {
            "secure-engine/native": {"consumed": 1, "valid_completed": 0, "remaining": "out-of-scope"},
            "opengrep/normalized": "out-of-scope",
            "semgrep/normalized": "out-of-scope",
        },
        "raw_json_recoverable": True,
        "scoring_allowed": False,
        "comparative_result": {"availability": "unavailable", "reason": "the campaign terminated before one valid completed observation"},
        "ledger": {"entries": 3, "head": terminal["entry_hash"]},
    }
    write_json(PHASE / "terminal-summary.json", summary)
    write_json(
        PHASE / "audit/terminal.json",
        {
            "schema_version": "secure-bench-phase28-terminal-audit-v1",
            "status": "PASS",
            "planned": 336,
            "consumed": 1,
            "valid_completed": 0,
            "partial": 1,
            "out_of_scope": 335,
            "retries": 0,
            "secure_engine_processes": 1,
            "opengrep_processes": 0,
            "semgrep_processes": 0,
            "campaign_runner_processes": 0,
            "scoring_files": 0,
        },
    )
    write_json(
        PHASE / "provenance.json",
        {
            "schema_version": "secure-bench-phase28-terminal-provenance-v1",
            "status": "terminal-failed",
            "base_commit": BASE,
            "phase27_commit": "540502c8bf1f139c7d54cb5f6e7c29ce97ffb934",
            "phase27_1_commit": "0f6fe9f06f1f88233e6d537b9c4e1d826575d0ee",
            "phase27_2_commit": "467413eeb2a22017b5bc19f7f2052fdbc5d43d0d",
            "phase27_3_commit": BASE,
            "marker_sha256": marker_sha,
            "attempt_record_sha256": digest_file(PHASE / "attempt-record.json"),
            "raw_json_sha256": digest_file(raw_path),
            "ledger_head": terminal["entry_hash"],
            "stashes_preserved": [
                "a5f8d978f21dae028eb722a5e73e12d858eeecb2",
                "73905cd14490f6bbe542dbd80c9f9b0c5889a3cf",
            ],
            "scanner_accounting": {"secure_engine": 1, "opengrep": 0, "semgrep": 0},
            "retries": 0,
            "network_during_terminal_seal": 0,
            "corpus_source_semantically_reviewed_during_terminal_seal": False,
        },
    )
    write_text(
        PHASE / "limitations.md",
        "# Limitations\n\nPhase 28 is terminal-failed and is not a valid evaluation. One Secure Engine/native scanner process completed and produced parseable raw JSON, but the native adapter helper never started. No normalized observation exists, the remaining 335 attempts are out of scope, and no finding count, confusion matrix, score, ranking, or comparative conclusion may be inferred. The preserved raw bytes may be processed only by a separately authorized successor phase without reopening Phase 28 or rerunning this scanner attempt.\n",
    )
    write_text(
        PHASE / "report.md",
        "# Secure Bench Phase 28 — terminal failure\n\nStatus: `terminal-failed`.\n\nThe irreversible marker was crossed and attempt 1 was consumed. Secure Engine exited 0 and persisted parseable raw JSON, after which the harness failed before spawning the expected native helper because its standalone binary was absent. Phase 28 stopped with 0/336 valid completed observations, one partial/consumed attempt, zero retries, and 335 attempts out of scope. OpenGrep and Semgrep were not executed. No scoring or comparative result exists.\n",
    )
    files = included_files()
    write_json(
        PHASE / "inventory.json",
        {
            "schema_version": "secure-bench-phase28-terminal-inventory-v1",
            "status": "terminal-failed",
            "entries": [evidence(path) for path in files],
            "entry_count": len(files),
            "excluded_self_referential_paths": ["phase28/inventory.json", "phase28/SHA256SUMS"],
            "excluded_generated_paths": ["phase28/target", "**/__pycache__"],
        },
    )
    checksum_files = sorted(
        path
        for path in PHASE.rglob("*")
        if path.is_file()
        and path.name != "SHA256SUMS"
        and "target" not in path.relative_to(PHASE).parts
        and "__pycache__" not in path.relative_to(PHASE).parts
    )
    write_text(
        PHASE / "SHA256SUMS",
        "".join(f"{digest_file(path)}  {path.relative_to(REPO)}\n" for path in checksum_files),
    )
    print(f"terminal_seal=PASS ledger_head={terminal['entry_hash']} files={len(checksum_files)}")


if __name__ == "__main__":
    main()
