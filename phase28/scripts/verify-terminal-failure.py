#!/usr/bin/env python3
"""Independently verify the scanner-free Phase 28 terminal-failure seal."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess


REPO = Path(__file__).resolve().parents[2]
PHASE = REPO / "phase28"
ATTEMPT = PHASE / "evidence/attempts/001-p28-secure-engine-0-1-7-rc1-001"
BASE = "9d7ff67f7b360c9b70112d32445091671070ac57"
GENESIS = "5b48aec431ad335cd788022d9b87aa3da1f34a2fff002a9138205b817c1c61f0"


def fail(message: str) -> None:
    raise ValueError(message)


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load(path: Path) -> object:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def verify_ledger(summary: dict[str, object]) -> None:
    entries = [json.loads(line) for line in (PHASE / "ledger/execution.jsonl").read_text(encoding="utf-8").splitlines()]
    if len(entries) != 3 or [entry["event"] for entry in entries] != ["genesis", "attempt-consumed", "terminal-close"]:
        fail("terminal ledger shape differs")
    previous = GENESIS
    for sequence, entry in enumerate(entries):
        core = {key: value for key, value in entry.items() if key != "entry_hash"}
        expected = hashlib.sha256(canonical(core)).hexdigest()
        if entry["sequence"] != sequence or entry["previous_entry_hash"] != previous or entry["entry_hash"] != expected:
            fail(f"terminal ledger chain differs at {sequence}")
        previous = entry["entry_hash"]
    if summary["ledger"]["head"] != previous:
        fail("terminal ledger head differs")


def verify_checksums() -> None:
    expected: set[str] = set()
    for line in (PHASE / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        digest, relative = line.split("  ", 1)
        path = REPO / relative
        if relative in expected or not path.is_file() or sha(path) != digest:
            fail(f"checksum differs: {relative}")
        expected.add(relative)
    actual = {
        str(path.relative_to(REPO))
        for path in PHASE.rglob("*")
        if path.is_file()
        and path.name != "SHA256SUMS"
        and "target" not in path.relative_to(PHASE).parts
        and "__pycache__" not in path.relative_to(PHASE).parts
    }
    if expected != actual:
        fail("SHA256SUMS coverage differs")
    inventory = load(PHASE / "inventory.json")
    inventory_paths = {entry["path"] for entry in inventory["entries"]}
    inventory_actual = actual - {"phase28/inventory.json"}
    if inventory_paths != inventory_actual:
        fail("terminal inventory coverage differs")
    for entry in inventory["entries"]:
        path = REPO / entry["path"]
        if entry["size_bytes"] != path.stat().st_size or entry["sha256"] != sha(path):
            fail(f"inventory entry differs: {entry['path']}")


def verify_processes() -> None:
    prohibited = {"secure", "secure-engine", "opengrep", "semgrep", "semgrep-core", "joern", "ollama"}
    observed = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            name = (entry / "comm").read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if name in prohibited:
            observed.append((entry.name, name))
    if observed:
        fail(f"prohibited processes are active: {observed}")


def git(*arguments: str) -> str:
    return subprocess.run(["git", *arguments], cwd=REPO, check=True, capture_output=True, text=True).stdout.strip()


def main() -> None:
    marker = load(PHASE / "IRREVERSIBLE_OPEN.json")
    started = load(ATTEMPT / "started.json")
    record = load(PHASE / "attempt-record.json")
    failure = load(PHASE / "failure-analysis.json")
    summary = load(PHASE / "terminal-summary.json")
    audit = load(PHASE / "audit/terminal.json")
    provenance = load(PHASE / "provenance.json")
    attempts = list((PHASE / "evidence/attempts").iterdir())
    if marker["git"]["head"] != BASE or marker["plan"]["attempt_count"] != 336 or marker["plan"]["retry_count"] != 0:
        fail("irreversible marker identity differs")
    if len(attempts) != 1 or started["sequence"] != 1 or started["retry_ordinal"] != 0:
        fail("consumed attempt evidence differs")
    if record["attempt_status"] != "partial-consumed" or not record["scanner_process"]["completed"]:
        fail("attempt was not sealed as partial/consumed")
    if record["scanner_process"]["exit_code"] != 0 or record["scanner_process"]["signal"] is not None:
        fail("scanner process status differs")
    raw = (ATTEMPT / "raw.json").read_bytes()
    if sha(ATTEMPT / "raw.json") != "2bfebba3a99d9442e9e56c7b5ffdc132e2e5076872b04b42fa8c9b57b209a8f3":
        fail("preserved raw JSON hash differs")
    if not isinstance(json.loads(raw.decode("utf-8")), dict):
        fail("preserved raw JSON is not parseable")
    if record["adapter_stage"]["started"] or Path(record["adapter_stage"]["expected_helper_path"]).exists():
        fail("native helper terminal state differs")
    if failure["status"] != "terminal-failed" or failure["scoring"] != "forbidden":
        fail("failure analysis differs")
    expected_counts = {"planned": 336, "consumed": 1, "valid_completed": 0, "partial": 1, "out_of_scope": 335, "retries": 0}
    if summary["status"] != "terminal-failed" or summary["attempts"] != expected_counts:
        fail("terminal summary accounting differs")
    if any(audit[key] != expected_counts[key] for key in expected_counts):
        fail("terminal audit accounting differs")
    if audit["opengrep_processes"] != 0 or audit["semgrep_processes"] != 0 or audit["scoring_files"] != 0:
        fail("terminal audit records unauthorized execution or scoring")
    if provenance["base_commit"] != BASE or provenance["retries"] != 0:
        fail("terminal provenance differs")
    forbidden_results = [PHASE / "results.json", PHASE / "comparison.json"]
    if any(path.exists() for path in forbidden_results):
        fail("scoring artifacts must not exist")
    verify_ledger(summary)
    verify_checksums()
    verify_processes()
    if git("rev-parse", "HEAD") != BASE or git("rev-parse", "main") != BASE:
        fail("base or main differs during terminal verification")
    branch = git("branch", "--show-current")
    if branch != "codex/phase-28-one-shot-independent-holdout-v2-execution":
        fail("Phase 28 branch differs")
    upstream = subprocess.run(
        ["git", "rev-parse", "--abbrev-ref", "@{upstream}"], cwd=REPO, capture_output=True, check=False
    )
    if upstream.returncode == 0:
        fail("Phase 28 branch unexpectedly has an upstream")
    for commit, path in (
        ("540502c8bf1f139c7d54cb5f6e7c29ce97ffb934", "phase27"),
        ("0f6fe9f06f1f88233e6d537b9c4e1d826575d0ee", "phase27-1"),
        ("467413eeb2a22017b5bc19f7f2052fdbc5d43d0d", "phase27-2"),
        (BASE, "phase27-3"),
    ):
        if subprocess.run(["git", "diff", "--quiet", commit, "--", path], cwd=REPO, check=False).returncode != 0:
            fail(f"historical phase differs: {path}")
    stash_objects = set(git("stash", "list", "--format=%H").splitlines())
    required_stashes = {
        "a5f8d978f21dae028eb722a5e73e12d858eeecb2",
        "73905cd14490f6bbe542dbd80c9f9b0c5889a3cf",
    }
    if not required_stashes <= stash_objects:
        fail("required Phase 28 stashes differ")
    print(
        "phase28_terminal_verification=PASS status=terminal-failed "
        "valid_completed=0 partial_consumed=1 out_of_scope=335 retries=0 "
        "scanner_processes_during_verification=0"
    )


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError, subprocess.CalledProcessError) as error:
        print(f"FAIL: {error}")
        raise SystemExit(1)
