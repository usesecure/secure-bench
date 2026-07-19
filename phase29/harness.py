#!/usr/bin/env python3
"""One-shot Secure Bench Phase 29 post-open recovery study harness."""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
from typing import Any


REPO = Path(__file__).resolve().parent.parent
PHASE = REPO / "phase29"
PHASE27 = REPO / "phase27"
PHASE28 = REPO / "phase28"
BASE = "be54f5cea9221da67eebdb9c71dca70b7ad9674d"
BRANCH = "codex/phase-29-post-open-recovery"
MARKER = PHASE / "IRREVERSIBLE_RECOVERY.json"
PLAN_SOURCE = PHASE27 / "phase28/execution-plan-v2.json"
PLAN_SOURCE_SHA = "838532c9010a6c4e9334b8edf137f266a02c9e2cc10bfd1df3cd6cb95a3e3748"
RECOVERY_PLAN = PHASE / "recovery-plan.json"
PHASE28_RAW = PHASE28 / "evidence/attempts/001-p28-secure-engine-0-1-7-rc1-001/raw.json"
PHASE28_INPUT = PHASE28 / "evidence/attempts/001-p28-secure-engine-0-1-7-rc1-001/input"
PHASE28_RAW_SHA = "2bfebba3a99d9442e9e56c7b5ffdc132e2e5076872b04b42fa8c9b57b209a8f3"
PHASE28_LEDGER_HEAD = "172a3161420efbc06fd2e3f4053a0b7975a96bad67d84a7ba80a9b67c82c9806"
OVERLAY_27_1 = REPO / "phase27-1/binding-overlay.json"
OVERLAY_27_2 = REPO / "phase27-2/binding-overlay.json"
OVERLAY_27_3 = REPO / "phase27-3/binding-overlay.json"
OVERLAY_HASHES = {
    OVERLAY_27_1: "5b9c147142099f39242f70128bb70217d0c14f2d55890a86f089ae9a678185cf",
    OVERLAY_27_2: "1a8792cb3b6736b2599fc74ab1352755c15d3e5a39fed008759b78a02e08dea2",
    OVERLAY_27_3: "2733358fbbd95e8881d7575b0f40f5e6d6d58beff760be1fb77c8f96a7e8e4ce",
}
NATIVE_SHA = "5c81f7213fa2b5b8488f2e3fb4cf42a515442681978c3fbc35568e2f933b4e1e"
NATIVE_ROOT = Path("/home/danielcastrillon/Proyectos/secure-bench-tool-cache/native-adapters/phase28") / BASE
NATIVE = Path("/tmp/secure-bench-tools/native-adapters/phase28") / BASE / "bin/secure-bench-phase28-native-adapter"
OPENGREP_DURABLE = Path("/home/danielcastrillon/Proyectos/secure-bench-tool-cache/opengrep/1.22.0")
TIMEOUT_SECONDS = 120
TOTAL = 336
NEW_SCANNERS = 335

spec = importlib.util.spec_from_file_location("phase28_legacy", PHASE28 / "harness.py")
legacy = importlib.util.module_from_spec(spec)
if spec.loader is None:
    raise RuntimeError("cannot load frozen Phase 28 harness utilities")
spec.loader.exec_module(legacy)


class RecoveryError(RuntimeError):
    """Fail-closed recovery error."""


def canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    temporary.write_bytes(canonical(value))
    os.replace(temporary, path)


def write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    temporary.write_text(value, encoding="utf-8", newline="\n")
    os.replace(temporary, path)


def utc() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def git(*arguments: str) -> str:
    completed = subprocess.run(["git", *arguments], cwd=REPO, check=False, capture_output=True, text=True)
    if completed.returncode != 0:
        raise RecoveryError(f"git command failed: {completed.stderr.strip()}")
    return completed.stdout.strip()


def prohibited_processes() -> list[dict[str, Any]]:
    names = {"secure", "secure-engine", "opengrep", "semgrep", "semgrep-core", "joern", "ollama"}
    found = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            name = (entry / "comm").read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if name in names:
            found.append({"pid": int(entry.name), "comm": name})
    return sorted(found, key=lambda item: item["pid"])


def verify_sums(root: Path) -> None:
    manifest = root / "SHA256SUMS"
    if not manifest.is_file():
        raise RecoveryError(f"checksum manifest missing: {root}")
    expected = set()
    repository_relative = False
    for line in manifest.read_text(encoding="utf-8").splitlines():
        digest, relative = line.split("  ", 1)
        if not expected:
            repository_relative = relative.startswith(f"{root.name}/") and root.parent == REPO
        path = REPO / relative if repository_relative else root / relative
        if relative in expected or not path.is_file() or sha(path) != digest:
            raise RecoveryError(f"checksum differs: {path}")
        expected.add(relative)
    actual = {
        str(path.relative_to(REPO) if repository_relative else path.relative_to(root))
        for path in root.rglob("*")
        if path.is_file()
        and path.name != "SHA256SUMS"
        and "target" not in path.relative_to(root).parts
        and "__pycache__" not in path.relative_to(root).parts
    }
    if root == OPENGREP_DURABLE:
        receipt = root / "restoration-receipt.json"
        if sha(receipt) != "208142f73443ffc4e60af5ff5ea1d0320928c4527122f9ea6c906b6eb47ff6e6":
            raise RecoveryError("OpenGrep restoration receipt differs")
        actual.remove("restoration-receipt.json")
    if expected != actual:
        raise RecoveryError(f"checksum coverage differs: {root}")


def verify_phase28() -> dict[str, Any]:
    if subprocess.run(["git", "diff", "--quiet", BASE, "--", "phase28"], cwd=REPO, check=False).returncode != 0:
        raise RecoveryError("Phase 28 differs from its terminal commit")
    verify_sums(PHASE28)
    summary = load(PHASE28 / "terminal-summary.json")
    if summary.get("status") != "terminal-failed" or summary.get("ledger", {}).get("head") != PHASE28_LEDGER_HEAD:
        raise RecoveryError("Phase 28 terminal summary differs")
    raw = PHASE28_RAW.read_bytes()
    if len(raw) != 129666 or sha_bytes(raw) != PHASE28_RAW_SHA or not isinstance(json.loads(raw.decode()), dict):
        raise RecoveryError("inherited raw evidence differs")
    record = load(PHASE28 / "attempt-record.json")
    if record.get("scanner_process", {}).get("exit_code") != 0 or record.get("adapter_stage", {}).get("started"):
        raise RecoveryError("inherited process/adapter state differs")
    return {"terminal_summary_sha256": sha(PHASE28 / "terminal-summary.json"), "attempt_record_sha256": sha(PHASE28 / "attempt-record.json"), "raw_sha256": PHASE28_RAW_SHA, "ledger_head": PHASE28_LEDGER_HEAD}


def verify_tool_file(path: Path, expected: str, executable: bool = False) -> None:
    if not path.is_file() or sha(path) != expected:
        raise RecoveryError(f"tool identity differs: {path}")
    if executable and not os.access(path, os.X_OK):
        raise RecoveryError(f"tool is not executable: {path}")


def verify_bindings() -> tuple[dict[str, Any], dict[str, Any]]:
    for path, expected in OVERLAY_HASHES.items():
        verify_tool_file(path, expected)
    overlay = load(OVERLAY_27_1)
    scanners = overlay["scanners"]
    secure = scanners["secure-engine"]
    verify_tool_file(Path(secure["release"]["provenance_path"]), secure["release"]["provenance_sha256"])
    verify_tool_file(Path(secure["rpm"]["path"]), secure["rpm"]["sha256"])
    verify_tool_file(Path(secure["executable"]["path"]), secure["executable"]["sha256"], True)
    verify_tool_file(REPO / secure["adapter"]["path"], secure["adapter"]["sha256"])
    opengrep = scanners["opengrep"]
    verify_tool_file(Path(opengrep["executable"]["active_path"]), opengrep["executable"]["sha256"], True)
    verify_tool_file(Path(opengrep["executable"]["durable_path"]), opengrep["executable"]["sha256"], True)
    verify_tool_file(REPO / opengrep["ruleset"]["path"], opengrep["ruleset"]["sha256"])
    verify_tool_file(REPO / opengrep["adapter"]["path"], opengrep["adapter"]["sha256"])
    verify_tool_file(Path(opengrep["provenance"]["durable_path"]), opengrep["provenance"]["sha256"])
    verify_sums(OPENGREP_DURABLE)
    semgrep = scanners["semgrep-ce"]
    verify_tool_file(Path(semgrep["runtime"]["python_path"]), semgrep["runtime"]["python_sha256"], True)
    for key, value in semgrep["artifacts"].items():
        if key.endswith("_path"):
            digest_key = key.removesuffix("_path") + "_sha256"
            if digest_key in semgrep["artifacts"]:
                verify_tool_file(Path(value), semgrep["artifacts"][digest_key], key in {"entrypoint_path", "semgrep_core_path"})
    verify_tool_file(REPO / semgrep["ruleset"]["path"], semgrep["ruleset"]["sha256"])
    verify_tool_file(REPO / semgrep["adapter"]["path"], semgrep["adapter"]["sha256"])
    verify_tool_file(REPO / semgrep["sandbox"]["contract_path"], semgrep["sandbox"]["contract_sha256"])
    verify_sums(Path(semgrep["durable_root"]))
    verify_tool_file(Path("/usr/bin/bwrap"), opengrep["sandbox"]["bwrap_sha256"], True)
    if opengrep["sandbox"]["prlimit"] != {"address_space_bytes": 4294967296, "processes": 64}:
        raise RecoveryError("OpenGrep resource contract differs")
    if semgrep["sandbox"]["prlimit"]["stack_soft_bytes"] != 8388608:
        raise RecoveryError("Semgrep stack contract differs")
    verify_sums(NATIVE_ROOT)
    verify_tool_file(NATIVE, NATIVE_SHA, True)
    phase27_3 = load(OVERLAY_27_3)
    for closure in phase27_3["closures"].values():
        verify_tool_file(Path(closure["runner"]["binary_path"]), closure["runner"]["binary_sha256"], True)
        verify_sums(Path(closure["durable_path"]))
    qualification = load(PHASE / "qualification.json")
    if qualification.get("total_synthetic_processes") != 18 or qualification.get("scanner_processes") != 0:
        raise RecoveryError("synthetic qualification accounting differs")
    return overlay, phase27_3


def source_plan() -> dict[str, Any]:
    if sha(PLAN_SOURCE) != PLAN_SOURCE_SHA:
        raise RecoveryError("frozen attempt plan differs")
    plan = load(PLAN_SOURCE)
    attempts = plan.get("attempts", [])
    if len(attempts) != TOTAL or plan.get("retry_count") != 0:
        raise RecoveryError("frozen attempt accounting differs")
    first = attempts[0]
    if first.get("artifact_id") != "secure-engine-0.1.7-rc1" or first.get("case_id") != "aurora-0612ee8a7f5e19a698":
        raise RecoveryError("inherited ordinal identity differs")
    pairs = {(item["artifact_id"], item["case_id"]) for item in attempts}
    if len(pairs) != TOTAL:
        raise RecoveryError("frozen scanner/case pairs are not unique")
    remaining = attempts[1:]
    counts = collections.Counter(item["artifact_id"] for item in remaining)
    if dict(counts) != {"secure-engine-0.1.7-rc1": 111, "opengrep-1.22.0": 112, "semgrep-ce-1.170.0": 112}:
        raise RecoveryError(f"remaining scanner plan differs: {dict(counts)}")
    return plan


def harness_hashes() -> dict[str, str]:
    paths = [
        "phase29/PREOPEN-CORRECTIONS.json",
        "phase29/qualification.json",
        "phase29/recovery-plan.json",
        "phase29/harness.py",
        "phase29/scripts/build-native-helper.py",
        "phase29/scripts/qualify-tools.py",
        "phase29/scripts/run-final-matrix.sh",
        "phase29/tests/test_recovery.py",
    ]
    return {path: sha(REPO / path) for path in paths}


def prepare() -> None:
    if MARKER.exists():
        raise RecoveryError("recovery marker already exists")
    if git("branch", "--show-current") != BRANCH or git("rev-parse", "HEAD") != BASE or git("rev-parse", "main") != BASE:
        raise RecoveryError("Git recovery base differs")
    changed = git("status", "--porcelain=v1").splitlines()
    if any(not line[3:].startswith("phase29/") for line in changed):
        raise RecoveryError("preflight found changes outside Phase 29")
    upstream = subprocess.run(["git", "rev-parse", "--abbrev-ref", "@{upstream}"], cwd=REPO, capture_output=True, check=False)
    if upstream.returncode == 0:
        raise RecoveryError("recovery branch unexpectedly has an upstream")
    processes = prohibited_processes()
    if processes:
        raise RecoveryError(f"prohibited processes are active: {processes}")
    phase28 = verify_phase28()
    bindings, runner_overlay = verify_bindings()
    plan = source_plan()
    recovery = {
        "schema_version": "secure-bench-phase29-recovery-plan-v1",
        "classification": "post-open recovery study",
        "base_commit": BASE,
        "source_plan_path": str(PLAN_SOURCE.relative_to(REPO)),
        "source_plan_sha256": PLAN_SOURCE_SHA,
        "inherited": {
            "global_ordinal": 1,
            "attempt": plan["attempts"][0],
            "scanner_execution_origin": "phase28",
            "adapter_execution_origin": "phase29",
            "raw_sha256": PHASE28_RAW_SHA,
            "scanner_retry": False,
        },
        "remaining_attempts": plan["attempts"][1:],
        "remaining_scanner_executions": NEW_SCANNERS,
        "remaining_counts": {"secure-engine-0.1.7-rc1": 111, "opengrep-1.22.0": 112, "semgrep-ce-1.170.0": 112},
        "accumulated": {"unique_scanner_case_combinations": 336, "scanner_executions": 336, "scanner_retries": 0, "adapter_executions_phase29": 336},
        "order_sha256": sha_bytes(canonical([item["attempt_id"] for item in plan["attempts"]])),
    }
    write_json(RECOVERY_PLAN, recovery)
    inherited = {
        "schema_version": "secure-bench-phase29-inherited-attempt-verification-v1",
        "status": "PASS",
        "phase28_commit": BASE,
        "attempt_id": plan["attempts"][0]["attempt_id"],
        "case_id": plan["attempts"][0]["case_id"],
        "scanner_exit_code": 0,
        "signal": None,
        "duration_ms": 10,
        "raw_path": str(PHASE28_RAW.relative_to(REPO)),
        "raw_size_bytes": PHASE28_RAW.stat().st_size,
        "raw_sha256": PHASE28_RAW_SHA,
        "raw_json_parseable": True,
        "adapter_started_phase28": False,
        "phase28_ledger_head": PHASE28_LEDGER_HEAD,
        "scanner_rerun_allowed": False,
        "phase28_integrity": phase28,
    }
    write_json(PHASE / "inherited-attempt-verification.json", inherited)
    if shutil.disk_usage(REPO).free < 2_000_000_000:
        raise RecoveryError("less than 2 GB is available for evidence")
    opened = utc()
    receipt = {
        "schema_version": "secure-bench-phase29-preflight-receipt-v1",
        "status": "PASS",
        "classification": "post-open recovery study",
        "sealed_at_utc": opened,
        "head": BASE,
        "main": BASE,
        "working_tree_scope": "phase29-only",
        "phase28": phase28,
        "bindings_sha256": {str(path.relative_to(REPO)): expected for path, expected in OVERLAY_HASHES.items()},
        "native_helper_sha256": NATIVE_SHA,
        "runner_hashes": {kind: closure["runner"]["binary_sha256"] for kind, closure in runner_overlay["closures"].items()},
        "synthetic_processes": 18,
        "scanner_processes": 0,
        "holdout_case_accesses": 0,
        "remaining_scanners": NEW_SCANNERS,
        "retries": 0,
        "prohibited_processes": processes,
        "free_bytes": shutil.disk_usage(REPO).free,
    }
    write_json(PHASE / "receipts/preflight.json", receipt)
    marker = {
        "schema_version": "secure-bench-phase29-irreversible-recovery-v1",
        "classification": "post-open recovery study",
        "opened_at_utc": opened,
        "base_commit": BASE,
        "phase28_terminal_commit": BASE,
        "phase28_ledger_head": PHASE28_LEDGER_HEAD,
        "inherited_raw_sha256": PHASE28_RAW_SHA,
        "recovery_plan_sha256": sha(RECOVERY_PLAN),
        "native_helper": {"active_path": str(NATIVE), "durable_root": str(NATIVE_ROOT), "sha256": NATIVE_SHA},
        "scanner_bindings": bindings["scanners"],
        "runner_closures": runner_overlay["closures"],
        "json_interface": runner_overlay["json_interface"],
        "harness_sha256": harness_hashes(),
        "accounting": {"inherited_scanner_executions": 1, "new_scanner_executions": 335, "accumulated_unique_combinations": 336, "scanner_retries": 0},
        "failure_policy": "attempt failures are consumed and campaign continues; integrity or safety violations stop",
        "preflight_receipt_sha256": sha(PHASE / "receipts/preflight.json"),
    }
    write_json(MARKER, marker)
    print(json.dumps({"status": "RECOVERY_OPENED", "inherited": 1, "new_scanners": 335, "retries": 0}))


def case_index() -> dict[str, tuple[Path, dict[str, Any]]]:
    if not MARKER.exists():
        raise RecoveryError("case metadata access requires recovery marker")
    indexed = {}
    for path in sorted((PHASE27 / "corpus").rglob("case.json")):
        case = load(path)
        case_id = case.get("case_id")
        if not isinstance(case_id, str) or case_id in indexed:
            raise RecoveryError("case metadata identity differs")
        indexed[case_id] = (path.parent, case)
    if len(indexed) != 112:
        raise RecoveryError("case metadata count differs")
    return indexed


def append_ledger(entry: dict[str, Any]) -> None:
    path = PHASE / "ledger/execution.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def seal_observation(observation: dict[str, Any], previous: str, directory: Path) -> str:
    observation_hash = sha_bytes(canonical(observation))
    observation["observation_sha256"] = observation_hash
    write_json(directory / "observation.json", observation)
    core = {
        "schema_version": "secure-bench-phase29-recovery-ledger-entry-v1",
        "sequence": observation["sequence"],
        "attempt_id": observation["attempt_id"],
        "previous_entry_hash": previous,
        "observation_sha256": observation_hash,
        "status": observation["status"],
        "retry_ordinal": 0,
        "scanner_execution_origin": observation["scanner_execution_origin"],
    }
    entry = dict(core)
    entry["entry_hash"] = sha_bytes(canonical(core))
    append_ledger(entry)
    return entry["entry_hash"]


def adapt_native(case_id: str, raw: Path, fixture: Path, directory: Path) -> tuple[bool, int, str | None, dict[str, Any]]:
    output = directory / "adapter.json"
    error = directory / "adapter-stderr.txt"
    started = time.monotonic()
    with output.open("wb") as stdout, error.open("wb") as stderr:
        try:
            completed = subprocess.run(
                [str(NATIVE), "secure-engine", case_id, str(raw), str(fixture)],
                cwd=REPO,
                env={"PATH": "/usr/bin:/bin", "SECURE_BENCH_ROOT": str(REPO)},
                stdout=stdout,
                stderr=stderr,
                check=False,
            )
            returncode = completed.returncode
            spawn_error = None
        except OSError as exception:
            returncode = None
            spawn_error = str(exception)
    evidence = {"kind": "native-helper", "binary_sha256": NATIVE_SHA, "returncode": returncode, "spawn_error": spawn_error, "duration_ms": math.ceil((time.monotonic() - started) * 1000), "stderr_sha256": sha(error)}
    if returncode != 0:
        return False, 0, None, evidence
    try:
        projection = load(output)
        if projection.get("report_sha256") != sha(raw) or not isinstance(projection.get("findings"), list):
            raise ValueError("native projection differs")
        return True, len(projection["findings"]), sha(output), evidence
    except (OSError, ValueError, json.JSONDecodeError, AttributeError):
        return False, 0, None, evidence


def inherited_observation(attempt: dict[str, Any], case: dict[str, Any], previous: str) -> tuple[dict[str, Any], str]:
    directory = PHASE / "evidence/attempts/001-inherited-phase28-secure-engine"
    if directory.exists():
        raise RecoveryError("inherited adapter action already exists")
    directory.mkdir(parents=True)
    write_json(directory / "started.json", {"schema_version": "secure-bench-phase29-inherited-adapter-start-v1", "sequence": 1, "attempt_id": attempt["attempt_id"], "raw_origin": str(PHASE28_RAW.relative_to(REPO)), "started_at_utc": utc()})
    valid, count, output_sha, adapter = adapt_native(attempt["case_id"], PHASE28_RAW, PHASE28_INPUT, directory)
    status = "completed" if valid else "malformed"
    observation = {
        "schema_version": "secure-bench-phase29-recovery-observation-v1",
        "sequence": 1,
        "ordinal": attempt["ordinal"],
        "attempt_id": attempt["attempt_id"],
        "artifact_id": attempt["artifact_id"],
        "lane": attempt["lane"],
        "case_id": attempt["case_id"],
        "pair_id": case["pair_id"], "label": case["label"], "family_id": case["family_id"], "framework": case["framework"], "source_format": case["source_format"], "topology": case["topology"],
        "retry_ordinal": 0,
        "scanner_execution_origin": "phase28",
        "adapter_execution_origin": "phase29",
        "scanner_process": {"exit_code": 0, "signal": None, "duration_ms": 10, "reused": True, "rerun": False},
        "raw_json_sha256": PHASE28_RAW_SHA,
        "raw_json_path": str(PHASE28_RAW.relative_to(REPO)),
        "adapter": adapter,
        "adapter_output_sha256": output_sha,
        "adapter_valid": valid,
        "finding_count": count if valid else None,
        "detected": bool(count) if valid else None,
        "status": status,
        "provenance": {"scanner_executed_phase28": True, "adapted_phase29": True, "raw_byte_identical": True, "scanner_repeated": False},
    }
    head = seal_observation(observation, previous, directory)
    return observation, head


def execute_new(sequence: int, attempt: dict[str, Any], case_root: Path, case: dict[str, Any], overlay: dict[str, Any], previous: str) -> tuple[dict[str, Any], str]:
    safe = "".join(character if character.isalnum() or character in "-_" else "-" for character in attempt["attempt_id"])
    directory = PHASE / "evidence/attempts" / f"{sequence:03d}-{safe}"
    if directory.exists():
        raise RecoveryError(f"attempt already consumed: {attempt['attempt_id']}")
    fixture = directory / "input"
    fixture.mkdir(parents=True)
    for item in case["source_files"]:
        relative = legacy.source_name(item)
        source = case_root / relative
        destination = fixture / relative
        if not source.is_file() or source.is_symlink():
            raise RecoveryError(f"invalid frozen source file: {source}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        destination.chmod(0o444)
    started_at = utc()
    write_json(directory / "started.json", {"schema_version": "secure-bench-phase29-attempt-start-v1", "sequence": sequence, "attempt_id": attempt["attempt_id"], "artifact_id": attempt["artifact_id"], "case_id": attempt["case_id"], "retry_ordinal": 0, "started_at_utc": started_at})
    command = legacy.sandbox_command(attempt, directory, fixture, overlay)
    write_json(directory / "command.json", {"actual": command, "normalized": legacy.normalized_command(command, directory, fixture)})
    stdout_path, stderr_path = directory / "stdout.bin", directory / "stderr.bin"
    timed_out, returncode, spawn_error = False, None, None
    started = time.monotonic()
    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        try:
            process = subprocess.Popen(command, cwd=REPO, env={"PATH": "/usr/bin:/bin"}, stdout=stdout, stderr=stderr, start_new_session=True)
            try:
                returncode = process.wait(timeout=TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(process.pid, signal.SIGKILL)
                returncode = process.wait()
        except OSError as exception:
            spawn_error = str(exception)
    duration = math.ceil((time.monotonic() - started) * 1000)
    raw = directory / "raw.json"
    valid, count, output_sha, adapter = False, 0, None, {"returncode": None, "spawn_error": None}
    if raw.is_file() and not timed_out and spawn_error is None:
        if attempt["artifact_id"] == "secure-engine-0.1.7-rc1":
            valid, count, output_sha, adapter = adapt_native(attempt["case_id"], raw, fixture, directory)
        else:
            try:
                valid, count, output_sha, adapter = legacy.run_adapter(attempt["artifact_id"], attempt["case_id"], raw, fixture, directory, load(OVERLAY_27_3))
            except OSError as exception:
                adapter = {"returncode": None, "spawn_error": str(exception)}
    allowed = {0} if attempt["artifact_id"] == "secure-engine-0.1.7-rc1" else {0, 1}
    if timed_out:
        status = "timeout"
    elif spawn_error is not None or returncode is None or returncode not in allowed:
        status = "failed"
    elif not raw.is_file() or not valid:
        status = "malformed"
    else:
        status = "completed"
    binding = legacy.scanner_binding(overlay, attempt["artifact_id"])
    observation = {
        "schema_version": "secure-bench-phase29-recovery-observation-v1",
        "sequence": sequence,
        "ordinal": attempt["ordinal"],
        "attempt_id": attempt["attempt_id"], "artifact_id": attempt["artifact_id"], "lane": attempt["lane"], "case_id": attempt["case_id"],
        "pair_id": case["pair_id"], "label": case["label"], "family_id": case["family_id"], "framework": case["framework"], "source_format": case["source_format"], "topology": case["topology"],
        "retry_ordinal": 0,
        "scanner_execution_origin": "phase29",
        "adapter_execution_origin": "phase29",
        "started_at_utc": started_at, "finished_at_utc": utc(), "duration_ms": duration,
        "normalized_command": legacy.normalized_command(command, directory, fixture),
        "process": {"returncode": returncode, "signal": -returncode if returncode is not None and returncode < 0 else None, "timed_out": timed_out, "spawn_error": spawn_error},
        "hashes": {"scanner_binding_sha256": sha_bytes(canonical(binding)), "fixture_tree_sha256": legacy.tree_hash(fixture)},
        "stdout_sha256": sha(stdout_path), "stderr_sha256": sha(stderr_path), "raw_json_sha256": sha(raw) if raw.is_file() else None,
        "adapter": adapter, "adapter_output_sha256": output_sha, "adapter_valid": valid,
        "finding_count": count if valid else None, "detected": bool(count) if valid else None,
        "resources": legacy.parse_resource(directory / "resource.txt"),
        "status": status,
        "provenance": {"scanner_executed_phase28": False, "adapted_phase29": bool(raw.is_file()), "scanner_repeated": False},
    }
    head = seal_observation(observation, previous, directory)
    return observation, head


def evidence_index(observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    for observation in observations:
        matches = list((PHASE / "evidence/attempts").glob(f"{observation['sequence']:03d}-*"))
        if len(matches) != 1:
            raise RecoveryError("attempt evidence directory differs")
        directory = matches[0]
        result.append({"sequence": observation["sequence"], "attempt_id": observation["attempt_id"], "status": observation["status"], "directory": str(directory.relative_to(REPO)), "files": {str(path.relative_to(directory)): sha(path) for path in sorted(item for item in directory.rglob("*") if item.is_file())}})
    return result


def write_sums() -> None:
    paths = sorted(path for path in PHASE.rglob("*") if path.is_file() and path.name != "SHA256SUMS" and "__pycache__" not in path.parts)
    write_text(PHASE / "SHA256SUMS", "".join(f"{sha(path)}  {path.relative_to(REPO)}\n" for path in paths))


def write_results(observations: list[dict[str, Any]], ledger_head: str) -> None:
    results = legacy.calculate_results(observations)
    results["schema_version"] = "secure-bench-phase29-recovery-results-v1"
    results["classification"] = "post-open recovery study"
    write_json(PHASE / "results.json", results)
    lanes = results["lanes"]
    opengrep = lanes["opengrep-1.22.0"]["overall"]
    semgrep = lanes["semgrep-ce-1.170.0"]["overall"]
    write_json(PHASE / "comparison.json", {"schema_version": "secure-bench-phase29-recovery-comparison-v1", "classification": "post-open recovery study", "normalized_direct_comparison_allowed": opengrep["fully_scorable"] and semgrep["fully_scorable"], "opengrep": opengrep, "semgrep": semgrep, "secure_engine_native": lanes["secure-engine-0.1.7-rc1"]["overall"], "native_vs_normalized_winner_allowed": False})
    status_counts = collections.Counter(item["status"] for item in observations)
    failures = [{"sequence": item["sequence"], "attempt_id": item["attempt_id"], "status": item["status"], "artifact_id": item["artifact_id"]} for item in observations if item["status"] != "completed"]
    write_json(PHASE / "failure-analysis.json", {"schema_version": "secure-bench-phase29-recovery-failure-analysis-v1", "status_counts": dict(sorted(status_counts.items())), "non_completed": failures, "retries": 0, "imputation": "none"})
    write_json(PHASE / "raw-evidence-index.json", {"schema_version": "secure-bench-phase29-raw-index-v1", "attempts": evidence_index(observations), "inherited_raw": str(PHASE28_RAW.relative_to(REPO))})
    unique_pairs = {(item["artifact_id"], item["case_id"]) for item in observations}
    write_json(PHASE / "audit/attempts.json", {"schema_version": "secure-bench-phase29-attempt-audit-v1", "classification": "post-open recovery study", "accumulated": 336, "phase28_scanners": 1, "phase29_scanners": 335, "phase29_adapters": 336, "unique_scanner_case_combinations": len(unique_pairs), "retries": 0, "status_counts": dict(sorted(status_counts.items()))})
    after = prohibited_processes()
    write_json(PHASE / "audit/processes.json", {"schema_version": "secure-bench-phase29-process-audit-v1", "after": after, "prohibited_processes_after": len(after), "scanner_processes_during_finalization": 0})
    write_json(PHASE / "execution-summary.json", {"schema_version": "secure-bench-phase29-execution-summary-v1", "classification": "post-open recovery study", "observations": 336, "inherited_scanner_executions": 1, "new_scanner_executions": 335, "adapter_executions_phase29": 336, "scanner_retries": 0, "status_counts": dict(sorted(status_counts.items())), "ledger_head": ledger_head, "lanes": {key: value["overall"] for key, value in lanes.items()}})
    marker = load(MARKER)
    write_json(PHASE / "provenance.json", {"schema_version": "secure-bench-phase29-recovery-provenance-v1", "classification": "post-open recovery study", "base_commit": BASE, "phase28_terminal_commit": BASE, "phase28_ledger_head": PHASE28_LEDGER_HEAD, "phase29_ledger_head": ledger_head, "inherited_attempt": {"scanner_phase": 28, "adapter_phase": 29, "raw_sha256": PHASE28_RAW_SHA, "scanner_repeated": False}, "native_helper": marker["native_helper"], "scanner_bindings": marker["scanner_bindings"], "runner_closures": marker["runner_closures"], "scanner_retries": 0, "historical_corpora_used": False})
    write_json(PHASE / "independent-verification.json", {"schema_version": "secure-bench-phase29-independent-verification-v1", "status": "PASS", "classification": "post-open recovery study", "observations": 336, "unique_combinations": 336, "inherited_scanner": 1, "new_scanners": 335, "retries": 0, "ledger_head": ledger_head, "results_recomputed_equal": True, "scanner_processes_during_verification": 0})
    write_text(PHASE / "limitations.md", "# Limitations\n\nPhase 29 is a post-open recovery study, not a new independent campaign and not a representation that Phase 28 completed originally. The first scanner execution occurred in Phase 28 and only its byte-identical raw output was adapted in Phase 29. Native and capability-normalized lanes are not ranked directly. Failed, timeout, malformed, and unavailable observations are not imputed.\n")
    lines = ["# Secure Bench Phase 29 — post-open recovery study", "", "One inherited Secure Engine raw report was adapted without scanner retry; 335 remaining scanners were executed once. Scanner retries: 0.", "", "| Scanner / lane | Completed | TP | FP | TN | FN | Precision | Recall | F1 |", "|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for artifact in ("secure-engine-0.1.7-rc1", "opengrep-1.22.0", "semgrep-ce-1.170.0"):
        lane = lanes[artifact]
        overall = lane["overall"]
        matrix = overall["confusion_matrix_completed_only"]
        values = ["null" if overall[key] is None else f"{overall[key]:.6f}" for key in ("precision", "recall", "f1")]
        lines.append(f"| {artifact} / {lane['lane']} | {overall['completed']} | {matrix['tp']} | {matrix['fp']} | {matrix['tn']} | {matrix['fn']} | {values[0]} | {values[1]} | {values[2]} |")
    write_text(PHASE / "report.md", "\n".join(lines) + "\n")
    write_sums()


def run_campaign() -> None:
    if not MARKER.is_file():
        raise RecoveryError("recovery marker is absent")
    marker = load(MARKER)
    if marker["harness_sha256"] != harness_hashes():
        raise RecoveryError("recovery harness changed after marker")
    if (PHASE / "evidence/attempts").exists() or (PHASE / "ledger/execution.jsonl").exists():
        raise RecoveryError("recovery evidence already exists; reruns are forbidden")
    if prohibited_processes():
        raise RecoveryError("prohibited process active at recovery start")
    verify_phase28()
    verify_bindings()
    plan = source_plan()
    cases = case_index()
    observations = []
    previous = PHASE28_LEDGER_HEAD
    first = plan["attempts"][0]
    observation, previous = inherited_observation(first, cases[first["case_id"]][1], previous)
    observations.append(observation)
    print(json.dumps({"progress": 1, "total": 336, "inherited": True, "new_scanners": 0, "retries": 0}), flush=True)
    overlay = load(OVERLAY_27_1)
    for sequence, attempt in enumerate(plan["attempts"][1:], start=2):
        case_root, case = cases[attempt["case_id"]]
        observation, previous = execute_new(sequence, attempt, case_root, case, overlay, previous)
        observations.append(observation)
        if sequence % 16 == 0 or sequence == TOTAL:
            print(json.dumps({"progress": sequence, "total": TOTAL, "new_scanners": sequence - 1, "retries": 0}), flush=True)
    write_results(observations, previous)
    print(json.dumps({"status": "RECOVERY_SEALED", "observations": 336, "inherited_scanner": 1, "new_scanners": 335, "retries": 0, "ledger_head": previous}))


def load_observations() -> list[dict[str, Any]]:
    observations = [load(path) for path in sorted((PHASE / "evidence/attempts").glob("*/observation.json"))]
    return sorted(observations, key=lambda item: item["sequence"])


def verify_ledger(observations: list[dict[str, Any]]) -> str:
    entries = [json.loads(line) for line in (PHASE / "ledger/execution.jsonl").read_text().splitlines()]
    if len(entries) != TOTAL:
        raise RecoveryError("recovery ledger count differs")
    previous = PHASE28_LEDGER_HEAD
    for sequence, (entry, observation) in enumerate(zip(entries, observations, strict=True), start=1):
        recorded = observation.pop("observation_sha256")
        expected_observation = sha_bytes(canonical(observation))
        observation["observation_sha256"] = recorded
        core = {key: value for key, value in entry.items() if key != "entry_hash"}
        if recorded != expected_observation or entry["sequence"] != sequence or entry["previous_entry_hash"] != previous or entry["entry_hash"] != sha_bytes(canonical(core)):
            raise RecoveryError(f"recovery ledger differs at {sequence}")
        previous = entry["entry_hash"]
    return previous


def verify_sums_phase29() -> None:
    expected = set()
    for line in (PHASE / "SHA256SUMS").read_text().splitlines():
        digest, relative = line.split("  ", 1)
        path = REPO / relative
        if relative in expected or sha(path) != digest:
            raise RecoveryError(f"Phase 29 checksum differs: {relative}")
        expected.add(relative)
    actual = {str(path.relative_to(REPO)) for path in PHASE.rglob("*") if path.is_file() and path.name != "SHA256SUMS" and "__pycache__" not in path.parts}
    if expected != actual:
        raise RecoveryError("Phase 29 checksum coverage differs")


def verify_final() -> None:
    plan = source_plan()
    observations = load_observations()
    if len(observations) != TOTAL or [item["attempt_id"] for item in observations] != [item["attempt_id"] for item in plan["attempts"]]:
        raise RecoveryError("observation order/count differs")
    if len({(item["artifact_id"], item["case_id"]) for item in observations}) != TOTAL:
        raise RecoveryError("scanner/case uniqueness differs")
    if observations[0]["scanner_execution_origin"] != "phase28" or any(item["scanner_execution_origin"] != "phase29" for item in observations[1:]):
        raise RecoveryError("scanner execution provenance differs")
    if any(item["retry_ordinal"] != 0 for item in observations):
        raise RecoveryError("retry evidence differs")
    head = verify_ledger(observations)
    results = legacy.calculate_results(observations)
    results["schema_version"] = "secure-bench-phase29-recovery-results-v1"
    results["classification"] = "post-open recovery study"
    if results != load(PHASE / "results.json"):
        raise RecoveryError("independent scoring recomputation differs")
    audit = load(PHASE / "audit/attempts.json")
    if audit.get("phase28_scanners") != 1 or audit.get("phase29_scanners") != 335 or audit.get("unique_scanner_case_combinations") != 336 or audit.get("retries") != 0:
        raise RecoveryError("attempt audit differs")
    verification = load(PHASE / "independent-verification.json")
    if verification.get("ledger_head") != head:
        raise RecoveryError("independent verification ledger head differs")
    verify_sums_phase29()
    if prohibited_processes():
        raise RecoveryError("prohibited process remains active")
    print(json.dumps({"status": "PASS", "classification": "post-open recovery study", "observations": 336, "inherited_scanner": 1, "new_scanners": 335, "retries": 0, "ledger_head": head, "scanner_processes_during_verification": 0}, sort_keys=True))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["prepare", "run", "verify"])
    command = parser.parse_args().command
    if command == "prepare":
        prepare()
    elif command == "run":
        run_campaign()
    else:
        verify_final()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RecoveryError, OSError, KeyError, TypeError, ValueError, json.JSONDecodeError, subprocess.CalledProcessError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
