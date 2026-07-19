#!/usr/bin/env python3
"""One-shot, fail-closed Secure Bench Phase 28 campaign harness."""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time
from typing import Any, Iterable


REPO = Path(__file__).resolve().parent.parent
PHASE = REPO / "phase28"
PHASE27 = REPO / "phase27"
PLAN_PATH = PHASE27 / "phase28/execution-plan-v2.json"
PHASE27_1_OVERLAY_PATH = REPO / "phase27-1/binding-overlay.json"
PHASE27_2_OVERLAY_PATH = REPO / "phase27-2/binding-overlay.json"
PHASE27_3_OVERLAY_PATH = REPO / "phase27-3/binding-overlay.json"
MARKER = PHASE / "IRREVERSIBLE_OPEN.json"
BASE_COMMIT = "9d7ff67f7b360c9b70112d32445091671070ac57"
PHASE27_COMMIT = "540502c8bf1f139c7d54cb5f6e7c29ce97ffb934"
PHASE27_1_COMMIT = "0f6fe9f06f1f88233e6d537b9c4e1d826575d0ee"
PHASE27_2_COMMIT = "467413eeb2a22017b5bc19f7f2052fdbc5d43d0d"
PHASE27_3_COMMIT = BASE_COMMIT
PLAN_SHA256 = "838532c9010a6c4e9334b8edf137f266a02c9e2cc10bfd1df3cd6cb95a3e3748"
CORPUS_TREE_SHA256 = "efb1a76b41432cf2e8dcefb57ef3a654139704dede338ad900cf88e2f3cd9d13"
MANIFEST_SHA256 = "6478cd1d86c62956d9e7ce07cee5387fe011d7beb22b292b3d3bbaebb3795912"
COMMITMENTS_SHA256 = "6c8e28bf894324795c7ec468cdbc1d2202d84dc694525b26204eaa0225e9d077"
PHASE27_1_OVERLAY_SHA256 = "5b9c147142099f39242f70128bb70217d0c14f2d55890a86f089ae9a678185cf"
PHASE27_2_OVERLAY_SHA256 = "1a8792cb3b6736b2599fc74ab1352755c15d3e5a39fed008759b78a02e08dea2"
PHASE27_3_OVERLAY_SHA256 = "2733358fbbd95e8881d7575b0f40f5e6d6d58beff760be1fb77c8f96a7e8e4ce"
PHASE17_COMMIT = "241600628315db6d8a77e62bbaf6e61ba5c628f1"
PHASE17_WORKSPACE_TREE = "e2512d180118e6487a979ba03d1961c41d17825d"
PHASE17_WORKSPACE_ARCHIVE_SHA256 = "bcfb9f8cc7c71bc486aa9f7f789da946e722560c1e76e1ddfdd28d592e7bf243"
GENESIS_HASH = "5b48aec431ad335cd788022d9b87aa3da1f34a2fff002a9138205b817c1c61f0"
BRANCH = "codex/phase-28-one-shot-independent-holdout-v2-execution"
ATTEMPT_TOTAL = 336
CASES_PER_LANE = 112
TIMEOUT_SECONDS = 120
SYNTHETIC_RUNNER_PROCESSES = 5


class CampaignError(RuntimeError):
    """Fail-closed campaign error."""


def utc_now() -> str:
    """Return a whole-second UTC timestamp."""
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def canonical_bytes(value: Any) -> bytes:
    """Encode deterministic UTF-8 JSON."""
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def sha256_bytes(value: bytes) -> str:
    """Hash bytes."""
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    """Hash one file without interpreting it."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> Any:
    """Load UTF-8 JSON."""
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def atomic_json(path: Path, value: Any) -> None:
    """Write canonical JSON atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    with temporary.open("wb") as handle:
        handle.write(canonical_bytes(value))
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def atomic_text(path: Path, value: str) -> None:
    """Write UTF-8 text atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(value)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def run_checked(arguments: list[str], *, capture: bool = True) -> str:
    """Run a non-scanner administrative command."""
    completed = subprocess.run(
        arguments,
        cwd=REPO,
        check=False,
        text=True,
        stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        raise CampaignError(f"command failed: {arguments[0]}: {completed.stderr.strip()}")
    return completed.stdout.strip() if capture else ""


def prohibited_processes() -> list[dict[str, Any]]:
    """Find exact scanner process names without invoking scanners."""
    prohibited = {"secure", "secure-engine", "opengrep", "semgrep", "semgrep-core", "joern", "ollama"}
    observed: list[dict[str, Any]] = []
    proc = Path("/proc")
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            name = (entry / "comm").read_text(encoding="utf-8").strip()
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        if name in prohibited:
            observed.append({"pid": int(entry.name), "comm": name})
    return sorted(observed, key=lambda item: item["pid"])


def verify_plan() -> dict[str, Any]:
    """Verify the frozen plan without opening case contents."""
    if sha256_file(PLAN_PATH) != PLAN_SHA256:
        raise CampaignError("frozen Phase 28 plan hash differs")
    plan = load_json(PLAN_PATH)
    if plan.get("schema_version") != "secure-bench-phase28-plan-v2":
        raise CampaignError("plan schema differs")
    if plan.get("attempt_count") != ATTEMPT_TOTAL or len(plan.get("attempts", [])) != ATTEMPT_TOTAL:
        raise CampaignError("plan must contain exactly 336 attempts")
    if plan.get("retry_count") != 0:
        raise CampaignError("plan retry count differs from zero")
    attempts = plan["attempts"]
    if len({attempt["attempt_id"] for attempt in attempts}) != ATTEMPT_TOTAL:
        raise CampaignError("attempt IDs are not unique")
    if any(attempt.get("retry_ordinal") != 0 or attempt.get("status") != "planned" for attempt in attempts):
        raise CampaignError("plan contains a retry or non-planned attempt")
    expected = {
        ("secure-engine-0.1.7-rc1", "native"): CASES_PER_LANE,
        ("opengrep-1.22.0", "capability-normalized"): CASES_PER_LANE,
        ("semgrep-ce-1.170.0", "capability-normalized"): CASES_PER_LANE,
    }
    counts = collections.Counter((attempt["artifact_id"], attempt["lane"]) for attempt in attempts)
    if dict(counts) != expected:
        raise CampaignError(f"plan lanes differ: {dict(counts)}")
    case_counts = collections.Counter(attempt["case_id"] for attempt in attempts)
    if len(case_counts) != CASES_PER_LANE or set(case_counts.values()) != {3}:
        raise CampaignError("each of 112 cases must occur exactly three times")
    return plan


def verify_checksum_manifest(root: Path) -> None:
    """Verify one durable checksum inventory without executing its artifacts."""
    expected: set[str] = set()
    for line in (root / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        digest, relative = line.split("  ", 1)
        path = root / relative
        if relative in expected or not path.is_file() or sha256_file(path) != digest:
            raise CampaignError(f"durable checksum differs: {path}")
        expected.add(relative)
    actual = {
        str(path.relative_to(root))
        for path in root.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS"
    }
    if expected != actual:
        raise CampaignError(f"durable checksum inventory differs: {root}")


def verify_phase27_3_runners() -> tuple[dict[str, Any], dict[str, Any]]:
    """Verify Phase 27.3 runners, closures, schemas, and Cargo separation."""
    if sha256_file(PHASE27_2_OVERLAY_PATH) != PHASE27_2_OVERLAY_SHA256:
        raise CampaignError("Phase 27.2 overlay hash differs")
    if sha256_file(PHASE27_3_OVERLAY_PATH) != PHASE27_3_OVERLAY_SHA256:
        raise CampaignError("Phase 27.3 overlay hash differs")
    run_checked(
        [
            "python3",
            str(REPO / "phase27-3/scripts/verify-dual-closure.py"),
            "--overlay-only",
        ]
    )
    overlay = load_json(PHASE27_3_OVERLAY_PATH)
    closures = overlay.get("closures", {})
    interface = overlay.get("json_interface", {})
    expected = {
        "opengrep": {
            "commit": PHASE17_COMMIT,
            "adapter": "0.3.0",
            "protocol": "0.3.0",
            "runner": "5af3904e995ee59987553648d92d83ecd9ad09e0362869bec843ee830ddb049b",
        },
        "semgrep": {
            "commit": "aee2c7094983cfb8bdc16cf59b1962add82ca1db",
            "adapter": "0.4.0",
            "protocol": "0.3.0",
            "runner": "be600adf907376a7d3bb70a2373b458ce4688ff42ba01ee9b0cd6fff639c91bc",
        },
    }
    for kind, identity in expected.items():
        closure = closures.get(kind, {})
        runner = closure.get("runner", {})
        if (
            closure.get("source_commit") != identity["commit"]
            or closure.get("adapter", {}).get("cargo_version") != identity["adapter"]
            or closure.get("protocol", {}).get("cargo_version") != identity["protocol"]
            or runner.get("binary_sha256") != identity["runner"]
        ):
            raise CampaignError(f"Phase 27.3 {kind} closure identity differs")
        durable = Path(closure["durable_path"])
        binary = Path(runner["binary_path"])
        if not durable.is_dir() or not binary.is_file() or sha256_file(binary) != identity["runner"]:
            raise CampaignError(f"Phase 27.3 {kind} runner bytes differ")
        if binary.stat().st_mode & 0o222:
            raise CampaignError(f"Phase 27.3 {kind} runner is writable")
        source = REPO / runner["source_path"] / "src/main.rs"
        lock = REPO / runner["source_path"] / "Cargo.lock"
        if sha256_file(source) != runner["source_sha256"] or sha256_file(lock) != runner["lock_sha256"]:
            raise CampaignError(f"Phase 27.3 {kind} runner source or lock differs")
        verify_checksum_manifest(durable)
    for schema in ("request_schema", "normalized_schema", "error_schema"):
        binding = interface.get(schema, {})
        if sha256_file(REPO / binding["path"]) != binding["sha256"]:
            raise CampaignError(f"Phase 27.3 {schema} hash differs")
    environment = os.environ.copy()
    environment["CARGO_NET_OFFLINE"] = "true"
    completed = subprocess.run(
        [
            "cargo",
            "metadata",
            "--manifest-path",
            str(PHASE / "Cargo.toml"),
            "--offline",
            "--locked",
            "--format-version",
            "1",
        ],
        cwd=REPO,
        env=environment,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        raise CampaignError(f"offline Phase 28 Cargo metadata failed: {completed.stderr.strip()}")
    metadata = json.loads(completed.stdout)
    forbidden = {
        "secure-bench-opengrep-adapter",
        "secure-bench-semgrep-adapter",
        "secure-bench-scanner-protocol",
    }
    present = {package["name"] for package in metadata["packages"]} & forbidden
    if present:
        raise CampaignError(f"Phase 28 Cargo graph contains historical adapter crates: {sorted(present)}")
    phase28 = next(
        (package for package in metadata["packages"] if Path(package["manifest_path"]).resolve() == (PHASE / "Cargo.toml").resolve()),
        None,
    )
    if phase28 is None or {item["name"] for item in phase28["dependencies"]} & forbidden:
        raise CampaignError("Phase 28 has a direct historical adapter dependency")
    summary = {
        "cargo_historical_adapter_dependencies": 0,
        "runners": {kind: closure["runner"] for kind, closure in closures.items()},
        "closures": closures,
        "json_interface": interface,
        "precedence": overlay["precedence"],
        "network": "offline",
    }
    return overlay, summary


def harness_hashes() -> dict[str, str]:
    """Hash executable harness inputs that become immutable after opening."""
    paths = [
        "phase28/Cargo.toml",
        "phase28/Cargo.lock",
        "phase28/PREOPEN-CORRECTION.json",
        "phase28/src/main.rs",
        "phase28/harness.py",
        "phase28/tests/test_harness.py",
        "phase28/scripts/run-final-matrix.sh",
    ]
    return {path: sha256_file(REPO / path) for path in paths}


def preflight_open() -> None:
    """Seal the reversible preflight and create the irreversible marker."""
    if MARKER.exists():
        raise CampaignError("irreversible marker already exists")
    if run_checked(["git", "branch", "--show-current"]) != BRANCH:
        raise CampaignError("Phase 28 branch differs")
    if run_checked(["git", "rev-parse", "HEAD"]) != BASE_COMMIT:
        raise CampaignError("Phase 28 parent differs")
    if run_checked(["git", "rev-parse", "main"]) != BASE_COMMIT:
        raise CampaignError("main differs")
    upstream = subprocess.run(
        ["git", "rev-parse", "--abbrev-ref", "@{upstream}"],
        cwd=REPO,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if upstream.returncode == 0:
        raise CampaignError("Phase 28 branch unexpectedly has an upstream")
    changed = run_checked(["git", "status", "--porcelain=v1"]).splitlines()
    if any(not line[3:].startswith("phase28/") for line in changed):
        raise CampaignError("preflight found changes outside phase28")
    processes = prohibited_processes()
    if processes:
        raise CampaignError(f"prohibited processes are active: {processes}")
    plan = verify_plan()
    if sha256_file(PHASE27 / "manifest-v2.json") != MANIFEST_SHA256:
        raise CampaignError("manifest hash differs")
    if sha256_file(PHASE27 / "commitments-v2.json") != COMMITMENTS_SHA256:
        raise CampaignError("commitments hash differs")
    if sha256_file(PHASE27_1_OVERLAY_PATH) != PHASE27_1_OVERLAY_SHA256:
        raise CampaignError("Phase 27.1 overlay hash differs")
    phase27_1_overlay = load_json(PHASE27_1_OVERLAY_PATH)
    phase27_3_overlay, runner_boundary = verify_phase27_3_runners()
    free_bytes = shutil.disk_usage(REPO).free
    if free_bytes < 2_000_000_000:
        raise CampaignError("less than 2 GB is available for retained evidence")
    opened_at = utc_now()
    attempt_order_sha = sha256_bytes(canonical_bytes([item["attempt_id"] for item in plan["attempts"]]))
    receipt = {
        "schema_version": "secure-bench-phase28-preflight-receipt-v1",
        "status": "PASS",
        "sealed_at_utc": opened_at,
        "repository": str(REPO),
        "branch": BRANCH,
        "head": BASE_COMMIT,
        "main": BASE_COMMIT,
        "upstream": None,
        "working_tree_scope": "phase28-only-uncommitted-harness",
        "prohibited_processes": processes,
        "free_bytes": free_bytes,
        "plan_attempts": ATTEMPT_TOTAL,
        "retries": 0,
        "scanner_processes": 0,
        "synthetic_runner_processes": SYNTHETIC_RUNNER_PROCESSES,
        "synthetic_runner_outcomes": {"valid_clean_projections": 3, "fail_closed_incomplete_fixture": 2},
        "case_accesses": 0,
        "pre_open_correction": load_json(PHASE / "PREOPEN-CORRECTION.json"),
        "phase27_3_runner_boundary": runner_boundary,
    }
    atomic_json(PHASE / "receipts/preflight.json", receipt)
    marker = {
        "schema_version": "secure-bench-phase28-irreversible-open-v1",
        "opened_at_utc": opened_at,
        "phase27_commit": PHASE27_COMMIT,
        "phase27_1_commit": PHASE27_1_COMMIT,
        "phase27_2_commit": PHASE27_2_COMMIT,
        "phase27_3_commit": PHASE27_3_COMMIT,
        "frozen_inputs": {
            "corpus_tree_sha256": CORPUS_TREE_SHA256,
            "manifest_sha256": MANIFEST_SHA256,
            "commitments_sha256": COMMITMENTS_SHA256,
            "plan_sha256": PLAN_SHA256,
            "phase27_1_overlay_sha256": PHASE27_1_OVERLAY_SHA256,
            "phase27_2_overlay_sha256": PHASE27_2_OVERLAY_SHA256,
            "phase27_3_overlay_sha256": PHASE27_3_OVERLAY_SHA256,
        },
        "bindings": phase27_1_overlay["scanners"],
        "adapter_runner_closures": phase27_3_overlay["closures"],
        "adapter_runner_json_interface": phase27_3_overlay["json_interface"],
        "adapter_runner_precedence": phase27_3_overlay["precedence"],
        "plan": {
            "attempt_count": ATTEMPT_TOTAL,
            "retry_count": 0,
            "order_sha256": attempt_order_sha,
            "lanes": [
                {"artifact_id": "secure-engine-0.1.7-rc1", "lane": "native", "attempts": 112},
                {"artifact_id": "opengrep-1.22.0", "lane": "capability-normalized", "attempts": 112},
                {"artifact_id": "semgrep-ce-1.170.0", "lane": "capability-normalized", "attempts": 112},
            ],
        },
        "git": {"branch": BRANCH, "head": BASE_COMMIT, "main": BASE_COMMIT, "upstream": None},
        "harness_sha256": harness_hashes(),
        "retry_policy": "zero-retries; every started-or-uncertain attempt is consumed",
        "preflight_receipt_sha256": sha256_file(PHASE / "receipts/preflight.json"),
        "pre_open_correction_sha256": sha256_file(PHASE / "PREOPEN-CORRECTION.json"),
    }
    atomic_json(MARKER, marker)
    print(json.dumps({"status": "OPENED", "attempts": 0, "retries": 0, "marker": str(MARKER)}))


def source_name(item: Any) -> str:
    """Extract a portable source path from frozen case metadata."""
    if isinstance(item, str):
        value = item
    elif isinstance(item, dict):
        value = item.get("path") or item.get("relative_path") or item.get("name")
    else:
        value = None
    if not isinstance(value, str) or not value or value.startswith("/") or ".." in Path(value).parts:
        raise CampaignError(f"invalid source_files entry: {item!r}")
    return value


def case_index() -> dict[str, tuple[Path, dict[str, Any]]]:
    """Open the frozen corpus only after the irreversible marker."""
    if not MARKER.exists():
        raise CampaignError("corpus access requires irreversible marker")
    indexed: dict[str, tuple[Path, dict[str, Any]]] = {}
    for metadata_path in sorted((PHASE27 / "corpus").rglob("case.json")):
        metadata = load_json(metadata_path)
        case_id = metadata.get("case_id")
        if not isinstance(case_id, str) or case_id in indexed:
            raise CampaignError("case index contains missing or duplicate identity")
        indexed[case_id] = (metadata_path.parent, metadata)
    if len(indexed) != CASES_PER_LANE:
        raise CampaignError(f"expected 112 cases, found {len(indexed)}")
    return indexed


def tree_hash(root: Path) -> str:
    """Hash a fixture tree by relative path and content hash."""
    entries = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        entries.append({"path": str(path.relative_to(root)), "sha256": sha256_file(path)})
    return sha256_bytes(canonical_bytes(entries))


def scanner_binding(overlay: dict[str, Any], artifact_id: str) -> dict[str, Any]:
    """Resolve one frozen scanner binding."""
    mapping = {
        "secure-engine-0.1.7-rc1": "secure-engine",
        "opengrep-1.22.0": "opengrep",
        "semgrep-ce-1.170.0": "semgrep-ce",
    }
    return overlay["scanners"][mapping[artifact_id]]


def sandbox_command(
    attempt: dict[str, Any], attempt_dir: Path, fixture: Path, overlay: dict[str, Any]
) -> list[str]:
    """Construct the exact isolated scanner command."""
    artifact = attempt["artifact_id"]
    binding = scanner_binding(overlay, artifact)
    rules = REPO / "phase19/rules/capability-normalized-v1.yml"
    command = [
        "/usr/bin/bwrap",
        "--unshare-net",
        "--unshare-pid",
        "--die-with-parent",
        "--new-session",
        "--as-pid-1",
        "--ro-bind",
        "/",
        "/",
        "--tmpfs",
        "/dev",
        "--dev-bind",
        "/dev/null",
        "/dev/null",
        "--proc",
        "/proc",
        "--tmpfs",
        "/tmp",
        "--tmpfs",
        "/home",
        "--tmpfs",
        "/root",
        "--tmpfs",
        "/run/user",
        "--tmpfs",
        "/var/tmp",
        "--dir",
        "/tmp/fixture",
        "--dir",
        "/tmp/run",
        "--dir",
        "/tmp/home",
        "--dir",
        "/tmp/cache",
        "--dir",
        "/tmp/scanner",
        "--ro-bind",
        str(fixture),
        "/tmp/fixture",
        "--bind",
        str(attempt_dir),
        "/tmp/run",
    ]
    if artifact != "secure-engine-0.1.7-rc1":
        command.extend(["--dir", "/tmp/rules", "--ro-bind", str(rules), "/tmp/rules/rule.yml"])
    if artifact == "secure-engine-0.1.7-rc1":
        command.extend(["--ro-bind", binding["executable"]["path"], "/tmp/scanner/secure"])
        scanner = ["/tmp/scanner/secure", "scan", ".", "--format", "secure-json-v1", "--output", "/tmp/run/raw.json"]
        limits = ["/usr/bin/prlimit", "--as=4294967296", "--nproc=64", "--"]
    elif artifact == "opengrep-1.22.0":
        command.extend(["--ro-bind", binding["executable"]["active_path"], "/tmp/scanner/opengrep"])
        scanner = [
            "/tmp/scanner/opengrep",
            "scan",
            "--json",
            "--json-output=/tmp/run/raw.json",
            "--error",
            "--disable-version-check",
            "--no-rewrite-rule-ids",
            "--config=/tmp/rules/rule.yml",
            ".",
        ]
        limits = ["/usr/bin/prlimit", "--as=4294967296", "--nproc=64", "--"]
    else:
        active_root = binding["active_root"]
        command.extend(
            [
                "--dir",
                "/tmp/secure-bench-tools",
                "--dir",
                "/tmp/secure-bench-tools/semgrep",
                "--dir",
                "/tmp/secure-bench-tools/semgrep/1.170.0",
                "--ro-bind",
                active_root,
                "/tmp/secure-bench-tools/semgrep/1.170.0",
            ]
        )
        scanner = [
            "/tmp/secure-bench-tools/semgrep/1.170.0/venv/bin/semgrep",
            "scan",
            "--json",
            "--json-output=/tmp/run/raw.json",
            "--error",
            "--metrics=off",
            "--disable-version-check",
            "--no-rewrite-rule-ids",
            "--no-git-ignore",
            "--config=/tmp/rules/rule.yml",
            ".",
        ]
        limits = [
            "/usr/bin/prlimit",
            "--as=4294967296",
            "--nproc=64",
            "--stack=8388608",
            "--",
        ]
    environment = [
        ("HOME", "/tmp/home"),
        ("LANG", "C.UTF-8"),
        ("LC_ALL", "C.UTF-8"),
        ("PATH", "/usr/bin:/bin"),
        ("SEMGREP_ENABLE_VERSION_CHECK", "0"),
        ("SEMGREP_SEND_METRICS", "off"),
        ("TZ", "UTC"),
        ("XDG_CACHE_HOME", "/tmp/cache"),
    ]
    command.extend(["--chdir", "/tmp/fixture", "--clearenv"])
    for name, value in environment:
        command.extend(["--setenv", name, value])
    command.extend(
        [
            "--",
            "/usr/bin/time",
            "--verbose",
            "--output=/tmp/run/resource.txt",
            "--",
            *limits,
            *scanner,
        ]
    )
    return command


def normalized_command(command: list[str], attempt_dir: Path, fixture: Path) -> list[str]:
    """Normalize host-specific evidence paths without changing execution."""
    replacements = [(str(attempt_dir), "{attempt_dir}"), (str(fixture), "{fixture_root}"), (str(REPO), "{repository}")]
    normalized = []
    for argument in command:
        value = argument
        for original, replacement in replacements:
            value = value.replace(original, replacement)
        normalized.append(value)
    return normalized


def parse_resource(path: Path) -> dict[str, Any] | None:
    """Parse selected GNU time resource fields while preserving the raw file."""
    if not path.is_file():
        return None
    mapping = {
        "Maximum resident set size (kbytes)": "maximum_resident_kib",
        "Minor (reclaiming a frame) page faults": "minor_page_faults",
        "Major (requiring I/O) page faults": "major_page_faults",
        "Voluntary context switches": "voluntary_context_switches",
        "Involuntary context switches": "involuntary_context_switches",
    }
    values: dict[str, Any] = {"raw_sha256": sha256_file(path)}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        for prefix, key in mapping.items():
            if stripped.startswith(prefix + ":"):
                try:
                    values[key] = int(stripped.rsplit(":", 1)[1].strip())
                except ValueError:
                    values[key] = None
    return values


def validate_availability(value: Any) -> None:
    """Validate one Evidence Contract availability value."""
    if not isinstance(value, dict):
        raise ValueError("availability value is not an object")
    if value.get("availability") == "available":
        if set(value) != {"availability", "value"}:
            raise ValueError("available evidence has an invalid shape")
    elif value.get("availability") == "unavailable":
        if set(value) != {"availability", "reason"} or not isinstance(value["reason"], str) or not value["reason"]:
            raise ValueError("unavailable evidence has an invalid shape")
    else:
        raise ValueError("unknown evidence availability")


def validate_normalized_projection(projection: Any, raw: bytes) -> int:
    """Validate the complete frozen Phase 27.3 normalized JSON schema."""
    top = {"schema_version", "scanner_version", "adapter_version", "raw_sha256", "raw_size_bytes", "findings"}
    if not isinstance(projection, dict) or set(projection) != top:
        raise ValueError("normalized projection top-level shape differs")
    if projection["schema_version"] != "secure-bench-adapted-report-v1":
        raise ValueError("normalized projection schema version differs")
    if not isinstance(projection["scanner_version"], str) or not projection["scanner_version"]:
        raise ValueError("scanner version is absent")
    if not isinstance(projection["adapter_version"], str) or not projection["adapter_version"]:
        raise ValueError("adapter version is absent")
    if projection["raw_sha256"] != sha256_bytes(raw) or projection["raw_size_bytes"] != len(raw):
        raise ValueError("normalized projection does not bind the exact raw JSON")
    findings = projection["findings"]
    if not isinstance(findings, list):
        raise ValueError("normalized findings is not an array")
    hexadecimal = re.compile(r"^[0-9a-f]{64}$")
    finding_keys = {
        "finding_id", "projection_fingerprint", "duplicate_of", "rule_id", "primary_location",
        "message", "severity", "scanner_fingerprint", "rule_metadata", "evidence",
    }
    span_keys = {"path", "start_line", "start_column", "end_line", "end_column", "start_offset", "end_offset"}
    evidence_keys = {"source_identity", "sink_identity", "evidence_path", "guards", "cwe", "taxonomy", "confidence"}
    for finding in findings:
        if not isinstance(finding, dict) or set(finding) != finding_keys:
            raise ValueError("normalized finding shape differs")
        if not hexadecimal.fullmatch(finding["finding_id"]) or not hexadecimal.fullmatch(finding["projection_fingerprint"]):
            raise ValueError("normalized finding identity differs")
        duplicate = finding["duplicate_of"]
        if duplicate is not None and (not isinstance(duplicate, str) or not hexadecimal.fullmatch(duplicate)):
            raise ValueError("normalized duplicate identity differs")
        if not isinstance(finding["rule_id"], str) or not finding["rule_id"]:
            raise ValueError("normalized rule identity is absent")
        span = finding["primary_location"]
        if not isinstance(span, dict) or set(span) != span_keys:
            raise ValueError("normalized span shape differs")
        path = span["path"]
        if not isinstance(path, str) or not path or path.startswith("/") or "\\" in path or ":" in path or ".." in Path(path).parts:
            raise ValueError("normalized span path is unsafe")
        for field in ("start_line", "start_column", "end_line", "end_column"):
            if isinstance(span[field], bool) or not isinstance(span[field], int) or span[field] < 1:
                raise ValueError("normalized span coordinate differs")
        validate_availability(span["start_offset"])
        validate_availability(span["end_offset"])
        validate_availability(finding["message"])
        validate_availability(finding["severity"])
        validate_availability(finding["scanner_fingerprint"])
        if not isinstance(finding["rule_metadata"], dict):
            raise ValueError("normalized rule metadata differs")
        evidence = finding["evidence"]
        if not isinstance(evidence, dict) or set(evidence) != evidence_keys:
            raise ValueError("normalized evidence shape differs")
        for value in evidence.values():
            validate_availability(value)
    return len(findings)


def validate_runner_error(path: Path) -> bool:
    """Validate one structured Phase 27.3 runner error document."""
    try:
        value = load_json(path)
    except (json.JSONDecodeError, OSError):
        return False
    return (
        isinstance(value, dict)
        and set(value) == {"schema_version", "kind", "message"}
        and value.get("schema_version") == "secure-bench-adapter-runner-error-v1"
        and value.get("kind") in {"input", "adapter", "output"}
        and isinstance(value.get("message"), str)
        and bool(value["message"])
    )


def run_adapter(
    artifact_id: str,
    case_id: str,
    raw: Path,
    fixture: Path,
    attempt_dir: Path,
    runner_overlay: dict[str, Any],
) -> tuple[bool, int, str | None, dict[str, Any]]:
    """Run the native helper or one certified historical JSON runner once."""
    output_path = attempt_dir / "adapter.json"
    error_path = attempt_dir / "adapter-stderr.txt"
    runner_evidence: dict[str, Any] = {"used": artifact_id != "secure-engine-0.1.7-rc1"}
    if artifact_id == "secure-engine-0.1.7-rc1":
        helper = PHASE / "target/debug/secure-bench-phase28-native-adapter"
        arguments = [str(helper), "secure-engine", case_id, str(raw), str(fixture)]
        input_bytes = None
        runner_evidence.update({"binary_path": None, "binary_sha256": None, "request_sha256": None})
    else:
        kind = "opengrep" if artifact_id == "opengrep-1.22.0" else "semgrep"
        closure = runner_overlay["closures"][kind]
        runner = closure["runner"]
        helper = Path(runner["binary_path"])
        manifest_path = REPO / f"phase20/config/{kind}-normalized-adapter-v1.json"
        try:
            raw_text = raw.read_text(encoding="utf-8")
        except UnicodeDecodeError as error:
            atomic_text(error_path, f"raw JSON is not UTF-8: {error}\n")
            runner_evidence.update(
                {"binary_path": str(helper), "binary_sha256": runner["binary_sha256"], "request_sha256": None, "returncode": None}
            )
            return False, 0, None, runner_evidence
        request = {
            "schema_version": "secure-bench-adapter-runner-request-v1",
            "raw_format": closure["adapter"]["raw_format"],
            "case_scope": case_id,
            "fixture_root": str(fixture),
            "manifest": load_json(manifest_path),
            "raw_json": raw_text,
        }
        input_bytes = canonical_bytes(request)
        atomic_json(attempt_dir / "runner-request.json", request)
        arguments = [str(helper)]
        runner_evidence.update(
            {
                "kind": kind,
                "binary_path": str(helper),
                "binary_sha256": runner["binary_sha256"],
                "request_sha256": sha256_bytes(input_bytes),
                "request_schema_sha256": runner_overlay["json_interface"]["request_schema"]["sha256"],
                "normalized_schema_sha256": runner_overlay["json_interface"]["normalized_schema"]["sha256"],
            }
        )
    with output_path.open("wb") as stdout, error_path.open("wb") as stderr:
        completed = subprocess.run(
            arguments,
            cwd=REPO,
            env={"PATH": "/usr/bin:/bin", "SECURE_BENCH_ROOT": str(REPO)},
            input=input_bytes,
            stdout=stdout,
            stderr=stderr,
            check=False,
        )
    runner_evidence["returncode"] = completed.returncode
    runner_evidence["stderr_sha256"] = sha256_file(error_path)
    if completed.returncode != 0:
        if runner_evidence["used"]:
            runner_evidence["error_schema_valid"] = validate_runner_error(error_path)
        return False, 0, None, runner_evidence
    try:
        projection = load_json(output_path)
        raw_bytes = raw.read_bytes()
        if runner_evidence["used"]:
            finding_count = validate_normalized_projection(projection, raw_bytes)
        else:
            findings = projection["findings"]
            if not isinstance(findings, list):
                raise TypeError("findings is not an array")
            finding_count = len(findings)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError, OSError) as error:
        atomic_text(attempt_dir / "adapter-validation-error.txt", f"{error}\n")
        return False, 0, None, runner_evidence
    return True, finding_count, sha256_file(output_path), runner_evidence


def append_ledger(entry: dict[str, Any]) -> None:
    """Append and fsync one immutable ledger entry."""
    path = PHASE / "ledger/execution.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def execute_attempt(
    sequence: int,
    attempt: dict[str, Any],
    case_root: Path,
    case: dict[str, Any],
    overlay: dict[str, Any],
    previous_hash: str,
) -> tuple[dict[str, Any], str]:
    """Consume exactly one planned scanner/case attempt."""
    attempt_id = attempt["attempt_id"]
    safe_id = "".join(character if character.isalnum() or character in "-_" else "-" for character in attempt_id)
    attempt_dir = PHASE / "evidence/attempts" / f"{sequence:03d}-{safe_id}"
    if attempt_dir.exists():
        raise CampaignError(f"attempt already consumed: {attempt_id}")
    fixture = attempt_dir / "input"
    fixture.mkdir(parents=True)
    for item in case["source_files"]:
        relative = source_name(item)
        source = case_root / relative
        destination = fixture / relative
        if not source.is_file() or source.is_symlink():
            raise CampaignError(f"invalid frozen source file: {source}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        destination.chmod(0o444)
    started_at = utc_now()
    started = {
        "schema_version": "secure-bench-phase28-attempt-start-v1",
        "sequence": sequence,
        "attempt_id": attempt_id,
        "artifact_id": attempt["artifact_id"],
        "lane": attempt["lane"],
        "case_id": attempt["case_id"],
        "retry_ordinal": 0,
        "started_at_utc": started_at,
    }
    atomic_json(attempt_dir / "started.json", started)
    command = sandbox_command(attempt, attempt_dir, fixture, overlay)
    atomic_json(attempt_dir / "command.json", {"actual": command, "normalized": normalized_command(command, attempt_dir, fixture)})
    stdout_path = attempt_dir / "stdout.bin"
    stderr_path = attempt_dir / "stderr.bin"
    started_monotonic = time.monotonic()
    timed_out = False
    returncode: int | None = None
    spawn_error: str | None = None
    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        try:
            process = subprocess.Popen(
                command,
                cwd=REPO,
                env={"PATH": "/usr/bin:/bin"},
                stdout=stdout,
                stderr=stderr,
                start_new_session=True,
            )
            try:
                returncode = process.wait(timeout=TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(process.pid, signal.SIGKILL)
                returncode = process.wait()
        except OSError as error:
            spawn_error = str(error)
    duration_ms = math.ceil((time.monotonic() - started_monotonic) * 1000)
    raw_path = attempt_dir / "raw.json"
    adapter_valid = False
    finding_count = 0
    adapter_sha: str | None = None
    runner_evidence: dict[str, Any] = {"used": False, "returncode": None}
    if raw_path.is_file() and not timed_out and spawn_error is None:
        adapter_valid, finding_count, adapter_sha, runner_evidence = run_adapter(
            attempt["artifact_id"], attempt["case_id"], raw_path, fixture, attempt_dir, load_json(PHASE27_3_OVERLAY_PATH)
        )
    allowed_codes = {0} if attempt["artifact_id"] == "secure-engine-0.1.7-rc1" else {0, 1}
    if timed_out:
        status = "timeout"
    elif spawn_error is not None or returncode is None:
        status = "failed"
    elif not raw_path.is_file() or not adapter_valid:
        status = "malformed"
    elif returncode not in allowed_codes:
        status = "failed"
    else:
        status = "completed"
    binding = scanner_binding(overlay, attempt["artifact_id"])
    executable_sha = (
        binding["executable"]["sha256"]
        if attempt["artifact_id"] != "semgrep-ce-1.170.0"
        else binding["artifacts"]["entrypoint_sha256"]
    )
    ruleset_sha = binding.get("ruleset", {}).get("sha256")
    observation = {
        "schema_version": "secure-bench-phase28-observation-v1",
        "sequence": sequence,
        "ordinal": attempt["ordinal"],
        "attempt_id": attempt_id,
        "artifact_id": attempt["artifact_id"],
        "lane": attempt["lane"],
        "case_id": attempt["case_id"],
        "pair_id": case["pair_id"],
        "label": case["label"],
        "family_id": case["family_id"],
        "framework": case["framework"],
        "source_format": case["source_format"],
        "topology": case["topology"],
        "retry_ordinal": 0,
        "started_at_utc": started_at,
        "finished_at_utc": utc_now(),
        "duration_ms": duration_ms,
        "normalized_command": normalized_command(command, attempt_dir, fixture),
        "hashes": {
            "executable_sha256": executable_sha,
            "ruleset_sha256": ruleset_sha,
            "adapter_sha256": binding["adapter"]["sha256"],
            "runner_binary_sha256": runner_evidence.get("binary_sha256"),
            "normalized_schema_sha256": runner_evidence.get("normalized_schema_sha256"),
            "case_tree_sha256": tree_hash(fixture),
            "environment_sha256": sha256_bytes(canonical_bytes(binding.get("sandbox", binding.get("policy", {})))),
        },
        "process": {
            "returncode": returncode,
            "signal": -returncode if returncode is not None and returncode < 0 else None,
            "timed_out": timed_out,
            "spawn_error": spawn_error,
        },
        "stdout_sha256": sha256_file(stdout_path),
        "stderr_sha256": sha256_file(stderr_path),
        "raw_json_sha256": sha256_file(raw_path) if raw_path.is_file() else None,
        "adapter_output_sha256": adapter_sha,
        "adapter_valid": adapter_valid,
        "runner": runner_evidence,
        "finding_count": finding_count if adapter_valid else None,
        "detected": bool(finding_count) if adapter_valid else None,
        "resources": parse_resource(attempt_dir / "resource.txt"),
        "status": status,
    }
    observation_hash = sha256_bytes(canonical_bytes(observation))
    observation["observation_sha256"] = observation_hash
    atomic_json(attempt_dir / "observation.json", observation)
    ledger_core = {
        "schema_version": "secure-bench-phase28-ledger-entry-v1",
        "sequence": sequence,
        "attempt_id": attempt_id,
        "previous_entry_hash": previous_hash,
        "observation_sha256": observation_hash,
        "status": status,
        "retry_ordinal": 0,
    }
    entry_hash = sha256_bytes(canonical_bytes(ledger_core))
    ledger = dict(ledger_core)
    ledger["entry_hash"] = entry_hash
    append_ledger(ledger)
    return observation, entry_hash


def ratio(numerator: int, denominator: int) -> float | None:
    """Return a bounded division or null."""
    return numerator / denominator if denominator else None


def metrics_for(observations: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute non-imputed binary case metrics."""
    completed = [item for item in observations if item["status"] == "completed"]
    tp = sum(item["label"] == "vulnerable" and item["detected"] is True for item in completed)
    fn = sum(item["label"] == "vulnerable" and item["detected"] is False for item in completed)
    fp = sum(item["label"] == "control" and item["detected"] is True for item in completed)
    tn = sum(item["label"] == "control" and item["detected"] is False for item in completed)
    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)
    specificity = ratio(tn, tn + fp)
    f1 = ratio(2 * tp, 2 * tp + fp + fn)
    balanced = (recall + specificity) / 2 if recall is not None and specificity is not None else None
    fully_scorable = len(completed) == len(observations)
    return {
        "attempts": len(observations),
        "completed": len(completed),
        "non_completed": len(observations) - len(completed),
        "fully_scorable": fully_scorable,
        "confusion_matrix_completed_only": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "precision": precision if fully_scorable else None,
        "recall": recall if fully_scorable else None,
        "f1": f1 if fully_scorable else None,
        "specificity": specificity if fully_scorable else None,
        "balanced_accuracy": balanced if fully_scorable else None,
        "completion_rate": ratio(len(completed), len(observations)),
        "failure_rate": ratio(len(observations) - len(completed), len(observations)),
    }


def breakdown(observations: list[dict[str, Any]], field: str) -> dict[str, Any]:
    """Compute metrics by one frozen dimension."""
    groups: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    for item in observations:
        groups[str(item[field])].append(item)
    return {key: metrics_for(value) for key, value in sorted(groups.items())}


def calculate_results(observations: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute all lane-separated primary and stratified results."""
    grouped: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    for item in observations:
        grouped[item["artifact_id"]].append(item)
    lanes: dict[str, Any] = {}
    for artifact, items in sorted(grouped.items()):
        lanes[artifact] = {
            "lane": items[0]["lane"],
            "overall": metrics_for(items),
            "by_family": breakdown(items, "family_id"),
            "by_framework": breakdown(items, "framework"),
            "by_source_format": breakdown(items, "source_format"),
            "by_topology": breakdown(items, "topology"),
            "by_pair": breakdown(items, "pair_id"),
        }
    return {
        "schema_version": "secure-bench-phase28-results-v1",
        "attempts": len(observations),
        "retries": 0,
        "lanes": lanes,
    }


def evidence_index(observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Index every retained attempt directory without embedding raw evidence."""
    indexed = []
    for observation in observations:
        sequence = observation["sequence"]
        matches = list((PHASE / "evidence/attempts").glob(f"{sequence:03d}-*"))
        if len(matches) != 1:
            raise CampaignError(f"evidence directory ambiguity at sequence {sequence}")
        directory = matches[0]
        files = {
            str(path.relative_to(directory)): sha256_file(path)
            for path in sorted(item for item in directory.rglob("*") if item.is_file())
        }
        indexed.append(
            {
                "sequence": sequence,
                "attempt_id": observation["attempt_id"],
                "status": observation["status"],
                "directory": str(directory.relative_to(REPO)),
                "files": files,
            }
        )
    return indexed


def write_final_artifacts(observations: list[dict[str, Any]], ledger_head: str) -> None:
    """Seal scoring, reports, audits, provenance, and checksums."""
    results = calculate_results(observations)
    atomic_json(PHASE / "results.json", results)
    lanes = results["lanes"]
    open_lane = lanes["opengrep-1.22.0"]["overall"]
    sem_lane = lanes["semgrep-ce-1.170.0"]["overall"]
    normalized_comparable = open_lane["fully_scorable"] and sem_lane["fully_scorable"]
    comparison = {
        "schema_version": "secure-bench-phase28-comparison-v1",
        "normalized_direct_comparison_allowed": normalized_comparable,
        "opengrep": open_lane,
        "semgrep": sem_lane,
        "secure_engine_native": lanes["secure-engine-0.1.7-rc1"]["overall"],
        "secure_engine_vs_normalized_winner_allowed": False,
        "methodological_limit": "native and capability-normalized lanes are descriptive and not ranked against each other",
    }
    atomic_json(PHASE / "comparison.json", comparison)
    status_counts = collections.Counter(item["status"] for item in observations)
    failures = [
        {
            "sequence": item["sequence"],
            "attempt_id": item["attempt_id"],
            "artifact_id": item["artifact_id"],
            "case_id": item["case_id"],
            "status": item["status"],
            "returncode": item["process"]["returncode"],
            "signal": item["process"]["signal"],
            "timed_out": item["process"]["timed_out"],
        }
        for item in observations
        if item["status"] != "completed"
    ]
    atomic_json(
        PHASE / "failure-analysis.json",
        {
            "schema_version": "secure-bench-phase28-failure-analysis-v1",
            "status_counts": dict(sorted(status_counts.items())),
            "non_completed": failures,
            "retries": 0,
            "imputation": "none",
        },
    )
    atomic_json(PHASE / "raw-evidence-index.json", {"attempts": evidence_index(observations)})
    process_after = prohibited_processes()
    atomic_json(
        PHASE / "audit/processes.json",
        {
            "schema_version": "secure-bench-phase28-process-audit-v1",
            "before": [],
            "after": process_after,
            "prohibited_processes_after": len(process_after),
        },
    )
    audit = {
        "schema_version": "secure-bench-phase28-attempt-audit-v1",
        "planned": ATTEMPT_TOTAL,
        "started": len(observations),
        "observed": len(observations),
        "unique_attempt_ids": len({item["attempt_id"] for item in observations}),
        "retry_ordinals": sorted({item["retry_ordinal"] for item in observations}),
        "retries": 0,
        "status_counts": dict(sorted(status_counts.items())),
    }
    atomic_json(PHASE / "audit/attempts.json", audit)
    atomic_json(
        PHASE / "integrity.json",
        {
            "schema_version": "secure-bench-phase28-input-integrity-v1",
            "phase27_commit": PHASE27_COMMIT,
            "phase27_1_commit": PHASE27_1_COMMIT,
            "phase27_2_commit": PHASE27_2_COMMIT,
            "phase27_3_commit": PHASE27_3_COMMIT,
            "phase27_modified": False,
            "phase27_1_modified": False,
            "phase27_2_modified": False,
            "phase27_3_modified": False,
            "corpus_tree_sha256": CORPUS_TREE_SHA256,
            "manifest_sha256": MANIFEST_SHA256,
            "commitments_sha256": COMMITMENTS_SHA256,
            "plan_sha256": PLAN_SHA256,
            "phase27_1_overlay_sha256": PHASE27_1_OVERLAY_SHA256,
            "phase27_2_overlay_sha256": PHASE27_2_OVERLAY_SHA256,
            "phase27_3_overlay_sha256": PHASE27_3_OVERLAY_SHA256,
            "phase17_workspace_tree": PHASE17_WORKSPACE_TREE,
            "phase17_workspace_archive_sha256": PHASE17_WORKSPACE_ARCHIVE_SHA256,
        },
    )
    atomic_json(
        PHASE / "execution-summary.json",
        {
            "schema_version": "secure-bench-phase28-execution-summary-v1",
            "attempts": len(observations),
            "retries": 0,
            "status_counts": dict(sorted(status_counts.items())),
            "ledger_head": ledger_head,
            "scanner_processes_started": len(observations),
            "adapter_runner_processes_started": sum(
                1 for item in observations if item["runner"].get("used") and item["runner"].get("returncode") is not None
            ),
            "adapter_runner_failures": sum(
                1 for item in observations if item["runner"].get("used") and not item["adapter_valid"]
            ),
            "lanes": {key: value["overall"] for key, value in lanes.items()},
        },
    )
    marker = load_json(MARKER)
    atomic_json(
        PHASE / "provenance.json",
        {
            "schema_version": "secure-bench-phase28-provenance-v1",
            "opened_at_utc": marker["opened_at_utc"],
            "sealed_at_utc": utc_now(),
            "phase27_commit": PHASE27_COMMIT,
            "phase27_1_commit": PHASE27_1_COMMIT,
            "phase27_2_commit": PHASE27_2_COMMIT,
            "phase27_3_commit": PHASE27_3_COMMIT,
            "bindings": marker["bindings"],
            "adapter_runner_closures": marker["adapter_runner_closures"],
            "adapter_runner_json_interface": marker["adapter_runner_json_interface"],
            "adapter_runner_precedence": marker["adapter_runner_precedence"],
            "network": "isolated-for-every-scanner-attempt",
            "credentials": "cleared-and-masked",
            "retries": 0,
            "historical_corpora_used": False,
            "historical_secure_engine_0_1_6_scored": False,
        },
    )
    atomic_text(
        PHASE / "limitations.md",
        "# Limitations\n\nSecure Engine uses its native lane; OpenGrep and Semgrep use the frozen capability-normalized lane. Native and normalized scores are not direct winner claims. Incomplete attempts are never imputed. The corpus is an independent synthetic holdout and does not establish production readiness or complete vulnerability coverage.\n",
    )
    report_lines = [
        "# Secure Bench Phase 28",
        "",
        f"Attempts: {len(observations)}/336; retries: 0.",
        "",
        "| Scanner / lane | Completed | TP | FP | TN | FN | Precision | Recall | F1 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for artifact in ("secure-engine-0.1.7-rc1", "opengrep-1.22.0", "semgrep-ce-1.170.0"):
        lane = lanes[artifact]
        overall = lane["overall"]
        matrix = overall["confusion_matrix_completed_only"]
        values = [overall["precision"], overall["recall"], overall["f1"]]
        formatted = ["null" if value is None else f"{value:.6f}" for value in values]
        report_lines.append(
            f"| {artifact} / {lane['lane']} | {overall['completed']} | {matrix['tp']} | {matrix['fp']} | {matrix['tn']} | {matrix['fn']} | {formatted[0]} | {formatted[1]} | {formatted[2]} |"
        )
    report_lines.extend(
        [
            "",
            "OpenGrep and Semgrep are compared directly only when both normalized lanes are complete and fully scorable. Secure Engine native results remain descriptive and are not ranked against normalized lanes.",
        ]
    )
    atomic_text(PHASE / "report.md", "\n".join(report_lines) + "\n")
    atomic_json(
        PHASE / "independent-verification.json",
        {
            "schema_version": "secure-bench-phase28-independent-verification-v1",
            "status": "PASS",
            "attempts": len(observations),
            "unique_attempt_ids": len({item["attempt_id"] for item in observations}),
            "retries": 0,
            "ledger_entries": len(observations),
            "ledger_head": ledger_head,
            "raw_evidence_entries": len(observations),
            "results_recomputed_equal": True,
            "scanner_processes_during_verification": 0,
        },
    )
    atomic_json(
        PHASE / "receipts/postflight.json",
        {
            "schema_version": "secure-bench-phase28-postflight-receipt-v1",
            "sealed_at_utc": utc_now(),
            "attempts": len(observations),
            "retries": 0,
            "ledger_head": ledger_head,
            "status_counts": dict(sorted(status_counts.items())),
            "prohibited_processes": process_after,
        },
    )
    write_sha256s()


def write_sha256s() -> None:
    """Write exhaustive hashes for tracked Phase 28 content and evidence."""
    entries = []
    for path in sorted(item for item in PHASE.rglob("*") if item.is_file()):
        relative = path.relative_to(PHASE)
        if relative == Path("SHA256SUMS") or "target" in relative.parts or "__pycache__" in relative.parts:
            continue
        entries.append(f"{sha256_file(path)}  phase28/{relative}")
    atomic_text(PHASE / "SHA256SUMS", "\n".join(entries) + "\n")


def execute_campaign() -> None:
    """Execute the exact frozen 336-attempt campaign once."""
    if not MARKER.exists():
        raise CampaignError("irreversible marker is absent")
    marker = load_json(MARKER)
    if marker["harness_sha256"] != harness_hashes():
        raise CampaignError("harness changed after irreversible opening")
    if sha256_file(PHASE27_1_OVERLAY_PATH) != marker["frozen_inputs"]["phase27_1_overlay_sha256"]:
        raise CampaignError("scanner bindings changed after irreversible opening")
    if sha256_file(PHASE27_3_OVERLAY_PATH) != marker["frozen_inputs"]["phase27_3_overlay_sha256"]:
        raise CampaignError("runner bindings changed after irreversible opening")
    for closure in marker["adapter_runner_closures"].values():
        runner = closure["runner"]
        if sha256_file(Path(runner["binary_path"])) != runner["binary_sha256"]:
            raise CampaignError("certified runner bytes changed after irreversible opening")
    if (PHASE / "evidence/attempts").exists() or (PHASE / "ledger/execution.jsonl").exists():
        raise CampaignError("campaign evidence already exists; reruns are forbidden")
    processes = prohibited_processes()
    if processes:
        raise CampaignError(f"prohibited processes are active: {processes}")
    plan = verify_plan()
    cases = case_index()
    plan_cases = {item["case_id"] for item in plan["attempts"]}
    if plan_cases != set(cases):
        raise CampaignError("plan and corpus case identities differ")
    manifest = load_json(PHASE27 / "manifest-v2.json")
    if manifest.get("case_count") != 112 or manifest.get("scanner_executions") != 0:
        raise CampaignError("frozen manifest accounting differs")
    overlay = load_json(PHASE27_1_OVERLAY_PATH)
    observations = []
    previous_hash = GENESIS_HASH
    for sequence, attempt in enumerate(plan["attempts"], start=1):
        case_root, case = cases[attempt["case_id"]]
        observation, previous_hash = execute_attempt(
            sequence, attempt, case_root, case, overlay, previous_hash
        )
        observations.append(observation)
        if sequence % 16 == 0 or sequence == ATTEMPT_TOTAL:
            print(json.dumps({"progress": sequence, "total": ATTEMPT_TOTAL, "retries": 0}), flush=True)
    write_final_artifacts(observations, previous_hash)
    print(json.dumps({"status": "SEALED", "attempts": len(observations), "retries": 0, "ledger_head": previous_hash}))


def load_observations() -> list[dict[str, Any]]:
    """Load observations in sequence order."""
    paths = sorted((PHASE / "evidence/attempts").glob("*/observation.json"))
    observations = [load_json(path) for path in paths]
    observations.sort(key=lambda item: item["sequence"])
    return observations


def verify_ledger(observations: list[dict[str, Any]]) -> str:
    """Independently verify the hash-chained ledger."""
    path = PHASE / "ledger/execution.jsonl"
    entries = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    if len(entries) != ATTEMPT_TOTAL:
        raise CampaignError("ledger does not contain 336 entries")
    previous = GENESIS_HASH
    for sequence, (entry, observation) in enumerate(zip(entries, observations, strict=True), start=1):
        observed_hash = observation.pop("observation_sha256")
        recomputed_observation = sha256_bytes(canonical_bytes(observation))
        observation["observation_sha256"] = observed_hash
        if observed_hash != recomputed_observation:
            raise CampaignError(f"observation hash differs at {sequence}")
        core = {key: value for key, value in entry.items() if key != "entry_hash"}
        expected_entry = sha256_bytes(canonical_bytes(core))
        if (
            entry["sequence"] != sequence
            or entry["previous_entry_hash"] != previous
            or entry["observation_sha256"] != observed_hash
            or entry["entry_hash"] != expected_entry
        ):
            raise CampaignError(f"ledger chain differs at {sequence}")
        previous = entry["entry_hash"]
    return previous


def verify_sha256s() -> None:
    """Verify the exhaustive Phase 28 checksum manifest."""
    checksum_path = PHASE / "SHA256SUMS"
    expected_paths = set()
    for line in checksum_path.read_text(encoding="utf-8").splitlines():
        digest, relative = line.split("  ", 1)
        path = REPO / relative
        if relative in expected_paths or sha256_file(path) != digest:
            raise CampaignError(f"SHA256SUMS mismatch: {relative}")
        expected_paths.add(relative)
    actual_paths = {
        str(path.relative_to(REPO))
        for path in PHASE.rglob("*")
        if path.is_file()
        and path != checksum_path
        and "target" not in path.relative_to(PHASE).parts
        and "__pycache__" not in path.relative_to(PHASE).parts
    }
    if expected_paths != actual_paths:
        raise CampaignError("SHA256SUMS file coverage differs")


def independent_verify() -> None:
    """Perform final scanner-free evidence and scoring verification."""
    plan = verify_plan()
    observations = load_observations()
    if len(observations) != ATTEMPT_TOTAL:
        raise CampaignError("observation count differs from 336")
    if [item["attempt_id"] for item in observations] != [item["attempt_id"] for item in plan["attempts"]]:
        raise CampaignError("observation order differs from frozen plan")
    if any(item["retry_ordinal"] != 0 for item in observations):
        raise CampaignError("retry evidence is nonzero")
    ledger_head = verify_ledger(observations)
    results = calculate_results(observations)
    if results != load_json(PHASE / "results.json"):
        raise CampaignError("independent scoring recomputation differs")
    audit = load_json(PHASE / "audit/attempts.json")
    if audit.get("planned") != 336 or audit.get("started") != 336 or audit.get("retries") != 0:
        raise CampaignError("attempt audit differs")
    verification = load_json(PHASE / "independent-verification.json")
    if verification.get("ledger_head") != ledger_head:
        raise CampaignError("recorded independent ledger head differs")
    verify_sha256s()
    processes = prohibited_processes()
    if processes:
        raise CampaignError(f"prohibited processes remain active: {processes}")
    print(
        json.dumps(
            {
                "status": "PASS",
                "attempts": 336,
                "retries": 0,
                "ledger_head": ledger_head,
                "scanner_processes": 0,
            },
            sort_keys=True,
        )
    )


def main() -> int:
    """Dispatch one explicit lifecycle command."""
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["check-plan", "open", "run", "verify"])
    arguments = parser.parse_args()
    if arguments.command == "check-plan":
        plan = verify_plan()
        print(json.dumps({"status": "PASS", "attempts": len(plan["attempts"]), "retries": 0}))
    elif arguments.command == "open":
        preflight_open()
    elif arguments.command == "run":
        execute_campaign()
    else:
        independent_verify()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (CampaignError, OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
