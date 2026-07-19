#!/usr/bin/env python3
"""Independently verify both historical adapter closures without scanners."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import tomllib
from typing import Any


BASE = "467413eeb2a22017b5bc19f7f2052fdbc5d43d0d"
PHASE17 = "241600628315db6d8a77e62bbaf6e61ba5c628f1"
PHASE18 = "aee2c7094983cfb8bdc16cf59b1962add82ca1db"
PHASE17_COMMIT_TREE = "0b5b8315d319ff8903e7611011eab38199326ec8"
PHASE18_COMMIT_TREE = "23faa0979e7bf641612a768d9952948bc6df2264"
PHASE17_TREE = "e2512d180118e6487a979ba03d1961c41d17825d"
PHASE18_TREE = "d2d32cc9147666c5447c225aa9bfe8ba5b0ca8bc"
PROTOCOL_TREE = "7fd40434d1226bbf4bdba6a042e2824856fa7590"
REPO = Path(__file__).resolve().parents[2]
PHASE = REPO / "phase27-3"
DEFAULT_OVERLAY = PHASE / "binding-overlay.json"
DURABLE = {
    "opengrep": Path(
        "/home/danielcastrillon/Proyectos/secure-bench-tool-cache/"
        "adapter-workspaces/opengrep-phase17"
    ),
    "semgrep": Path(
        "/home/danielcastrillon/Proyectos/secure-bench-tool-cache/"
        "adapter-workspaces/semgrep-phase18"
    ),
}
RUNNER_HASHES = {
    "opengrep": "5af3904e995ee59987553648d92d83ecd9ad09e0362869bec843ee830ddb049b",
    "semgrep": "be600adf907376a7d3bb70a2373b458ce4688ff42ba01ee9b0cd6fff639c91bc",
}
RUNNER_LOCKS = {
    "opengrep": "4510745e806917c3c6ed93f7bde315b627b8181684424c31375d0efb5090cba9",
    "semgrep": "3227b2efff7e88ef1b1401ba164dc5d51ee75531a75c83bbc7a32b135c3f5cf3",
}
RUNNER_SOURCES = {
    "opengrep": "3e08f5b17dc84c5acd8dc4275fbf176b3c5c0d0a597b4314440494b8b579995e",
    "semgrep": "1a7611f11482a76e0f75a78d9b7c81b09810fd374f2c8cde7b625f34551efdda",
}


def fail(message: str) -> None:
    raise ValueError(message)


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_object(kind: bytes, payload: bytes) -> bytes:
    return hashlib.sha1(kind + b" " + str(len(payload)).encode() + b"\0" + payload).digest()


def git_tree(path: Path, ignored: set[str] | None = None) -> str:
    ignored = ignored or set()
    entries: list[bytes] = []
    for child in sorted(path.iterdir(), key=lambda item: os.fsencode(item.name)):
        if child.name in ignored:
            continue
        info = child.lstat()
        name = os.fsencode(child.name)
        if stat.S_ISDIR(info.st_mode):
            oid = bytes.fromhex(git_tree(child))
            mode = b"40000"
        elif stat.S_ISLNK(info.st_mode):
            oid = git_object(b"blob", os.fsencode(os.readlink(child)))
            mode = b"120000"
        elif stat.S_ISREG(info.st_mode):
            oid = git_object(b"blob", child.read_bytes())
            mode = b"100755" if info.st_mode & 0o111 else b"100644"
        else:
            fail(f"unsupported filesystem object: {child}")
        entries.append(mode + b" " + name + b"\0" + oid)
    return git_object(b"tree", b"".join(entries)).hex()


def at(document: Any, dotted: str) -> Any:
    value = document
    for component in dotted.split("."):
        if not isinstance(value, dict) or component not in value:
            fail(f"missing overlay field: {dotted}")
        value = value[component]
    return value


def expect(document: Any, dotted: str, expected: Any) -> None:
    actual = at(document, dotted)
    if actual != expected:
        fail(f"{dotted}: expected {expected!r}, got {actual!r}")


def verify_overlay(document: Any) -> None:
    if set(document) != {
        "schema_version",
        "overlay_version",
        "scope",
        "precedence",
        "closures",
        "json_interface",
        "phase28_consumption",
    }:
        fail("unexpected top-level overlay fields")
    expected = {
        "schema_version": "secure-bench-phase27-3-dual-adapter-closure-overlay-v1",
        "overlay_version": "1.0.0",
        "scope.base_commit": BASE,
        "scope.target": "phase28-preflight-dual-adapter-json-boundary-only",
        "scope.phase27_immutable": True,
        "scope.phase27_1_immutable": True,
        "scope.phase27_2_immutable": True,
        "scope.phase28_execution_authorized": False,
        "scope.holdout_access": "forbidden",
        "precedence.mode": "separate-historical-closures-with-json-process-boundary",
        "precedence.phase27_1_contextualized_cargo_identities_superseded": True,
        "precedence.separate_processes_required": True,
        "precedence.shared_rust_types_between_workspaces_forbidden": True,
        "precedence.phase27_1_overlay.sha256": "5b9c147142099f39242f70128bb70217d0c14f2d55890a86f089ae9a678185cf",
        "precedence.phase27_2_overlay.sha256": "1a8792cb3b6736b2599fc74ab1352755c15d3e5a39fed008759b78a02e08dea2",
        "closures.opengrep.source_commit": PHASE17,
        "closures.opengrep.commit_tree": PHASE17_COMMIT_TREE,
        "closures.opengrep.workspace_tree": PHASE17_TREE,
        "closures.opengrep.adapter.cargo_version": "0.3.0",
        "closures.opengrep.adapter.tree": "d5ee03764e2d8c53a6b976a727ce660a386772ae",
        "closures.opengrep.adapter.raw_format": "opengrep-json-v1",
        "closures.opengrep.protocol.cargo_version": "0.3.0",
        "closures.opengrep.protocol.tree": PROTOCOL_TREE,
        "closures.opengrep.runner.lock_sha256": RUNNER_LOCKS["opengrep"],
        "closures.opengrep.runner.source_sha256": RUNNER_SOURCES["opengrep"],
        "closures.opengrep.runner.binary_sha256": RUNNER_HASHES["opengrep"],
        "closures.semgrep.source_commit": PHASE18,
        "closures.semgrep.commit_tree": PHASE18_COMMIT_TREE,
        "closures.semgrep.phase17_workspace_tree": PHASE17_TREE,
        "closures.semgrep.phase18_workspace_tree": PHASE18_TREE,
        "closures.semgrep.adapter.cargo_version": "0.4.0",
        "closures.semgrep.adapter.tree": "eb7c38b4f59f2c71426e99decb418d63dea5ab8e",
        "closures.semgrep.adapter.raw_format": "semgrep-json-v1",
        "closures.semgrep.protocol.cargo_version": "0.3.0",
        "closures.semgrep.protocol.tree": PROTOCOL_TREE,
        "closures.semgrep.runner.lock_sha256": RUNNER_LOCKS["semgrep"],
        "closures.semgrep.runner.source_sha256": RUNNER_SOURCES["semgrep"],
        "closures.semgrep.runner.binary_sha256": RUNNER_HASHES["semgrep"],
        "json_interface.request_schema.sha256": "a75fa1edba1cce5bfaeb877a97c12ef5f40dc9e873a55d84edf50b205227bd60",
        "json_interface.normalized_schema.id": "secure-bench-adapted-report-v1",
        "json_interface.normalized_schema.sha256": "9a8cc038d12c8cdf13a05537a45ae773831290549576df5f58c28f10fcb5e91b",
        "json_interface.error_schema.sha256": "fa93f04624015b4962494092643537a89695e40c47c078aa62e56e1c3340978d",
        "json_interface.raw_formats_are_not_interchangeable": True,
        "json_interface.rust_type_exchange_between_runners": False,
        "phase28_consumption.runner_failure_belongs_to_current_attempt": True,
        "phase28_consumption.runner_failure_authorizes_scanner_retry": False,
        "phase28_consumption.campaign_attempts": 336,
        "phase28_consumption.execution_authorized_by_this_overlay": False,
    }
    for dotted, exact in expected.items():
        expect(document, dotted, exact)
    if at(document, "closures.opengrep.adapter.cargo_version") == at(
        document, "closures.semgrep.adapter.cargo_version"
    ):
        fail("adapter versions were incorrectly forced to match")
    if at(document, "closures.opengrep.adapter.package_id") == at(
        document, "closures.semgrep.adapter.package_id"
    ):
        fail("adapters must have distinct package IDs")
    if at(document, "closures.opengrep.protocol.public_protocol_version") != at(
        document, "closures.semgrep.protocol.public_protocol_version"
    ):
        fail("public protocol versions diverge")
    if at(document, "precedence.phase27_2_status") != (
        "preserved-valid-opengrep-certification-superseded-for-multi-adapter-composition"
    ):
        fail("Phase 27.2 precedence is ambiguous")


def verify_git_identities() -> None:
    values = subprocess.run(
        [
            "git",
            "-C",
            str(REPO),
            "rev-parse",
            f"{PHASE17}^{{tree}}",
            f"{PHASE17}:phase17",
            f"{PHASE18}^{{tree}}",
            f"{PHASE18}:phase17",
            f"{PHASE18}:phase18",
            "refs/heads/main",
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    if values != [
        PHASE17_COMMIT_TREE,
        PHASE17_TREE,
        PHASE18_COMMIT_TREE,
        PHASE17_TREE,
        PHASE18_TREE,
        BASE,
    ]:
        fail(f"Git identity mismatch: {values}")


def verify_checksum_manifest(root: Path) -> None:
    manifest = root / "SHA256SUMS"
    entries: set[str] = set()
    for line in manifest.read_text(encoding="utf-8").splitlines():
        digest, relative = line.split("  ", 1)
        if relative in entries or relative == "SHA256SUMS":
            fail(f"invalid checksum entry in {root}: {relative}")
        entries.add(relative)
        path = root / relative
        if not path.is_file() or sha256(path) != digest:
            fail(f"checksum mismatch: {path}")
    actual = {
        str(path.relative_to(root))
        for path in root.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS"
    }
    if entries != actual:
        fail(f"checksum inventory mismatch: {root}")


def lock_packages(path: Path) -> set[tuple[str, str, str | None]]:
    with path.open("rb") as handle:
        lock = tomllib.load(handle)
    return {
        (package["name"], package["version"], package.get("source"))
        for package in lock["package"]
    }


def verify_no_new_registry_packages(kind: str, root: Path) -> None:
    runner = lock_packages(root / "runner-source/Cargo.lock")
    historical = lock_packages(root / "workspace/phase17/Cargo.lock")
    if kind == "semgrep":
        historical |= lock_packages(root / "workspace/phase18/Cargo.lock")
    unexpected = {item for item in runner - historical if item[2] is not None}
    if unexpected:
        fail(f"unexpected registry packages in {kind} runner: {sorted(unexpected)}")


def verify_runner_source(kind: str, root: Path) -> None:
    source = root / "runner-source/src/main.rs"
    text = source.read_text(encoding="utf-8")
    required = ["adapt_report", "public_projection", "raw_json.as_bytes()"]
    if any(item not in text for item in required):
        fail(f"{kind} runner does not directly expose the historical API")
    forbidden = [
        "Command::new",
        "std::process::Command",
        "SE1001",
        "SE1002",
        "SE1003",
        "SE1004",
        "SE1005",
        "SE1006",
        "SE1007",
        "finding_count",
        "true_positive",
        "false_positive",
    ]
    if any(item in text for item in forbidden):
        fail(f"{kind} runner contains forbidden process or scoring logic")
    if sha256(root / "runner-source/Cargo.lock") != RUNNER_LOCKS[kind]:
        fail(f"{kind} runner lock mismatch")
    if sha256(source) != RUNNER_SOURCES[kind]:
        fail(f"{kind} runner source mismatch")
    binary = root / "bin" / f"secure-bench-{kind}-json-runner"
    if sha256(binary) != RUNNER_HASHES[kind]:
        fail(f"{kind} runner binary mismatch")
    if binary.stat().st_mode & 0o222:
        fail(f"{kind} runner binary is writable")


def verify_metadata(kind: str, root: Path) -> None:
    with tempfile.TemporaryDirectory(
        prefix=f"secure-bench-phase27-3-{kind}-", dir="/home/danielcastrillon/Proyectos"
    ) as temporary:
        context = Path(temporary)
        subprocess.run(["cp", "-a", f"{root / 'workspace'}/.", str(context)], check=True)
        subprocess.run(["chmod", "-R", "u+w", str(context)], check=True)
        phase = "phase17" if kind == "opengrep" else "phase18"
        runner = context / phase / "independent-runner"
        runner.mkdir()
        subprocess.run(["cp", "-a", f"{root / 'runner-source'}/.", str(runner)], check=True)
        environment = os.environ.copy()
        environment["CARGO_NET_OFFLINE"] = "true"
        output = subprocess.run(
            [
                "cargo",
                "metadata",
                "--manifest-path",
                str(runner / "Cargo.toml"),
                "--offline",
                "--locked",
                "--format-version",
                "1",
            ],
            check=True,
            capture_output=True,
            text=True,
            env=environment,
        ).stdout
        metadata = json.loads(output)
        local = {
            package["name"]: package
            for package in metadata["packages"]
            if package["name"].startswith("secure-bench-")
        }
        adapter = f"secure-bench-{kind}-adapter"
        runner_name = f"secure-bench-{kind}-json-runner"
        expected_adapter_version = "0.3.0" if kind == "opengrep" else "0.4.0"
        expected = {
            adapter: expected_adapter_version,
            "secure-bench-scanner-protocol": "0.3.0",
            runner_name: "0.1.0",
        }
        if {name: package["version"] for name, package in local.items()} != expected:
            fail(f"unexpected {kind} local package closure")
        identifiers = {name: package["id"] for name, package in local.items()}
        nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
        adapter_deps = {dependency["pkg"] for dependency in nodes[identifiers[adapter]]["deps"]}
        runner_deps = {dependency["pkg"] for dependency in nodes[identifiers[runner_name]]["deps"]}
        protocol = identifiers["secure-bench-scanner-protocol"]
        if protocol not in adapter_deps or protocol not in runner_deps:
            fail(f"{kind} adapter and runner do not share their closure protocol")


def verify_durable(protection: bool) -> None:
    for kind, root in DURABLE.items():
        if not root.is_dir():
            fail(f"missing durable cache: {root}")
        verify_checksum_manifest(root)
        if git_tree(root / "workspace/phase17") != PHASE17_TREE:
            fail(f"{kind} Phase 17 workspace tree mismatch")
        if kind == "semgrep" and git_tree(root / "workspace/phase18") != PHASE18_TREE:
            fail("Semgrep Phase 18 workspace tree mismatch")
        verify_no_new_registry_packages(kind, root)
        verify_runner_source(kind, root)
        verify_metadata(kind, root)
        if protection:
            writable = [path for path in root.rglob("*") if path.lstat().st_mode & 0o222]
            if writable:
                fail(f"durable cache contains writable paths: {writable[:3]}")


def verify_phase_files() -> None:
    verify_checksum_manifest(PHASE)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--overlay", type=Path, default=DEFAULT_OVERLAY)
    parser.add_argument("--overlay-only", action="store_true")
    parser.add_argument("--skip-protection", action="store_true")
    parser.add_argument("--skip-phase-sums", action="store_true")
    arguments = parser.parse_args()
    verify_overlay(load_json(arguments.overlay))
    if arguments.overlay_only:
        print("phase27_3_overlay=PASS")
        return 0
    verify_git_identities()
    verify_durable(not arguments.skip_protection)
    if not arguments.skip_phase_sums:
        verify_phase_files()
    print(
        "phase27_3_dual_closure=PASS scanner_processes=0 holdout_accesses=0 "
        "phase28_attempts=0 phase28_retries=0 network_requests=0"
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
