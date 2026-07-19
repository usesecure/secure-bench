#!/usr/bin/env python3
"""Independently verify the atomic Phase 17 Cargo closure without scanners."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tomllib
from typing import Any


BASE = "0f6fe9f06f1f88233e6d537b9c4e1d826575d0ee"
COMMIT = "241600628315db6d8a77e62bbaf6e61ba5c628f1"
COMMIT_TREE = "0b5b8315d319ff8903e7611011eab38199326ec8"
WORKSPACE_TREE = "e2512d180118e6487a979ba03d1961c41d17825d"
REPO = Path(__file__).resolve().parents[2]
PHASE = REPO / "phase27-2"
DEFAULT_OVERLAY = PHASE / "binding-overlay.json"
MATERIALIZED = Path(
    "/home/danielcastrillon/Proyectos/"
    "secure-bench-phase17-workspace-241600628315db6d8a77e62bbaf6e61ba5c628f1"
)
DURABLE = Path(
    "/home/danielcastrillon/Proyectos/secure-bench-tool-cache/phase17-workspace/"
    "241600628315db6d8a77e62bbaf6e61ba5c628f1"
)
FILES = {
    "Cargo.toml": "84cffd7bf1454aa7b6a755bd27ec9c3067a6902a1913b521efabd14121432e64",
    "Cargo.lock": "4c826bbc6f77a3db0084257b383cb6892bc23a265234b08bc738e03bcb77ef36",
    "opengrep-adapter/Cargo.toml": "70f7c274b47518a3cbce1dd66e381d9250cd18dda1f411254dda79c65208984b",
    "opengrep-adapter/src/lib.rs": "81891e9dd2f84c4dbf2946450b194db51b64b9bcbaeee18093c736ddf54e5fa2",
    "opengrep-adapter/src/main.rs": "d53c55d72f79bd74020d128be8673aba81f772db6965e553f8fa58f9fa8fe4e4",
    "scanner-protocol/Cargo.toml": "da5f89e0c223cb0cc328febb2920978b6a00cd9e87362c7d71dce52e01f3efe1",
    "scanner-protocol/src/lib.rs": "30ee34b335fbaf32fdbd1e09920e1656cafc6b5fed38ac60c7c99de2dd9d815f",
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


def git_tree(path: Path) -> str:
    entries: list[bytes] = []
    for child in sorted(path.iterdir(), key=lambda item: os.fsencode(item.name)):
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
            fail(f"unsupported filesystem object in workspace: {child}")
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
        "closure",
        "phase28_consumption",
    }:
        fail("unexpected top-level overlay fields")
    expected = {
        "schema_version": "secure-bench-phase27-2-adapter-protocol-closure-overlay-v1",
        "overlay_version": "1.0.0",
        "scope.base_commit": BASE,
        "scope.target": "phase28-preflight-opengrep-cargo-closure-only",
        "scope.phase27_immutable": True,
        "scope.phase27_1_immutable": True,
        "scope.phase28_execution_authorized": False,
        "scope.holdout_access": "forbidden",
        "precedence.mode": "atomic-two-package-cargo-closure",
        "precedence.priority": "after-phase27-1-for-opengrep-cargo-pair-only",
        "precedence.atomic_pair_required": True,
        "precedence.mixed_workspace_or_version_forbidden": True,
        "precedence.phase27_1_overlay_sha256": "5b9c147142099f39242f70128bb70217d0c14f2d55890a86f089ae9a678185cf",
        "closure.source_commit": COMMIT,
        "closure.commit_tree": COMMIT_TREE,
        "closure.workspace_tree": WORKSPACE_TREE,
        "closure.workspace_archive_sha256": "bcfb9f8cc7c71bc486aa9f7f789da946e722560c1e76e1ddfdd28d592e7bf243",
        "closure.materialized_path": str(MATERIALIZED / "phase17"),
        "closure.durable_path": str(DURABLE / "workspace"),
        "closure.workspace_manifest.sha256": FILES["Cargo.toml"],
        "closure.lock.sha256": FILES["Cargo.lock"],
        "closure.packages.secure-bench-opengrep-adapter.cargo_version": "0.3.0",
        "closure.packages.secure-bench-opengrep-adapter.public_adapter_version": "1.0.0",
        "closure.packages.secure-bench-opengrep-adapter.tree": "d5ee03764e2d8c53a6b976a727ce660a386772ae",
        "closure.packages.secure-bench-scanner-protocol.cargo_version": "0.3.0",
        "closure.packages.secure-bench-scanner-protocol.public_protocol_version": "1.0.0",
        "closure.packages.secure-bench-scanner-protocol.tree": "7fd40434d1226bbf4bdba6a042e2824856fa7590",
        "closure.dependency_edge.requirement": "=0.3.0",
        "closure.dependency_edge.relative_path": "../scanner-protocol",
        "closure.dependency_edge.same_workspace": True,
        "closure.dependency_edge.external_or_registry_protocol_forbidden": True,
        "phase28_consumption.overlay_path": "phase27-2/binding-overlay.json",
        "phase28_consumption.phase27_1_remains_authoritative_for_other_bindings": True,
        "phase28_consumption.phase28_campaign_must_remain_unopened": True,
    }
    for dotted, exact in expected.items():
        expect(document, dotted, exact)
    replaced = at(document, "precedence.replaces_jointly")
    if replaced != [
        "cargo.secure-bench-opengrep-adapter",
        "cargo.secure-bench-scanner-protocol",
    ]:
        fail("Cargo pair must be replaced jointly and in canonical order")
    versions = {
        at(document, "closure.packages.secure-bench-opengrep-adapter.cargo_version"),
        at(document, "closure.packages.secure-bench-scanner-protocol.cargo_version"),
    }
    if versions != {"0.3.0"}:
        fail("mixed or non-historical Cargo versions")


def verify_files(workspace: Path) -> None:
    if not workspace.is_dir():
        fail(f"missing workspace: {workspace}")
    if git_tree(workspace) != WORKSPACE_TREE:
        fail(f"workspace tree mismatch: {workspace}")
    for relative, expected in FILES.items():
        path = workspace / relative
        if not path.is_file() or sha256(path) != expected:
            fail(f"closure hash mismatch: {path}")


def verify_materialized() -> None:
    result = subprocess.run(
        ["git", "-C", str(MATERIALIZED), "rev-parse", "HEAD", "HEAD^{tree}"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    if result != [COMMIT, COMMIT_TREE]:
        fail("materialized worktree commit or tree mismatch")
    status = subprocess.run(
        ["git", "-C", str(MATERIALIZED), "status", "--porcelain"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    if status:
        fail("materialized Phase 17 worktree is dirty")
    verify_files(MATERIALIZED / "phase17")


def verify_metadata() -> None:
    environment = os.environ.copy()
    environment["CARGO_NET_OFFLINE"] = "true"
    output = subprocess.run(
        [
            "cargo",
            "metadata",
            "--manifest-path",
            str(DURABLE / "workspace/Cargo.toml"),
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
    members = set(metadata["workspace_members"])
    packages = {package["id"]: package for package in metadata["packages"]}
    local = [packages[identifier] for identifier in members]
    identities = {(package["name"], package["version"]) for package in local}
    if identities != {
        ("secure-bench-opengrep-adapter", "0.3.0"),
        ("secure-bench-scanner-protocol", "0.3.0"),
    }:
        fail(f"unexpected Phase 17 workspace identities: {sorted(identities)}")
    adapter = next(package for package in local if package["name"] == "secure-bench-opengrep-adapter")
    protocol = next(package for package in local if package["name"] == "secure-bench-scanner-protocol")
    dependency = next(
        item for item in adapter["dependencies"] if item["name"] == "secure-bench-scanner-protocol"
    )
    if dependency["req"] != "=0.3.0" or Path(dependency["path"]) != Path(protocol["manifest_path"]).parent:
        fail("adapter does not resolve the protocol from the same closure")
    if dependency["source"] is not None:
        fail("protocol resolved from a registry or external source")
    with (DURABLE / "workspace/Cargo.lock").open("rb") as handle:
        lock = tomllib.load(handle)
    locked = {
        (package["name"], package["version"])
        for package in lock["package"]
        if package["name"] in {"secure-bench-opengrep-adapter", "secure-bench-scanner-protocol"}
    }
    if locked != {
        ("secure-bench-opengrep-adapter", "0.3.0"),
        ("secure-bench-scanner-protocol", "0.3.0"),
    }:
        fail("lock does not bind the atomic 0.3.0 pair")


def verify_phase_files() -> None:
    checksum = PHASE / "SHA256SUMS"
    expected_files: set[str] = set()
    with checksum.open("r", encoding="utf-8") as handle:
        for line in handle:
            digest, relative = line.rstrip("\n").split("  ", 1)
            if relative in expected_files:
                fail(f"duplicate SHA256SUMS entry: {relative}")
            expected_files.add(relative)
            if sha256(PHASE / relative) != digest:
                fail(f"Phase 27.2 checksum mismatch: {relative}")
    actual_files = {
        str(path.relative_to(PHASE))
        for path in PHASE.rglob("*")
        if path.is_file()
        and "target" not in path.relative_to(PHASE).parts
        and path != checksum
    }
    if actual_files != expected_files:
        fail("Phase 27.2 SHA256SUMS file set differs")


def verify_durable_protection() -> None:
    for path in [DURABLE, *DURABLE.rglob("*")]:
        if path.lstat().st_mode & 0o222:
            fail(f"durable cache remains writable: {path}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--overlay", type=Path, default=DEFAULT_OVERLAY)
    parser.add_argument("--overlay-only", action="store_true")
    parser.add_argument("--workspace-only", type=Path)
    parser.add_argument("--skip-protection", action="store_true")
    arguments = parser.parse_args()
    if arguments.workspace_only is not None:
        verify_files(arguments.workspace_only)
        print(json.dumps({"status": "PASS", "workspace_tree": WORKSPACE_TREE}, sort_keys=True))
        return 0
    document = load_json(arguments.overlay)
    verify_overlay(document)
    if arguments.overlay_only:
        print(json.dumps({"scope": "overlay-only", "status": "PASS"}, sort_keys=True))
        return 0
    if sha256(REPO / "phase27-1/binding-overlay.json") != at(
        document, "precedence.phase27_1_overlay_sha256"
    ):
        fail("Phase 27.1 overlay changed")
    verify_materialized()
    verify_files(DURABLE / "workspace")
    verify_metadata()
    verify_phase_files()
    if not arguments.skip_protection:
        verify_durable_protection()
    print(
        json.dumps(
            {
                "cargo_pair": ["0.3.0", "0.3.0"],
                "holdout_accesses": 0,
                "phase28_attempts": 0,
                "scanner_processes": 0,
                "status": "PASS",
                "workspace_tree": WORKSPACE_TREE,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, json.JSONDecodeError, subprocess.CalledProcessError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
