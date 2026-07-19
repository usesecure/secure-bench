#!/usr/bin/env python3
"""Independently verify the Phase 27.1 scanner binding overlay without scanners."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any


BASE = "540502c8bf1f139c7d54cb5f6e7c29ce97ffb934"
REPO = Path(__file__).resolve().parents[2]
DEFAULT_OVERLAY = REPO / "phase27-1" / "binding-overlay.json"


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


def value_at(document: Any, dotted: str) -> Any:
    value = document
    for component in dotted.split("."):
        if not isinstance(value, dict) or component not in value:
            fail(f"missing binding field: {dotted}")
        value = value[component]
    return value


def expect(document: Any, dotted: str, expected: Any) -> None:
    actual = value_at(document, dotted)
    if actual != expected:
        fail(f"{dotted}: expected {expected!r}, got {actual!r}")


def verify_overlay(document: Any) -> None:
    if set(document) != {
        "schema_version",
        "overlay_version",
        "scope",
        "precedence",
        "phase28_consumption",
        "scanners",
    }:
        fail("unexpected top-level overlay fields")
    expect(document, "schema_version", "secure-bench-phase27-1-scanner-binding-overlay-v1")
    expect(document, "overlay_version", "1.0.0")
    expect(document, "scope.base_commit", BASE)
    expect(document, "scope.target", "phase28-preflight-scanner-identities-only")
    expect(document, "scope.phase27_immutable", True)
    expect(document, "scope.phase28_execution_authorized", False)
    expect(document, "scope.holdout_access", "forbidden")
    expect(document, "precedence.mode", "conditional-identity-overlay")
    expect(document, "precedence.applies_when_base_status", "verify-at-phase28-preflight")
    expect(document, "precedence.priority", "after-phase27-plan-before-phase28-preflight")
    expect(document, "phase28_consumption.overlay_path", "phase27-1/binding-overlay.json")
    expect(document, "phase28_consumption.phase27_changes_required", False)
    expect(document, "phase28_consumption.phase28_campaign_must_remain_unopened", True)
    scanners = value_at(document, "scanners")
    if set(scanners) != {"secure-engine", "opengrep", "semgrep-ce"}:
        fail("scanner set must be exact")

    expected = {
        "scanners.secure-engine.id": "secure-engine",
        "scanners.secure-engine.version": "0.1.7",
        "scanners.secure-engine.release_candidate": "rc1",
        "scanners.secure-engine.lane": "native",
        "scanners.secure-engine.release.commit": "1e3d300cb7092097f21be164b6c403b71f2b2520",
        "scanners.secure-engine.release.tree": "8f08ac800a43afcd39eb70cecd29c8643a24157b",
        "scanners.secure-engine.rpm.sha256": "8f26b69981c7ba88081496b0c1dd1fce9da62c03a38927e07b3d64541cf45f75",
        "scanners.secure-engine.executable.path": "/home/danielcastrillon/Proyectos/secure-engine-rc/0.1.7-rc1/extracted/secure",
        "scanners.secure-engine.executable.sha256": "5feca58fda54e4f9af0bf3846d04a98825d7315e64cbf80268a2395cf07ff2e6",
        "scanners.secure-engine.adapter.sha256": "18b0ce241fefdd81619a547772a6871128b5fe020341158b3d62a05563236413",
        "scanners.opengrep.id": "opengrep",
        "scanners.opengrep.version": "1.22.0",
        "scanners.opengrep.lane": "capability_normalized",
        "scanners.opengrep.executable.active_path": "/tmp/secure-bench-tools/opengrep/1.22.0/opengrep_manylinux_x86",
        "scanners.opengrep.executable.sha256": "45bcd58440e397ed52c50e953ccf5948909ea77087c9186fc7d277216f62e319",
        "scanners.opengrep.sigstore.status": "preserved-not-reverified-this-run",
        "scanners.opengrep.ruleset.sha256": "06af4cf6d10da30ad585d57b781cf6aef734add03b90ea36c78e920c4c10a07c",
        "scanners.opengrep.adapter.sha256": "6a922a0ecac31b55f1591782df548822caa62064aaf7f8b9c1b0addc07cd0998",
        "scanners.opengrep.sandbox.working_directory": "/tmp/fixture",
        "scanners.semgrep-ce.id": "semgrep-ce",
        "scanners.semgrep-ce.version": "1.170.0",
        "scanners.semgrep-ce.lane": "capability_normalized",
        "scanners.semgrep-ce.active_root": "/tmp/secure-bench-tools/semgrep/1.170.0",
        "scanners.semgrep-ce.runtime.python_sha256": "7af874aca05879e1823cd820913b42fb8d8b994738a05ec39ce4256d85b03861",
        "scanners.semgrep-ce.artifacts.wheel_sha256": "09a7e8eeff5e2549161124957184f3566f484370aa6127e425897cef725eb99b",
        "scanners.semgrep-ce.artifacts.dependency_lock_sha256": "50bc99977b0205235301b2508c5cc84dbc4a421f593f18d75e19fa19d7969e39",
        "scanners.semgrep-ce.artifacts.wheel_count": 66,
        "scanners.semgrep-ce.artifacts.wheel_closure_sha256": "5371b438dc6e3c5529794b21c668057164f52fa1375e0e91ee6c8f241fb74181",
        "scanners.semgrep-ce.artifacts.requirements_lock_sha256": "bae00f126f98e84b32b92269d42f6567abab789307383094009030d7f13caf50",
        "scanners.semgrep-ce.artifacts.installed_inventory_sha256": "703922233fb0e415b50e4b88ba9622dc6ea3d207a5f4fcb64b6b980da35056df",
        "scanners.semgrep-ce.artifacts.entrypoint_sha256": "0280e5c6cca8d8e4cb2c41858b06697b957daf23d718cac411999c4c515507e1",
        "scanners.semgrep-ce.artifacts.core_runner_sha256": "76f298b49667228a6157504ab8b7b56f87033693ed0aab279faa465bb895058a",
        "scanners.semgrep-ce.artifacts.semgrep_core_sha256": "33e39c192b7271e3a9f64167ad61303aa49b556efda683cf94aea9db90ec9fc3",
        "scanners.semgrep-ce.ruleset.sha256": "06af4cf6d10da30ad585d57b781cf6aef734add03b90ea36c78e920c4c10a07c",
        "scanners.semgrep-ce.adapter.sha256": "53317a4e71b14548d618fd79430b74b8fc906edebbf7180cbea418df98b1afc3",
        "scanners.semgrep-ce.sandbox.working_directory": "/tmp/fixture",
        "scanners.semgrep-ce.sandbox.prlimit.address_space_bytes": 4294967296,
        "scanners.semgrep-ce.sandbox.prlimit.processes": 64,
        "scanners.semgrep-ce.sandbox.prlimit.stack_soft_bytes": 8388608,
        "scanners.semgrep-ce.sandbox.prlimit.stack_hard_bytes": 8388608,
    }
    for dotted, exact in expected.items():
        expect(document, dotted, exact)


def verify_hash(path: Path, expected: str) -> None:
    if not path.is_file():
        fail(f"missing regular file: {path}")
    actual = sha256(path)
    if actual != expected:
        fail(f"hash mismatch for {path}: {actual}")


def verify_external_artifacts() -> None:
    files = {
        REPO / "phase16/policies/adapter-precedence-v2.json": "18b0ce241fefdd81619a547772a6871128b5fe020341158b3d62a05563236413",
        REPO / "phase19/rules/capability-normalized-v1.yml": "06af4cf6d10da30ad585d57b781cf6aef734add03b90ea36c78e920c4c10a07c",
        REPO / "phase20/config/opengrep-normalized-adapter-v1.json": "6a922a0ecac31b55f1591782df548822caa62064aaf7f8b9c1b0addc07cd0998",
        REPO / "phase20/config/semgrep-normalized-adapter-v1.json": "53317a4e71b14548d618fd79430b74b8fc906edebbf7180cbea418df98b1afc3",
        REPO / "phase23/config/corrected-environment-contract-v1.json": "df737de168c1c78855ee589cbe105f9123601be3571a765dfcc21cddbf4cbe5a",
        Path("/usr/bin/bwrap"): "139bf12775025adf5c8523d119c5ad2950281335573708fd839c60181a3886dc",
        Path("/usr/bin/python3.14"): "7af874aca05879e1823cd820913b42fb8d8b994738a05ec39ce4256d85b03861",
        Path("/home/danielcastrillon/Proyectos/secure-engine-rc/0.1.7-rc1/provenance.json"): "80c543e8821a2f3ebc692f3fd325c35efcafcd34b6b4dbf3c758ff19dedd6826",
        Path("/home/danielcastrillon/Proyectos/secure-engine-rc/0.1.7-rc1/rpm/secure-engine-0.1.7-1.fc44.x86_64.rpm"): "8f26b69981c7ba88081496b0c1dd1fce9da62c03a38927e07b3d64541cf45f75",
        Path("/home/danielcastrillon/Proyectos/secure-engine-rc/0.1.7-rc1/extracted/secure"): "5feca58fda54e4f9af0bf3846d04a98825d7315e64cbf80268a2395cf07ff2e6",
        Path("/tmp/secure-bench-tools/opengrep/1.22.0/opengrep_manylinux_x86"): "45bcd58440e397ed52c50e953ccf5948909ea77087c9186fc7d277216f62e319",
        Path("/home/danielcastrillon/Proyectos/secure-bench-tool-cache/opengrep/1.22.0/opengrep_manylinux_x86"): "45bcd58440e397ed52c50e953ccf5948909ea77087c9186fc7d277216f62e319",
        REPO / "phase17/provenance/opengrep-v1.22.0.json": "245d3796801741304fcedc9df6c98cd43886c1da8477c83427ca6c47ab09a58e",
        Path("/home/danielcastrillon/Proyectos/secure-bench-tool-cache/opengrep/1.22.0/provenance.json"): "245d3796801741304fcedc9df6c98cd43886c1da8477c83427ca6c47ab09a58e",
        Path("/tmp/secure-bench-tools/semgrep/1.170.0/dependency-lock.json"): "50bc99977b0205235301b2508c5cc84dbc4a421f593f18d75e19fa19d7969e39",
        Path("/tmp/secure-bench-tools/semgrep/1.170.0/requirements.lock"): "bae00f126f98e84b32b92269d42f6567abab789307383094009030d7f13caf50",
        Path("/tmp/secure-bench-tools/semgrep/1.170.0/installed-distributions.json"): "703922233fb0e415b50e4b88ba9622dc6ea3d207a5f4fcb64b6b980da35056df",
        Path("/tmp/secure-bench-tools/semgrep/1.170.0/venv/bin/semgrep"): "0280e5c6cca8d8e4cb2c41858b06697b957daf23d718cac411999c4c515507e1",
        Path("/tmp/secure-bench-tools/semgrep/1.170.0/venv/lib/python3.14/site-packages/semgrep/core_runner.py"): "76f298b49667228a6157504ab8b7b56f87033693ed0aab279faa465bb895058a",
        Path("/tmp/secure-bench-tools/semgrep/1.170.0/venv/lib/python3.14/site-packages/semgrep/bin/semgrep-core"): "33e39c192b7271e3a9f64167ad61303aa49b556efda683cf94aea9db90ec9fc3",
        Path("/home/danielcastrillon/Proyectos/secure-bench-tool-cache/semgrep/1.170.0/venv.tar.zst"): "9c4ebccb8efd7e2d4e95fa684a9f686f53cd5e27c1c86401036b135695c14483",
    }
    for path, expected in files.items():
        verify_hash(path, expected)

    for path in (
        Path("/tmp/secure-bench-tools/opengrep/1.22.0/opengrep_manylinux_x86"),
        Path("/home/danielcastrillon/Proyectos/secure-bench-tool-cache/opengrep/1.22.0/opengrep_manylinux_x86"),
        Path("/home/danielcastrillon/Proyectos/secure-engine-rc/0.1.7-rc1/extracted/secure"),
    ):
        if stat.S_IMODE(path.stat().st_mode) != 0o555:
            fail(f"unexpected executable mode: {path}")

    active = Path("/tmp/secure-bench-tools/semgrep/1.170.0")
    durable = Path("/home/danielcastrillon/Proyectos/secure-bench-tool-cache/semgrep/1.170.0")
    lock = load_json(active / "dependency-lock.json")
    if lock.get("package_count") != 66 or len(lock.get("packages", [])) != 66:
        fail("Semgrep dependency lock does not contain exactly 66 wheels")
    if lock.get("closure_sha256") != "5371b438dc6e3c5529794b21c668057164f52fa1375e0e91ee6c8f241fb74181":
        fail("Semgrep wheel closure identity differs")
    packages = lock["packages"]
    expected_names = {package["filename"] for package in packages}
    for wheelhouse in (active / "wheelhouse", durable / "wheelhouse"):
        actual_names = {path.name for path in wheelhouse.glob("*.whl")}
        if actual_names != expected_names:
            fail(f"wheel set mismatch in {wheelhouse}")
        for package in packages:
            wheel = wheelhouse / package["filename"]
            verify_hash(wheel, package["sha256"])
            if wheel.stat().st_size != package["size_bytes"]:
                fail(f"wheel size mismatch: {wheel}")
    inventory = load_json(active / "installed-distributions.json")
    if len(inventory) != 66:
        fail("Semgrep installed inventory does not contain exactly 66 distributions")


def verify_phase_files() -> None:
    phase = REPO / "phase27-1"
    checksum_file = phase / "SHA256SUMS"
    expected_files: set[str] = set()
    with checksum_file.open("r", encoding="utf-8") as handle:
        for line in handle:
            digest, relative = line.rstrip("\n").split("  ", 1)
            if relative in expected_files:
                fail(f"duplicate SHA256SUMS entry: {relative}")
            expected_files.add(relative)
            verify_hash(phase / relative, digest)
    actual_files = {
        str(path.relative_to(phase))
        for path in phase.rglob("*")
        if path.is_file() and "target" not in path.relative_to(phase).parts and path != checksum_file
    }
    if actual_files != expected_files:
        fail("SHA256SUMS file set differs from Phase 27.1 files")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--overlay", type=Path, default=DEFAULT_OVERLAY)
    parser.add_argument("--overlay-only", action="store_true")
    arguments = parser.parse_args()
    document = load_json(arguments.overlay)
    verify_overlay(document)
    if arguments.overlay_only:
        print(json.dumps({"status": "PASS", "scope": "overlay-only"}, sort_keys=True))
        return 0
    verify_external_artifacts()
    verify_phase_files()
    print(
        json.dumps(
            {
                "holdout_accesses": 0,
                "phase28_attempts": 0,
                "scanner_processes": 0,
                "status": "PASS",
                "wheel_count": 66,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
