#!/usr/bin/env python3
"""Qualify the native helper and frozen JSON runners using synthetic inputs only."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile


REPO = Path(__file__).resolve().parents[2]
PHASE = REPO / "phase29"
COMMIT = "be54f5cea9221da67eebdb9c71dca70b7ad9674d"
NATIVE = Path("/tmp/secure-bench-tools/native-adapters/phase28") / COMMIT / "bin/secure-bench-phase28-native-adapter"
DURABLE_NATIVE = Path("/home/danielcastrillon/Proyectos/secure-bench-tool-cache/native-adapters/phase28") / COMMIT
EXPECTED_NATIVE_SHA = "5c81f7213fa2b5b8488f2e3fb4cf42a515442681978c3fbc35568e2f933b4e1e"
OVERLAY_PATH = REPO / "phase27-3/binding-overlay.json"
OVERLAY_SHA = "2733358fbbd95e8881d7575b0f40f5e6d6d58beff760be1fb77c8f96a7e8e4ce"


def sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha(path: Path) -> str:
    return sha_bytes(path.read_bytes())


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def synthetic_finding() -> dict[str, object]:
    return {
        "rule_id": "synthetic-rule",
        "taxonomy": {
            "taxonomy_version": "1.0.0",
            "category_id": "secure-bench.category.command-execution",
            "invariant_id": "secure-bench.invariant.command-control-data-separation",
        },
        "primary_cwe": {"id": "CWE-78"},
        "verification_state": "verified-deterministic-path",
        "guards": [],
        "evidence_contract_v2": {
            "contract_version": "2.0.0",
            "semantics_version": "secure-evidence-semantics-v2",
            "path": [
                {
                    "role": "source",
                    "effect": "preserves_influence",
                    "source_kind": "http_body_field",
                    "span": {"path": "src/example.ts", "span": {"start_byte": 1, "end_byte": 12, "start_line": 2, "start_column": 1, "end_line": 2, "end_column": 12}},
                    "summarizable": False,
                },
                {
                    "role": "propagation",
                    "effect": "preserves_influence",
                    "span": {"path": "src/example.ts", "span": {"start_byte": 13, "end_byte": 24, "start_line": 3, "start_column": 1, "end_line": 3, "end_column": 12}},
                    "summarizable": False,
                },
                {
                    "role": "sink",
                    "effect": "preserves_influence",
                    "sink_kind": "os_command_execution",
                    "span": {"path": "src/example.ts", "span": {"start_byte": 25, "end_byte": 36, "start_line": 4, "start_column": 1, "end_line": 4, "end_column": 12}},
                    "summarizable": False,
                },
            ],
            "connected_edges": [True, True],
            "effective_barriers": [],
            "unresolved_call": False,
            "uncertain": False,
            "fingerprint": "a" * 64,
            "duplicate_fingerprint": "b" * 64,
        },
        "evidence_path": [
            {"kind": "source", "edge_id_from_previous": None, "semantic": {"role": "source", "identity": "source.http_body_field", "certainty": "proven"}, "location": {"path": "src/example.ts", "span": {"start_line": 2, "start_column": 1, "end_line": 2, "end_column": 12}}},
            {"kind": "transformation", "edge_id_from_previous": "edge-1", "semantic": {"role": "propagation", "identity": "effect.preserves_influence", "certainty": "proven"}, "location": {"path": "src/example.ts", "span": {"start_line": 3, "start_column": 1, "end_line": 3, "end_column": 12}}},
            {"kind": "sink", "edge_id_from_previous": "edge-2", "semantic": {"role": "sink", "identity": "sink.os_command_execution", "certainty": "proven"}, "location": {"path": "src/example.ts", "span": {"start_line": 4, "start_column": 1, "end_line": 4, "end_column": 12}}},
        ],
    }


def native_report(findings: list[dict[str, object]]) -> bytes:
    return canonical({"schema_version": "secure-json-v1", "scan": {"complete": True}, "errors": [], "findings": findings})


def run_native(case: str, raw: bytes, root: Path) -> subprocess.CompletedProcess[bytes]:
    path = root / f"{case}.json"
    path.write_bytes(raw)
    return subprocess.run(
        [str(NATIVE), "secure-engine", f"phase29-synthetic-{case}", str(path), str(root)],
        cwd=REPO,
        env={"PATH": "/usr/bin:/bin", "SECURE_BENCH_ROOT": str(REPO)},
        capture_output=True,
        check=False,
    )


def validate_native(output: bytes, raw: bytes, findings: int) -> None:
    value = json.loads(output)
    if set(value) != {"schema_version", "report_sha256", "findings"}:
        raise RuntimeError("native projection schema differs")
    if value["schema_version"] != "secure-json-v1" or value["report_sha256"] != sha_bytes(raw):
        raise RuntimeError("native projection does not bind raw bytes")
    if not isinstance(value["findings"], list) or len(value["findings"]) != findings:
        raise RuntimeError("native projection finding count differs")


def run_runner(binary: Path, request: dict[str, object]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [str(binary)],
        cwd=REPO,
        env={"PATH": "/usr/bin:/bin"},
        input=canonical(request),
        capture_output=True,
        check=False,
    )


def main() -> None:
    receipt = PHASE / "qualification.json"
    if receipt.exists():
        raise RuntimeError("qualification already exists; synthetic processes must not be repeated")
    if sha(NATIVE) != EXPECTED_NATIVE_SHA or sha(DURABLE_NATIVE / "bin/secure-bench-phase28-native-adapter") != EXPECTED_NATIVE_SHA:
        raise RuntimeError("native helper bytes differ")
    if sha(OVERLAY_PATH) != OVERLAY_SHA:
        raise RuntimeError("Phase 27.3 overlay differs")
    overlay = json.loads(OVERLAY_PATH.read_text())
    spec = importlib.util.spec_from_file_location("phase28_harness", REPO / "phase28/harness.py")
    legacy = importlib.util.module_from_spec(spec)
    if spec.loader is None:
        raise RuntimeError("cannot load normalized schema validator")
    spec.loader.exec_module(legacy)
    native_processes = 0
    runner_processes = 0
    with tempfile.TemporaryDirectory(prefix="secure-bench-phase29-qualification-", dir="/home/danielcastrillon/Proyectos") as temporary:
        root = Path(temporary)
        finding = synthetic_finding()
        cases = {
            "clean": (native_report([]), 0, True),
            "finding": (native_report([finding]), 1, True),
            "multiple": (native_report([finding, copy.deepcopy(finding)]), 2, True),
            "malformed": (b"{\n", 0, False),
            "missing-fields": (canonical({"schema_version": "secure-json-v1"}), 0, False),
        }
        native_results = {}
        first_finding = None
        for name, (raw, count, success) in cases.items():
            completed = run_native(name, raw, root)
            native_processes += 1
            if (completed.returncode == 0) != success:
                raise RuntimeError(f"native qualification status differs: {name}")
            if success:
                validate_native(completed.stdout, raw, count)
            native_results[name] = {"expected_success": success, "returncode": completed.returncode, "stdout_sha256": sha_bytes(completed.stdout), "stderr_sha256": sha_bytes(completed.stderr)}
            if name == "finding":
                first_finding = completed.stdout
        repeat = run_native("finding", cases["finding"][0], root)
        native_processes += 1
        if repeat.returncode != 0 or repeat.stdout != first_finding:
            raise RuntimeError("native helper output is not deterministic")
        runner_results = {}
        for kind in ("opengrep", "semgrep"):
            closure = overlay["closures"][kind]
            binary = Path(closure["runner"]["binary_path"])
            if sha(binary) != closure["runner"]["binary_sha256"]:
                raise RuntimeError(f"{kind} runner bytes differ")
            durable = Path(closure["durable_path"])
            phase = "phase17" if kind == "opengrep" else "phase18"
            workspace = durable / "workspace" / phase
            manifest = json.loads((workspace / f"manifests/{kind}-v{'1.22.0' if kind == 'opengrep' else '1.170.0'}-conformance.json").read_text())
            fixture = workspace / "fixtures/conformance/workspace"
            outputs = {}
            for report_name in ("clean", "finding"):
                raw = (workspace / f"fixtures/conformance/reports/{report_name}.json").read_bytes()
                request = {
                    "schema_version": "secure-bench-adapter-runner-request-v1",
                    "raw_format": closure["adapter"]["raw_format"],
                    "case_scope": f"phase29-synthetic-{kind}-{report_name}",
                    "fixture_root": str(fixture),
                    "manifest": manifest,
                    "raw_json": raw.decode(),
                }
                completed = run_runner(binary, request)
                runner_processes += 1
                if completed.returncode != 0:
                    raise RuntimeError(f"{kind} runner rejected {report_name}")
                projection = json.loads(completed.stdout)
                legacy.validate_normalized_projection(projection, raw)
                outputs[report_name] = completed.stdout
            repeat_request = {
                "schema_version": "secure-bench-adapter-runner-request-v1",
                "raw_format": closure["adapter"]["raw_format"],
                "case_scope": f"phase29-synthetic-{kind}-clean",
                "fixture_root": str(fixture),
                "manifest": manifest,
                "raw_json": (workspace / "fixtures/conformance/reports/clean.json").read_text(),
            }
            repeated = run_runner(binary, repeat_request)
            runner_processes += 1
            if repeated.returncode != 0 or repeated.stdout != outputs["clean"]:
                raise RuntimeError(f"{kind} runner output is not deterministic")
            runner_results[kind] = {"binary_sha256": sha(binary), "clean_stdout_sha256": sha_bytes(outputs["clean"]), "finding_stdout_sha256": sha_bytes(outputs["finding"]), "deterministic": True}
    value = {
        "schema_version": "secure-bench-phase29-tool-qualification-v1",
        "classification": "post-open recovery study preflight synthetic qualification",
        "native_helper": {
            "binary_sha256": EXPECTED_NATIVE_SHA,
            "processes_this_successful_run": native_processes,
            "prior_preflight_processes": 6,
            "total_processes": native_processes + 6,
            "results": native_results,
            "deterministic_repetition": True,
        },
        "normalized_runners": {"processes": runner_processes, "results": runner_results, "schemas_valid": True, "deterministic_repetition": True},
        "total_synthetic_processes": native_processes + runner_processes + 6,
        "scanner_processes": 0,
        "holdout_cases": 0,
        "network_requests": 0,
    }
    receipt.write_bytes(canonical(value))
    print(f"tool_qualification=PASS native_processes={native_processes} runner_processes={runner_processes} scanners=0")


if __name__ == "__main__":
    main()
