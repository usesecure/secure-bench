#!/usr/bin/env python3
"""Fail-closed tamper tests for the Phase 27.3 overlay verifier."""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import unittest


PHASE = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "verify_dual_closure", PHASE / "scripts/verify-dual-closure.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load independent verifier")
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


class FailClosedOverlayTests(unittest.TestCase):
    """Every identity or precedence drift must be rejected."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.overlay = json.loads((PHASE / "binding-overlay.json").read_text(encoding="utf-8"))

    def reject(self, dotted: str, replacement: object) -> None:
        document = copy.deepcopy(self.overlay)
        value = document
        components = dotted.split(".")
        for component in components[:-1]:
            value = value[component]
        value[components[-1]] = replacement
        with self.assertRaises(ValueError):
            VERIFY.verify_overlay(document)

    def test_rejects_identity_tampering(self) -> None:
        vectors = {
            "closures.opengrep.adapter.cargo_version": "0.1.0",
            "closures.semgrep.adapter.cargo_version": "0.3.0",
            "closures.semgrep.protocol.cargo_version": "0.1.0",
            "closures.opengrep.source_commit": "0" * 40,
            "closures.semgrep.phase18_workspace_tree": "0" * 40,
            "closures.opengrep.runner.lock_sha256": "0" * 64,
            "closures.opengrep.runner.source_sha256": "0" * 64,
            "closures.semgrep.runner.binary_sha256": "0" * 64,
        }
        for dotted, replacement in vectors.items():
            with self.subTest(dotted=dotted):
                self.reject(dotted, replacement)

    def test_rejects_interface_and_precedence_tampering(self) -> None:
        vectors = {
            "closures.opengrep.adapter.raw_format": "semgrep-json-v1",
            "closures.semgrep.adapter.raw_format": "opengrep-json-v1",
            "json_interface.normalized_schema.sha256": "0" * 64,
            "json_interface.rust_type_exchange_between_runners": True,
            "precedence.separate_processes_required": False,
            "precedence.phase27_2_status": "authoritative",
            "phase28_consumption.runner_failure_authorizes_scanner_retry": True,
        }
        for dotted, replacement in vectors.items():
            with self.subTest(dotted=dotted):
                self.reject(dotted, replacement)


if __name__ == "__main__":
    unittest.main()
