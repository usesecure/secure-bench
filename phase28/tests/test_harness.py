"""Scanner-free unit tests for Phase 28 orchestration and scoring."""

from __future__ import annotations

import importlib.util
import hashlib
import json
from pathlib import Path
import unittest


HARNESS = Path(__file__).resolve().parent.parent / "harness.py"
SPEC = importlib.util.spec_from_file_location("phase28_harness", HARNESS)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load Phase 28 harness")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class HarnessTests(unittest.TestCase):
    """Exercise only deterministic scanner-free logic."""

    def test_plan_is_exactly_frozen(self) -> None:
        plan = MODULE.verify_plan()
        self.assertEqual(336, len(plan["attempts"]))
        self.assertEqual(0, plan["retry_count"])

    def test_complete_metrics_are_not_imputed(self) -> None:
        observations = [
            {"status": "completed", "label": "vulnerable", "detected": True},
            {"status": "completed", "label": "control", "detected": False},
        ]
        metrics = MODULE.metrics_for(observations)
        self.assertEqual({"tp": 1, "fp": 0, "tn": 1, "fn": 0}, metrics["confusion_matrix_completed_only"])
        self.assertEqual(1.0, metrics["f1"])

    def test_incomplete_lane_nulls_primary_metrics(self) -> None:
        observations = [
            {"status": "completed", "label": "vulnerable", "detected": True},
            {"status": "timeout", "label": "control", "detected": None},
        ]
        metrics = MODULE.metrics_for(observations)
        self.assertFalse(metrics["fully_scorable"])
        self.assertIsNone(metrics["precision"])
        self.assertIsNone(metrics["balanced_accuracy"])

    def test_phase28_cargo_graph_declares_no_historical_adapter_crates(self) -> None:
        manifest = (HARNESS.parent / "Cargo.toml").read_text(encoding="utf-8")
        for package in (
            "secure-bench-opengrep-adapter",
            "secure-bench-semgrep-adapter",
            "secure-bench-scanner-protocol",
        ):
            self.assertNotIn(package, manifest)

    def test_normalized_projection_binds_exact_raw_json(self) -> None:
        raw = b'{"results":[]}\n'
        projection = {
            "schema_version": "secure-bench-adapted-report-v1",
            "scanner_version": "synthetic-1",
            "adapter_version": "1.0.0",
            "raw_sha256": hashlib.sha256(raw).hexdigest(),
            "raw_size_bytes": len(raw),
            "findings": [],
        }
        self.assertEqual(0, MODULE.validate_normalized_projection(projection, raw))
        projection["raw_size_bytes"] += 1
        with self.assertRaises(ValueError):
            MODULE.validate_normalized_projection(projection, raw)

    def test_phase27_3_runner_boundary_is_frozen(self) -> None:
        overlay_path = HARNESS.parents[1] / "phase27-3/binding-overlay.json"
        overlay_bytes = overlay_path.read_bytes()
        self.assertEqual(MODULE.PHASE27_3_OVERLAY_SHA256, hashlib.sha256(overlay_bytes).hexdigest())
        overlay = json.loads(overlay_bytes)
        self.assertTrue(overlay["precedence"]["separate_processes_required"])
        self.assertFalse(overlay["json_interface"]["rust_type_exchange_between_runners"])


if __name__ == "__main__":
    unittest.main()
