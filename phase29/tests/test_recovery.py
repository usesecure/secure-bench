"""Scanner-free Phase 29 recovery harness tests."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


HARNESS = Path(__file__).resolve().parents[1] / "harness.py"
SPEC = importlib.util.spec_from_file_location("phase29_harness", HARNESS)
MODULE = importlib.util.module_from_spec(SPEC)
if SPEC.loader is None:
    raise RuntimeError("cannot load Phase 29 harness")
SPEC.loader.exec_module(MODULE)


class RecoveryTests(unittest.TestCase):
    """Verify frozen accounting without executing a scanner."""

    def test_source_plan_has_one_inherited_and_335_remaining(self) -> None:
        plan = MODULE.source_plan()
        self.assertEqual(336, len(plan["attempts"]))
        self.assertEqual("aurora-0612ee8a7f5e19a698", plan["attempts"][0]["case_id"])
        self.assertEqual(0, plan["retry_count"])

    def test_recovery_constants_preserve_post_open_accounting(self) -> None:
        self.assertEqual(336, MODULE.TOTAL)
        self.assertEqual(335, MODULE.NEW_SCANNERS)
        self.assertEqual("172a3161420efbc06fd2e3f4053a0b7975a96bad67d84a7ba80a9b67c82c9806", MODULE.PHASE28_LEDGER_HEAD)

    def test_metrics_never_impute_incomplete_observations(self) -> None:
        metrics = MODULE.legacy.metrics_for([
            {"status": "completed", "label": "vulnerable", "detected": True},
            {"status": "timeout", "label": "control", "detected": None},
        ])
        self.assertFalse(metrics["fully_scorable"])
        self.assertIsNone(metrics["precision"])


if __name__ == "__main__":
    unittest.main()
