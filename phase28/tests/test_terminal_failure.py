"""Scanner-free tests for the explicit Phase 28 terminal state."""

from __future__ import annotations

import json
from pathlib import Path
import unittest


PHASE = Path(__file__).resolve().parent.parent


class TerminalFailureTests(unittest.TestCase):
    """Ensure terminal accounting cannot be mistaken for scoring."""

    def test_terminal_counts_are_explicit(self) -> None:
        summary = json.loads((PHASE / "terminal-summary.json").read_text(encoding="utf-8"))
        self.assertEqual("terminal-failed", summary["status"])
        self.assertEqual(
            {"planned": 336, "consumed": 1, "valid_completed": 0, "partial": 1, "out_of_scope": 335, "retries": 0},
            summary["attempts"],
        )
        self.assertFalse(summary["scoring_allowed"])

    def test_scoring_artifacts_are_absent(self) -> None:
        self.assertFalse((PHASE / "results.json").exists())
        self.assertFalse((PHASE / "comparison.json").exists())

    def test_preserved_raw_is_parseable_but_unadapted(self) -> None:
        record = json.loads((PHASE / "attempt-record.json").read_text(encoding="utf-8"))
        self.assertTrue(record["raw_json"]["json_parseable"])
        self.assertFalse(record["adapter_stage"]["started"])
        self.assertEqual("unavailable", record["adapter_stage"]["finding_count"]["availability"])


if __name__ == "__main__":
    unittest.main()
