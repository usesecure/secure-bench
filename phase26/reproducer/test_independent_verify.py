#!/usr/bin/env python3
"""Synthetic-only tests for the Phase 26 independent verifier."""

import importlib.util
import json
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("independent_verify.py")
SPEC = importlib.util.spec_from_file_location("phase26_independent_verify", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load independent verifier")
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


class SerializationTests(unittest.TestCase):
    def setUp(self):
        self.fixtures = Path(__file__).with_name("fixtures")

    def test_observation_payload_uses_exact_bytes(self):
        raw = (self.fixtures / "observation.json").read_bytes()
        self.assertEqual(VERIFY.digest(raw), "2afcec764895fa2ad4f1d6cad0d6a2ce4cc9f68515611eb488195a0d580ee286")
        self.assertNotEqual(VERIFY.digest(VERIFY.value_bytes(json.loads(raw))), VERIFY.digest(raw))

    def test_value_projection_matches_serde_key_order(self):
        raw = (self.fixtures / "ledger-projection.json").read_bytes()
        self.assertEqual(VERIFY.value_bytes(json.loads(raw)), raw)
        self.assertTrue(raw.endswith(b"\n"))
        self.assertEqual(
            list(json.loads(raw)),
            ["event", "payload_sha256", "previous_entry_hash", "schema_version", "sequence"],
        )

    def test_sequence_serializer_rejects_objects(self):
        with self.assertRaisesRegex(ValueError, "cannot accept an object"):
            VERIFY.sequence_bytes({"field": "value"})

    def test_safe_relative_path(self):
        self.assertEqual(VERIFY.relative("attempts/001/raw.json").as_posix(), "attempts/001/raw.json")
        for value in ("/absolute", "../escape", "a/../b", "a\\b"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                VERIFY.relative(value)

    def test_duplicate_json_key_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "repeats key"):
            VERIFY.strict_json_loads(b'{"sequence":1,"sequence":2}')

    def test_metric_arithmetic(self):
        decisions = ([{"outcome": "tp"}] * 56 + [{"outcome": "fp"}] * 16 + [{"outcome": "tn"}] * 40)
        metrics = VERIFY.metrics_from_decisions(decisions)
        self.assertEqual((metrics["tp"], metrics["fp"], metrics["tn"], metrics["fn_count"]), (56, 16, 40, 0))
        self.assertEqual(metrics["precision"], {"numerator": 7, "denominator": 9, "decimal": "0.777778"})
        self.assertEqual(metrics["balanced_accuracy"], {"numerator": 6, "denominator": 7, "decimal": "0.857143"})


if __name__ == "__main__":
    unittest.main()
