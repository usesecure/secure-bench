#!/usr/bin/env python3
"""Synthetic unit tests for Phase 27 verification primitives."""

from __future__ import annotations

import unittest

import verify_phase27


class VerificationPrimitiveTests(unittest.TestCase):
    def test_merkle_is_deterministic(self) -> None:
        leaves = [verify_phase27.sha256(b"left"), verify_phase27.sha256(b"right")]
        self.assertEqual(verify_phase27.merkle_root(leaves), verify_phase27.merkle_root(list(leaves)))

    def test_schema_rejects_additional_property(self) -> None:
        schema = {"type": "object", "additionalProperties": False, "properties": {"ok": {"const": True}}, "required": ["ok"]}
        with self.assertRaises(verify_phase27.VerificationError):
            verify_phase27.validate_schema({"ok": True, "extra": 1}, schema)

    def test_schema_accepts_exact_object(self) -> None:
        schema = {"type": "object", "additionalProperties": False, "properties": {"ok": {"const": True}}, "required": ["ok"]}
        verify_phase27.validate_schema({"ok": True}, schema)

    def test_normalization_removes_layout_not_tokens(self) -> None:
        self.assertEqual(verify_phase27.normalized_text("const x = 1;\n"), "constx=1;")
        self.assertNotEqual(verify_phase27.normalized_text("const x = 1;\n"), verify_phase27.normalized_text("const x = 2;\n"))


if __name__ == "__main__":
    unittest.main()
