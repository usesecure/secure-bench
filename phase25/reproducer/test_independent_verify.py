#!/usr/bin/env python3
"""Synthetic-only state and environment tests for the Phase 25 verifier."""

import copy
import unittest
from pathlib import Path

import independent_verify as verifier


def observation(state):
    completed = state == "completed"
    malformed = state == "malformed"
    timeout = state == "timeout"
    has_raw = completed or malformed
    return {
        "state": state,
        "finding_count": 0 if completed else None,
        "failure": None if completed else "synthetic failure",
        "timed_out": timeout,
        "raw_output_path": "synthetic/raw.json" if has_raw else None,
        "raw_output_sha256": verifier.ZERO_HASH if has_raw else None,
    }


class VerifierStateTests(unittest.TestCase):
    def test_all_operational_states_are_validated(self):
        for state in ("completed", "failed", "timeout", "malformed", "unavailable"):
            verifier.validate_observation_state(observation(state))

    def test_invalid_state_combinations_fail(self):
        invalid = observation("timeout")
        invalid["timed_out"] = False
        with self.assertRaises(ValueError):
            verifier.validate_observation_state(invalid)

        invalid = observation("failed")
        invalid["finding_count"] = 0
        with self.assertRaises(ValueError):
            verifier.validate_observation_state(invalid)

    def test_pwd_and_extra_environment_fail_closed(self):
        valid = {
            "address_space": [4294967296, 4294967296],
            "processes": [64, 64],
            "stack": [8388608, 8388608],
            "environment": verifier.EFFECTIVE_ENVIRONMENT,
            "mountinfo": " /proc  /tmp/run  /tmp/fixture  /tmp/rules/rule.yml ",
        }
        verifier.validate_effective_environment(valid)
        for environment in (
            [item for item in verifier.EFFECTIVE_ENVIRONMENT if not item.startswith("PWD=")],
            ["PWD=/tmp/wrong" if item.startswith("PWD=") else item for item in verifier.EFFECTIVE_ENVIRONMENT],
            sorted([*verifier.EFFECTIVE_ENVIRONMENT, "PYTHONPATH=/injected"]),
        ):
            invalid = copy.deepcopy(valid)
            invalid["environment"] = environment
            with self.assertRaises(ValueError):
                verifier.validate_effective_environment(invalid)

    def test_exact_command_rejects_runtime_shell_bwrap_and_python_injection(self):
        expected = verifier.expected_command(
            Path("/repository"),
            "phase25/fixtures/clean",
            Path("/repository/phase25/output/attempts/001"),
        )
        for injected in (
            [*expected, "/bin/sh"],
            [*expected, "-c"],
            [expected[0], "--setenv", "INJECTED", "true", *expected[1:]],
            [*expected, "/tmp/other-wrapper.py"],
        ):
            self.assertNotEqual(injected, expected)


if __name__ == "__main__":
    unittest.main()
