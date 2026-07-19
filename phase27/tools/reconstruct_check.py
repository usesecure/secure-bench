#!/usr/bin/env python3
"""Reconstruct every fixture from frozen factors and compare bytes without execution."""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

import build_holdout


ROOT = Path(__file__).resolve().parents[1]


def derive(seed: bytes, label: str) -> str:
    return hmac.new(seed, label.encode(), hashlib.sha256).hexdigest()


def main() -> None:
    design = json.loads((ROOT / "preregistration/design-v2.json").read_text(encoding="utf-8"))
    manifest = json.loads((ROOT / "manifest-v2.json").read_text(encoding="utf-8"))
    seed = bytes.fromhex(design["seed"]["hex"])
    manifest_pairs = {item["pair_id"]: item for item in manifest["pairs"]}
    manifest_cases = {item["case_id"]: item for item in manifest["cases"]}
    checked_cases = 0
    checked_sources = 0
    for family_index, family_data in enumerate(build_holdout.FAMILIES):
        family = family_data[0]
        for slot in range(8):
            framework = build_holdout.FRAMEWORKS[slot % 4]
            source_format = build_holdout.FORMATS[(slot + family_index) % 4]
            topology = build_holdout.TOPOLOGIES[(slot + 2 * family_index + slot // 4) % 4]
            orientation = "vulnerable-first" if (family_index + slot) % 2 == 0 else "control-first"
            variant = build_holdout.VARIANTS[(family_index * 8 + slot) % len(build_holdout.VARIANTS)]
            pair_digest = derive(seed, f"pair/{family}/{slot}/{framework}/{source_format}/{topology}/{variant}")
            pair_id = f"orbit-{family.lower()}-{pair_digest[:14]}"
            pair = manifest_pairs.get(pair_id)
            if pair is None:
                raise SystemExit(f"missing reconstructed pair: {pair_id}")
            labels = ["vulnerable", "control"] if orientation == "vulnerable-first" else ["control", "vulnerable"]
            for order, label in enumerate(labels, start=1):
                case_digest = derive(seed, f"case/{pair_id}/{label}")
                case_id = f"aurora-{case_digest[:18]}"
                ticket = f"ticket-{case_digest[18:34]}"
                entry = manifest_cases.get(case_id)
                if entry is None:
                    raise SystemExit(f"missing reconstructed case: {case_id}")
                metadata_path = ROOT.parent / entry["metadata_path"]
                metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                expected, _, _, _ = build_holdout.render_case(
                    family, framework, source_format, topology, variant, label == "control", ticket
                )
                if set(expected) != {item["path"] for item in metadata["source_files"]}:
                    raise SystemExit(f"source inventory reconstruction mismatch: {case_id}")
                for name, content in expected.items():
                    if (metadata_path.parent / name).read_text(encoding="utf-8") != content:
                        raise SystemExit(f"source byte reconstruction mismatch: {case_id}/{name}")
                    checked_sources += 1
                checked_cases += 1
    if checked_cases != 112:
        raise SystemExit(f"reconstructed {checked_cases}, expected 112")
    print(json.dumps({"status": "passed", "reconstructed_cases": checked_cases, "reconstructed_source_files": checked_sources, "case_executions": 0, "scanner_executions": 0}, sort_keys=True))


if __name__ == "__main__":
    main()
