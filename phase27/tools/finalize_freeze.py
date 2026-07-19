#!/usr/bin/env python3
"""Create Phase 27 commitments, provenance, genesis, freeze marker, and checksums."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent
ZERO = "0" * 64
HOLDOUT = "phase-27-independent-holdout-v2-clean-restart"


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def merkle_root(leaves: list[str]) -> str:
    level = [bytes.fromhex(item) for item in leaves]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(b"node\x00" + level[index] + level[index + 1]).digest() for index in range(0, len(level), 2)]
    return level[0].hex()


def corpus_tree(manifest: dict[str, Any]) -> str:
    records = []
    for case in manifest["cases"]:
        metadata_path = REPO / case["metadata_path"]
        records.append((case["metadata_path"], sha256(metadata_path.read_bytes())))
        metadata = load(metadata_path)
        for source in metadata["source_files"]:
            path = metadata_path.parent / source["path"]
            records.append((path.relative_to(REPO).as_posix(), sha256(path.read_bytes())))
    return sha256(canonical(sorted(records)))


def main() -> None:
    marker_path = ROOT / "FROZEN_NOT_EXECUTED.json"
    if marker_path.exists():
        raise SystemExit("refusing to rewrite an existing freeze")
    manifest_path = ROOT / "manifest-v2.json"
    manifest = load(manifest_path)
    if manifest["status"] != "authored-unfrozen" or manifest["scanner_executions"] != 0 or manifest["case_executions"] != 0:
        raise SystemExit("manifest is not eligible for freeze")
    review_path = ROOT / "review/neutral-review-v2.json"
    syntax_path = ROOT / "review/syntax-v2.json"
    review = load(review_path)
    syntax = load(syntax_path)
    if review["status"] != "passed-before-freeze" or review["reviewed_cases"] != 112 or syntax["status"] != "passed-before-freeze" or syntax["files_parsed"] < 112:
        raise SystemExit("neutral review or syntax parse missing")
    frozen_at = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    manifest["status"] = "frozen-not-executed"
    write(manifest_path, manifest)
    manifest_hash = sha256(manifest_path.read_bytes())

    artifacts = [
        {
            "artifact_id": "secure-engine-0.1.7-rc1",
            "version": "0.1.7-rc1",
            "lane": "native",
            "git_commit": "1e3d300cb7092097f21be164b6c403b71f2b2520",
            "git_tree": "8f08ac800a43afcd39eb70cecd29c8643a24157b",
            "rpm_sha256": "8f26b69981c7ba88081496b0c1dd1fce9da62c03a38927e07b3d64541cf45f75",
            "executable_sha256": "5feca58fda54e4f9af0bf3846d04a98825d7315e64cbf80268a2395cf07ff2e6",
        },
        {"artifact_id": "opengrep-1.22.0", "version": "1.22.0", "lane": "capability-normalized", "identity_status": "verify-at-phase28-preflight"},
        {"artifact_id": "semgrep-ce-1.170.0", "version": "1.170.0", "lane": "capability-normalized", "identity_status": "verify-at-phase28-preflight"},
    ]
    attempts = []
    for artifact in artifacts:
        for ordinal, case in enumerate(sorted(manifest["cases"], key=lambda item: item["case_id"]), start=1):
            attempts.append({
                "attempt_id": f"p28-{artifact['artifact_id']}-{ordinal:03d}",
                "artifact_id": artifact["artifact_id"],
                "lane": artifact["lane"],
                "case_id": case["case_id"],
                "ordinal": ordinal,
                "retry_ordinal": 0,
                "status": "planned",
            })
    plan = {
        "schema_version": "secure-bench-phase28-plan-v2",
        "phase": 28,
        "status": "frozen-not-executed",
        "attempt_count": 336,
        "retry_count": 0,
        "lanes_separate": True,
        "non_numeric_statuses": ["failed", "timeout", "malformed", "unsupported", "unavailable"],
        "artifacts": artifacts,
        "attempts": attempts,
    }
    write(ROOT / "phase28/execution-plan-v2.json", plan)

    process_attestation = {
        "schema_version": "secure-bench-phase27-process-attestation-v2",
        "phase": 27,
        "status": "authoring-and-verification-only",
        "scanner_executions": 0,
        "case_executions": 0,
        "phase28_attempts_executed": 0,
        "network_downloads": 0,
        "pushes": 0,
        "prohibited_path_accesses": 0,
        "scope": "Only repository metadata, neutral contracts, generated fixtures, and neutral verification tools",
    }
    write(ROOT / "audit/process-attestation-v2.json", process_attestation)

    design = load(ROOT / "preregistration/design-v2.json")
    taxonomy_path = REPO / "taxonomy/secure-bench-taxonomy-v1.json"
    provenance = {
        "schema_version": "secure-bench-phase27-provenance-v2",
        "phase": 27,
        "holdout_id": HOLDOUT,
        "authoritative_base": manifest["authoritative_base"],
        "seed_sha256": manifest["seed_sha256"],
        "design_sha256": manifest["design_sha256"],
        "taxonomy": {"path": "taxonomy/secure-bench-taxonomy-v1.json", "sha256": sha256(taxonomy_path.read_bytes()), "content_hash": "22852bd7401020b315af11dfa2b60c0b46f78eb19f95079e6400d7b3bea3272c"},
        "secure_engine_rc1_identity": artifacts[0],
        "review_receipt_sha256": sha256(review_path.read_bytes()),
        "syntax_receipt_sha256": sha256(syntax_path.read_bytes()),
        "historical_overlap": {"status": "unavailable", "reason": "No allowed redacted precomputed index was present in the neutral schemas, taxonomy, policies, or contracts used for authoring; historical corpus access remained prohibited."},
        "process_attestation": process_attestation,
        "limitations": [
            "No scanner behavior informed fixture design.",
            "No historical corpus content or result was used for novelty comparison.",
            "Tree-sitter validates syntax but not framework type semantics.",
            "Phase 28 identity and sandbox preflight remain mandatory before execution.",
        ],
    }
    write(ROOT / "provenance-v2.json", provenance)

    leaves = []
    for case in sorted(manifest["cases"], key=lambda item: item["case_id"]):
        payload = b"leaf\x00" + case["case_id"].encode() + b"\x00" + bytes.fromhex(case["exact_fingerprint"]) + bytes.fromhex(case["metadata_sha256"])
        leaves.append({"case_id": case["case_id"], "leaf_hash": sha256(payload)})
    root_hash = merkle_root([item["leaf_hash"] for item in leaves])
    commitments = {
        "schema_version": "secure-bench-phase27-commitments-v2",
        "holdout_id": HOLDOUT,
        "algorithm": "sha256-domain-separated-binary-merkle-v1",
        "leaf_count": 112,
        "manifest_sha256": manifest_hash,
        "leaves": leaves,
        "merkle_root": root_hash,
    }
    commitments_path = ROOT / "commitments-v2.json"
    write(commitments_path, commitments)
    commitments_hash = sha256(commitments_path.read_bytes())

    genesis_content = {
        "schema_version": "secure-bench-phase27-ledger-entry-v2",
        "sequence": 0,
        "event": "holdout-frozen-not-executed",
        "holdout_id": HOLDOUT,
        "timestamp_utc": frozen_at,
        "previous_entry_hash": ZERO,
        "commitment_root": root_hash,
        "commitments_sha256": commitments_hash,
        "execution_count": 0,
    }
    genesis = {**genesis_content, "entry_hash": sha256(canonical(genesis_content))}
    ledger_path = ROOT / "ledger/genesis.jsonl"
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    ledger_path.write_text(json.dumps(genesis, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")

    for path in (ROOT / "corpus").rglob("*"):
        if path.is_file():
            os.chmod(path, 0o444)
    marker = {
        "schema_version": "secure-bench-phase27-freeze-marker-v2",
        "phase": 27,
        "holdout_id": HOLDOUT,
        "status": "frozen-not-executed",
        "frozen_at_utc": frozen_at,
        "manifest_sha256": manifest_hash,
        "commitments_sha256": commitments_hash,
        "merkle_root": root_hash,
        "genesis_entry_hash": genesis["entry_hash"],
        "corpus_tree_sha256": corpus_tree(manifest),
        "scanner_executions": 0,
        "case_executions": 0,
        "phase28_executed": False,
    }
    write(marker_path, marker)

    files = []
    for path in ROOT.rglob("*"):
        relative = path.relative_to(REPO).as_posix()
        if not path.is_file() or relative == "phase27/SHA256SUMS" or "/target/" in relative or "/__pycache__/" in relative:
            continue
        files.append((relative, sha256(path.read_bytes())))
    files.sort()
    (ROOT / "SHA256SUMS").write_text("".join(f"{digest}  {relative}\n" for relative, digest in files), encoding="utf-8")
    print(json.dumps({"status": "frozen-not-executed", "manifest_sha256": manifest_hash, "merkle_root": root_hash, "genesis_entry_hash": genesis["entry_hash"], "corpus_tree_sha256": marker["corpus_tree_sha256"], "sha256sum_entries": len(files), "phase28_attempts": 336, "scanner_executions": 0, "case_executions": 0}, sort_keys=True))


if __name__ == "__main__":
    main()
