#!/usr/bin/env python3
"""Independent deterministic verifier for Phase 27 artifacts and frozen corpus."""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


BASE = "df1cf5f078ec861581f1d11dcc8d4ae35feb0315"
HOLDOUT = "phase-27-independent-holdout-v2-clean-restart"
FRAMEWORKS = ["node", "express", "next-app-router", "server-actions"]
FORMATS = ["javascript", "jsx", "typescript", "tsx"]
TOPOLOGIES = ["direct", "helper-mediated", "inter-file-aliased", "control-flow-sensitive"]
FAMILIES = [f"SE100{number}" for number in range(1, 8)]
VARIANTS = [
    "aliasing", "destructuring", "wrappers", "misleading-names-comments",
    "mutable-allowlists", "non-dominating-guards", "caught-exceptions",
    "blocklists", "suffix-tricks", "ambiguous-helpers",
]


class VerificationError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise VerificationError(message)


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"invalid JSON {path}: {error}")


def normalized_text(text: str) -> str:
    lines = []
    in_block = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("/*"):
            in_block = not stripped.endswith("*/")
            continue
        if in_block:
            if stripped.endswith("*/"):
                in_block = False
            continue
        if stripped.startswith("//"):
            continue
        lines.append(re.sub(r"\s+", "", line))
    return "".join(lines)


def validate_schema(value: Any, schema: dict[str, Any], path: str = "$") -> None:
    if "const" in schema and value != schema["const"]:
        fail(f"schema const mismatch at {path}")
    if "enum" in schema and value not in schema["enum"]:
        fail(f"schema enum mismatch at {path}")
    expected_type = schema.get("type")
    if expected_type:
        mapping = {
            "object": lambda item: isinstance(item, dict),
            "array": lambda item: isinstance(item, list),
            "string": lambda item: isinstance(item, str),
            "integer": lambda item: isinstance(item, int) and not isinstance(item, bool),
            "boolean": lambda item: isinstance(item, bool),
            "null": lambda item: item is None,
        }
        allowed = expected_type if isinstance(expected_type, list) else [expected_type]
        if not any(mapping[name](value) for name in allowed):
            fail(f"schema type mismatch at {path}: expected {allowed}")
    if isinstance(value, dict):
        required = schema.get("required", [])
        missing = [key for key in required if key not in value]
        if missing:
            fail(f"schema missing keys at {path}: {missing}")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            extras = sorted(set(value) - set(properties))
            if extras:
                fail(f"schema additional keys at {path}: {extras}")
        for key, subschema in properties.items():
            if key in value:
                validate_schema(value[key], subschema, f"{path}.{key}")
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            fail(f"schema minItems failed at {path}")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            fail(f"schema maxItems failed at {path}")
        if schema.get("uniqueItems") and len({canonical(item) for item in value}) != len(value):
            fail(f"schema uniqueItems failed at {path}")
        if "items" in schema:
            for index, item in enumerate(value):
                validate_schema(item, schema["items"], f"{path}[{index}]")
    if isinstance(value, str) and "pattern" in schema and not re.fullmatch(schema["pattern"], value):
        fail(f"schema pattern failed at {path}")


def schema_check(root: Path, instance: Path, schema: Path) -> Any:
    value = load_json(root / instance)
    validate_schema(value, load_json(root / schema), instance.as_posix())
    return value


def safe_relative(root: Path, raw: str, prefix: str) -> Path:
    if raw.startswith("/") or ".." in Path(raw).parts or not raw.startswith(prefix):
        fail(f"unsafe path in manifest: {raw}")
    path = (root / raw).resolve()
    if not path.is_relative_to(root.resolve()):
        fail(f"path escapes repository: {raw}")
    return path


def recompute_case(metadata: dict[str, Any], case_dir: Path) -> tuple[str, str, str]:
    sources: dict[str, str] = {}
    for record in metadata["source_files"]:
        name = record["path"]
        if Path(name).name != name or Path(name).suffix not in {".js", ".jsx", ".ts", ".tsx"}:
            fail(f"invalid source filename: {name}")
        data = (case_dir / name).read_bytes()
        if sha256(data) != record["sha256"] or len(data) != record["bytes"]:
            fail(f"source inventory mismatch: {case_dir / name}")
        sources[name] = data.decode("utf-8")
    exact_payload = [{"path": name, "content": sources[name]} for name in sorted(sources)]
    normalized_payload = {
        "family": metadata["family_id"],
        "framework": metadata["framework"],
        "source_format": metadata["source_format"],
        "topology": metadata["topology"],
        "variant": metadata["adversarial_variant"],
        "label": metadata["label"],
        "sources": [{"path": name, "content": normalized_text(sources[name])} for name in sorted(sources)],
    }
    combined = "\n".join(sources[name] for name in sorted(sources))
    return sha256(canonical(exact_payload)), sha256(canonical(normalized_payload)), combined


def line_exists(case_dir: Path, node: dict[str, Any]) -> None:
    source = (case_dir / node["file"]).read_text(encoding="utf-8").splitlines()
    start = node["start_line"]
    end = node["end_line"]
    if start < 1 or end < start or end > len(source):
        fail(f"evidence span out of range: {case_dir / node['file']}")


def verify_cases(root: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    case_schema = load_json(root / "phase27/schemas/case-v2.schema.json")
    ids: set[str] = set()
    exacts: set[str] = set()
    normalized: set[str] = set()
    metadata_by_id: dict[str, dict[str, Any]] = {}
    combined_by_id: dict[str, str] = {}
    labels = Counter()
    family_cases = Counter()

    for entry in manifest["cases"]:
        case_id = entry["case_id"]
        if case_id in ids:
            fail(f"duplicate case id: {case_id}")
        ids.add(case_id)
        metadata_path = safe_relative(root, entry["metadata_path"], "phase27/corpus/")
        if sha256(metadata_path.read_bytes()) != entry["metadata_sha256"]:
            fail(f"metadata hash mismatch: {case_id}")
        metadata = load_json(metadata_path)
        validate_schema(metadata, case_schema, entry["metadata_path"])
        for factor in ["case_id", "pair_id", "label", "family_id", "framework", "source_format", "topology", "orientation", "adversarial_variant", "exact_fingerprint", "normalized_fingerprint"]:
            if metadata[factor] != entry[factor]:
                fail(f"manifest/metadata mismatch for {case_id}: {factor}")
        exact, norm, combined = recompute_case(metadata, metadata_path.parent)
        if exact != metadata["exact_fingerprint"] or norm != metadata["normalized_fingerprint"]:
            fail(f"fingerprint mismatch: {case_id}")
        exacts.add(exact)
        normalized.add(norm)
        labels[metadata["label"]] += 1
        family_cases[(metadata["family_id"], metadata["label"])] += 1
        evidence = metadata["evidence_contract_v2"]
        if evidence["contract_version"] != "2.0.0" or evidence["expected_outcome"] != metadata["label"]:
            fail(f"evidence contract identity mismatch: {case_id}")
        if metadata["label"] == "vulnerable":
            finding = evidence["expected_finding"]
            if finding is None or evidence["control_proof"] is not None or len(finding["path"]) != 2:
                fail(f"invalid vulnerable evidence: {case_id}")
            for node in finding["path"]:
                line_exists(metadata_path.parent, node)
            if finding["effective_barriers"] or finding["unresolved_call"] or finding["uncertain"]:
                fail(f"vulnerable path is not exact: {case_id}")
        else:
            proof = evidence["control_proof"]
            if proof is None or evidence["expected_finding"] is not None or proof["status"] != "effective-barrier-dominates-sink":
                fail(f"invalid control evidence: {case_id}")
            line_exists(metadata_path.parent, proof["barrier"])
            line_exists(metadata_path.parent, proof["sink"])
            if proof["barrier"]["file"] == proof["sink"]["file"] and proof["barrier"]["start_line"] > proof["sink"]["start_line"]:
                fail(f"control barrier does not dominate sink: {case_id}")
            if metadata["family_id"] == "SE1007":
                required = ["requirePrincipal()", "protectedRecord.tenantId !== principal.tenantId", "protectedRecord.ownerId !== principal.userId", "stableResourceId", "records.update("]
                if not all(token in combined for token in required):
                    fail(f"authorization control is not fail-closed and scoped: {case_id}")
        metadata_by_id[case_id] = metadata
        combined_by_id[case_id] = combined

    if len(ids) != 112 or len(exacts) != 112 or len(normalized) != 112:
        fail("case or fingerprint uniqueness count mismatch")
    if labels != Counter({"vulnerable": 56, "control": 56}):
        fail(f"label balance mismatch: {labels}")
    for family in FAMILIES:
        if family_cases[(family, "vulnerable")] != 8 or family_cases[(family, "control")] != 8:
            fail(f"family label balance mismatch: {family}")

    pair_factors = {"framework": Counter(), "source_format": Counter(), "topology": Counter(), "orientation": Counter(), "adversarial_variant": Counter()}
    matrices = {"framework": Counter(), "source_format": Counter(), "topology": Counter()}
    seen_pairs: set[str] = set()
    for pair in manifest["pairs"]:
        pair_id = pair["pair_id"]
        if pair_id in seen_pairs:
            fail(f"duplicate pair id: {pair_id}")
        seen_pairs.add(pair_id)
        case_ids = pair["case_ids_in_orientation_order"]
        if len(case_ids) != 2 or {metadata_by_id[item]["label"] for item in case_ids} != {"vulnerable", "control"}:
            fail(f"pair is not a vulnerability/control pair: {pair_id}")
        if pair["orientation"] == "vulnerable-first" and metadata_by_id[case_ids[0]]["label"] != "vulnerable":
            fail(f"orientation mismatch: {pair_id}")
        if pair["orientation"] == "control-first" and metadata_by_id[case_ids[0]]["label"] != "control":
            fail(f"orientation mismatch: {pair_id}")
        for factor in ["framework", "source_format", "topology", "orientation", "adversarial_variant"]:
            pair_factors[factor][pair[factor]] += 1
        for factor in ["framework", "source_format", "topology"]:
            matrices[factor][(pair["family_id"], pair[factor])] += 1
        vulnerable_id = next(item for item in case_ids if metadata_by_id[item]["label"] == "vulnerable")
        control_id = next(item for item in case_ids if metadata_by_id[item]["label"] == "control")
        ratio = difflib.SequenceMatcher(None, combined_by_id[vulnerable_id], combined_by_id[control_id]).ratio()
        if ratio < 0.48:
            fail(f"counterfactual pair differs too broadly ({ratio:.3f}): {pair_id}")

    if len(seen_pairs) != 56:
        fail("pair count mismatch")
    for value in FRAMEWORKS:
        if pair_factors["framework"][value] != 14:
            fail(f"framework balance mismatch: {value}")
    for value in FORMATS:
        if pair_factors["source_format"][value] != 14:
            fail(f"format balance mismatch: {value}")
    for value in TOPOLOGIES:
        if pair_factors["topology"][value] != 14:
            fail(f"topology balance mismatch: {value}")
    if pair_factors["orientation"] != Counter({"vulnerable-first": 28, "control-first": 28}):
        fail("orientation balance mismatch")
    if set(pair_factors["adversarial_variant"]) != set(VARIANTS) or min(pair_factors["adversarial_variant"].values()) < 5:
        fail("adversarial variants are not distributed")
    for family in FAMILIES:
        for factor, values in [("framework", FRAMEWORKS), ("source_format", FORMATS), ("topology", TOPOLOGIES)]:
            for value in values:
                if matrices[factor][(family, value)] != 2:
                    fail(f"matrix cell mismatch: {family} x {factor}={value}")

    if manifest["aggregate_exact_fingerprint"] != sha256(canonical(sorted(exacts))):
        fail("aggregate exact fingerprint mismatch")
    if manifest["aggregate_normalized_fingerprint"] != sha256(canonical(sorted(normalized))):
        fail("aggregate normalized fingerprint mismatch")
    return {"pairs": len(seen_pairs), "cases": len(ids), "exact_unique": len(exacts), "normalized_unique": len(normalized)}


def merkle_root(leaves: list[str]) -> str:
    level = [bytes.fromhex(item) for item in leaves]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(b"node\x00" + level[index] + level[index + 1]).digest() for index in range(0, len(level), 2)]
    return level[0].hex()


def verify_frozen(root: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    if manifest["status"] != "frozen-not-executed":
        fail("manifest is not frozen")
    review = schema_check(root, Path("phase27/review/neutral-review-v2.json"), Path("phase27/schemas/review-v2.schema.json"))
    syntax = schema_check(root, Path("phase27/review/syntax-v2.json"), Path("phase27/schemas/syntax-v2.schema.json"))
    if syntax["files_parsed"] < 112 or sum(syntax[key] for key in ["javascript", "jsx", "typescript", "tsx"]) != syntax["files_parsed"]:
        fail("syntax inventory counts are invalid")
    plan = schema_check(root, Path("phase27/phase28/execution-plan-v2.json"), Path("phase27/schemas/phase28-plan-v2.schema.json"))
    if Counter(item["lane"] for item in plan["attempts"]) != Counter({"native": 112, "capability-normalized": 224}):
        fail("Phase 28 lane counts mismatch")
    artifact_counts = Counter(item["artifact_id"] for item in plan["attempts"])
    if set(artifact_counts.values()) != {112} or len(artifact_counts) != 3:
        fail("Phase 28 artifact attempt counts mismatch")
    if any(item["status"] != "planned" or item["retry_ordinal"] != 0 for item in plan["attempts"]):
        fail("Phase 28 contains execution state or retries")

    commitments = schema_check(root, Path("phase27/commitments-v2.json"), Path("phase27/schemas/commitments-v2.schema.json"))
    if commitments["manifest_sha256"] != sha256((root / "phase27/manifest-v2.json").read_bytes()):
        fail("commitments manifest hash mismatch")
    expected_leaves = []
    for case in sorted(manifest["cases"], key=lambda item: item["case_id"]):
        payload = b"leaf\x00" + case["case_id"].encode() + b"\x00" + bytes.fromhex(case["exact_fingerprint"]) + bytes.fromhex(case["metadata_sha256"])
        expected_leaves.append({"case_id": case["case_id"], "leaf_hash": sha256(payload)})
    if commitments["leaves"] != expected_leaves:
        fail("commitment leaves mismatch")
    if commitments["merkle_root"] != merkle_root([item["leaf_hash"] for item in expected_leaves]):
        fail("Merkle root mismatch")

    provenance = schema_check(root, Path("phase27/provenance-v2.json"), Path("phase27/schemas/provenance-v2.schema.json"))
    if provenance["review_receipt_sha256"] != sha256((root / "phase27/review/neutral-review-v2.json").read_bytes()) or provenance["syntax_receipt_sha256"] != sha256((root / "phase27/review/syntax-v2.json").read_bytes()):
        fail("provenance receipt hashes mismatch")
    if provenance["historical_overlap"]["status"] != "unavailable" or provenance["process_attestation"]["scanner_executions"] != 0 or provenance["process_attestation"]["case_executions"] != 0:
        fail("provenance execution/overlap attestation mismatch")

    ledger_path = root / "phase27/ledger/genesis.jsonl"
    lines = [line for line in ledger_path.read_text(encoding="utf-8").splitlines() if line]
    if len(lines) != 1:
        fail("genesis ledger must contain exactly one entry")
    ledger = json.loads(lines[0])
    validate_schema(ledger, load_json(root / "phase27/schemas/ledger-entry-v2.schema.json"), "genesis")
    declared = ledger.pop("entry_hash")
    if declared != sha256(canonical(ledger)):
        fail("genesis hash chain mismatch")
    ledger["entry_hash"] = declared

    marker = schema_check(root, Path("phase27/FROZEN_NOT_EXECUTED.json"), Path("phase27/schemas/freeze-marker-v2.schema.json"))
    if marker["manifest_sha256"] != commitments["manifest_sha256"] or marker["commitments_sha256"] != sha256((root / "phase27/commitments-v2.json").read_bytes()) or marker["merkle_root"] != commitments["merkle_root"] or marker["genesis_entry_hash"] != declared:
        fail("freeze marker linkage mismatch")
    corpus_records = []
    for case in manifest["cases"]:
        metadata_path = root / case["metadata_path"]
        corpus_records.append((case["metadata_path"], sha256(metadata_path.read_bytes())))
        metadata = load_json(metadata_path)
        for source in metadata["source_files"]:
            path = metadata_path.parent / source["path"]
            corpus_records.append((path.relative_to(root).as_posix(), sha256(path.read_bytes())))
    if marker["corpus_tree_sha256"] != sha256(canonical(sorted(corpus_records))):
        fail("frozen corpus tree mismatch")

    sums_path = root / "phase27/SHA256SUMS"
    listed: dict[str, str] = {}
    for line in sums_path.read_text(encoding="utf-8").splitlines():
        digest, relative = line.split("  ", 1)
        if relative in listed:
            fail(f"duplicate checksum entry: {relative}")
        listed[relative] = digest
    actual_files = set()
    for path in (root / "phase27").rglob("*"):
        relative = path.relative_to(root).as_posix()
        if not path.is_file() or relative == "phase27/SHA256SUMS" or "/target/" in relative or "/__pycache__/" in relative:
            continue
        actual_files.add(relative)
        if listed.get(relative) != sha256(path.read_bytes()):
            fail(f"SHA256SUMS mismatch: {relative}")
    if set(listed) != actual_files:
        fail(f"SHA256SUMS coverage mismatch missing={sorted(actual_files-set(listed))} extra={sorted(set(listed)-actual_files)}")
    return {"merkle_root": commitments["merkle_root"], "genesis_entry_hash": declared, "sha256sum_entries": len(listed), "syntax_files": syntax["files_parsed"], "reviewed_cases": review["reviewed_cases"]}


def git(root: Path, *args: str, check: bool = True) -> str:
    result = subprocess.run(["git", *args], cwd=root, text=True, capture_output=True, check=False)
    if check and result.returncode != 0:
        fail(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def verify_git(root: Path, require_clean: bool, require_commit: bool) -> dict[str, Any]:
    main = git(root, "rev-parse", "refs/heads/main")
    head = git(root, "rev-parse", "HEAD")
    if main != BASE:
        fail(f"main moved: {main}")
    result = {"main": main, "head": head}
    if require_clean and git(root, "status", "--porcelain=v1", "--untracked-files=all"):
        fail("working tree is not clean")
    if require_commit:
        parents = git(root, "show", "-s", "--format=%P", "HEAD").split()
        if parents != [BASE]:
            fail(f"Phase 27 parent mismatch: {parents}")
        verify = subprocess.run(["git", "verify-commit", "HEAD"], cwd=root, text=True, capture_output=True, check=False)
        if verify.returncode != 0:
            fail(f"commit signature invalid: {verify.stderr.strip()}")
        message = git(root, "show", "-s", "--format=%B", "HEAD")
        trailers = [line for line in message.splitlines() if line.startswith("Signed-off-by:")]
        if len(trailers) != 1:
            fail(f"expected exactly one DCO trailer, found {len(trailers)}")
        result.update({"parent": parents[0], "signature": "valid", "dco_count": len(trailers)})
    return result


def write_review(root: Path) -> None:
    receipt = {
        "schema_version": "secure-bench-phase27-neutral-review-v2",
        "status": "passed-before-freeze",
        "reviewed_pairs": 56,
        "reviewed_cases": 112,
        "vulnerable_path_reviews": 56,
        "control_semantic_reviews": 56,
        "authorization_control_reviews": 8,
        "exact_unique": 112,
        "normalized_unique": 112,
        "balance_verified": True,
        "case_executions": 0,
        "scanner_executions": 0,
    }
    path = root / "phase27/review/neutral-review-v2.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run() -> dict[str, Any]:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--pre-freeze", action="store_true")
    parser.add_argument("--write-review", action="store_true")
    parser.add_argument("--require-clean", action="store_true")
    parser.add_argument("--require-commit", action="store_true")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    design = schema_check(root, Path("phase27/preregistration/design-v2.json"), Path("phase27/schemas/design-v2.schema.json"))
    freeze = load_json(root / "phase27/preregistration/design-freeze-v2.json")
    if freeze["design_sha256"] != sha256((root / "phase27/preregistration/design-v2.json").read_bytes()) or freeze["seed_sha256"] != sha256(bytes.fromhex(design["seed"]["hex"])):
        fail("pre-authoring freeze hash mismatch")
    manifest = schema_check(root, Path("phase27/manifest-v2.json"), Path("phase27/schemas/manifest-v2.schema.json"))
    contract = schema_check(root, Path("phase27/contracts/evidence-contract-v2.json"), Path("schemas/evidence-contract-v2.schema.json"))
    if manifest["contract_sha256"] != sha256((root / "phase27/contracts/evidence-contract-v2.json").read_bytes()) or contract["contract_version"] != "2.0.0":
        fail("Evidence Contract v2 linkage mismatch")
    summary = verify_cases(root, manifest)
    summary.update(verify_git(root, args.require_clean, args.require_commit))
    if args.pre_freeze:
        if manifest["status"] != "authored-unfrozen":
            fail("pre-freeze review requires authored-unfrozen manifest")
        if args.write_review:
            write_review(root)
    else:
        summary.update(verify_frozen(root, manifest))
    return summary


if __name__ == "__main__":
    try:
        print(json.dumps({"status": "passed", **run()}, sort_keys=True))
    except VerificationError as error:
        print(json.dumps({"status": "failed", "detail": str(error)}, sort_keys=True), file=sys.stderr)
        raise SystemExit(1)
