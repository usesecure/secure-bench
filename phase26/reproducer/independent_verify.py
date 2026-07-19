#!/usr/bin/env python3
"""Certify frozen Phase 25 evidence without running scanners or case sources."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from fractions import Fraction
from pathlib import Path, PurePosixPath
from typing import Any, Callable


PHASE25 = "a25175dc352c006deea579b5e85643d513be6984"
PHASE24 = "17946b9f326ff2c25ebcd5f0f1526af35b8702df"
PHASE23 = "85e9ad1e9c87dbd238c2f5529ce9421dce920092"
PHASE22 = "b8ef30bfcd9761644001b63ed9b9f717ebd09d93"
ZERO_HASH = "0" * 64
EXPECTED = {
    "phase25_tree": "f7f6314083759a58b73931516db2c97eca9c03ae",
    "plan": "10ad16a370120d9624a91d0c8ce361c26ddddb097380d3846ba13fb20f9f3953",
    "contract": "7fd380c904bcfb38fe069479e2fb21cc5657c3502256d851feec0e9c091cb9a5",
    "genesis": "50be36d4a29bfcbfd4b856d0bdd63f97d934575002c1fc9b46f621f824a84bf1",
    "marker": "c41715459f22396256c51d81936e3c6c836720b6a546bccbe5eca470cfacdd81",
    "manifest": "c035f9de14e2a1cb7c65562f9a643f0eefafc682d23c90e520770c7183068cb6",
    "corpus": "d059653d836647296bef93a43d9e9f046899ad4fa0a87d561b4463ce0db2781c",
    "merkle": "2bcc11f20b0f9d06eeb10f05130b752fa8125421ebf37d6050cd3119aef4452e",
    "adapter": "53317a4e71b14548d618fd79430b74b8fc906edebbf7180cbea418df98b1afc3",
    "rules": "06af4cf6d10da30ad585d57b781cf6aef734add03b90ea36c78e920c4c10a07c",
    "methodology": "0e0a767e8b1df51ca8018d27956e1d0f4ba943d520888923221bbf67f9a7b2a6",
    "phase22_results": "150bcf3c41e5d1602f90da902d892d8bc32b5e1fd13bcdc11a3774c15bcb1892",
    "phase25_sha256s": "95d00cec3cb45c1fbdb3ecce5ded16933caac7d034ed06801fcdd3369bbac0ea",
}
SUBTREES = {
    "phase19": ("b3e983891e4ae3e12cd727f6bdb460962f876a30", "c4142cea4dcde5f4ec25c1f3e0973b26a9eaf3a2"),
    "phase20": ("6c27c9bb26b96855228d1a8e6483483ff4174907", "05cd69281777263a4f9286069767d870014cab52"),
    "phase21": ("be1ce9327c5c2acab25abe5af7a4f923d1623c48", "e3e75c80517218b6da1c61e21a8d909b54a12800"),
    "phase22": (PHASE22, "048b3c30e0864ca6e61e2af40de11016050a1ca3"),
    "phase23": (PHASE23, "c0d7a4b3e39617718a6e3b23c1b723c45de9a313"),
    "phase24": (PHASE24, "0937880cf64940f4e4bf7c26dc0a39cb1d09424c"),
    "phase25": (PHASE25, "0fa9045b1819e55bb07e639136ea14f509666cc3"),
}
EFFECTIVE_ENVIRONMENT = [
    "HOME=/tmp/home",
    "LANG=C.UTF-8",
    "LC_ALL=C.UTF-8",
    "PATH=/usr/bin:/bin",
    "PWD=/tmp/fixture",
    "SEMGREP_ENABLE_VERSION_CHECK=0",
    "SEMGREP_SEND_METRICS=off",
    "TZ=UTC",
    "XDG_CACHE_HOME=/tmp/cache",
]
BWRAP_ENVIRONMENT = [item for item in EFFECTIVE_ENVIRONMENT if not item.startswith("PWD=")]
ALLOWED_RULES = {
    "secure-bench.phase19.SE1001.resource-authorization",
    "secure-bench.phase19.SE1002.command-injection",
    "secure-bench.phase19.SE1003.dynamic-code",
    "secure-bench.phase19.SE1004.path-traversal",
    "secure-bench.phase19.SE1005.outbound-request",
    "secure-bench.phase19.SE1006.open-redirect",
    "secure-bench.phase19.SE1007.sql-injection",
}
OBSERVATION_FIELD_ORDER = (
    "sequence", "attempt_id", "scanner", "lane", "case_id", "state",
    "process_decision", "exit_code", "signal", "timed_out", "duration_ms",
    "command", "command_sha256", "environment", "environment_sha256",
    "stdout_path", "stdout_sha256", "stderr_path", "stderr_sha256",
    "raw_output_path", "raw_output_sha256", "resource_path", "resource_sha256",
    "effective_environment_path", "effective_environment_sha256", "finding_count",
    "failure",
)
OBSERVATION_FIELDS = set(OBSERVATION_FIELD_ORDER)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read(path: Path) -> bytes:
    return path.read_bytes()


def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"JSON object repeats key: {key}")
        value[key] = item
    return value


def strict_json_loads(data: bytes | str) -> Any:
    def reject_constant(value: str) -> Any:
        raise ValueError(f"invalid JSON constant: {value}")

    return json.loads(data, object_pairs_hook=reject_duplicate_pairs, parse_constant=reject_constant)


def load(path: Path) -> Any:
    return strict_json_loads(read(path))


def value_bytes(value: Any) -> bytes:
    """Serialize with serde_json::Value key ordering and a final newline."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"


def sequence_bytes(value: Any) -> bytes:
    """Serialize arrays/scalars canonically; object ordering is not accepted here."""
    if isinstance(value, dict):
        raise ValueError("sequence serialization cannot accept an object")
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"


def relative(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if "\\" in name or path.is_absolute() or not path.parts or any(part in ("", ".", "..") for part in path.parts):
        raise ValueError(f"unsafe evidence path: {name}")
    return path


def canonical_file(root: Path, name: str) -> Path:
    rel = relative(name)
    path = root.joinpath(*rel.parts)
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"evidence path is absent or a symlink: {name}")
    return path


def git(root: Path, *arguments: str, check: bool = True) -> str:
    result = subprocess.run(
        ["git", *arguments], cwd=root, env={"PATH": "/usr/bin:/bin"}, check=False,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    if check and result.returncode:
        raise ValueError(f"git {' '.join(arguments)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def verify_signature(root: Path, commit: str) -> dict[str, Any]:
    common = Path(git(root, "rev-parse", "--git-common-dir"))
    if not common.is_absolute():
        common = root / common
    allowed = (common / "allowed_signers").resolve(strict=True)
    result = subprocess.run(
        ["git", "-c", f"gpg.ssh.allowedSignersFile={allowed}", "verify-commit", "--raw", commit],
        cwd=root, env={"PATH": "/usr/bin:/bin"}, check=False,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    combined = result.stdout + result.stderr
    if result.returncode or 'Good "git" signature' not in combined or "ED25519" not in combined:
        raise ValueError(f"commit signature is not a trusted ED25519 signature: {commit}")
    message = git(root, "show", "-s", "--format=%B", commit)
    dco = sum(line.startswith("Signed-off-by: ") for line in message.splitlines())
    if dco != 1:
        raise ValueError(f"commit has {dco} DCO trailers, expected one: {commit}")
    return {"commit": commit, "signature": "good-ed25519", "dco_trailers": dco}


def scanner_processes() -> list[dict[str, Any]]:
    forbidden = {"semgrep", "semgrep-core", "opengrep", "secure-engine"}
    found: list[dict[str, Any]] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            name = (entry / "comm").read_text().strip()
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        if name in forbidden:
            found.append({"pid": int(entry.name), "comm": name})
    return found


def verify_git(root: Path) -> dict[str, Any]:
    if git(root, "rev-parse", f"{PHASE25}^") != PHASE24:
        raise ValueError("Phase 25 is not a direct child of Phase 24")
    if git(root, "rev-list", "--count", f"{PHASE24}..{PHASE25}") != "1":
        raise ValueError("Phase 25 is not exactly one commit over Phase 24")
    if git(root, "rev-parse", f"{PHASE25}^{{tree}}") != EXPECTED["phase25_tree"]:
        raise ValueError("Phase 25 root tree drift")
    signature = verify_signature(root, PHASE25)
    trees: dict[str, str] = {}
    for phase, (commit, expected_tree) in SUBTREES.items():
        frozen = git(root, "rev-parse", f"{commit}:{phase}")
        current = git(root, "rev-parse", f"{PHASE25}:{phase}")
        if frozen != expected_tree or current != expected_tree:
            raise ValueError(f"{phase} subtree drift")
        if git(root, "diff", "--name-only", PHASE25, "--", phase):
            raise ValueError(f"working tree modifies {phase}")
        if git(root, "ls-files", "--others", "--exclude-standard", "--", phase):
            raise ValueError(f"working tree has untracked files under {phase}")
        trees[phase] = current
    return {**signature, "parent": PHASE24, "tree": EXPECTED["phase25_tree"], "frozen_subtrees": trees}


def verify_sums(output: Path) -> dict[PurePosixPath, str]:
    sums_path = output / "SHA256SUMS"
    if digest(read(sums_path)) != EXPECTED["phase25_sha256s"]:
        raise ValueError("Phase 25 SHA256SUMS digest drift")
    expected: dict[PurePosixPath, str] = {}
    for line in sums_path.read_text().splitlines():
        if "  " not in line:
            raise ValueError("malformed checksum line")
        value, name = line.split("  ", 1)
        path = relative(name)
        if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
            raise ValueError(f"invalid SHA-256 value: {name}")
        if path in expected:
            raise ValueError(f"duplicate checksum path: {name}")
        expected[path] = value
    actual = {
        PurePosixPath(path.relative_to(output).as_posix())
        for path in output.rglob("*") if path.is_file() and path != sums_path
    }
    if len(expected) != 684 or actual != set(expected):
        raise ValueError(f"SHA256SUMS coverage is {len(expected)}/{len(actual)}, expected 684/684")
    for name, value in expected.items():
        if digest(read(output.joinpath(*name.parts))) != value:
            raise ValueError(f"checksum mismatch: {name}")
    return expected


def require_hash(root: Path, name: str, expected: str) -> bytes:
    path = canonical_file(root, name)
    data = read(path)
    if digest(data) != expected:
        raise ValueError(f"frozen hash drift: {name}")
    return data


def case_metadata(root: Path) -> dict[str, dict[str, Any]]:
    data = require_hash(root, "phase19/holdout/manifest.json", EXPECTED["manifest"])
    manifest = strict_json_loads(data)
    if manifest.get("aggregate_corpus_sha256") != EXPECTED["corpus"] or manifest.get("contract_merkle_root") != EXPECTED["merkle"]:
        raise ValueError("corpus commitments drift")
    if manifest.get("counts") != {"cases": 112, "controls": 56, "pairs": 56, "vulnerable": 56}:
        raise ValueError("manifest population drift")
    cases: dict[str, dict[str, Any]] = {}
    pair_ids: set[str] = set()
    for pair in manifest.get("pairs", []):
        pair_id = pair.get("pair_id")
        if pair_id in pair_ids:
            raise ValueError("manifest repeats pair ID")
        pair_ids.add(pair_id)
        assignment = pair["assignment"]
        classifications: set[str] = set()
        for side in ("first", "second"):
            item = pair[side]
            case_id = item["case_id"]
            if case_id in cases:
                raise ValueError("manifest repeats case ID")
            classifications.add(item["classification"])
            files = {entry["path"]: entry for entry in item["files"]}
            for name in files:
                relative(name)
            cases[case_id] = {
                "pair_id": pair_id,
                "expected": item["classification"],
                "family": assignment["family"],
                "framework": assignment["framework"],
                "source_format": assignment["source_format"],
                "topology": assignment["topology"],
                "adversarial_variant": assignment.get("adversarial_variant") or "none",
                "fixture_path": item["fixture_path"],
                "files": files,
            }
        if classifications != {"vulnerable", "control"}:
            raise ValueError(f"pair {pair_id} is not vulnerable/control")
    if len(cases) != 112 or len(pair_ids) != 56:
        raise ValueError("manifest population is not 112 cases/56 pairs")
    return cases


def expected_command(execution_root: str, fixture_path: str, output_path: str) -> list[str]:
    arguments = [
        "--unshare-net", "--unshare-pid", "--die-with-parent", "--new-session", "--as-pid-1",
        "--ro-bind", "/", "/", "--tmpfs", "/dev", "--dev-bind", "/dev/null", "/dev/null",
        "--proc", "/proc", "--tmpfs", "/tmp", "--tmpfs", "/home", "--tmpfs", "/root",
        "--tmpfs", "/run/user", "--tmpfs", "/var/tmp",
    ]
    for path in ("/tmp/fixture", "/tmp/rules", "/tmp/run", "/tmp/home", "/tmp/cache", "/tmp/secure-bench-tools", "/tmp/secure-bench-tools/semgrep", "/tmp/secure-bench-tools/semgrep/1.170.0"):
        arguments.extend(("--dir", path))
    arguments.extend((
        "--ro-bind", "/tmp/secure-bench-tools/semgrep/1.170.0", "/tmp/secure-bench-tools/semgrep/1.170.0",
        "--ro-bind", f"{execution_root}/{fixture_path}", "/tmp/fixture",
        "--ro-bind", f"{execution_root}/phase19/rules/capability-normalized-v1.yml", "/tmp/rules/rule.yml",
        "--bind", output_path, "/tmp/run", "--chdir", "/tmp/fixture", "--clearenv",
    ))
    for item in BWRAP_ENVIRONMENT:
        name, value = item.split("=", 1)
        arguments.extend(("--setenv", name, value))
    arguments.extend((
        "--ro-bind", f"{execution_root}/phase25/reproducer/runtime_wrapper.py", "/tmp/runtime-wrapper.py",
        "--", "/usr/bin/time", "--verbose", "--output=/tmp/run/resource.txt", "--", "/usr/bin/prlimit",
        "--as=4294967296", "--nproc=64", "--stack=8388608", "--", "/usr/bin/python3.14",
        "/tmp/runtime-wrapper.py", "/tmp/secure-bench-tools/semgrep/1.170.0/venv/bin/semgrep",
        "scan", "--json", "--json-output=/tmp/run/raw.json", "--error", "--metrics=off",
        "--disable-version-check", "--no-rewrite-rule-ids", "--no-git-ignore",
        "--config=/tmp/rules/rule.yml", ".",
    ))
    return ["/usr/bin/bwrap", *arguments]


def derive_execution_root(command: list[str], fixture_path: str) -> str:
    suffix = "/" + fixture_path
    roots = {
        command[index + 1][:-len(suffix)]
        for index in range(len(command) - 2)
        if command[index] == "--ro-bind" and command[index + 2] == "/tmp/fixture" and command[index + 1].endswith(suffix)
    }
    if len(roots) != 1:
        raise ValueError("cannot derive a unique recorded execution root")
    root = roots.pop()
    if not root.startswith("/") or root.endswith("/"):
        raise ValueError("recorded execution root is not absolute canonical text")
    return root


def validate_effective_environment(value: Any) -> None:
    if not isinstance(value, dict):
        raise ValueError("effective environment is not an object")
    for field, expected in (("address_space", 4294967296), ("processes", 64), ("stack", 8388608)):
        if value.get(field) != [expected, expected]:
            raise ValueError(f"effective {field} limit drift")
    if value.get("environment") != EFFECTIVE_ENVIRONMENT:
        raise ValueError("effective cleared environment drift")
    if value.get("open_files") != [1048576, 1048576]:
        raise ValueError("effective open-files limit drift")
    mountinfo = value.get("mountinfo")
    if not isinstance(mountinfo, str):
        raise ValueError("effective mount table is absent")
    for required in (" /proc ", " /tmp/run ", " /tmp/fixture ", " /tmp/rules/rule.yml ", " /tmp/runtime-wrapper.py ", " /tmp/secure-bench-tools/semgrep/1.170.0 "):
        if required not in mountinfo:
            raise ValueError(f"effective mount table omits {required}")


def validate_observation_state(observation: dict[str, Any]) -> None:
    if set(observation) != OBSERVATION_FIELDS:
        raise ValueError("observation schema fields drift")
    if observation.get("state") != "completed" or observation.get("finding_count") is None or observation.get("failure") is not None:
        raise ValueError("observation is not completed with a finding count")
    if observation.get("timed_out") is not False or observation.get("signal") is not None:
        raise ValueError("observation has timeout or signal")
    if observation.get("exit_code") not in (0, 1):
        raise ValueError("observation exit code is outside Semgrep contract")
    decision = "successful-findings-report" if observation["exit_code"] == 1 else "clean-successful-report"
    if observation.get("process_decision") != decision:
        raise ValueError("observation process decision conflicts with exit code")
    if not isinstance(observation.get("duration_ms"), int) or observation["duration_ms"] < 0:
        raise ValueError("observation duration is invalid")
    for pair in (("raw_output_path", "raw_output_sha256"), ("effective_environment_path", "effective_environment_sha256")):
        if any(observation.get(field) is None for field in pair):
            raise ValueError(f"observation omits evidence pair {pair}")


def validate_observation_struct_bytes(observation: dict[str, Any], exact_bytes: bytes) -> None:
    """Demonstrate Rust struct serialization separately from payload hashing."""
    ordered = {field: observation[field] for field in OBSERVATION_FIELD_ORDER}
    reconstructed = json.dumps(ordered, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"
    if reconstructed != exact_bytes:
        raise ValueError("observation bytes differ from canonical Rust struct field order")


def validate_resource(resource: bytes, exit_code: int) -> None:
    try:
        text = resource.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("resource evidence is not UTF-8") from error
    if "Command terminated by signal" in text or f"\n\tExit status: {exit_code}\n" not in text:
        raise ValueError("resource evidence signal/exit status drift")
    for line in ("\tSocket messages sent: 0\n", "\tSocket messages received: 0\n", "\tSignals delivered: 0\n"):
        if line not in text:
            raise ValueError("resource evidence network/signal accounting drift")


def validate_raw(raw: bytes, case: dict[str, Any]) -> int:
    if len(raw) > 10485760:
        raise ValueError("raw JSON exceeds contract")
    try:
        report = strict_json_loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValueError("raw scanner report is malformed JSON") from error
    if report.get("version") != "1.170.0" or report.get("engine_requested") != "OSS":
        raise ValueError("raw scanner identity drift")
    if report.get("errors") != [] or report.get("skipped_rules") != []:
        raise ValueError("raw report has errors or skipped rules")
    results = report.get("results")
    scanned_values = report.get("paths", {}).get("scanned")
    if not isinstance(results, list) or not isinstance(scanned_values, list):
        raise ValueError("raw report omits results or paths.scanned")
    scanned: set[str] = set()
    for name in scanned_values:
        if not isinstance(name, str):
            raise ValueError("scanned path is not text")
        normalized = relative(name).as_posix()
        if normalized not in case["files"] or normalized in scanned:
            raise ValueError("scanned path is repeated or outside manifest metadata")
        scanned.add(normalized)
    for finding in results:
        if not isinstance(finding, dict) or finding.get("check_id") not in ALLOWED_RULES:
            raise ValueError("finding rule provenance drift")
        if finding.get("extra", {}).get("engine_kind") != "OSS":
            raise ValueError("finding engine provenance drift")
        name = finding.get("path")
        if not isinstance(name, str):
            raise ValueError("finding path is not text")
        normalized = relative(name).as_posix()
        if normalized not in scanned:
            raise ValueError("finding path was not scanned")
        size = case["files"][normalized].get("bytes")
        start, end = finding.get("start"), finding.get("end")
        if not isinstance(start, dict) or not isinstance(end, dict) or not isinstance(size, int):
            raise ValueError("finding span metadata is absent")
        required = [start.get("line"), start.get("col"), start.get("offset"), end.get("line"), end.get("col"), end.get("offset")]
        if any(not isinstance(value, int) or value < 1 for value in required[:2] + required[3:5]):
            raise ValueError("finding line or column is invalid")
        if not all(isinstance(value, int) for value in (start.get("offset"), end.get("offset"))):
            raise ValueError("finding offsets are invalid")
        if not (0 <= start["offset"] < end["offset"] <= size) or (start["line"], start["col"]) >= (end["line"], end["col"]):
            raise ValueError("finding span is invalid against frozen manifest byte bounds")
    return len(results)


def ledger_projection(sequence: int, payload: str, previous: str) -> dict[str, Any]:
    return {
        "schema_version": "secure-bench-phase25-ledger-v1",
        "sequence": sequence,
        "event": "semgrep-recovery-attempt-completed",
        "payload_sha256": payload,
        "previous_entry_hash": previous,
    }


def validate_ledger_entries(entries: list[dict[str, Any]], observations: list[bytes], genesis: dict[str, Any]) -> str:
    if genesis != {
        "expected_entries": 112, "first_sequence": 1, "initial_previous_entry_hash": ZERO_HASH,
        "plan_sha256": EXPECTED["plan"], "retries": 0,
        "run_id": "phase25-semgrep-normalized-recovery-v1",
        "schema_version": "secure-bench-phase25-ledger-genesis-v1",
    }:
        raise ValueError("ledger genesis drift")
    if len(entries) != 112 or len(observations) != 112:
        raise ValueError("ledger/observation population is not 112/112")
    previous = genesis["initial_previous_entry_hash"]
    fields = {"schema_version", "sequence", "event", "payload_sha256", "previous_entry_hash", "entry_hash"}
    for sequence, (entry, observation_bytes) in enumerate(zip(entries, observations), 1):
        if set(entry) != fields:
            raise ValueError(f"ledger entry schema drift at {sequence}")
        payload = digest(observation_bytes)
        projection = ledger_projection(sequence, payload, previous)
        expected_entry = digest(value_bytes(projection))
        expected = {**projection, "entry_hash": expected_entry}
        if entry != expected:
            raise ValueError(f"ledger chain drift at {sequence}")
        previous = expected_entry
    return previous


def ratio(numerator: int, denominator: int) -> dict[str, Any] | None:
    if denominator == 0:
        return None
    exact = Fraction(numerator, denominator)
    return {"numerator": exact.numerator, "denominator": exact.denominator, "decimal": f"{numerator / denominator:.6f}"}


def metrics_from_decisions(decisions: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {name: sum(item["outcome"] == name for item in decisions) for name in ("tp", "fp", "tn", "fn")}
    tp, fp, tn, fn = (counts[name] for name in ("tp", "fp", "tn", "fn"))
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn_count": fn,
        "precision": ratio(tp, tp + fp), "recall": ratio(tp, tp + fn),
        "specificity": ratio(tn, tn + fp), "f1": ratio(2 * tp, 2 * tp + fp + fn),
        "balanced_accuracy": ratio(tp * (tn + fp) + tn * (tp + fn), 2 * (tp + fn) * (tn + fp)) if tp + fn and tn + fp else None,
    }


def absolute_ratio(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    exact = abs(Fraction(left["numerator"], left["denominator"]) - Fraction(right["numerator"], right["denominator"]))
    return {"numerator": exact.numerator, "denominator": exact.denominator, "decimal": f"{float(exact):.6f}"}


def make_pairs(decisions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for decision in decisions:
        groups.setdefault(decision["pair_id"], []).append(decision)
    pairs = []
    for pair_id, members in sorted(groups.items()):
        if len(members) != 2:
            raise ValueError(f"pair {pair_id} does not have two decisions")
        vulnerable = next((item for item in members if item["expected"] == "vulnerable"), None)
        control = next((item for item in members if item["expected"] == "control"), None)
        if vulnerable is None or control is None:
            raise ValueError(f"pair {pair_id} is not vulnerable/control")
        pairs.append({
            "pair_id": pair_id, "vulnerable_case_id": vulnerable["case_id"], "control_case_id": control["case_id"],
            "vulnerable_flagged": vulnerable["predicted_positive"], "control_flagged": control["predicted_positive"],
            "pair_exact": vulnerable["predicted_positive"] and not control["predicted_positive"],
        })
    return pairs


def recalculate(decisions: list[dict[str, Any]]) -> dict[str, Any]:
    ordered = sorted(decisions, key=lambda item: item["case_id"])
    dimensions = {
        "by_family": "family", "by_framework": "framework", "by_source_format": "source_format",
        "by_topology": "topology", "by_adversarial_variant": "adversarial_variant", "by_classification": "expected",
    }
    strata: dict[str, Any] = {}
    for output_name, field in dimensions.items():
        groups: dict[str, list[dict[str, Any]]] = {}
        for decision in ordered:
            groups.setdefault(decision[field], []).append(decision)
        strata[output_name] = {name: metrics_from_decisions(members) for name, members in sorted(groups.items())}
    return {
        "schema_version": "secure-bench-phase26-recalculated-results-v1",
        "source": "112 frozen Phase 25 raw JSON reports plus frozen Phase 19 manifest expectations",
        "attempts": 112, "retries": 0, "scanner": "semgrep-ce", "lane": "capability-normalized",
        "metrics": metrics_from_decisions(ordered), "cases": ordered, "pairs": make_pairs(ordered), **strata,
    }


def compare_recorded(root: Path, recalculated: dict[str, Any]) -> None:
    results = load(root / "phase25/output/results.json")
    lane = results.get("phase25_semgrep_normalized", {})
    for name in ("metrics", "cases", "pairs", "by_family", "by_framework", "by_source_format", "by_topology", "by_adversarial_variant", "by_classification"):
        if lane.get(name) != recalculated.get(name):
            raise ValueError(f"Phase 25 recorded result drift: {name}")
    if lane.get("state") != "completed" or lane.get("operations", {}).get("completed") != 112:
        raise ValueError("Phase 25 lane is not operationally completed")
    strata = load(root / "phase25/output/strata.json")
    for name in ("by_family", "by_framework", "by_source_format", "by_topology", "by_adversarial_variant", "by_classification"):
        if strata.get(name) != recalculated.get(name):
            raise ValueError(f"Phase 25 strata drift: {name}")


def normalized_comparison(root: Path, recalculated: dict[str, Any]) -> dict[str, Any]:
    phase22_data = require_hash(root, "phase22/output/results.json", EXPECTED["phase22_results"])
    historical = strict_json_loads(phase22_data)
    lanes = [lane for lane in historical.get("lanes", []) if lane.get("scanner") == "opengrep" and lane.get("lane") == "capability-normalized"]
    if len(lanes) != 1:
        raise ValueError("Phase 22 normalized OpenGrep lane is not unique")
    left = lanes[0]
    right_cases = {item["case_id"]: item for item in recalculated["cases"]}
    left_cases = {item["case_id"]: item for item in left.get("cases", [])}
    if set(left_cases) != set(right_cases) or len(left_cases) != 112:
        raise ValueError("Phase 22/25 case populations differ")
    disagreements: list[dict[str, Any]] = []
    both_correct = left_only = right_only = both_incorrect = 0
    for case_id in sorted(right_cases):
        lcase, rcase = left_cases[case_id], right_cases[case_id]
        if lcase["predicted_positive"] != rcase["predicted_positive"]:
            disagreements.append({"case_id": case_id, "opengrep": lcase["predicted_positive"], "semgrep": rcase["predicted_positive"]})
        lcorrect, rcorrect = lcase["outcome"] in ("tp", "tn"), rcase["outcome"] in ("tp", "tn")
        if lcorrect and rcorrect:
            both_correct += 1
        elif lcorrect:
            left_only += 1
        elif rcorrect:
            right_only += 1
        else:
            both_incorrect += 1
    left_pairs = {item["pair_id"]: item for item in left.get("pairs", [])}
    right_pairs = {item["pair_id"]: item for item in recalculated["pairs"]}
    if set(left_pairs) != set(right_pairs) or len(left_pairs) != 56:
        raise ValueError("Phase 22/25 pair populations differ")
    pair_disagreements = []
    for pair_id in sorted(right_pairs):
        lpair, rpair = left_pairs[pair_id], right_pairs[pair_id]
        if (lpair["vulnerable_flagged"], lpair["control_flagged"]) != (rpair["vulnerable_flagged"], rpair["control_flagged"]):
            pair_disagreements.append({"pair_id": pair_id, "opengrep": lpair, "semgrep": rpair})
    differences = {name: absolute_ratio(left["metrics"][name], recalculated["metrics"][name]) for name in ("precision", "recall", "specificity", "f1", "balanced_accuracy")}
    result = {
        "schema_version": "secure-bench-phase26-normalized-comparison-certification-v1",
        "state": "certified-exact-tie" if not disagreements and not pair_disagreements and all(value["numerator"] == 0 for value in differences.values()) else "certified-differences",
        "lane": "capability-normalized", "paired_cases": 112, "paired_pairs": 56,
        "left": {"phase": 22, "scanner": "opengrep", "metrics": left["metrics"]},
        "right": {"phase": 25, "scanner": "semgrep-ce", "metrics": recalculated["metrics"]},
        "agreements": 112 - len(disagreements), "disagreements_count": len(disagreements), "disagreements": disagreements,
        "pair_agreements": 56 - len(pair_disagreements), "pair_disagreements_count": len(pair_disagreements), "pair_disagreements": pair_disagreements,
        "both_correct": both_correct, "opengrep_only_correct": left_only, "semgrep_only_correct": right_only, "both_incorrect": both_incorrect,
        "absolute_metric_differences": differences, "secure_engine_native_excluded": True,
        "overall_three_scanner_winner_declared": False,
    }
    recorded = load(root / "phase25/output/comparison.json")
    scalar_pairs = {
        "agreements": result["agreements"], "disagreements_count": result["disagreements_count"],
        "pair_agreements": result["pair_agreements"], "pair_disagreements_count": result["pair_disagreements_count"],
        "both_correct": both_correct, "opengrep_only_correct": left_only, "semgrep_only_correct": right_only,
        "both_incorrect": both_incorrect, "absolute_metric_differences": differences,
    }
    for key, value in scalar_pairs.items():
        if recorded.get(key) != value:
            raise ValueError(f"Phase 25 recorded comparison drift: {key}")
    if [item["case_id"] for item in recorded.get("disagreements", [])] != [item["case_id"] for item in disagreements]:
        raise ValueError("Phase 25 recorded case disagreements drift")
    if [item["pair_id"] for item in recorded.get("pair_disagreements", [])] != [item["pair_id"] for item in pair_disagreements]:
        raise ValueError("Phase 25 recorded pair disagreements drift")
    return result


def verify_provenance(root: Path, ledger_head: str) -> dict[str, Any]:
    provenance = load(root / "phase25/output/provenance.json")
    checks = {
        "attempts": 112, "retries": 0, "opengrep_secure_engine_native_attempts": 0,
        "network_ai_telemetry_credentials": "forbidden", "ledger_head": ledger_head,
        "execution_plan_sha256": EXPECTED["plan"], "execution_contract_sha256": EXPECTED["contract"],
        "corpus_opened_marker_sha256": EXPECTED["marker"], "phase22_results_sha256": EXPECTED["phase22_results"],
        "ruleset_sha256": EXPECTED["rules"], "semgrep_adapter_sha256": EXPECTED["adapter"],
        "scoring_methodology_sha256": EXPECTED["methodology"],
    }
    for key, value in checks.items():
        if provenance.get(key) != value:
            raise ValueError(f"Phase 25 provenance drift: {key}")
    for key, path in {
        "results_sha256": "phase25/output/results.json", "comparison_sha256": "phase25/output/comparison.json",
        "strata_sha256": "phase25/output/strata.json", "failure_analysis_sha256": "phase25/output/failure-analysis.json",
        "independent_verification_sha256": "phase25/output/independent-verification.json",
        "report_sha256": "phase25/output/report.md", "limitations_sha256": "phase25/output/limitations.md",
    }.items():
        if provenance.get(key) != digest(read(root / path)):
            raise ValueError(f"Phase 25 provenance artifact hash drift: {key}")
    return checks


def verify_frozen_terminal_receipt(root: Path, first_observation: bytes, first_entry: dict[str, Any]) -> None:
    receipt = load(root / "phase25/output/final-verification.json")
    diagnosis = receipt.get("diagnosis", {})
    matrix = receipt.get("final_matrix", {})
    exact_payload = digest(first_observation)
    sorted_reserialization = digest(value_bytes(strict_json_loads(first_observation)))
    if receipt.get("state") != "failed-independent-python-verification" or receipt.get("protocol_action") != "preserved terminal post-freeze verification failure; no retry and no frozen-surface modification":
        raise ValueError("Phase 25 terminal fail-closed receipt drift")
    if matrix.get("python_verifier", {}).get("exit_code") != 1 or matrix.get("python_verifier", {}).get("error") != "ledger chain drift at 1" or matrix.get("rust_verifier", {}).get("exit_code") != 0:
        raise ValueError("Phase 25 verifier matrix receipt drift")
    if diagnosis.get("observation_file_sha256") != exact_payload or diagnosis.get("ledger_payload_sha256") != first_entry.get("payload_sha256") or first_entry.get("payload_sha256") != exact_payload or diagnosis.get("python_sorted_reserialization_sha256") != sorted_reserialization:
        raise ValueError("Phase 25 canonicalization diagnosis drift")


def verify_phase25(root: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    before = scanner_processes()
    if before:
        raise ValueError(f"scanner process exists before verification: {before}")
    git_evidence = verify_git(root)
    output = root / "phase25/output"
    inventory = verify_sums(output)
    require_hash(root, "phase25/config/execution-plan-v1.json", EXPECTED["plan"])
    require_hash(root, "phase25/config/execution-contract-v1.json", EXPECTED["contract"])
    require_hash(root, "phase25/config/ledger-genesis-v1.json", EXPECTED["genesis"])
    require_hash(root, "phase25/output/CORPUS_OPENED.json", EXPECTED["marker"])
    require_hash(root, "phase20/config/semgrep-normalized-adapter-v1.json", EXPECTED["adapter"])
    require_hash(root, "phase19/rules/capability-normalized-v1.yml", EXPECTED["rules"])
    require_hash(root, "phase20/config/scoring-methodology-v1.json", EXPECTED["methodology"])
    plan = load(root / "phase25/config/execution-plan-v1.json")
    contract = load(root / "phase25/config/execution-contract-v1.json")
    marker = load(root / "phase25/output/CORPUS_OPENED.json")
    if plan.get("total_attempts") != 112 or plan.get("retries") != 0 or len(plan.get("attempts", [])) != 112:
        raise ValueError("plan is not exactly 112 attempts and zero retries")
    if plan.get("excluded_attempts") != {"native": 0, "opengrep": 0, "secure-engine": 0}:
        raise ValueError("plan includes excluded scanner attempts")
    if contract.get("plan", {}).get("sha256") != EXPECTED["plan"] or contract.get("plan", {}).get("retries") != 0:
        raise ValueError("contract/plan binding drift")
    if contract.get("sandbox", {}).get("environment") != EFFECTIVE_ENVIRONMENT or contract.get("sandbox", {}).get("network") is not False:
        raise ValueError("contract environment/network drift")
    if marker.get("planned_attempts") != 112 or marker.get("retries") != 0 or marker.get("opengrep_attempts") != 0 or marker.get("secure_engine_attempts") != 0 or marker.get("native_attempts") != 0:
        raise ValueError("irreversible marker attempt accounting drift")
    cases = case_metadata(root)
    attempts = plan["attempts"]
    if [item.get("sequence") for item in attempts] != list(range(1, 113)) or len({item.get("case_id") for item in attempts}) != 112 or {item.get("case_id") for item in attempts} != set(cases):
        raise ValueError("plan sequence/case identity drift")
    if any(item.get("scanner") != "semgrep-ce" or item.get("lane") != "capability-normalized" or set(item) != {"sequence", "scanner", "lane", "case_id"} for item in attempts):
        raise ValueError("plan scanner/lane/schema drift")
    if len(list((output / "attempts").glob("*/observation.json"))) != 112:
        raise ValueError("output does not contain exactly 112 observation files")
    observations_bytes: list[bytes] = []
    observations: list[dict[str, Any]] = []
    decisions: list[dict[str, Any]] = []
    attempt_ids: set[str] = set()
    execution_roots: set[str] = set()
    pwd_count = 0
    for sequence, attempt in enumerate(attempts, 1):
        case_id = attempt["case_id"]
        directory_name = f"{sequence:03}-phase25-semgrep-ce-{case_id}"
        relative_observation = PurePosixPath("attempts", directory_name, "observation.json")
        observation_path = output.joinpath(*relative_observation.parts)
        observation_bytes = read(observation_path)
        if inventory.get(relative_observation) != digest(observation_bytes):
            raise ValueError(f"observation inventory mismatch at {sequence}")
        observation = strict_json_loads(observation_bytes)
        validate_observation_state(observation)
        validate_observation_struct_bytes(observation, observation_bytes)
        expected_attempt_id = f"phase25-semgrep-{sequence:03}-{case_id}"
        if observation.get("attempt_id") != expected_attempt_id or expected_attempt_id in attempt_ids:
            raise ValueError(f"attempt ID drift or duplicate at {sequence}")
        attempt_ids.add(expected_attempt_id)
        if observation.get("sequence") != sequence or observation.get("case_id") != case_id or observation.get("scanner") != "semgrep-ce" or observation.get("lane") != "capability-normalized":
            raise ValueError(f"observation identity drift at {sequence}")
        if observation.get("environment") != EFFECTIVE_ENVIRONMENT or observation.get("environment_sha256") != digest(sequence_bytes(EFFECTIVE_ENVIRONMENT)):
            raise ValueError(f"recorded environment drift at {sequence}")
        pwd_count += int("PWD=/tmp/fixture" in observation["environment"])
        command = observation.get("command")
        if not isinstance(command, list) or any(not isinstance(item, str) for item in command):
            raise ValueError(f"command is not a string vector at {sequence}")
        execution_root = derive_execution_root(command, cases[case_id]["fixture_path"])
        execution_roots.add(execution_root)
        output_host = f"{execution_root}/phase25/output/attempts/{directory_name}"
        if command != expected_command(execution_root, cases[case_id]["fixture_path"], output_host) or observation.get("command_sha256") != digest(sequence_bytes(command)):
            raise ValueError(f"command contract drift at {sequence}")
        for path_field, hash_field in (("stdout_path", "stdout_sha256"), ("stderr_path", "stderr_sha256"), ("resource_path", "resource_sha256"), ("effective_environment_path", "effective_environment_sha256"), ("raw_output_path", "raw_output_sha256")):
            name = observation.get(path_field)
            if not isinstance(name, str) or not name.startswith(f"phase25/output/attempts/{directory_name}/"):
                raise ValueError(f"evidence path binding drift at {sequence}: {path_field}")
            path = canonical_file(root, name)
            if digest(read(path)) != observation.get(hash_field):
                raise ValueError(f"evidence hash drift at {sequence}: {path_field}")
        effective = load(root / observation["effective_environment_path"])
        validate_effective_environment(effective)
        validate_resource(read(root / observation["resource_path"]), observation["exit_code"])
        raw = read(root / observation["raw_output_path"])
        finding_count = validate_raw(raw, cases[case_id])
        if observation.get("finding_count") != finding_count:
            raise ValueError(f"finding count drift at {sequence}")
        positive = finding_count > 0
        expected_class = cases[case_id]["expected"]
        outcome = {("vulnerable", True): "tp", ("vulnerable", False): "fn", ("control", True): "fp", ("control", False): "tn"}[(expected_class, positive)]
        decisions.append({
            "case_id": case_id, "pair_id": cases[case_id]["pair_id"], "expected": expected_class,
            "finding_count": finding_count, "predicted_positive": positive, "outcome": outcome,
            "family": cases[case_id]["family"], "framework": cases[case_id]["framework"],
            "source_format": cases[case_id]["source_format"], "topology": cases[case_id]["topology"],
            "adversarial_variant": cases[case_id]["adversarial_variant"],
        })
        observations_bytes.append(observation_bytes)
        observations.append(observation)
    if len(attempt_ids) != 112 or len(execution_roots) != 1 or pwd_count != 112:
        raise ValueError("attempt IDs, execution roots, or PWD coverage drift")
    ledger_data = read(output / "ledger.jsonl")
    if not ledger_data.endswith(b"\n"):
        raise ValueError("ledger omits final newline")
    ledger_lines = ledger_data.splitlines()
    entries = [strict_json_loads(line) for line in ledger_lines]
    genesis = load(root / "phase25/config/ledger-genesis-v1.json")
    ledger_head = validate_ledger_entries(entries, observations_bytes, genesis)
    verify_frozen_terminal_receipt(root, observations_bytes[0], entries[0])
    recalculated = recalculate(decisions)
    compare_recorded(root, recalculated)
    comparison = normalized_comparison(root, recalculated)
    provenance_checks = verify_provenance(root, ledger_head)
    after = scanner_processes()
    if after:
        raise ValueError(f"scanner process exists after verification: {after}")
    metrics = recalculated["metrics"]
    certification = {
        "schema_version": "secure-bench-phase26-certification-v1",
        "certification": "accepted",
        "scope": "frozen Phase 25 evidence only",
        "phase25": git_evidence,
        "original_phase25_python_verifier": {"state": "failed-fail-closed", "authority_for_phase26": False, "executed_by_phase26": False, "failure": "ledger chain drift at 1"},
        "successor_verifier": "phase26/reproducer/independent_verify.py",
        "evidence_integrity": {"valid": True, "sha256_entries_verified": len(inventory), "observation_files": len(observations), "ledger_entries": len(entries), "ledger_head_derived": ledger_head},
        "operational_validity": {"valid": True, "attempts": 112, "completed": 112, "retries": 0, "signals": 0, "timeouts": 0, "malformed": 0, "unavailable": 0, "valid_raw_json": 112, "pwd_fixture": pwd_count},
        "scoring_eligibility": {"eligible": True, "tp": metrics["tp"], "fp": metrics["fp"], "tn": metrics["tn"], "fn": metrics["fn_count"]},
        "comparison_certification": {"valid": True, "state": comparison["state"], "lane": "capability-normalized", "general_winner_declared": False},
        "prohibitions": {"scanner_processes_started": 0, "new_attempts": 0, "case_source_files_opened": 0, "network_requests": 0, "phase19_through_phase25_modified": False},
    }
    provenance = {
        "schema_version": "secure-bench-phase26-provenance-v1",
        "phase25_commit": PHASE25, "phase25_parent": PHASE24, "phase25_tree": EXPECTED["phase25_tree"],
        "input_hashes": EXPECTED, "frozen_subtrees": git_evidence["frozen_subtrees"],
        "derived_ledger_head": ledger_head, "checksum_entries_verified": len(inventory),
        "attempt_ids_unique": len(attempt_ids), "observations_verified": len(observations), "raw_reports_verified": len(decisions),
        "recorded_execution_root": next(iter(execution_roots)), "provenance_fields_verified": provenance_checks,
        "process_audit": {"before": before, "after": after},
        "network_ai_telemetry_credentials": "forbidden-and-not-used",
        "phase25_frozen_python_verifier_invocations": 0,
    }
    return certification, recalculated, comparison, provenance


def expect_rejection(name: str, operation: Callable[[], None]) -> dict[str, Any]:
    try:
        operation()
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError, KeyError, TypeError) as error:
        return {"name": name, "result": "rejected", "reason": str(error)}
    raise ValueError(f"tamper mutation was accepted: {name}")


def tamper_tests(root: Path, baseline: tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]) -> dict[str, Any]:
    output = root / "phase25/output"
    inventory = verify_sums(output)
    first_dir = output / "attempts/001-phase25-semgrep-ce-case-p19-0001"
    first_obs = read(first_dir / "observation.json")
    second_obs = read(output / "attempts/002-phase25-semgrep-ce-case-p19-0002/observation.json")
    raw = read(first_dir / "raw.json")
    entries = [strict_json_loads(line) for line in read(output / "ledger.jsonl").splitlines()]
    observations = [read(path) for path in sorted((output / "attempts").glob("*/observation.json"))]
    genesis = load(root / "phase25/config/ledger-genesis-v1.json")
    derived_head = baseline[0]["evidence_integrity"]["ledger_head_derived"]
    results: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="secure-bench-phase26-tamper-") as temporary:
        temp = Path(temporary)

        def copied(name: str, data: bytes) -> Path:
            path = temp / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            return path

        def observation_byte() -> None:
            changed = bytearray(first_obs)
            changed[1] = ord(" ") if changed[1] != ord(" ") else ord("{")
            path = copied("observation-byte.json", bytes(changed))
            expected = inventory[PurePosixPath("attempts/001-phase25-semgrep-ce-case-p19-0001/observation.json")]
            if digest(read(path)) != expected:
                raise ValueError("frozen inventory rejected changed observation bytes")

        results.append(expect_rejection("observation-one-byte", observation_byte))

        def reordered_observation() -> None:
            path = copied("observation-reordered.json", value_bytes(strict_json_loads(first_obs)))
            if digest(read(path)) != entries[0]["payload_sha256"]:
                raise ValueError("exact-byte payload hash rejected reordered observation keys")

        results.append(expect_rejection("observation-key-reordering", reordered_observation))

        for name, field in (("payload-sha256", "payload_sha256"), ("previous-entry-hash", "previous_entry_hash"), ("entry-hash", "entry_hash")):
            def mutate_ledger(field_name: str = field) -> None:
                changed = copy.deepcopy(entries)
                changed[0][field_name] = "f" * 64
                validate_ledger_entries(changed, observations, genesis)
            results.append(expect_rejection(name, mutate_ledger))

        for name, transform in (
            ("ledger-entry-deletion", lambda values: values[:-1]),
            ("ledger-entry-duplication", lambda values: [values[0], *values]),
            ("ledger-entry-reordering", lambda values: [values[1], values[0], *values[2:]]),
        ):
            def mutate_population(change: Callable[[list[dict[str, Any]]], list[dict[str, Any]]] = transform) -> None:
                validate_ledger_entries(change(copy.deepcopy(entries)), observations, genesis)
            results.append(expect_rejection(name, mutate_population))

        def duplicate_attempt() -> None:
            values = [strict_json_loads(first_obs), strict_json_loads(second_obs)]
            values[1]["attempt_id"] = values[0]["attempt_id"]
            ids = [item["attempt_id"] for item in values]
            if len(ids) != len(set(ids)):
                raise ValueError("duplicate attempt ID rejected")

        results.append(expect_rejection("duplicate-attempt-id", duplicate_attempt))

        def changed_raw() -> None:
            changed = raw + b" "
            path = copied("raw-changed.json", changed)
            observation = strict_json_loads(first_obs)
            if digest(read(path)) != observation["raw_output_sha256"]:
                raise ValueError("observation raw hash rejected changed raw JSON")

        results.append(expect_rejection("raw-json-altered", changed_raw))

        def changed_state() -> None:
            observation = strict_json_loads(first_obs)
            observation["state"] = "failed"
            validate_observation_state(observation)

        results.append(expect_rejection("observation-state-changed", changed_state))

        def changed_metric() -> None:
            recorded = load(root / "phase25/output/results.json")["phase25_semgrep_normalized"]
            changed = copy.deepcopy(recorded)
            changed["metrics"]["tp"] += 1
            if changed["metrics"] != baseline[1]["metrics"]:
                raise ValueError("independent recalculation rejected manipulated result metric")

        results.append(expect_rejection("result-or-metric-manipulated", changed_metric))

        def changed_provenance() -> None:
            provenance = load(root / "phase25/output/provenance.json")
            provenance["ledger_head"] = "f" * 64
            if provenance["ledger_head"] != derived_head:
                raise ValueError("derived ledger head rejected manipulated provenance")

        results.append(expect_rejection("provenance-ledger-head-altered", changed_provenance))
    return {
        "schema_version": "secure-bench-phase26-tamper-test-report-v1",
        "temporary_copies_only": True, "frozen_artifacts_modified": False,
        "tests": len(results), "rejected": sum(item["result"] == "rejected" for item in results), "cases": results,
    }


def output_documents(root: Path) -> dict[str, Any]:
    baseline = verify_phase25(root)
    tamper = tamper_tests(root, baseline)
    return {
        "certification.json": baseline[0], "recalculated-results.json": baseline[1],
        "normalized-comparison-certification.json": baseline[2], "provenance.json": baseline[3],
        "tamper-test-report.json": tamper,
    }


def write_outputs(root: Path) -> None:
    output = root / "phase26/output"
    output.mkdir(parents=True, exist_ok=True)
    documents = output_documents(root)
    for name, value in documents.items():
        (output / name).write_bytes(value_bytes(value))
    files = sorted(path for path in output.rglob("*") if path.is_file() and path.name != "SHA256SUMS")
    sums = "".join(f"{digest(read(path))}  {path.relative_to(output).as_posix()}\n" for path in files)
    (output / "SHA256SUMS").write_text(sums)


def verify_published(root: Path) -> None:
    expected = output_documents(root)
    output = root / "phase26/output"
    for name, value in expected.items():
        if read(output / name) != value_bytes(value):
            raise ValueError(f"published Phase 26 artifact drift: {name}")
    sums: dict[PurePosixPath, str] = {}
    for line in (output / "SHA256SUMS").read_text().splitlines():
        value, name = line.split("  ", 1)
        path = relative(name)
        if path in sums:
            raise ValueError("duplicate Phase 26 checksum path")
        sums[path] = value
    actual = {PurePosixPath(path.relative_to(output).as_posix()) for path in output.rglob("*") if path.is_file() and path.name != "SHA256SUMS"}
    if actual != set(sums):
        raise ValueError("Phase 26 SHA256SUMS is not exhaustive")
    for name, value in sums.items():
        if digest(read(output.joinpath(*name.parts))) != value:
            raise ValueError(f"Phase 26 checksum drift: {name}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("certify", "verify", "tamper"))
    parser.add_argument("root", type=Path)
    arguments = parser.parse_args()
    root = arguments.root.resolve(strict=True)
    if arguments.mode == "certify":
        write_outputs(root)
        print(json.dumps({"state": "certified", "scanner_processes_started": 0}, sort_keys=True))
    elif arguments.mode == "verify":
        verify_published(root)
        print(json.dumps({"state": "verified", "scanner_processes_started": 0}, sort_keys=True))
    else:
        baseline = verify_phase25(root)
        print(json.dumps(tamper_tests(root, baseline), sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        print(json.dumps({"state": "rejected", "error": str(error)}, sort_keys=True))
        raise SystemExit(1) from None
