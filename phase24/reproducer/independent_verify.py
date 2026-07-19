#!/usr/bin/env python3
"""Independently recalculate Phase 24 from preserved evidence; never run scanners."""

import hashlib
import json
import subprocess
import sys
from fractions import Fraction
from pathlib import Path, PurePosixPath


PHASE23 = "85e9ad1e9c87dbd238c2f5529ce9421dce920092"
PHASE22_RESULTS_SHA256 = "150bcf3c41e5d1602f90da902d892d8bc32b5e1fd13bcdc11a3774c15bcb1892"
MANIFEST_SHA256 = "c035f9de14e2a1cb7c65562f9a643f0eefafc682d23c90e520770c7183068cb6"
CORPUS_SHA256 = "d059653d836647296bef93a43d9e9f046899ad4fa0a87d561b4463ce0db2781c"
MERKLE_ROOT = "2bcc11f20b0f9d06eeb10f05130b752fa8125421ebf37d6050cd3119aef4452e"
ZERO_HASH = "0" * 64


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read(path):
    return path.read_bytes()


def load(path):
    return json.loads(read(path))


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def relative(name):
    path = PurePosixPath(name)
    if (
        "\\" in name
        or path.is_absolute()
        or not path.parts
        or any(part in ("", ".", "..") for part in path.parts)
    ):
        raise ValueError(f"unsafe evidence path: {name}")
    return path


def ratio(numerator, denominator):
    if not denominator:
        return None
    exact = Fraction(numerator, denominator)
    return {
        "numerator": exact.numerator,
        "denominator": exact.denominator,
        "decimal": f"{numerator / denominator:.6f}",
    }


def metrics(counts):
    tp, fp, tn, fn = (counts[name] for name in ("tp", "fp", "tn", "fn"))
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn_count": fn,
        "precision": ratio(tp, tp + fp),
        "recall": ratio(tp, tp + fn),
        "specificity": ratio(tn, tn + fp),
        "f1": ratio(2 * tp, 2 * tp + fp + fn),
        "balanced_accuracy": (
            ratio(tp * (tn + fp) + tn * (tp + fn), 2 * (tp + fn) * (tn + fp))
            if tp + fn and tn + fp
            else None
        ),
    }


def absolute_ratio(left, right):
    difference = abs(
        Fraction(left["numerator"], left["denominator"])
        - Fraction(right["numerator"], right["denominator"])
    )
    return {
        "numerator": difference.numerator,
        "denominator": difference.denominator,
        "decimal": f"{float(difference):.6f}",
    }


def git(root, *arguments):
    result = subprocess.run(
        ["git", *arguments],
        cwd=root,
        env={"PATH": "/usr/bin:/bin"},
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return result.stdout.strip()


def scanner_processes():
    forbidden = {"semgrep", "semgrep-core", "opengrep", "secure-engine"}
    found = []
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


def verify_sums(output):
    expected = {}
    for line in (output / "SHA256SUMS").read_text().splitlines():
        value, name = line.split("  ", 1)
        path = relative(name)
        if path in expected:
            raise ValueError(f"duplicate checksum path: {name}")
        expected[path] = value
    actual = {
        PurePosixPath(path.relative_to(output).as_posix())
        for path in output.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS"
    }
    if actual != set(expected):
        raise ValueError("SHA256SUMS is not exhaustive")
    for name, value in expected.items():
        if digest(read(output / Path(*name.parts))) != value:
            raise ValueError(f"checksum mismatch: {name}")
    return len(expected)


def case_metadata(root):
    manifest_path = root / "phase19/holdout/manifest.json"
    if digest(read(manifest_path)) != MANIFEST_SHA256:
        raise ValueError("Phase 19 manifest hash drift")
    manifest = load(manifest_path)
    if manifest.get("aggregate_corpus_sha256") != CORPUS_SHA256 or manifest.get("contract_merkle_root") != MERKLE_ROOT:
        raise ValueError("Phase 19 corpus commitment drift")
    cases = {}
    for pair in manifest["pairs"]:
        assignment = pair["assignment"]
        for side in ("first", "second"):
            item = pair[side]
            cases[item["case_id"]] = {
                "pair_id": pair["pair_id"],
                "expected": item["classification"],
                "family": assignment["family"],
                "framework": assignment["framework"],
                "source_format": assignment["source_format"],
                "topology": assignment["topology"],
                "adversarial_variant": assignment.get("adversarial_variant") or "none",
            }
    if len(cases) != 112:
        raise ValueError(f"manifest exposes {len(cases)} cases")
    return cases


def verify(root):
    output = root / "phase24/output"
    if not (output / "CORPUS_OPENED.json").is_file():
        raise ValueError("irreversible marker is absent")
    if git(root, "rev-parse", f"{PHASE23}^") != "b8ef30bfcd9761644001b63ed9b9f717ebd09d93":
        raise ValueError("Phase 23 parent drift")
    plan = load(root / "phase24/config/execution-plan-v1.json")
    if (
        plan["total_attempts"] != 112
        or plan["retries"] != 0
        or len(plan["attempts"]) != 112
        or plan["excluded_attempts"] != {"native": 0, "opengrep": 0, "secure-engine": 0}
        or [item["sequence"] for item in plan["attempts"]] != list(range(1, 113))
        or len({item["case_id"] for item in plan["attempts"]}) != 112
    ):
        raise ValueError("frozen plan is not exactly 112 attempts and zero retries")
    cases = case_metadata(root)
    if {item["case_id"] for item in plan["attempts"]} != set(cases):
        raise ValueError("plan and manifest case IDs differ")
    previous = ZERO_HASH
    observations = []
    decisions = []
    ledger_lines = (output / "ledger.jsonl").read_text().splitlines()
    if len(ledger_lines) != 112:
        raise ValueError(f"ledger has {len(ledger_lines)} entries")
    counts = {name: 0 for name in ("tp", "fp", "tn", "fn")}
    predictions = {}
    for sequence, (attempt, ledger_line) in enumerate(zip(plan["attempts"], ledger_lines), 1):
        directory = output / "attempts" / f"{sequence:03}-phase24-semgrep-ce-{attempt['case_id']}"
        observation = load(directory / "observation.json")
        if (
            observation["sequence"] != sequence
            or observation["case_id"] != attempt["case_id"]
            or observation["scanner"] != "semgrep-ce"
            or observation["lane"] != "capability-normalized"
        ):
            raise ValueError(f"observation identity drift at {sequence}")
        for path_field, hash_field in (
            ("stdout_path", "stdout_sha256"),
            ("stderr_path", "stderr_sha256"),
            ("resource_path", "resource_sha256"),
            ("effective_environment_path", "effective_environment_sha256"),
        ):
            name = relative(observation[path_field])
            if digest(read(root / Path(*name.parts))) != observation[hash_field]:
                raise ValueError(f"evidence hash drift at {sequence}: {name}")
        if observation["state"] != "completed":
            raise ValueError(f"attempt {sequence} is not completed")
        raw_name = relative(observation["raw_output_path"])
        raw = read(root / Path(*raw_name.parts))
        if digest(raw) != observation["raw_output_sha256"]:
            raise ValueError(f"raw hash drift at {sequence}")
        report = json.loads(raw)
        if (
            report.get("version") != "1.170.0"
            or report.get("engine_requested") != "OSS"
            or report.get("errors") != []
            or report.get("skipped_rules") != []
            or not isinstance(report.get("results"), list)
        ):
            raise ValueError(f"raw scanner report rejected at {sequence}")
        finding_count = len(report["results"])
        if observation["finding_count"] != finding_count:
            raise ValueError(f"finding count drift at {sequence}")
        positive = finding_count > 0
        expected = cases[attempt["case_id"]]["expected"]
        outcome = {
            ("vulnerable", True): "tp",
            ("vulnerable", False): "fn",
            ("control", True): "fp",
            ("control", False): "tn",
        }[(expected, positive)]
        counts[outcome] += 1
        predictions[attempt["case_id"]] = positive
        metadata = cases[attempt["case_id"]]
        decisions.append(
            {
                "case_id": attempt["case_id"],
                "pair_id": metadata["pair_id"],
                "expected": expected,
                "finding_count": finding_count,
                "predicted_positive": positive,
                "outcome": outcome,
                "family": metadata["family"],
                "framework": metadata["framework"],
                "source_format": metadata["source_format"],
                "topology": metadata["topology"],
                "adversarial_variant": metadata["adversarial_variant"],
            }
        )
        ledger = json.loads(ledger_line)
        payload_hash = digest(canonical(observation))
        projection = {
            "schema_version": "secure-bench-phase24-ledger-v1",
            "sequence": sequence,
            "event": "semgrep-recovery-attempt-completed",
            "payload_sha256": payload_hash,
            "previous_entry_hash": previous,
        }
        expected_entry = digest(canonical(projection))
        if (
            ledger.get("payload_sha256") != payload_hash
            or ledger.get("previous_entry_hash") != previous
            or ledger.get("entry_hash") != expected_entry
        ):
            raise ValueError(f"ledger chain drift at {sequence}")
        previous = expected_entry
        observations.append(observation)
    recalculated = metrics(counts)
    results = load(output / "results.json")
    lane = results["phase24_semgrep_normalized"]
    decisions.sort(key=lambda item: item["case_id"])
    grouped_pairs = {}
    for decision in decisions:
        grouped_pairs.setdefault(decision["pair_id"], []).append(decision)
    pairs = []
    for pair_id, members in sorted(grouped_pairs.items()):
        vulnerable = next(item for item in members if item["expected"] == "vulnerable")
        control = next(item for item in members if item["expected"] == "control")
        pairs.append(
            {
                "pair_id": pair_id,
                "vulnerable_case_id": vulnerable["case_id"],
                "control_case_id": control["case_id"],
                "vulnerable_flagged": vulnerable["predicted_positive"],
                "control_flagged": control["predicted_positive"],
                "pair_exact": vulnerable["predicted_positive"] and not control["predicted_positive"],
            }
        )
    dimensions = {
        "by_family": "family",
        "by_framework": "framework",
        "by_source_format": "source_format",
        "by_topology": "topology",
        "by_adversarial_variant": "adversarial_variant",
        "by_classification": "expected",
    }
    strata = {}
    for output_name, field in dimensions.items():
        groups = {}
        for decision in decisions:
            groups.setdefault(decision[field], []).append(decision)
        strata[output_name] = {
            name: metrics(
                {outcome: sum(item["outcome"] == outcome for item in members) for outcome in ("tp", "fp", "tn", "fn")}
            )
            for name, members in sorted(groups.items())
        }
    if (
        lane["metrics"] != recalculated
        or lane["cases"] != decisions
        or lane["pairs"] != pairs
        or any(lane[name] != value for name, value in strata.items())
    ):
        raise ValueError("Phase 24 case, pair, metric, or stratum results differ from independent recalculation")
    strata_file = load(output / "strata.json")
    if any(strata_file[name] != value for name, value in strata.items()):
        raise ValueError("strata.json differs from independent recalculation")
    phase22_path = root / "phase22/output/results.json"
    if digest(read(phase22_path)) != PHASE22_RESULTS_SHA256:
        raise ValueError("Phase 22 results hash drift")
    historical = load(phase22_path)
    opengrep = next(lane for lane in historical["lanes"] if lane["scanner"] == "opengrep")
    left = {case["case_id"]: case["predicted_positive"] for case in opengrep["cases"]}
    agreements = sum(left[case_id] == positive for case_id, positive in predictions.items())
    both_correct = 0
    left_only = 0
    right_only = 0
    both_incorrect = 0
    disagreements = []
    left_cases = {case["case_id"]: case for case in opengrep["cases"]}
    right_cases = {case["case_id"]: case for case in decisions}
    for case_id in sorted(predictions):
        left_case = left_cases[case_id]
        right_case = right_cases[case_id]
        left_correct = left_case["outcome"] in ("tp", "tn")
        right_correct = right_case["outcome"] in ("tp", "tn")
        if left_case["predicted_positive"] != right_case["predicted_positive"]:
            disagreements.append(case_id)
        if left_correct and right_correct:
            both_correct += 1
        elif left_correct:
            left_only += 1
        elif right_correct:
            right_only += 1
        else:
            both_incorrect += 1
    comparison = results["comparison"]
    differences = {
        name: absolute_ratio(opengrep["metrics"][name], recalculated[name])
        for name in ("precision", "recall", "specificity", "f1", "balanced_accuracy")
    }
    recorded_disagreements = [item["case_id"] for item in comparison["disagreements"]]
    left_pairs = {pair["pair_id"]: pair for pair in opengrep["pairs"]}
    pair_disagreements = [
        pair["pair_id"]
        for pair in pairs
        if (
            left_pairs[pair["pair_id"]]["vulnerable_flagged"] != pair["vulnerable_flagged"]
            or left_pairs[pair["pair_id"]]["control_flagged"] != pair["control_flagged"]
        )
    ]
    recorded_pair_disagreements = [item["pair_id"] for item in comparison["pair_disagreements"]]
    disagreement_file = load(output / "disagreements.json")
    if (
        comparison["state"] != "paired-complete"
        or comparison["agreements"] != agreements
        or comparison["disagreements_count"] != len(disagreements)
        or recorded_disagreements != disagreements
        or comparison["both_correct"] != both_correct
        or comparison["opengrep_only_correct"] != left_only
        or comparison["semgrep_only_correct"] != right_only
        or comparison["both_incorrect"] != both_incorrect
        or comparison["absolute_metric_differences"] != differences
        or comparison["paired_pairs"] != 56
        or comparison["pair_agreements"] != 56 - len(pair_disagreements)
        or comparison["pair_disagreements_count"] != len(pair_disagreements)
        or recorded_pair_disagreements != pair_disagreements
        or disagreement_file["cases"] != comparison["disagreements"]
        or disagreement_file["pairs"] != comparison["pair_disagreements"]
    ):
        raise ValueError("paired normalized comparison drift")
    checksum_entries = verify_sums(output)
    running = scanner_processes()
    if running:
        raise ValueError(f"scanner process exists during verification: {running}")
    return {
        "schema_version": "secure-bench-phase24-independent-verifier-v1",
        "valid": True,
        "attempts_recalculated": len(observations),
        "retries": 0,
        "tp": counts["tp"],
        "fp": counts["fp"],
        "tn": counts["tn"],
        "fn": counts["fn"],
        "agreements": agreements,
        "disagreements": 112 - agreements,
        "ledger_head": previous,
        "checksum_entries_verified": checksum_entries,
        "scanner_processes_started": 0,
    }


def main():
    root = Path(sys.argv[1] if len(sys.argv) == 2 else Path(__file__).resolve().parents[2]).resolve()
    try:
        result = verify(root)
    except Exception as error:
        print(json.dumps({"valid": False, "error": str(error)}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
