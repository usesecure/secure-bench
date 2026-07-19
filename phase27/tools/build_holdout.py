#!/usr/bin/env python3
"""Deterministically materialize the Phase 27 clean-restart holdout."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import shutil
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent
DESIGN_PATH = ROOT / "preregistration" / "design-v2.json"
CORPUS = ROOT / "corpus"
CONTRACTS = ROOT / "contracts"
MANIFEST = ROOT / "manifest-v2.json"

FRAMEWORKS = ["node", "express", "next-app-router", "server-actions"]
FORMATS = ["javascript", "jsx", "typescript", "tsx"]
TOPOLOGIES = ["direct", "helper-mediated", "inter-file-aliased", "control-flow-sensitive"]
EXTENSIONS = {"javascript": "js", "jsx": "jsx", "typescript": "ts", "tsx": "tsx"}
VARIANTS = [
    "aliasing",
    "destructuring",
    "wrappers",
    "misleading-names-comments",
    "mutable-allowlists",
    "non-dominating-guards",
    "caught-exceptions",
    "blocklists",
    "suffix-tricks",
    "ambiguous-helpers",
]

FAMILIES = [
    ("SE1001", "secure-bench.category.command-execution", "secure-bench.invariant.command-control-data-separation", "CWE-78", "os-command-execution"),
    ("SE1002", "secure-bench.category.sql-construction", "secure-bench.invariant.sql-control-data-separation", "CWE-89", "sql-query-execution"),
    ("SE1003", "secure-bench.category.filesystem-boundary", "secure-bench.invariant.filesystem-path-confinement", "CWE-22", "filesystem-read"),
    ("SE1004", "secure-bench.category.outbound-request-boundary", "secure-bench.invariant.outbound-destination-policy", "CWE-918", "outbound-request"),
    ("SE1005", "secure-bench.category.redirect-boundary", "secure-bench.invariant.redirect-destination-policy", "CWE-601", "redirect-response"),
    ("SE1006", "secure-bench.category.dynamic-code-execution", "secure-bench.invariant.dynamic-code-control-data-separation", "CWE-95", "dynamic-code-evaluation"),
    ("SE1007", "secure-bench.category.authorization-dominance", "secure-bench.invariant.authorization-before-sensitive-operation", "CWE-862", "protected-record-mutation"),
]


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def derive(seed: bytes, label: str) -> str:
    return hmac.new(seed, label.encode(), hashlib.sha256).hexdigest()


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


def source_lines(framework: str, typed: bool) -> list[str]:
    if framework in {"node", "express"}:
        return [
            'const incomingValue = req.query?.probe ?? req.body?.probe ?? "";',
            "const payloadToken = String(incomingValue);",
        ]
    if framework == "next-app-router":
        return [
            "const packet = await request.json();",
            'const payloadToken = String(packet.probe ?? "");',
        ]
    annotation = ": FormData" if typed else ""
    return [f"const payloadToken = String(formData.get(\"probe\") ?? \"\");"]


def handler_signature(framework: str, typed: bool) -> str:
    if framework == "node":
        return "export async function acceptEnvelope(req: any, res: any) {" if typed else "export async function acceptEnvelope(req, res) {"
    if framework == "express":
        return "export async function inspectParcel(req: any, res: any) {" if typed else "export async function inspectParcel(req, res) {"
    if framework == "next-app-router":
        return "export async function POST(request: Request) {" if typed else "export async function POST(request) {"
    return "export async function submitParcel(formData: FormData) {" if typed else "export async function submitParcel(formData) {"


def normal_return(framework: str) -> list[str]:
    if framework in {"node", "express"}:
        return ["res.status?.(204);", "return res.end?.();"]
    if framework == "next-app-router":
        return ["return new Response(null, { status: 204 });"]
    return ["return { accepted: true };"]


def imports_for(family: str) -> list[str]:
    if family == "SE1001":
        return ['import { execFileSync } from "node:child_process";']
    if family == "SE1003":
        return [
            'import { readFile } from "node:fs/promises";',
            'import { resolve, sep } from "node:path";',
        ]
    return []


def variant_lines(variant: str) -> tuple[list[str], str]:
    if variant == "aliasing":
        return ["const transitValue = payloadToken;"], "transitValue"
    if variant == "destructuring":
        return ["const { signal: transitValue } = { signal: payloadToken };"], "transitValue"
    if variant == "wrappers":
        return ["const relayValue = (value) => value;", "const transitValue = relayValue(payloadToken);"], "transitValue"
    if variant == "misleading-names-comments":
        return ["// Upstream validation is advisory and does not establish safety.", "const approvedLookingValue = payloadToken;"], "approvedLookingValue"
    if variant == "mutable-allowlists":
        return [
            'const tentativeDestinations = ["api.example.invalid"];',
            'tentativeDestinations.push("preview.example.invalid");',
            "const transitValue = payloadToken;",
        ], "transitValue"
    if variant == "non-dominating-guards":
        return [
            'if (payloadToken.length === 0) console.warn("empty candidate");',
            "const transitValue = payloadToken;",
        ], "transitValue"
    if variant == "caught-exceptions":
        return [
            'try { if (!payloadToken) throw new Error("candidate rejected"); } catch { /* compatibility path */ }',
            "const transitValue = payloadToken;",
        ], "transitValue"
    if variant == "blocklists":
        return ['const transitValue = payloadToken.replace("../", "");'], "transitValue"
    if variant == "suffix-tricks":
        return [
            'const suffixApproved = payloadToken.endsWith(".example.invalid");',
            "void suffixApproved;",
            "const transitValue = payloadToken;",
        ], "transitValue"
    return [
        "const maybeAcceptable = (value) => value.length < 4096;",
        "const advisoryDecision = maybeAcceptable(payloadToken);",
        "void advisoryDecision;",
        "const transitValue = payloadToken;",
    ], "transitValue"


def operation_lines(family: str, safe: bool, value: str) -> tuple[list[str], str, str | None]:
    if family == "SE1001":
        if safe:
            return [f'execFileSync("/usr/bin/printf", ["%s", {value}], {{ shell: false }});'], "execFileSync(", "shell: false"
        return [f'execFileSync("/bin/sh", ["-c", "printf %s " + {value}]);'], "execFileSync(", None
    if family == "SE1002":
        if safe:
            return [f'await database.query("SELECT note FROM journal WHERE slug = ?", [{value}]);'], "database.query(", "slug = ?"
        return [f'await database.query("SELECT note FROM journal WHERE slug = \'" + {value} + "\'");'], "database.query(", None
    if family == "SE1003":
        if safe:
            return [
                'const archiveRoot = resolve("/srv/ledger");',
                f"const candidatePath = resolve(archiveRoot, {value});",
                "if (!candidatePath.startsWith(archiveRoot + sep)) throw new Error(\"outside archive\");",
                'await readFile(candidatePath, "utf8");',
            ], "await readFile(", "candidatePath.startsWith"
        return [f'await readFile(resolve("/srv/ledger", {value}), "utf8");'], "await readFile(", None
    if family == "SE1004":
        if safe:
            return [
                f"const destination = new URL({value});",
                'if (destination.protocol !== "https:" || destination.hostname !== "api.example.invalid" || destination.port) throw new Error("destination denied");',
                "await fetch(destination);",
            ], "await fetch(", "destination.hostname"
        return [f"await fetch({value});"], "await fetch(", None
    if family == "SE1005":
        if safe:
            return [
                f'const destination = new URL({value}, "https://app.example.invalid");',
                'if (destination.origin !== "https://app.example.invalid") throw new Error("redirect denied");',
                "return Response.redirect(destination.pathname + destination.search + destination.hash, 303);",
            ], "Response.redirect(", "destination.origin"
        return [f"return Response.redirect({value}, 303);"], "Response.redirect(", None
    if family == "SE1006":
        if safe:
            return [f"const decodedData = JSON.parse({value});", "Object.freeze(decodedData);"], "JSON.parse(", "JSON.parse("
        return [f'Function("return (" + {value} + ")")();'], "Function(", None
    if safe:
        return [
            "const principal = await requirePrincipal();",
            f"const protectedRecord = await records.load({value});",
            'if (!protectedRecord || protectedRecord.tenantId !== principal.tenantId || protectedRecord.ownerId !== principal.userId) throw new Error("forbidden");',
            "const stableResourceId = protectedRecord.id;",
            'await records.update({ id: stableResourceId, tenantId: principal.tenantId, ownerId: principal.userId }, { state: "approved" });',
        ], "records.update(", "protectedRecord.tenantId"
    return [
        f"const requesterClaimedActor = {value};",
        'if (requesterClaimedActor) console.info("actor supplied");',
        f'await records.update({{ id: {value} }}, {{ state: "approved" }});',
    ], "records.update(", None


def indent(lines: list[str], width: int = 2) -> list[str]:
    prefix = " " * width
    return [prefix + line for line in lines]


def render_case(
    family: str,
    framework: str,
    source_format: str,
    topology: str,
    variant: str,
    safe: bool,
    ticket: str,
) -> tuple[dict[str, str], str, str, str | None]:
    typed = source_format in {"typescript", "tsx"}
    jsx = source_format in {"jsx", "tsx"}
    extension = EXTENSIONS[source_format]
    header = [
        "/* Neutral Secure Bench fixture. It is data and is never executed during Phase 27. */",
        f'const fixtureTicket = "{ticket}";',
        "void fixtureTicket;",
    ]
    source = source_lines(framework, typed)
    variant_code, flow = variant_lines(variant)
    operation, sink_needle, barrier_needle = operation_lines(family, safe, flow if topology != "direct" else flow)
    flow_sensitive = []
    if topology == "control-flow-sensitive":
        flow_sensitive = (
            [f'if ({flow}.length === 0) throw new Error("empty input");']
            if safe
            else [f'if ({flow}.length === 0) console.warn("candidate retained");']
        )
    jsx_line = [f'const inspectionBadge = <output data-ticket="{ticket[:12]}">{{payloadToken.length}}</output>;', "void inspectionBadge;"] if jsx else []
    signature = handler_signature(framework, typed)

    if topology == "inter-file-aliased":
        entry = header + [f'import {{ forwardSignal as settleParcel }} from "./policy.{extension}";', "", signature]
        entry += indent(source + jsx_line + variant_code)
        call = [f"return await settleParcel({flow});"] if family == "SE1005" else [f"await settleParcel({flow});"] + normal_return(framework)
        entry += indent(call) + ["", "}"]
        policy = imports_for(family) + ["", "export async function forwardSignal(candidate) {"]
        policy += indent(flow_sensitive + operation) + ["}"]
        return {
            f"entry.{extension}": "\n".join(entry).strip() + "\n",
            f"policy.{extension}": "\n".join(policy).strip() + "\n",
        }, sink_needle, f"policy.{extension}", barrier_needle

    imports = imports_for(family)
    entry = imports + ([""] if imports else []) + header + ["", signature]
    entry += indent(source + jsx_line + variant_code)
    if topology == "helper-mediated":
        call = [f"return await completeParcel({flow});"] if family == "SE1005" else [f"await completeParcel({flow});"] + normal_return(framework)
        entry += indent(call) + ["", "}", "", "async function completeParcel(candidate) {"]
        helper_operation, sink_needle, barrier_needle = operation_lines(family, safe, "candidate")
        entry += indent(helper_operation) + ["}"]
    else:
        entry += indent(flow_sensitive + operation)
        if family != "SE1005":
            entry += indent(normal_return(framework))
        entry += ["}"]
    return {f"entry.{extension}": "\n".join(entry).strip() + "\n"}, sink_needle, f"entry.{extension}", barrier_needle


def locate(text: str, needle: str) -> dict[str, int]:
    for number, line in enumerate(text.splitlines(), start=1):
        column = line.find(needle)
        if column >= 0:
            return {
                "start_line": number,
                "start_column": column + 1,
                "end_line": number,
                "end_column": column + len(needle) + 1,
            }
    raise ValueError(f"needle not found: {needle}")


def build_contract() -> dict[str, Any]:
    return {
        "schema_version": "secure-bench-evidence-contract-v2",
        "contract_version": "2.0.0",
        "taxonomy": {
            "schema_version": "secure-bench-taxonomy-v1",
            "taxonomy_version": "1.0.0",
            "artifact_sha256": sha256((REPO / "taxonomy" / "secure-bench-taxonomy-v1.json").read_bytes()),
            "content_hash": "22852bd7401020b315af11dfa2b60c0b46f78eb19f95079e6400d7b3bea3272c",
        },
        "source_semantic_kinds": ["http-query-value", "http-body-field", "form-data-value", "protected-resource-id"],
        "sink_semantic_kinds": [item[4] for item in FAMILIES],
        "location_rules": {"exact_normalized_file": True, "exact_span": True, "bidirectional_containment": True, "maximum_containment_lines": 2},
        "path_rules": {"source_before_sink": True, "connected_hops": True, "summarizable_nodes_only": True, "helper_summary_preserves_endpoints": True},
        "barrier_rules": {"guard_requires_terminating_failure": True, "sanitizer_requires_semantic_effect": True, "authorization_binds_operation": True, "effective_barrier_blocks_match": True},
        "partial_rules": {"taxonomy_and_endpoints_required": True, "unresolved_call_is_partial": True, "uncertainty_is_partial": True, "detection_credit": False},
        "duplicate_rules": {"semantic_fields_only": True, "exclude_prose": True, "exclude_tool_and_rule_identity": True, "duplicate_credit": False},
        "non_scoring_fields": ["rule_id", "tool_identity", "message", "severity", "prose"],
    }


def main() -> None:
    design = json.loads(DESIGN_PATH.read_text(encoding="utf-8"))
    if design["pre_authoring_counts"] != {"pairs": 0, "cases": 0, "scanner_executions": 0, "case_executions": 0}:
        raise SystemExit("pre-authoring freeze is not pristine")
    seed = bytes.fromhex(design["seed"]["hex"])
    if CORPUS.exists():
        raise SystemExit("refusing to overwrite an existing corpus")

    contract = build_contract()
    write_json(CONTRACTS / "evidence-contract-v2.json", contract)
    contract_hash = sha256((CONTRACTS / "evidence-contract-v2.json").read_bytes())
    cases: list[dict[str, Any]] = []
    pairs: list[dict[str, Any]] = []

    for family_index, family_data in enumerate(FAMILIES):
        family, category, invariant, cwe, sink_kind = family_data
        for slot in range(8):
            framework = FRAMEWORKS[slot % 4]
            source_format = FORMATS[(slot + family_index) % 4]
            topology = TOPOLOGIES[(slot + 2 * family_index + slot // 4) % 4]
            orientation = "vulnerable-first" if (family_index + slot) % 2 == 0 else "control-first"
            variant = VARIANTS[(family_index * 8 + slot) % len(VARIANTS)]
            pair_digest = derive(seed, f"pair/{family}/{slot}/{framework}/{source_format}/{topology}/{variant}")
            pair_id = f"orbit-{family.lower()}-{pair_digest[:14]}"
            labels = ["vulnerable", "control"] if orientation == "vulnerable-first" else ["control", "vulnerable"]
            pair_cases: list[str] = []

            for order, label in enumerate(labels, start=1):
                safe = label == "control"
                case_digest = derive(seed, f"case/{pair_id}/{label}")
                case_id = f"aurora-{case_digest[:18]}"
                ticket = f"ticket-{case_digest[18:34]}"
                case_dir = CORPUS / family / pair_id / f"{order:02d}-{label}-{case_id}"
                sources, sink_needle, sink_name, barrier_needle = render_case(
                    family, framework, source_format, topology, variant, safe, ticket
                )
                for name, text in sources.items():
                    path = case_dir / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(text, encoding="utf-8")

                source_name = next(name for name, text in sources.items() if "const payloadToken" in text)
                source_span = locate(sources[source_name], "const payloadToken")
                sink_span = locate(sources[sink_name], sink_needle)
                barrier_span = locate(sources[sink_name], barrier_needle) if barrier_needle else None
                source_kind = "form-data-value" if framework == "server-actions" else ("http-body-field" if framework == "next-app-router" else "http-query-value")
                if family == "SE1007":
                    source_kind = "protected-resource-id"

                source_records = []
                for name in sorted(sources):
                    data = sources[name].encode()
                    source_records.append({"path": name, "sha256": sha256(data), "bytes": len(data)})
                exact_payload = [{"path": item["path"], "content": sources[item["path"]]} for item in source_records]
                exact_fingerprint = sha256(canonical(exact_payload))
                normalized_payload = {
                    "family": family,
                    "framework": framework,
                    "source_format": source_format,
                    "topology": topology,
                    "variant": variant,
                    "label": label,
                    "sources": [{"path": name, "content": normalized_text(sources[name])} for name in sorted(sources)],
                }
                normalized_fingerprint = sha256(canonical(normalized_payload))
                source_node = {"role": "source", "effect": "preserves-influence", "source_kind": source_kind, "sink_kind": None, "file": source_name, **source_span}
                sink_node = {"role": "sink", "effect": "preserves-influence", "source_kind": None, "sink_kind": sink_kind, "file": sink_name, **sink_span}
                expected_finding = None
                control_proof = None
                if safe:
                    control_proof = {
                        "status": "effective-barrier-dominates-sink",
                        "barrier": {"role": "barrier", "effect": "authorizes-operation" if family == "SE1007" else "constrains-to-policy", "file": sink_name, **(barrier_span or sink_span)},
                        "sink": sink_node,
                    }
                else:
                    expected_finding = {"path": [source_node, sink_node], "connected_edges": [True], "effective_barriers": [], "unresolved_call": False, "uncertain": False}
                metadata = {
                    "schema_version": "secure-bench-phase27-case-v2",
                    "case_id": case_id,
                    "pair_id": pair_id,
                    "label": label,
                    "family_id": family,
                    "framework": framework,
                    "source_format": source_format,
                    "topology": topology,
                    "orientation": orientation,
                    "adversarial_variant": variant,
                    "fixture_ticket": ticket,
                    "source_files": source_records,
                    "exact_fingerprint": exact_fingerprint,
                    "normalized_fingerprint": normalized_fingerprint,
                    "evidence_contract_v2": {
                        "contract_path": "phase27/contracts/evidence-contract-v2.json",
                        "contract_sha256": contract_hash,
                        "contract_version": "2.0.0",
                        "taxonomy": {"version": "1.0.0", "category_id": category, "invariant_id": invariant, "primary_cwe": cwe},
                        "expected_outcome": label,
                        "expected_finding": expected_finding,
                        "control_proof": control_proof,
                    },
                }
                metadata_path = case_dir / "case.json"
                write_json(metadata_path, metadata)
                relative_metadata = metadata_path.relative_to(REPO).as_posix()
                cases.append({
                    "case_id": case_id,
                    "pair_id": pair_id,
                    "label": label,
                    "family_id": family,
                    "framework": framework,
                    "source_format": source_format,
                    "topology": topology,
                    "orientation": orientation,
                    "adversarial_variant": variant,
                    "metadata_path": relative_metadata,
                    "metadata_sha256": sha256(metadata_path.read_bytes()),
                    "exact_fingerprint": exact_fingerprint,
                    "normalized_fingerprint": normalized_fingerprint,
                })
                pair_cases.append(case_id)
            pairs.append({
                "pair_id": pair_id,
                "family_id": family,
                "framework": framework,
                "source_format": source_format,
                "topology": topology,
                "orientation": orientation,
                "adversarial_variant": variant,
                "case_ids_in_orientation_order": pair_cases,
            })

    exacts = [case["exact_fingerprint"] for case in cases]
    normalized = [case["normalized_fingerprint"] for case in cases]
    if len(set(exacts)) != 112 or len(set(normalized)) != 112:
        raise SystemExit("fingerprint uniqueness failed")
    manifest = {
        "schema_version": "secure-bench-phase27-manifest-v2",
        "phase": 27,
        "holdout_id": design["holdout_id"],
        "status": "authored-unfrozen",
        "authoritative_base": design["authoritative_base"],
        "design_sha256": sha256(DESIGN_PATH.read_bytes()),
        "seed_sha256": sha256(seed),
        "contract_sha256": contract_hash,
        "pair_count": len(pairs),
        "case_count": len(cases),
        "vulnerable_count": Counter(item["label"] for item in cases)["vulnerable"],
        "control_count": Counter(item["label"] for item in cases)["control"],
        "pairs": pairs,
        "cases": sorted(cases, key=lambda item: item["case_id"]),
        "aggregate_exact_fingerprint": sha256(canonical(sorted(exacts))),
        "aggregate_normalized_fingerprint": sha256(canonical(sorted(normalized))),
        "scanner_executions": 0,
        "case_executions": 0,
    }
    write_json(MANIFEST, manifest)
    print(json.dumps({"pairs": len(pairs), "cases": len(cases), "manifest": MANIFEST.relative_to(REPO).as_posix(), "aggregate_exact": manifest["aggregate_exact_fingerprint"], "aggregate_normalized": manifest["aggregate_normalized_fingerprint"]}, sort_keys=True))


if __name__ == "__main__":
    main()
