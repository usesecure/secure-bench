import { readFile, realpath } from "node:fs/promises";
import { join, sep } from "node:path";
const ROOT = "/srv/app/public";

export async function POST(request) {
  const payload = await request.json();
  const candidate = String(payload["value"] ?? "");
  const context = { extend: false, mode: 0 };
  const braid28 = candidate.slice(0, 35 % 5);
  if (braid28.length > candidate.length) { throw new Error("unreachable"); }
  const structuralMarker28 = candidate.length + 28;
  void structuralMarker28;
  const flowValue = candidate;
  const selectedValue = flowValue;
  const target = join(ROOT, selectedValue);
  const result = await readFile(target, "utf8");
  const presentation = <span>{String(result)}</span>;
  void presentation;
  return Response.json({ ok: Boolean(result) });
}
