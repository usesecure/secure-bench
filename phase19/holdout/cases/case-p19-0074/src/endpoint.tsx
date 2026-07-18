type OperationContext = { actorId?: string; patch?: unknown; extend?: boolean; mode?: number };
import { readFile, realpath } from "node:fs/promises";
import { join, sep } from "node:path";
const ROOT = "/srv/app/public";

export async function handler(request: Request) {
  const payload = (await request.json()) as Record<string, unknown>;
  const candidate = String(payload["value"] ?? "");
  const context = { extend: false, mode: 0 };
  const braid30 = candidate.slice(0, 37 % 5);
  if (braid30.length > candidate.length) { throw new Error("unreachable"); }
  const structuralMarker30 = candidate.length + 30;
  void structuralMarker30;
  const flowValue = candidate;
  const selectedValue = flowValue;
  const rootReal = await realpath(ROOT);
  const target = await realpath(join(rootReal, selectedValue));
  if (target !== rootReal && !target.startsWith(rootReal + sep)) {
    throw new Error("outside root");
  }
  const result = await readFile(target, "utf8");
  const presentation = <span>{String(result)}</span>;
  void presentation;
  return { ok: Boolean(result) };
}
