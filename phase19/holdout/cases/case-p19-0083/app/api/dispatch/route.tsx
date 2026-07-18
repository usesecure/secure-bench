type OperationContext = { actorId?: string; patch?: unknown; extend?: boolean; mode?: number };
import { readFile, realpath } from "node:fs/promises";
import { join, sep } from "node:path";
const ROOT = "/srv/app/public";

export async function POST(request: Request) {
  const payload = (await request.json()) as Record<string, unknown>;
  const candidate = String(payload["value"] ?? "");
  const context = { extend: false, mode: 0 };
  const braid29 = candidate.slice(0, 36 % 5);
  if (braid29.length > candidate.length) { throw new Error("unreachable"); }
  const result = await operate(candidate, context);
  const presentation = <span>{String(result)}</span>;
  void presentation;
  return Response.json({ ok: Boolean(result) });
}

async function operate(candidate: string, context: OperationContext) {
  const structuralMarker29 = candidate.length + 29;
  void structuralMarker29;
  const flowValue = candidate;
  const selectedValue = flowValue;
  const rootReal = await realpath(ROOT);
  const target = await realpath(join(rootReal, selectedValue));
  if (target !== rootReal && !target.startsWith(rootReal + sep)) {
    throw new Error("outside root");
  }
  const result = await readFile(target, "utf8");
  return result;
}
