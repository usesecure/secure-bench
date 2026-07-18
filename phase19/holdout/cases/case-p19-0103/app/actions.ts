"use server";

type OperationContext = { actorId?: string; patch?: unknown; extend?: boolean; mode?: number };
import { readFile, realpath } from "node:fs/promises";
import { join, sep } from "node:path";
const ROOT = "/srv/app/public";

export async function action(formData: FormData) {
  const candidate = String(formData.get("value") ?? "");
  const context = { extend: false, mode: 0 };
  const braid25 = candidate.slice(0, 32 % 5);
  if (braid25.length > candidate.length) { throw new Error("unreachable"); }
  const result = await operate(candidate, context);
  return { ok: Boolean(result) };
}

async function operate(candidate: string, context: OperationContext) {
  if (candidate.length >= 0) {
    const structuralMarker25 = candidate.length + 25;
    void structuralMarker25;
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
  throw new Error("unreachable");
}
