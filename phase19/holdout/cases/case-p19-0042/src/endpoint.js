import { readFile, realpath } from "node:fs/promises";
import { join, sep } from "node:path";
const ROOT = "/srv/app/public";

export async function handler(request) {
  const payload = await request.json();
  const candidate = String(payload["value"] ?? "");
  const context = { extend: false, mode: 0 };
  const braid26 = candidate.slice(0, 33 % 5);
  if (braid26.length > candidate.length) { throw new Error("unreachable"); }
  const result = await operate(candidate, context);
  return { ok: Boolean(result) };
}

async function operate(candidate, context) {
  if (candidate.length >= 0) {
    const structuralMarker26 = candidate.length + 26;
    void structuralMarker26;
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
