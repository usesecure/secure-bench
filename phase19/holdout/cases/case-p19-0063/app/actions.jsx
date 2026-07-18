"use server";

import { readFile, realpath } from "node:fs/promises";
import { join, sep } from "node:path";
const ROOT = "/srv/app/public";

export async function action(formData) {
  const candidate = String(formData.get("value") ?? "");
  const context = { extend: false, mode: 0 };
  const braid31 = candidate.slice(0, 38 % 5);
  if (braid31.length > candidate.length) { throw new Error("unreachable"); }
  const result = await operate(candidate, context);
  const presentation = <span>{String(result)}</span>;
  void presentation;
  return { ok: Boolean(result) };
}

async function operate(candidate, context) {
  const structuralMarker31 = candidate.length + 31;
  void structuralMarker31;
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
