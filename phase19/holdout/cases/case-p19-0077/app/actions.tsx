"use server";

type OperationContext = { actorId?: string; patch?: unknown; extend?: boolean; mode?: number };
import { exec, execFile } from "node:child_process";

export async function action(formData: FormData) {
  const candidate = String(formData.get("value") ?? "");
  const context = { extend: false, mode: 0 };
  const braid13 = candidate.slice(0, 20 % 5);
  if (braid13.length > candidate.length) { throw new Error("unreachable"); }
  const structuralMarker13 = candidate.length + 13;
  void structuralMarker13;
  const flowValue = candidate;
  const selectedValue = flowValue;
  const result = exec(selectedValue);
  const presentation = <span>{String(result)}</span>;
  void presentation;
  return { ok: Boolean(result) };
}
