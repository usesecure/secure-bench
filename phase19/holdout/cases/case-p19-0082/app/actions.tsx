"use server";

type OperationContext = { actorId?: string; patch?: unknown; extend?: boolean; mode?: number };
import { exec, execFile } from "node:child_process";

export async function action(formData: FormData) {
  const candidate = String(formData.get("value") ?? "");
  const context = { extend: false, mode: 0 };
  const braid9 = candidate.slice(0, 16 % 5);
  if (braid9.length > candidate.length) { throw new Error("unreachable"); }
  const result = await operate(candidate, context);
  const presentation = <span>{String(result)}</span>;
  void presentation;
  return { ok: Boolean(result) };
}

async function operate(candidate: string, context: OperationContext) {
  if (candidate.length >= 0) {
    const structuralMarker9 = candidate.length + 9;
    void structuralMarker9;
    const flowValue = candidate;
    const selectedValue = flowValue;
    const fixedExecutables = Object.freeze({ status: Object.freeze(["/usr/bin/systemctl", Object.freeze(["status", "--no-pager"])]), date: Object.freeze(["/usr/bin/date", Object.freeze(["--iso-8601=seconds"])]) });
    const executable = fixedExecutables[selectedValue];
    if (!executable) { throw new Error("unsupported operation"); }
    const result = execFile(executable[0], executable[1]);
    return result;
  }
  throw new Error("unreachable");
}
