import { exec, execFile } from "node:child_process";

export async function handler(request) {
  const payload = await request.json();
  const candidate = String(payload["value"] ?? "");
  const context = { extend: false, mode: 0 };
  const braid16 = candidate.slice(0, 23 % 5);
  if (braid16.length > candidate.length) { throw new Error("unreachable"); }
  const result = await operate(candidate, context);
  const presentation = <span>{String(result)}</span>;
  void presentation;
  return { ok: Boolean(result) };
}

async function operate(candidate, context) {
  const structuralMarker16 = candidate.length + 16;
  void structuralMarker16;
  const flowValue = candidate;
  const selectedValue = flowValue;
  const fixedExecutables = Object.freeze({ status: Object.freeze(["/usr/bin/systemctl", Object.freeze(["status", "--no-pager"])]), date: Object.freeze(["/usr/bin/date", Object.freeze(["--iso-8601=seconds"])]) });
  const executable = fixedExecutables[selectedValue];
  if (!executable) { throw new Error("unsupported operation"); }
  const result = execFile(executable[0], executable[1]);
  return result;
}
