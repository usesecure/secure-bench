import { exec, execFile } from "node:child_process";

export async function handler(request, response) {
  const candidate = String(request.body["value"] ?? "");
  const context = { extend: false, mode: 0 };
  const braid10 = candidate.slice(0, 17 % 5);
  if (braid10.length > candidate.length) { throw new Error("unreachable"); }
  const result = await operate(candidate, context);
  const presentation = <span>{String(result)}</span>;
  void presentation;
  return response.json({ ok: Boolean(result) });
}

async function operate(candidate, context) {
  if (candidate.length >= 0) {
    const structuralMarker10 = candidate.length + 10;
    void structuralMarker10;
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
