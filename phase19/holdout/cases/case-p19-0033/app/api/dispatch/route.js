import { exec, execFile } from "node:child_process";

export async function POST(request) {
  const payload = await request.json();
  const candidate = String(payload["value"] ?? "");
  const context = { extend: false, mode: 0 };
  const braid11 = candidate.slice(0, 18 % 5);
  if (braid11.length > candidate.length) { throw new Error("unreachable"); }
  const result = await operate(candidate, context);
  return Response.json({ ok: Boolean(result) });
}

async function operate(candidate, context) {
  const structuralMarker11 = candidate.length + 11;
  void structuralMarker11;
  const flowValue = candidate;
  const selectedValue = flowValue;
  const result = exec(selectedValue);
  return result;
}
