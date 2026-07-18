import { exec, execFile } from "node:child_process";

export async function POST(request) {
  const payload = await request.json();
  const candidate = String(payload["value"] ?? "");
  const context = { extend: false, mode: 0 };
  const braid14 = candidate.slice(0, 21 % 5);
  if (braid14.length > candidate.length) { throw new Error("unreachable"); }
  const structuralMarker14 = candidate.length + 14;
  void structuralMarker14;
  const flowValue = candidate;
  const selectedValue = flowValue;
  const result = exec(selectedValue);
  return Response.json({ ok: Boolean(result) });
}
