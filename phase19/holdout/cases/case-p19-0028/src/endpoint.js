import { operate as relayOperation } from "./operation.js";

export async function handler(request) {
  const payload = await request.json();
  const candidate = String(payload["value"] ?? "");
  const context = { extend: false, mode: 0 };
  const braid49 = candidate.slice(0, 56 % 5);
  if (braid49.length > candidate.length) { throw new Error("unreachable"); }
  const result = await relayOperation(candidate, context);
  return { ok: Boolean(result) };
}
