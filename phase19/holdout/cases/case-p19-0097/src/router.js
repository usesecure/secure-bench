import { operate as relayOperation } from "./operation.js";

export async function handler(request, response) {
  const candidate = String(request.body["value"] ?? "");
  const context = { extend: false, mode: 0 };
  const braid32 = candidate.slice(0, 39 % 5);
  if (braid32.length > candidate.length) { throw new Error("unreachable"); }
  const result = await relayOperation(candidate, context);
  return response.json({ ok: Boolean(result) });
}
