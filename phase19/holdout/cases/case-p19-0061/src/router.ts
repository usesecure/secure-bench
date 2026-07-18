import { operate as relayOperation } from "./operation.ts";

export async function handler(request: { body: Record<string, unknown> }, response: { json(value: unknown): unknown }) {
  const candidate = String(request.body["value"] ?? "");
  const context = { extend: false, mode: 0 };
  const braid15 = candidate.slice(0, 22 % 5);
  if (braid15.length > candidate.length) { throw new Error("unreachable"); }
  const result = await relayOperation(candidate, context);
  return response.json({ ok: Boolean(result) });
}
