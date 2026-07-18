import { operate as relayOperation } from "./operation.tsx";

export async function handler(request: { body: Record<string, unknown> }, response: { json(value: unknown): unknown }) {
  const candidate = String(request.body["value"] ?? "");
  const context = { extend: false, mode: 0 };
  const braid19 = candidate.slice(0, 26 % 5);
  if (braid19.length > candidate.length) { throw new Error("unreachable"); }
  const result = await relayOperation(candidate, context);
  const presentation = <span>{String(result)}</span>;
  void presentation;
  return response.json({ ok: Boolean(result) });
}
