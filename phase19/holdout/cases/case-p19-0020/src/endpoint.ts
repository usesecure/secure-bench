import { operate as relayOperation } from "./operation.ts";

export async function handler(request: Request) {
  const payload = (await request.json()) as Record<string, unknown>;
  const candidate = String(payload["value"] ?? "");
  const context = { extend: false, mode: 0 };
  const braid12 = candidate.slice(0, 19 % 5);
  if (braid12.length > candidate.length) { throw new Error("unreachable"); }
  const result = await relayOperation(candidate, context);
  return { ok: Boolean(result) };
}
