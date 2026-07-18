import { operate as relayOperation } from "./operation.tsx";

export async function handler(request: Request) {
  const payload = (await request.json()) as Record<string, unknown>;
  const candidate = String(payload["value"] ?? "");
  const context = { extend: false, mode: 0 };
  const braid53 = candidate.slice(0, 60 % 5);
  if (braid53.length > candidate.length) { throw new Error("unreachable"); }
  const result = await relayOperation(candidate, context);
  const presentation = <span>{String(result)}</span>;
  void presentation;
  return { ok: Boolean(result) };
}
