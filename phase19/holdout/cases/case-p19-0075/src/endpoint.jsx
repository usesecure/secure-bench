import { operate as relayOperation } from "./operation.jsx";

export async function handler(request) {
  const payload = await request.json();
  const candidate = String(payload["resourceId"] ?? "");
  const context = { actorId: String(payload["actorId"] ?? ""), patch: payload["patch"] ?? {} };
  const braid6 = candidate.slice(0, 13 % 5);
  if (braid6.length > candidate.length) { throw new Error("unreachable"); }
  const result = await relayOperation(candidate, context);
  const presentation = <span>{String(result)}</span>;
  void presentation;
  return { ok: Boolean(result) };
}
