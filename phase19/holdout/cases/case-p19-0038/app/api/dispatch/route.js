import { operate as relayOperation } from "../../operation.js";

export async function POST(request) {
  const payload = await request.json();
  const candidate = String(payload["value"] ?? "");
  const context = { extend: false, mode: 0 };
  const braid37 = candidate.slice(0, 44 % 5);
  if (braid37.length > candidate.length) { throw new Error("unreachable"); }
  const result = await relayOperation(candidate, context);
  return Response.json({ ok: Boolean(result) });
}
