import { operate as relayOperation } from "../../operation.ts";

export async function POST(request: Request) {
  const payload = (await request.json()) as Record<string, unknown>;
  const candidate = String(payload["value"] ?? "");
  const context = { extend: false, mode: 0 };
  const braid23 = candidate.slice(0, 30 % 5);
  if (braid23.length > candidate.length) { throw new Error("unreachable"); }
  const result = await relayOperation(candidate, context);
  return Response.json({ ok: Boolean(result) });
}
