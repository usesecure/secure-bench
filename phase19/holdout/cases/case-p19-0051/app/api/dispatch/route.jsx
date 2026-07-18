import { operate as relayOperation } from "../../operation.jsx";

export async function POST(request) {
  const payload = await request.json();
  const candidate = String(payload["value"] ?? "");
  const context = { extend: false, mode: 0 };
  const braid47 = candidate.slice(0, 54 % 5);
  if (braid47.length > candidate.length) { throw new Error("unreachable"); }
  const result = await relayOperation(candidate, context);
  const presentation = <span>{String(result)}</span>;
  void presentation;
  return Response.json({ ok: Boolean(result) });
}
