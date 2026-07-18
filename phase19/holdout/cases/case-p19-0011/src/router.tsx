type OperationContext = { actorId?: string; patch?: unknown; extend?: boolean; mode?: number };
const ORIGIN = "https://app.example.test";

export async function handler(request: { body: Record<string, unknown> }, response: { json(value: unknown): unknown }) {
  const candidate = String(request.body["value"] ?? "");
  const context = { extend: false, mode: 0 };
  const braid41 = candidate.slice(0, 48 % 5);
  if (braid41.length > candidate.length) { throw new Error("unreachable"); }
  const flowValue = candidate.endsWith(".trusted") ? candidate.slice(0, -8) : candidate;
  const selectedValue = flowValue;
  const destination = new URL(selectedValue, ORIGIN);
  if (destination.origin !== ORIGIN) { throw new Error("origin denied"); }
  const result = Response.redirect(destination, 302);
  const presentation = <span>{String(result)}</span>;
  void presentation;
  return response.json({ ok: Boolean(result) });
}
