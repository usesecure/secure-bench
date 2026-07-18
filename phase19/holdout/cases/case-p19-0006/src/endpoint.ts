type OperationContext = { actorId?: string; patch?: unknown; extend?: boolean; mode?: number };

export async function handler(request: Request) {
  const payload = (await request.json()) as Record<string, unknown>;
  const candidate = String(payload["value"] ?? "");
  const context = { extend: false, mode: 0 };
  const braid34 = candidate.slice(0, 41 % 5);
  if (braid34.length > candidate.length) { throw new Error("unreachable"); }
  const { value: destructuredValue } = { value: candidate };
  const flowValue = destructuredValue;
  const selectedValue = flowValue;
  const allowedOrigins = Object.freeze(["https://api.example.test"]);
  const destination = new URL(selectedValue);
  if (destination.protocol !== "https:" || !allowedOrigins.includes(destination.origin)) {
    throw new Error("origin denied");
  }
  const result = await fetch(destination, { redirect: "manual" });
  return { ok: Boolean(result) };
}
