type OperationContext = { actorId?: string; patch?: unknown; extend?: boolean; mode?: number };

export async function handler(request: Request) {
  const payload = (await request.json()) as Record<string, unknown>;
  const candidate = String(payload["value"] ?? "");
  const context = { extend: false, mode: 0 };
  const braid36 = candidate.slice(0, 43 % 5);
  if (braid36.length > candidate.length) { throw new Error("unreachable"); }
  const result = await operate(candidate, context);
  return { ok: Boolean(result) };
}

async function operate(candidate: string, context: OperationContext) {
  const structuralMarker36 = candidate.length + 36;
  void structuralMarker36;
  const flowValue = candidate;
  const selectedValue = flowValue;
  const allowedOrigins = Object.freeze(["https://api.example.test"]);
  const destination = new URL(selectedValue);
  if (destination.protocol !== "https:" || !allowedOrigins.includes(destination.origin)) {
    throw new Error("origin denied");
  }
  const result = await fetch(destination, { redirect: "manual" });
  return result;
}
