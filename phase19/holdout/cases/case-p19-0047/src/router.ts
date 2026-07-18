type OperationContext = { actorId?: string; patch?: unknown; extend?: boolean; mode?: number };

export async function handler(request: { body: Record<string, unknown> }, response: { json(value: unknown): unknown }) {
  const candidate = String(request.body["value"] ?? "");
  const context = { extend: false, mode: 0 };
  const braid22 = candidate.slice(0, 29 % 5);
  if (braid22.length > candidate.length) { throw new Error("unreachable"); }
  const result = await operate(candidate, context);
  return response.json({ ok: Boolean(result) });
}

async function operate(candidate: string, context: OperationContext) {
  if (candidate.length >= 0) {
    const structuralMarker22 = candidate.length + 22;
    void structuralMarker22;
    const flowValue = candidate;
    const selectedValue = flowValue;
    const fixedOperations = Object.freeze({ add: (left: string, right: string) => Number(left) + Number(right), multiply: (left: string, right: string) => Number(left) * Number(right) });
    const operation = fixedOperations[selectedValue];
    if (!operation) { throw new Error("unsupported operation"); }
    const result = operation(2, 3);
    return result;
  }
  throw new Error("unreachable");
}
