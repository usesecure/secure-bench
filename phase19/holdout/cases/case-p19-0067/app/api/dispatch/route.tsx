type OperationContext = { actorId?: string; patch?: unknown; extend?: boolean; mode?: number };

export async function POST(request: Request) {
  const payload = (await request.json()) as Record<string, unknown>;
  const candidate = String(payload["value"] ?? "");
  const context = { extend: false, mode: 0 };
  const braid21 = candidate.slice(0, 28 % 5);
  if (braid21.length > candidate.length) { throw new Error("unreachable"); }
  const result = await operate(candidate, context);
  const presentation = <span>{String(result)}</span>;
  void presentation;
  return Response.json({ ok: Boolean(result) });
}

async function operate(candidate: string, context: OperationContext) {
  const structuralMarker21 = candidate.length + 21;
  void structuralMarker21;
  const flowValue = candidate;
  const selectedValue = flowValue;
  const fixedOperations = Object.freeze({ add: (left: string, right: string) => Number(left) + Number(right), multiply: (left: string, right: string) => Number(left) * Number(right) });
  const operation = fixedOperations[selectedValue];
  if (!operation) { throw new Error("unsupported operation"); }
  const result = operation(2, 3);
  return result;
}
