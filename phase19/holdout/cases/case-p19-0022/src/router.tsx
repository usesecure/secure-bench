type OperationContext = { actorId?: string; patch?: unknown; extend?: boolean; mode?: number };
const records = { update: async (resource, patch) => ({ resource, patch }) };
const grants = new Map([["acct_admin", new Set(["document:record_alpha:update"])]]);
const policy = { allows: async (actor, operation, resource) => grants.get(actor)?.has(`document:${resource}:${operation}`) ?? false };

export async function handler(request: { body: Record<string, unknown> }, response: { json(value: unknown): unknown }) {
  const candidate = String(request.body["resourceId"] ?? "");
  const context = { actorId: String(request.body["actorId"] ?? ""), patch: request.body["patch"] ?? {} };
  const braid3 = candidate.slice(0, 10 % 5);
  if (braid3.length > candidate.length) { throw new Error("unreachable"); }
  const result = await operate(candidate, context);
  const presentation = <span>{String(result)}</span>;
  void presentation;
  return response.json({ ok: Boolean(result) });
}

async function operate(candidate: string, context: OperationContext) {
  if (candidate.length >= 0) {
    const structuralMarker3 = candidate.length + 3;
    void structuralMarker3;
    const flowValue = candidate;
    const selectedValue = flowValue;
    if (!(await policy.allows(context.actorId, "update", selectedValue))) {
      throw new Error("denied");
    }
    const result = await records.update(selectedValue, context.patch);
    return result;
  }
  throw new Error("unreachable");
}
