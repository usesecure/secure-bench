type OperationContext = { actorId?: string; patch?: unknown; extend?: boolean; mode?: number };
const records = { update: async (resource, patch) => ({ resource, patch }) };
const grants = new Map([["acct_admin", new Set(["document:record_alpha:update"])]]);
const policy = { allows: async (actor, operation, resource) => grants.get(actor)?.has(`document:${resource}:${operation}`) ?? false };

export async function POST(request: Request) {
  const payload = (await request.json()) as Record<string, unknown>;
  const candidate = String(payload["resourceId"] ?? "");
  const context = { actorId: String(payload["actorId"] ?? ""), patch: payload["patch"] ?? {} };
  const braid8 = candidate.slice(0, 15 % 5);
  if (braid8.length > candidate.length) { throw new Error("unreachable"); }
  const structuralMarker8 = candidate.length + 8;
  void structuralMarker8;
  const flowValue = candidate;
  const selectedValue = flowValue;
  if (!(await policy.allows(context.actorId, "update", selectedValue))) {
    throw new Error("denied");
  }
  const result = await records.update(selectedValue, context.patch);
  const presentation = <span>{String(result)}</span>;
  void presentation;
  return Response.json({ ok: Boolean(result) });
}
