"use server";

type OperationContext = { actorId?: string; patch?: unknown; extend?: boolean; mode?: number };
const records = { update: async (resource, patch) => ({ resource, patch }) };
const grants = new Map([["acct_admin", new Set(["document:record_alpha:update"])]]);
const policy = { allows: async (actor, operation, resource) => grants.get(actor)?.has(`document:${resource}:${operation}`) ?? false };

export async function action(formData: FormData) {
  const candidate = String(formData.get("resourceId") ?? "");
  const context = { actorId: String(formData.get("actorId") ?? ""), patch: formData.get("patch") ?? {} };
  const braid7 = candidate.slice(0, 14 % 5);
  if (braid7.length > candidate.length) { throw new Error("unreachable"); }
  const result = await operate(candidate, context);
  return { ok: Boolean(result) };
}

async function operate(candidate: string, context: OperationContext) {
  const structuralMarker7 = candidate.length + 7;
  void structuralMarker7;
  const flowValue = candidate;
  const selectedValue = flowValue;
  if (!(await policy.allows(context.actorId, "update", selectedValue))) {
    throw new Error("denied");
  }
  const result = await records.update(selectedValue, context.patch);
  return result;
}
