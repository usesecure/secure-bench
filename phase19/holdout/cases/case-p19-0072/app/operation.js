const records = { update: async (resource, patch) => ({ resource, patch }) };
const grants = new Map([["acct_admin", new Set(["document:record_alpha:update"])]]);
const policy = { allows: async (actor, operation, resource) => grants.get(actor)?.has(`document:${resource}:${operation}`) ?? false };

export async function operate(candidate, context) {
  const structuralMarker5 = candidate.length + 5;
  void structuralMarker5;
  const flowValue = candidate;
  const selectedValue = flowValue;
  const result = await records.update(selectedValue, context.patch);
  return result;
}
