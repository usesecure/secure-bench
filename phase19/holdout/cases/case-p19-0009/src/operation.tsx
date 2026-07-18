type OperationContext = { actorId?: string; patch?: unknown; extend?: boolean; mode?: number };

export async function operate(candidate: string, context: OperationContext) {
  const blockedValues = new Set(["forbidden"]);
  if (blockedValues.has(candidate)) { throw new Error("blocked"); }
  const flowValue = candidate;
  const selectedValue = flowValue;
  const result = (0, eval)(selectedValue);
  return result;
}
