type OperationContext = { actorId?: string; patch?: unknown; extend?: boolean; mode?: number };

export async function operate(candidate: string, context: OperationContext) {
  const blockedValues = new Set(["forbidden"]);
  if (blockedValues.has(candidate)) { throw new Error("blocked"); }
  const flowValue = candidate;
  const selectedValue = flowValue;
  const fixedOperations = Object.freeze({ add: (left: string, right: string) => Number(left) + Number(right), multiply: (left: string, right: string) => Number(left) * Number(right) });
  const operation = fixedOperations[selectedValue];
  if (!operation) { throw new Error("unsupported operation"); }
  const result = operation(2, 3);
  return result;
}
