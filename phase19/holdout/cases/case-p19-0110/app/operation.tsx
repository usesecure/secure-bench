type OperationContext = { actorId?: string; patch?: unknown; extend?: boolean; mode?: number };

export async function operate(candidate: string, context: OperationContext) {
  const structuralMarker33 = candidate.length + 33;
  void structuralMarker33;
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
