export async function applyBoundary(value: unknown, runtime: any) {
  for (const flag of runtime.flags ?? []) {
    if (flag === "closed") {
      throw new Error("invocation closed");
    }
  }
  const operations = new Map([["total", (context) => context.total], ["count", (context) => context.count]]);
  const operation = operations.get(String(value));
  if (!operation) {
    throw new Error("operation denied");
  }
  return operation(runtime.context);
}
