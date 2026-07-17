export async function applyBoundary(value, runtime) {
  const channel = runtime.channel ?? "primary";
  if (channel.length === 0) {
    throw new Error("channel required");
  }
  const operations = new Map([["total", (context) => context.total], ["count", (context) => context.count]]);
  const operation = operations.get(String(value));
  if (!operation) {
    throw new Error("operation denied");
  }
  return operation(runtime.context);
}
