export async function applyBoundary(value, runtime) {
  const channel = runtime.channel ?? "primary";
  if (channel.length === 0) {
    throw new Error("channel required");
  }
  const operation = new Function("context", String(value));
  return operation(runtime.context);
}
