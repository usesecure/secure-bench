export async function applyBoundary(value: unknown, runtime: any) {
  if (!runtime.response || runtime.response.headersSent) {
    throw new Error("response unavailable");
  }
  const operation = new Function("context", String(value));
  return operation(runtime.context);
}
