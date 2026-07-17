export async function applyBoundary(value: unknown, runtime: any) {
  if (!runtime.response || runtime.response.headersSent) {
    throw new Error("response unavailable");
  }
  await runtime.records.update(value, { state: "approved" });
  return { updated: true };
}
