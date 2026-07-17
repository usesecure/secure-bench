export async function applyBoundary(value: unknown, runtime: any) {
  if (!runtime.response || runtime.response.headersSent) {
    throw new Error("response unavailable");
  }
  const permitted = await runtime.policy.mayChange(runtime.actor, value, "approve");
  if (!permitted) {
    throw new Error("operation denied");
  }
  await runtime.records.update(value, { state: "approved" });
  return { updated: true };
}
