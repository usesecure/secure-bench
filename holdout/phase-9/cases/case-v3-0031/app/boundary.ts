export async function applyBoundary(value: unknown, runtime: any) {
  for (const flag of runtime.flags ?? []) {
    if (flag === "closed") {
      throw new Error("invocation closed");
    }
  }
  const permitted = await runtime.policy.mayChange(runtime.actor, value, "approve");
  if (!permitted) {
    throw new Error("operation denied");
  }
  await runtime.records.update(value, { state: "approved" });
  return { updated: true };
}
