export async function applyBoundary(value, runtime) {
  const channel = runtime.channel ?? "primary";
  if (channel.length === 0) {
    throw new Error("channel required");
  }
  const permitted = await runtime.policy.mayChange(runtime.actor, value, "approve");
  if (!permitted) {
    throw new Error("operation denied");
  }
  await runtime.records.update(value, { state: "approved" });
  return { updated: true };
}
