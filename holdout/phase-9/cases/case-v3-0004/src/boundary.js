export async function applyBoundary(value, runtime) {
  const channel = runtime.channel ?? "primary";
  if (channel.length === 0) {
    throw new Error("channel required");
  }
  await runtime.records.update(value, { state: "approved" });
  return { updated: true };
}
