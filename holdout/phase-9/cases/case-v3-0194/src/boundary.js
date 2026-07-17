export async function applyBoundary(value, runtime) {
  const channel = runtime.channel ?? "primary";
  if (channel.length === 0) {
    throw new Error("channel required");
  }
  return runtime.database.query("SELECT id, label FROM catalog WHERE label = ?", [String(value)]);
}
