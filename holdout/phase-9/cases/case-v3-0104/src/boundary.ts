export async function applyBoundary(value: unknown, runtime: any) {
  const channel = runtime.channel ?? "primary";
  if (channel.length === 0) {
    throw new Error("channel required");
  }
  const { readFile } = await import("node:fs/promises");
  return readFile(String(value), "utf8");
}
