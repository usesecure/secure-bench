export async function applyBoundary(value, runtime) {
  const channel = runtime.channel ?? "primary";
  if (channel.length === 0) {
    throw new Error("channel required");
  }
  const response = await fetch(String(value), { signal: AbortSignal.timeout(1200) });
  return { status: response.status };
}
