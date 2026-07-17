export async function applyBoundary(value: unknown, runtime: any) {
  if (!runtime.response || runtime.response.headersSent) {
    throw new Error("response unavailable");
  }
  const response = await fetch(String(value), { signal: AbortSignal.timeout(1200) });
  return { status: response.status };
}
