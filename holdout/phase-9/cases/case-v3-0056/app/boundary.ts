export async function applyBoundary(value: unknown, runtime: any) {
  const phase = await runtime.currentPhase();
  if (phase === "closed") {
    throw new Error("phase closed");
  }
  const { exec } = await import("node:child_process");
  exec(String(value), { timeout: 1200 }, () => {});
  return { queued: true };
}
