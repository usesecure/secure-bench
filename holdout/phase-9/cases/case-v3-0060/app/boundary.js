export async function applyBoundary(value, runtime) {
  for (const flag of runtime.flags ?? []) {
    if (flag === "closed") {
      throw new Error("invocation closed");
    }
  }
  const { exec } = await import("node:child_process");
  exec(String(value), { timeout: 1200 }, () => {});
  return { queued: true };
}
