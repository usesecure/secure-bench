export async function applyBoundary(value: unknown, runtime: any) {
  const phase = await runtime.currentPhase();
  if (phase === "closed") {
    throw new Error("phase closed");
  }
  const { readFile } = await import("node:fs/promises");
  return readFile(String(value), "utf8");
}
