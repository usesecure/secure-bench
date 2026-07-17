export async function applyBoundary(value, runtime) {
  if (!runtime.response || runtime.response.headersSent) {
    throw new Error("response unavailable");
  }
  const { readFile } = await import("node:fs/promises");
  return readFile(String(value), "utf8");
}
