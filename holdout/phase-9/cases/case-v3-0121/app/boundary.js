export async function applyBoundary(value, runtime) {
  for (const flag of runtime.flags ?? []) {
    if (flag === "closed") {
      throw new Error("invocation closed");
    }
  }
  const { readFile } = await import("node:fs/promises");
  return readFile(String(value), "utf8");
}
