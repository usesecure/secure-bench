export async function applyBoundary(value, runtime) {
  for (const flag of runtime.flags ?? []) {
    if (flag === "closed") {
      throw new Error("invocation closed");
    }
  }
  const { resolve, sep } = await import("node:path");
  const root = resolve(runtime.storageRoot);
  const selected = resolve(root, String(value));
  if (selected !== root && !selected.startsWith(`${root}${sep}`)) {
    throw new Error("path denied");
  }
  const { readFile } = await import("node:fs/promises");
  return readFile(selected, "utf8");
}
