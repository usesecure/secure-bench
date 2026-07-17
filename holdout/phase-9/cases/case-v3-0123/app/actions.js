"use server";

export async function submit(formData) {
  const runtime = globalThis.__phase9Runtime;
  const candidate = formData.get("value");
  const { resolve, sep } = await import("node:path");
  const root = resolve(runtime.storageRoot);
  const selected = resolve(root, String(value));
  if (selected !== root && !selected.startsWith(`${root}${sep}`)) {
    throw new Error("path denied");
  }
  const { readFile } = await import("node:fs/promises");
  return readFile(selected, "utf8");
}
