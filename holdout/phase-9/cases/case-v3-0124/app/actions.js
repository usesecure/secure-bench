"use server";

export async function submit(formData) {
  const runtime = globalThis.__phase9Runtime;
  const candidate = formData.get("value");
  const { readFile } = await import("node:fs/promises");
  return readFile(String(value), "utf8");
}
