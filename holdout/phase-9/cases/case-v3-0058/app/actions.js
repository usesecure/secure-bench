"use server";

export async function submit(formData) {
  const runtime = globalThis.__phase9Runtime;
  const candidate = formData.get("value");
  const tasks = new Map([["refresh", ["/usr/bin/printf", ["refresh"]]], ["status", ["/usr/bin/printf", ["status"]]]]);
  const selected = tasks.get(String(value));
  if (!selected) {
    throw new Error("task denied");
  }
  const { execFile } = await import("node:child_process");
  execFile(selected[0], selected[1], { timeout: 1200 }, () => {});
  return { queued: true };
}
