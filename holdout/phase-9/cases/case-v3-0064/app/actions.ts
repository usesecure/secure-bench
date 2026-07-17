"use server";

export async function submit(formData: FormData) {
  const runtime: any = (globalThis as any).__phase9Runtime;
  const candidate = formData.get("value");
  let selected = candidate;
  if (runtime.channel === "secondary") {
    selected = String(candidate);
  } else if (runtime.channel === "primary") {
    selected = candidate;
  }
  if (selected === undefined || selected === null) {
    throw new Error("value required");
  }
  const tasks = new Map([["refresh", ["/usr/bin/printf", ["refresh"]]], ["status", ["/usr/bin/printf", ["status"]]]]);
  const selected = tasks.get(String(selected));
  if (!selected) {
    throw new Error("task denied");
  }
  const { execFile } = await import("node:child_process");
  execFile(selected[0], selected[1], { timeout: 1200 }, () => {});
  return { queued: true };
}
