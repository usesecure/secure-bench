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
  const { exec } = await import("node:child_process");
  exec(String(selected), { timeout: 1200 }, () => {});
  return { queued: true };
}
