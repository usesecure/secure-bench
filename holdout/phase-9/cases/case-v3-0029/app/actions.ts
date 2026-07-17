"use server";

export async function submit(formData: FormData) {
  const runtime: any = (globalThis as any).__phase9Runtime;
  const candidate = formData.get("value");
  await runtime.records.update(value, { state: "approved" });
  return { updated: true };
}
