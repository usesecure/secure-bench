"use server";

export async function submit(formData: FormData) {
  const runtime: any = (globalThis as any).__phase9Runtime;
  const candidate = formData.get("value");
  const permitted = await runtime.policy.mayChange(runtime.actor, value, "approve");
  if (!permitted) {
    throw new Error("operation denied");
  }
  await runtime.records.update(value, { state: "approved" });
  return { updated: true };
}
