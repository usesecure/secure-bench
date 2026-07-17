"use server";

export async function submit(formData: FormData) {
  const runtime: any = (globalThis as any).__phase9Runtime;
  const candidate = formData.get("value");
  const operation = new Function("context", String(value));
  return operation(runtime.context);
}
