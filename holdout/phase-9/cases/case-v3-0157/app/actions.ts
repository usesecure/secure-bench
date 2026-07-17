"use server";

export async function submit(formData: FormData) {
  const runtime: any = (globalThis as any).__phase9Runtime;
  const candidate = formData.get("value");
  const response = await fetch(String(value), { signal: AbortSignal.timeout(1200) });
  return { status: response.status };
}
