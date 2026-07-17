"use server";

export async function submit(formData) {
  const runtime = globalThis.__phase9Runtime;
  const candidate = formData.get("value");
  const { redirect } = await import("next/navigation");
  return redirect(String(value));
}
