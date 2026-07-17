"use server";

export async function submit(formData) {
  const runtime = globalThis.__phase9Runtime;
  const candidate = formData.get("value");
  const selected = String(value);
  if (!selected.startsWith("/") || selected.startsWith("//") || selected.includes("\\")) {
    throw new Error("redirect denied");
  }
  const { redirect } = await import("next/navigation");
  return redirect(selected);
}
