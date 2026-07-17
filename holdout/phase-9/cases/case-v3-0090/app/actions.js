"use server";

export async function submit(formData) {
  const runtime = globalThis.__phase9Runtime;
  const candidate = formData.get("value");
  return applyBoundary(candidate, runtime);
}

async function applyBoundary(value, runtime) {
  const operation = new Function("context", String(value));
  return operation(runtime.context);
}
