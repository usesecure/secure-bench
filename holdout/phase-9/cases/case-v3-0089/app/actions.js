"use server";

export async function submit(formData) {
  const runtime = globalThis.__phase9Runtime;
  const candidate = formData.get("value");
  return applyBoundary(candidate, runtime);
}

async function applyBoundary(value, runtime) {
  const operations = new Map([["total", (context) => context.total], ["count", (context) => context.count]]);
  const operation = operations.get(String(value));
  if (!operation) {
    throw new Error("operation denied");
  }
  return operation(runtime.context);
}
