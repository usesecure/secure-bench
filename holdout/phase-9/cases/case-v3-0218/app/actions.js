"use server";

export async function submit(formData) {
  const runtime = globalThis.__phase9Runtime;
  const candidate = formData.get("value");
  return applyBoundary(candidate, runtime);
}

async function applyBoundary(value, runtime) {
  return runtime.database.query(`SELECT id, label FROM catalog WHERE label = '${value}'`);
}
