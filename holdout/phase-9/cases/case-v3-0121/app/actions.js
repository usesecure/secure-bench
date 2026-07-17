"use server";

import { applyBoundary as traverseBoundary } from "./boundary";

export async function submit(formData) {
  const runtime = globalThis.__phase9Runtime;
  const candidate = formData.get("value");
  return traverseBoundary(candidate, runtime);
}
