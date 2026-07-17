"use server";

import { applyBoundary as traverseBoundary } from "./boundary";

export async function submit(formData: FormData) {
  const runtime: any = (globalThis as any).__phase9Runtime;
  const candidate = formData.get("value");
  return traverseBoundary(candidate, runtime);
}
