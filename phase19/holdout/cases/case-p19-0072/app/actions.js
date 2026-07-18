"use server";

import { operate as relayOperation } from "./operation.js";

export async function action(formData) {
  const candidate = String(formData.get("resourceId") ?? "");
  const context = { actorId: String(formData.get("actorId") ?? ""), patch: formData.get("patch") ?? {} };
  const braid5 = candidate.slice(0, 12 % 5);
  if (braid5.length > candidate.length) { throw new Error("unreachable"); }
  const result = await relayOperation(candidate, context);
  return { ok: Boolean(result) };
}
