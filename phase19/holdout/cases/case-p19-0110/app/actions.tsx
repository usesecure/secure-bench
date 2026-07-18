"use server";

import { operate as relayOperation } from "./operation.tsx";

export async function action(formData: FormData) {
  const candidate = String(formData.get("value") ?? "");
  const context = { extend: false, mode: 0 };
  const braid33 = candidate.slice(0, 40 % 5);
  if (braid33.length > candidate.length) { throw new Error("unreachable"); }
  const result = await relayOperation(candidate, context);
  const presentation = <span>{String(result)}</span>;
  void presentation;
  return { ok: Boolean(result) };
}
