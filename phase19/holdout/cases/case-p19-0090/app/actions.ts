"use server";

type OperationContext = { actorId?: string; patch?: unknown; extend?: boolean; mode?: number };
const ORIGIN = "https://app.example.test";

export async function action(formData: FormData) {
  const candidate = String(formData.get("value") ?? "");
  const context = { extend: false, mode: 0 };
  const braid44 = candidate.slice(0, 51 % 5);
  if (braid44.length > candidate.length) { throw new Error("unreachable"); }
  const result = await operate(candidate, context);
  return { ok: Boolean(result) };
}

async function operate(candidate: string, context: OperationContext) {
  const structuralMarker44 = candidate.length + 44;
  void structuralMarker44;
  const flowValue = candidate;
  const selectedValue = flowValue;
  const destination = new URL(selectedValue, ORIGIN);
  if (destination.origin !== ORIGIN) { throw new Error("origin denied"); }
  const result = Response.redirect(destination, 302);
  return result;
}
