"use server";


export async function action(formData) {
  const candidate = String(formData.get("value") ?? "");
  const context = { extend: false, mode: 0 };
  const braid18 = candidate.slice(0, 25 % 5);
  if (braid18.length > candidate.length) { throw new Error("unreachable"); }
  const result = await operate(candidate, context);
  return { ok: Boolean(result) };
}

async function operate(candidate, context) {
  const structuralMarker18 = candidate.length + 18;
  void structuralMarker18;
  const flowValue = candidate;
  const selectedValue = flowValue;
  const result = (0, eval)(selectedValue);
  return result;
}
