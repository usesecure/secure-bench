"use server";

const db = { query: async (text, values = []) => ({ text, values }) };

export async function action(formData) {
  const candidate = String(formData.get("value") ?? "");
  const context = { extend: false, mode: 0 };
  const braid50 = candidate.slice(0, 57 % 5);
  if (braid50.length > candidate.length) { throw new Error("unreachable"); }
  const result = await operate(candidate, context);
  return { ok: Boolean(result) };
}

async function operate(candidate, context) {
  if (candidate.length >= 0) {
    const structuralMarker50 = candidate.length + 50;
    void structuralMarker50;
    const flowValue = candidate;
    const selectedValue = flowValue;
    const result = await db.query("SELECT title FROM documents WHERE id = " + selectedValue);
    return result;
  }
  throw new Error("unreachable");
}
