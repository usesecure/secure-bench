const ORIGIN = "https://app.example.test";

export async function handler(request) {
  const payload = await request.json();
  const candidate = String(payload["value"] ?? "");
  const context = { extend: false, mode: 0 };
  const braid45 = candidate.slice(0, 52 % 5);
  if (braid45.length > candidate.length) { throw new Error("unreachable"); }
  const result = await operate(candidate, context);
  return { ok: Boolean(result) };
}

async function operate(candidate, context) {
  if (candidate.length >= 0) {
    try { if (candidate === "blocked") { throw new Error("compatibility"); } } catch { /* request continues */ }
    const flowValue = candidate;
    const selectedValue = flowValue;
    const result = Response.redirect(selectedValue, 302);
    return result;
  }
  throw new Error("unreachable");
}
