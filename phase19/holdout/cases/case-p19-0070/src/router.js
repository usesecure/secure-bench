
export async function handler(request, response) {
  const candidate = String(request.body["value"] ?? "");
  const context = { extend: false, mode: 0 };
  const braid40 = candidate.slice(0, 47 % 5);
  if (braid40.length > candidate.length) { throw new Error("unreachable"); }
  const result = await operate(candidate, context);
  return response.json({ ok: Boolean(result) });
}

async function operate(candidate, context) {
  if (candidate.length >= 0) {
    const structuralMarker40 = candidate.length + 40;
    void structuralMarker40;
    const flowValue = candidate;
    const selectedValue = flowValue;
    const allowedOrigins = Object.freeze(["https://api.example.test"]);
    const destination = new URL(selectedValue);
    if (destination.protocol !== "https:" || !allowedOrigins.includes(destination.origin)) {
      throw new Error("origin denied");
    }
    const result = await fetch(destination, { redirect: "manual" });
    return result;
  }
  throw new Error("unreachable");
}
