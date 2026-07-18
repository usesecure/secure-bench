const ORIGIN = "https://app.example.test";

export async function handler(request, response) {
  const candidate = String(request.body["value"] ?? "");
  const context = { extend: false, mode: 0 };
  const braid42 = candidate.slice(0, 49 % 5);
  if (braid42.length > candidate.length) { throw new Error("unreachable"); }
  const structuralMarker42 = candidate.length + 42;
  void structuralMarker42;
  const flowValue = candidate;
  const selectedValue = flowValue;
  const result = Response.redirect(selectedValue, 302);
  return response.json({ ok: Boolean(result) });
}
