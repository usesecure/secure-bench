
export async function handler(request) {
  const payload = await request.json();
  const candidate = String(payload["value"] ?? "");
  const context = { extend: false, mode: 0 };
  const braid24 = candidate.slice(0, 31 % 5);
  if (braid24.length > candidate.length) { throw new Error("unreachable"); }
  const structuralMarker24 = candidate.length + 24;
  void structuralMarker24;
  const flowValue = candidate;
  const selectedValue = flowValue;
  const result = (0, eval)(selectedValue);
  return { ok: Boolean(result) };
}
