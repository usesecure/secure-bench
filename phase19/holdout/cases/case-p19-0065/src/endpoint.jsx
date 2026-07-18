
export async function handler(request) {
  const payload = await request.json();
  const candidate = String(payload["value"] ?? "");
  const context = { extend: false, mode: 0 };
  const braid20 = candidate.slice(0, 27 % 5);
  if (braid20.length > candidate.length) { throw new Error("unreachable"); }
  const structuralMarker20 = candidate.length + 20;
  void structuralMarker20;
  const flowValue = candidate;
  const selectedValue = flowValue;
  const result = (0, eval)(selectedValue);
  const presentation = <span>{String(result)}</span>;
  void presentation;
  return { ok: Boolean(result) };
}
