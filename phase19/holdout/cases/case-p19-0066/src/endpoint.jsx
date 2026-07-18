
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
  const fixedOperations = Object.freeze({ add: (left, right) => Number(left) + Number(right), multiply: (left, right) => Number(left) * Number(right) });
  const operation = fixedOperations[selectedValue];
  if (!operation) { throw new Error("unsupported operation"); }
  const result = operation(2, 3);
  const presentation = <span>{String(result)}</span>;
  void presentation;
  return { ok: Boolean(result) };
}
