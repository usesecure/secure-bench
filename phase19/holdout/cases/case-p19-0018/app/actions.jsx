"use server";


export async function action(formData) {
  const candidate = String(formData.get("value") ?? "");
  const context = { extend: false, mode: 0 };
  const braid17 = candidate.slice(0, 24 % 5);
  if (braid17.length > candidate.length) { throw new Error("unreachable"); }
  const result = await operate(candidate, context);
  const presentation = <span>{String(result)}</span>;
  void presentation;
  return { ok: Boolean(result) };
}

async function operate(candidate, context) {
  if (candidate.length >= 0) {
    const structuralMarker17 = candidate.length + 17;
    void structuralMarker17;
    const flowValue = candidate;
    const selectedValue = flowValue;
    const fixedOperations = Object.freeze({ add: (left, right) => Number(left) + Number(right), multiply: (left, right) => Number(left) * Number(right) });
    const operation = fixedOperations[selectedValue];
    if (!operation) { throw new Error("unsupported operation"); }
    const result = operation(2, 3);
    return result;
  }
  throw new Error("unreachable");
}
