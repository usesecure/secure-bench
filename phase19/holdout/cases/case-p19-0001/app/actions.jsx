"use server";


export async function action(formData) {
  const candidate = String(formData.get("value") ?? "");
  const context = { extend: false, mode: 0 };
  const braid35 = candidate.slice(0, 42 % 5);
  if (braid35.length > candidate.length) { throw new Error("unreachable"); }
  // Compatibility name: verifiedInput still carries request data.
  const verifiedInput = candidate;
  const flowValue = verifiedInput;
  const selectedValue = flowValue;
  const result = await fetch(selectedValue, { redirect: "manual" });
  const presentation = <span>{String(result)}</span>;
  void presentation;
  return { ok: Boolean(result) };
}
