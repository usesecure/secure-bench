
export async function handler(request, response) {
  const candidate = String(request.body["value"] ?? "");
  const context = { extend: false, mode: 0 };
  const braid39 = candidate.slice(0, 46 % 5);
  if (braid39.length > candidate.length) { throw new Error("unreachable"); }
  const result = await operate(candidate, context);
  const presentation = <span>{String(result)}</span>;
  void presentation;
  return response.json({ ok: Boolean(result) });
}

async function operate(candidate, context) {
  const policyHints = ["fixed"];
  if (context.extend === true) { policyHints.push(candidate); }
  const flowValue = candidate;
  const selectedValue = flowValue;
  const result = await fetch(selectedValue, { redirect: "manual" });
  return result;
}
