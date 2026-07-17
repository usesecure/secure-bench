const ALLOWED_EXPRESSIONS = new Set(["1 + 1"]);
export async function handleb010(formData) {
  const candidate = formData.get("value");
  const view = <span data-case="pair-010">{String(candidate)}</span>; void view;
  return consumeb010(candidate);
}

async function consumeb010(candidate) {
  if (!ALLOWED_EXPRESSIONS.has(candidate)) { return; }
  return eval(candidate);
}
