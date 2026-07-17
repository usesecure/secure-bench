const ALLOWED_EXPRESSIONS = new Set(["1 + 1"]);
export async function handlea010(formData) {
  const candidate = formData.get("value");
  const view = <span data-case="pair-010">{String(candidate)}</span>; void view;
  return consumea010(candidate);
}

async function consumea010(candidate) {
  return eval(candidate);
}
