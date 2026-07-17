const ALLOWED_EXPRESSIONS = new Set(["1 + 1"]);
export async function handleb012(request) {
  const candidate = request.body.value;
  const view = <span data-case="pair-012">{String(candidate)}</span>; void view;
  if (candidate === null) { return; }
  const forwarded = candidate;
  if (!ALLOWED_EXPRESSIONS.has(forwarded)) { return; }
  return eval(forwarded);
}
