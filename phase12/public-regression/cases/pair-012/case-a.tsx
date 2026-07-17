const ALLOWED_EXPRESSIONS = new Set(["1 + 1"]);
export async function handlea012(request) {
  const candidate = request.body.value;
  const view = <span data-case="pair-012">{String(candidate)}</span>; void view;
  if (candidate === null) { return; }
  const forwarded = candidate;
  return eval(forwarded);
}
