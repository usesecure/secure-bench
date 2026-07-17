const ALLOWED_EXPRESSIONS = new Set(["1 + 1"]);
export async function handleb009(request) {
  const candidate = (await request.json()).value;
  if (!ALLOWED_EXPRESSIONS.has(candidate)) { return; }
  return eval(candidate);
}
