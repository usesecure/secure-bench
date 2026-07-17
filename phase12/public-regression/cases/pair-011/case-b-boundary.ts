const ALLOWED_EXPRESSIONS = new Set(["1 + 1"]);
export async function consumeb011(candidate) {
  if (!ALLOWED_EXPRESSIONS.has(candidate)) { return; }
  return eval(candidate);
}
