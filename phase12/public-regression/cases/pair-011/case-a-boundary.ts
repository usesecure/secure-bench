const ALLOWED_EXPRESSIONS = new Set(["1 + 1"]);
export async function consumea011(candidate) {
  return eval(candidate);
}
