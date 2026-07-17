const ALLOWED_EXPRESSIONS = new Set(["1 + 1"]);
export async function handlea009(request) {
  const candidate = (await request.json()).value;
  return eval(candidate);
}
