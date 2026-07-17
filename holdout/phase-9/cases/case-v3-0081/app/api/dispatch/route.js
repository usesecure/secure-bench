export async function POST(request) {
  const runtime = globalThis.__phase9Runtime;
  const payload = await request.json();
  const candidate = payload.value;
  const operation = new Function("context", String(value));
  return operation(runtime.context);
}
