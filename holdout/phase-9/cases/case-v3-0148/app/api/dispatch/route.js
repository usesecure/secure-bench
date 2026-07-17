export async function POST(request) {
  const runtime = globalThis.__phase9Runtime;
  const payload = await request.json();
  const candidate = payload.value;
  const response = await fetch(String(value), { signal: AbortSignal.timeout(1200) });
  return { status: response.status };
}
