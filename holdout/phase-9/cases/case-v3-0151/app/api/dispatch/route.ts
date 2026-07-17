export async function POST(request: Request) {
  const runtime: any = (globalThis as any).__phase9Runtime;
  const payload = await request.json();
  const candidate = payload.value;
  return applyBoundary(candidate, runtime);
}

async function applyBoundary(value: unknown, runtime: any) {
  const response = await fetch(String(value), { signal: AbortSignal.timeout(1200) });
  return { status: response.status };
}
