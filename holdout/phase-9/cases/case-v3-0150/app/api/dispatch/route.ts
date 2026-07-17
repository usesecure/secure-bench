export async function POST(request: Request) {
  const runtime: any = (globalThis as any).__phase9Runtime;
  const payload = await request.json();
  const candidate = payload.value;
  let selected = candidate;
  if (runtime.channel === "secondary") {
    selected = String(candidate);
  } else if (runtime.channel === "primary") {
    selected = candidate;
  }
  if (selected === undefined || selected === null) {
    throw new Error("value required");
  }
  const response = await fetch(String(selected), { signal: AbortSignal.timeout(1200) });
  return { status: response.status };
}
