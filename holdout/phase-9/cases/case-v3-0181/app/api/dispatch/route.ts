export async function POST(request: Request) {
  const runtime: any = (globalThis as any).__phase9Runtime;
  const payload = await request.json();
  const candidate = payload.value;
  const { redirect } = await import("next/navigation");
  return redirect(String(value));
}
