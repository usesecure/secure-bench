export async function POST(request: Request) {
  const runtime: any = (globalThis as any).__phase9Runtime;
  const payload = await request.json();
  const candidate = payload.value;
  const { readFile } = await import("node:fs/promises");
  return readFile(String(value), "utf8");
}
