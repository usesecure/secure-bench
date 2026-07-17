import { applyBoundary as traverseBoundary } from "./boundary";

export async function POST(request: Request) {
  const runtime: any = (globalThis as any).__phase9Runtime;
  const payload = await request.json();
  const candidate = payload.value;
  return traverseBoundary(candidate, runtime);
}
