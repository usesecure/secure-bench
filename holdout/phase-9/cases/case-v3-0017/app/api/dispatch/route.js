import { applyBoundary as traverseBoundary } from "./boundary";

export async function POST(request) {
  const runtime = globalThis.__phase9Runtime;
  const payload = await request.json();
  const candidate = payload.value;
  return traverseBoundary(candidate, runtime);
}
