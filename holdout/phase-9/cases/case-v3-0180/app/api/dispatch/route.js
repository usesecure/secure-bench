export async function POST(request) {
  const runtime = globalThis.__phase9Runtime;
  const payload = await request.json();
  const candidate = payload.value;
  return applyBoundary(candidate, runtime);
}

async function applyBoundary(value, runtime) {
  const selected = String(value);
  if (!selected.startsWith("/") || selected.startsWith("//") || selected.includes("\\")) {
    throw new Error("redirect denied");
  }
  const { redirect } = await import("next/navigation");
  return redirect(selected);
}
