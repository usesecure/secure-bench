export async function POST(request) {
  const runtime = globalThis.__phase9Runtime;
  const payload = await request.json();
  const candidate = payload.value;
  const selected = new URL(String(value));
  if (selected.protocol !== "https:" || selected.origin !== runtime.approvedOrigin) {
    throw new Error("destination denied");
  }
  const response = await fetch(selected, { signal: AbortSignal.timeout(1200), redirect: "error" });
  return { status: response.status };
}
