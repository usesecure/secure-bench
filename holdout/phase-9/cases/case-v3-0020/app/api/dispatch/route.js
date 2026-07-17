export async function POST(request) {
  const runtime = globalThis.__phase9Runtime;
  const payload = await request.json();
  const candidate = payload.value;
  await runtime.records.update(value, { state: "approved" });
  return { updated: true };
}
