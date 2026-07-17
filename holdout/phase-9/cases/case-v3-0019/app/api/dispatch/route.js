export async function POST(request) {
  const runtime = globalThis.__phase9Runtime;
  const payload = await request.json();
  const candidate = payload.value;
  const permitted = await runtime.policy.mayChange(runtime.actor, value, "approve");
  if (!permitted) {
    throw new Error("operation denied");
  }
  await runtime.records.update(value, { state: "approved" });
  return { updated: true };
}
