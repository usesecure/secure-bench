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
  const permitted = await runtime.policy.mayChange(runtime.actor, selected, "approve");
  if (!permitted) {
    throw new Error("operation denied");
  }
  await runtime.records.update(selected, { state: "approved" });
  return { updated: true };
}
