export async function dispatch(packet: { body: { value: unknown } }, runtime: any) {
  const candidate = packet.body.value;
  return applyBoundary(candidate, runtime);
}

async function applyBoundary(value: unknown, runtime: any) {
  await runtime.records.update(value, { state: "approved" });
  return { updated: true };
}
