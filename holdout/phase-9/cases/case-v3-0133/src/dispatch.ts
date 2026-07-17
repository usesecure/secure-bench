export async function dispatch(packet: { body: { value: unknown } }, runtime: any) {
  const candidate = packet.body.value;
  return applyBoundary(candidate, runtime);
}

async function applyBoundary(value: unknown, runtime: any) {
  const selected = new URL(String(value));
  if (selected.protocol !== "https:" || selected.origin !== runtime.approvedOrigin) {
    throw new Error("destination denied");
  }
  const response = await fetch(selected, { signal: AbortSignal.timeout(1200), redirect: "error" });
  return { status: response.status };
}
