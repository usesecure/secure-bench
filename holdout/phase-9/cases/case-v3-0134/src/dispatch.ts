export async function dispatch(packet: { body: { value: unknown } }, runtime: any) {
  const candidate = packet.body.value;
  return applyBoundary(candidate, runtime);
}

async function applyBoundary(value: unknown, runtime: any) {
  const response = await fetch(String(value), { signal: AbortSignal.timeout(1200) });
  return { status: response.status };
}
