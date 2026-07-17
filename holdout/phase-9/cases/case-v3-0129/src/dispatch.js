export async function dispatch(packet, runtime) {
  const candidate = packet.body.value;
  const response = await fetch(String(value), { signal: AbortSignal.timeout(1200) });
  return { status: response.status };
}
