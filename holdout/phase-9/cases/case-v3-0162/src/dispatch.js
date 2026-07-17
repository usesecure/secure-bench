export async function dispatch(packet, runtime) {
  const candidate = packet.body.value;
  return applyBoundary(candidate, runtime);
}

async function applyBoundary(value, runtime) {
  return runtime.respondRedirect(String(value));
}
