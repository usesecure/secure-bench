export async function dispatch(packet, runtime) {
  const candidate = packet.body.value;
  return applyBoundary(candidate, runtime);
}

async function applyBoundary(value, runtime) {
  const { readFile } = await import("node:fs/promises");
  return readFile(String(value), "utf8");
}
