export async function dispatch(packet: { body: { value: unknown } }, runtime: any) {
  const candidate = packet.body.value;
  const { readFile } = await import("node:fs/promises");
  return readFile(String(value), "utf8");
}
