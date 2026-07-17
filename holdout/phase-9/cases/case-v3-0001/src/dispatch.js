export async function dispatch(packet, runtime) {
  const candidate = packet.body.value;
  await runtime.records.update(value, { state: "approved" });
  return { updated: true };
}
