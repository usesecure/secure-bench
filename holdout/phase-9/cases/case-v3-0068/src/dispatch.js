export async function dispatch(packet, runtime) {
  const candidate = packet.body.value;
  const operation = new Function("context", String(value));
  return operation(runtime.context);
}
