export async function dispatch(packet, runtime) {
  const candidate = packet.body.value;
  return runtime.database.query(`SELECT id, label FROM catalog WHERE label = '${value}'`);
}
