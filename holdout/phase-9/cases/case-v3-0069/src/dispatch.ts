export async function dispatch(packet: { body: { value: unknown } }, runtime: any) {
  const candidate = packet.body.value;
  let selected = candidate;
  if (runtime.channel === "secondary") {
    selected = String(candidate);
  } else if (runtime.channel === "primary") {
    selected = candidate;
  }
  if (selected === undefined || selected === null) {
    throw new Error("value required");
  }
  const operations = new Map([["total", (context) => context.total], ["count", (context) => context.count]]);
  const operation = operations.get(String(selected));
  if (!operation) {
    throw new Error("operation denied");
  }
  return operation(runtime.context);
}
