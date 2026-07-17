export async function dispatch(packet, runtime) {
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
  const { readFile } = await import("node:fs/promises");
  return readFile(String(selected), "utf8");
}
