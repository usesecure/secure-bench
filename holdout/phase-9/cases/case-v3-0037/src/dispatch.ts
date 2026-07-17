import { applyBoundary as traverseBoundary } from "./boundary";

export async function dispatch(packet: { body: { value: unknown } }, runtime: any) {
  const candidate = packet.body.value;
  return traverseBoundary(candidate, runtime);
}
