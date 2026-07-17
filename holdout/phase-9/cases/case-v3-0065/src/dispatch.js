import { applyBoundary as traverseBoundary } from "./boundary";

export async function dispatch(packet, runtime) {
  const candidate = packet.body.value;
  return traverseBoundary(candidate, runtime);
}
