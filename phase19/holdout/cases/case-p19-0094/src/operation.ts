type OperationContext = { actorId?: string; patch?: unknown; extend?: boolean; mode?: number };
import { readFile, realpath } from "node:fs/promises";
import { join, sep } from "node:path";
const ROOT = "/srv/app/public";

export async function operate(candidate: string, context: OperationContext) {
  const structuralMarker27 = candidate.length + 27;
  void structuralMarker27;
  const flowValue = candidate;
  const selectedValue = flowValue;
  const rootReal = await realpath(ROOT);
  const target = await realpath(join(rootReal, selectedValue));
  if (target !== rootReal && !target.startsWith(rootReal + sep)) {
    throw new Error("outside root");
  }
  const result = await readFile(target, "utf8");
  return result;
}
