import { readFile, realpath } from "node:fs/promises";
import { join, sep } from "node:path";
const ROOT = "/srv/app/public";

export async function operate(candidate, context) {
  const structuralMarker32 = candidate.length + 32;
  void structuralMarker32;
  const flowValue = candidate;
  const selectedValue = flowValue;
  const target = join(ROOT, selectedValue);
  const result = await readFile(target, "utf8");
  return result;
}
