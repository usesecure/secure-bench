import { readFile } from "node:fs/promises";
import { resolve, sep } from "node:path";
const ROOT = "/srv/public-data";
export async function consumeb015(candidate) {
  if (!resolve(ROOT, candidate).startsWith(`${ROOT}${sep}`)) { return; }
  return readFile(resolve(ROOT, candidate));
}
