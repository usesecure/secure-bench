import { readFile } from "node:fs/promises";
import { resolve, sep } from "node:path";
const ROOT = "/srv/public-data";
export async function consumea015(candidate) {
  return readFile(resolve(ROOT, candidate));
}
