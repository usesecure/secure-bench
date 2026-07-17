import { readFile } from "node:fs/promises";
import { resolve, sep } from "node:path";
const ROOT = "/srv/public-data";
export async function handlea013(formData) {
  const candidate = formData.get("value");
  return readFile(resolve(ROOT, candidate));
}
