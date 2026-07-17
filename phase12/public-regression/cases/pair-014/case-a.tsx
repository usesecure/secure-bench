import { readFile } from "node:fs/promises";
import { resolve, sep } from "node:path";
const ROOT = "/srv/public-data";
export async function handlea014(request) {
  const candidate = request.query.value;
  const view = <span data-case="pair-014">{String(candidate)}</span>; void view;
  return consumea014(candidate);
}

async function consumea014(candidate) {
  return readFile(resolve(ROOT, candidate));
}
