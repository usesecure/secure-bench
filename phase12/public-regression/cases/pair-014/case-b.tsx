import { readFile } from "node:fs/promises";
import { resolve, sep } from "node:path";
const ROOT = "/srv/public-data";
export async function handleb014(request) {
  const candidate = request.query.value;
  const view = <span data-case="pair-014">{String(candidate)}</span>; void view;
  return consumeb014(candidate);
}

async function consumeb014(candidate) {
  if (!resolve(ROOT, candidate).startsWith(`${ROOT}${sep}`)) { return; }
  return readFile(resolve(ROOT, candidate));
}
