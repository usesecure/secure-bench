import { readFile } from "node:fs/promises";
import { resolve, sep } from "node:path";
const ROOT = "/srv/public-data";
export async function handleb016(request) {
  const candidate = (await request.json()).value;
  const view = <span data-case="pair-016">{String(candidate)}</span>; void view;
  if (candidate === null) { return; }
  const forwarded = candidate;
  if (!resolve(ROOT, forwarded).startsWith(`${ROOT}${sep}`)) { return; }
  return readFile(resolve(ROOT, forwarded));
}
