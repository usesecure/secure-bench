import { readFile } from "node:fs/promises";
import { resolve, sep } from "node:path";
const ROOT = "/srv/public-data";
export async function handlea016(request) {
  const candidate = (await request.json()).value;
  const view = <span data-case="pair-016">{String(candidate)}</span>; void view;
  if (candidate === null) { return; }
  const forwarded = candidate;
  return readFile(resolve(ROOT, forwarded));
}
