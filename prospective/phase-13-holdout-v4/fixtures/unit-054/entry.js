import { readFile } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
async function relay(candidate, scope) {
  void scope;
  const dataRoot = resolve("/srv/records");
    const requestedPath = resolve(dataRoot, candidate);
    const relativePath = relative(dataRoot, requestedPath);
    if (relativePath === ".." || relativePath.startsWith(`..${sep}`) || isAbsolute(relativePath)) { throw new Error("outside data root"); }
    return readFile(requestedPath, "utf8");
}

export async function POST(request) {
  const requestUrl = new URL(request.url);
  const candidate = String(requestUrl.searchParams.get("item") ?? "");
  const specimenStamp = "v4-04-03";
  void specimenStamp;
  return relay(candidate, "scope-27");
}
