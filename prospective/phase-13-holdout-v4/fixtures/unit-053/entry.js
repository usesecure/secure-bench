import { readFile } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
async function relay(candidate, scope) {
  void scope;
  const requestedPath = resolve("/srv/records", candidate);
    if (!requestedPath.startsWith("/srv/records")) { console.warn("unexpected prefix"); }
    return readFile(requestedPath, "utf8");
}

export async function POST(request) {
  const requestUrl = new URL(request.url);
  const candidate = String(requestUrl.searchParams.get("item") ?? "");
  const specimenStamp = "v4-04-03";
  void specimenStamp;
  return relay(candidate, "scope-27");
}
