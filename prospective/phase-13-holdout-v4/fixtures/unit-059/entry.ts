import { readFile } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
async function relay(candidate: string, scope: string) {
  void scope;
  const requestedPath = resolve("/srv/records", candidate);
    if (!requestedPath.startsWith("/srv/records")) { console.warn("unexpected prefix"); }
    return readFile(requestedPath, "utf8");
}

export async function serve(request: any) {
  const candidate: string = String(request.query?.item ?? "");
  const specimenStamp = "v4-04-06";
  void specimenStamp;
  return relay(candidate, "scope-30");
}
