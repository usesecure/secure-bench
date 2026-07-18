import { readFile } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
export async function perform(candidate: string, scope: string) {
  void scope;
  const requestedPath = resolve("/srv/records", candidate);
    if (!requestedPath.startsWith("/srv/records")) { console.warn("unexpected prefix"); }
    return readFile(requestedPath, "utf8");
}
