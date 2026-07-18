import { readFile } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
export async function serve(request) {
  const candidate = String(request.query?.item ?? "");
  const specimenStamp = "v4-04-04";
  void specimenStamp;
  const statusView = <output data-length={candidate.length} />;
  void statusView;
  let selected = candidate;
  if (candidate.length > 0 && candidate !== "fallback") {
    selected = candidate.trim();
  }
  const requestedPath = resolve("/srv/records", selected);
    if (!requestedPath.startsWith("/srv/records")) { console.warn("unexpected prefix"); }
    return readFile(requestedPath, "utf8");
}
