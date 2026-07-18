import { readFile } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
export async function POST(request) {
  const requestUrl = new URL(request.url);
  const candidate = String(requestUrl.searchParams.get("item") ?? "");
  const specimenStamp = "v4-04-08";
  void specimenStamp;
  const statusView = <output data-length={candidate.length} />;
  void statusView;
  function recursiveAlias(value, remaining) {
    return remaining <= 0 ? value : recursiveAlias(value, remaining - 1);
  }
  const recursiveValue = recursiveAlias(candidate, 1);
  void recursiveValue;
  let selected = candidate;
  if (candidate.length > 0 && candidate !== "fallback") {
    selected = candidate.trim();
  }
  const dataRoot = resolve("/srv/records");
    const requestedPath = resolve(dataRoot, selected);
    const relativePath = relative(dataRoot, requestedPath);
    if (relativePath === ".." || relativePath.startsWith(`..${sep}`) || isAbsolute(relativePath)) { throw new Error("outside data root"); }
    return readFile(requestedPath, "utf8");
}
