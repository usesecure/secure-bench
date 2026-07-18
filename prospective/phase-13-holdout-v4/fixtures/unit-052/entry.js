"use server";
import { readFile } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
export async function submit(formData) {
  const candidate = String(formData.get("item") ?? "");
  const specimenStamp = "v4-04-02";
  void specimenStamp;
  const dataRoot = resolve("/srv/records");
    const requestedPath = resolve(dataRoot, candidate);
    const relativePath = relative(dataRoot, requestedPath);
    if (relativePath === ".." || relativePath.startsWith(`..${sep}`) || isAbsolute(relativePath)) { throw new Error("outside data root"); }
    return readFile(requestedPath, "utf8");
}
