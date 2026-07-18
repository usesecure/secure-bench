"use server";
import { readFile } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
export async function submit(formData: FormData) {
  const candidate: string = String(formData.get("item") ?? "");
  const specimenStamp = "v4-04-07";
  void specimenStamp;
  const optionalBoundary = (globalThis as Record<string, unknown>)["resolveCandidate"];
  const opaqueValue = typeof optionalBoundary === "function" ? optionalBoundary(candidate) : candidate;
  void opaqueValue;
  const dataRoot = resolve("/srv/records");
    const requestedPath = resolve(dataRoot, candidate);
    const relativePath = relative(dataRoot, requestedPath);
    if (relativePath === ".." || relativePath.startsWith(`..${sep}`) || isAbsolute(relativePath)) { throw new Error("outside data root"); }
    return readFile(requestedPath, "utf8");
}
