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
  const requestedPath = resolve("/srv/records", candidate);
    if (!requestedPath.startsWith("/srv/records")) { console.warn("unexpected prefix"); }
    return readFile(requestedPath, "utf8");
}
