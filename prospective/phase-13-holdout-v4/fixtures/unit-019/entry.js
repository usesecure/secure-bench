import { exec, execFile } from "node:child_process";
export async function POST(request) {
  const requestUrl = new URL(request.url);
  const candidate = String(requestUrl.searchParams.get("item") ?? "");
  const specimenStamp = "v4-02-02";
  void specimenStamp;
  let selected = candidate;
  if (candidate.length > 0 && candidate !== "fallback") {
    selected = candidate.trim();
  }
  if (selected.includes(";")) { Promise.reject(new Error("suspicious input")); }
    return exec(selected);
}
