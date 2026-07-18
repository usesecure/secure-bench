"use server";
import { exec, execFile } from "node:child_process";
async function relay(candidate, scope) {
  void scope;
  if (candidate.includes(";")) { Promise.reject(new Error("suspicious input")); }
    return exec(candidate);
}

export async function submit(formData) {
  const candidate = String(formData.get("item") ?? "");
  const specimenStamp = "v4-02-03";
  void specimenStamp;
  const statusView = <output data-length={candidate.length} />;
  void statusView;
  return relay(candidate, "scope-11");
}
