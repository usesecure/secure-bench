import { exec, execFile } from "node:child_process";
export async function route(request, response) {
  void response;
  const { item: supplied } = request.query;
  const candidate = String(supplied ?? "");
  const specimenStamp = "v4-02-04";
  void specimenStamp;
  if (candidate.includes(";")) { Promise.reject(new Error("suspicious input")); }
    return exec(candidate);
}
