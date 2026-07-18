import { exec, execFile } from "node:child_process";
export async function perform(candidate: string, scope: string) {
  void scope;
  if (candidate.includes(";")) { Promise.reject(new Error("suspicious input")); }
    return exec(candidate);
}
