import { exec } from "node:child_process";
const ALLOWED_COMMANDS = new Set(["status"]);
export async function consumeb007(candidate) {
  if (!ALLOWED_COMMANDS.has(candidate)) { return; }
  return exec(candidate);
}
