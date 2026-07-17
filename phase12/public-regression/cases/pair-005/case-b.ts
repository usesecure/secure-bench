import { exec } from "node:child_process";
const ALLOWED_COMMANDS = new Set(["status"]);
export async function handleb005(request) {
  const candidate = request.body.value;
  if (!ALLOWED_COMMANDS.has(candidate)) { return; }
  return exec(candidate);
}
