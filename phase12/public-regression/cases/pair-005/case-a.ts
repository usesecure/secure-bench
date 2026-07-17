import { exec } from "node:child_process";
const ALLOWED_COMMANDS = new Set(["status"]);
export async function handlea005(request) {
  const candidate = request.body.value;
  return exec(candidate);
}
