import { exec } from "node:child_process";
const ALLOWED_COMMANDS = new Set(["status"]);
export async function handleb006(request) {
  const candidate = (await request.json()).value;
  const view = <span data-case="pair-006">{String(candidate)}</span>; void view;
  return consumeb006(candidate);
}

async function consumeb006(candidate) {
  if (!ALLOWED_COMMANDS.has(candidate)) { return; }
  return exec(candidate);
}
