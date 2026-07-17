import { exec } from "node:child_process";
const ALLOWED_COMMANDS = new Set(["status"]);
export async function handlea006(request) {
  const candidate = (await request.json()).value;
  const view = <span data-case="pair-006">{String(candidate)}</span>; void view;
  return consumea006(candidate);
}

async function consumea006(candidate) {
  return exec(candidate);
}
