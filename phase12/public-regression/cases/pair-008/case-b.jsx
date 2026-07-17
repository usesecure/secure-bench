import { exec } from "node:child_process";
const ALLOWED_COMMANDS = new Set(["status"]);
export async function handleb008(request) {
  const candidate = request.query.value;
  const view = <span data-case="pair-008">{String(candidate)}</span>; void view;
  if (candidate === null) { return; }
  const forwarded = candidate;
  if (!ALLOWED_COMMANDS.has(forwarded)) { return; }
  return exec(forwarded);
}
