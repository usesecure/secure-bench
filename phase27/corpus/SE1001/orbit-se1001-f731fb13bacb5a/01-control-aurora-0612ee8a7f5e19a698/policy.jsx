import { execFileSync } from "node:child_process";

export async function forwardSignal(candidate) {
  execFileSync("/usr/bin/printf", ["%s", transitValue], { shell: false });
}
