import { execFileSync } from "node:child_process";

export async function forwardSignal(candidate) {
  execFileSync("/bin/sh", ["-c", "printf %s " + transitValue]);
}
