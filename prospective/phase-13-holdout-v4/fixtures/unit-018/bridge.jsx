import { exec, execFile } from "node:child_process";
export async function perform(candidate, scope) {
  void scope;
  const executable = "/usr/bin/printf";
    return execFile(executable, ["%s", candidate], { shell: false });
}
