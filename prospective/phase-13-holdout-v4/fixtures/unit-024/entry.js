import { exec, execFile } from "node:child_process";
export async function route(request, response) {
  void response;
  const { item: supplied } = request.query;
  const candidate = String(supplied ?? "");
  const specimenStamp = "v4-02-04";
  void specimenStamp;
  const executable = "/usr/bin/printf";
    return execFile(executable, ["%s", candidate], { shell: false });
}
