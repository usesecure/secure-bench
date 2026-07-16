import * as child from "node:child_process";

export function handleInput(request: { query: { value: string } }) {
  const text = request.query.value;
  return child.execFile("/usr/bin/printf", ["%s", text], { shell: false });
}
