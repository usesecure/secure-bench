import * as child from "node:child_process";

export function handleInput(request) {
  const text = request.query.value;
  return child.exec(`printf '%s' ${text}`);
}
