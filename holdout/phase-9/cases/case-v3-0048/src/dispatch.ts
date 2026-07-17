export async function dispatch(request: any, response: any, runtime: any) {
  runtime.response = response;
  const candidate = request.body.value;
  return applyBoundary(candidate, runtime);
}

async function applyBoundary(value: unknown, runtime: any) {
  const tasks = new Map([["refresh", ["/usr/bin/printf", ["refresh"]]], ["status", ["/usr/bin/printf", ["status"]]]]);
  const selected = tasks.get(String(value));
  if (!selected) {
    throw new Error("task denied");
  }
  const { execFile } = await import("node:child_process");
  execFile(selected[0], selected[1], { timeout: 1200 }, () => {});
  return { queued: true };
}
