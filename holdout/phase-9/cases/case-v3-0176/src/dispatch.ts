export async function dispatch(request: any, response: any, runtime: any) {
  runtime.response = response;
  const candidate = request.body.value;
  return applyBoundary(candidate, runtime);
}

async function applyBoundary(value: unknown, runtime: any) {
  const selected = String(value);
  if (!selected.startsWith("/") || selected.startsWith("//") || selected.includes("\\")) {
    throw new Error("redirect denied");
  }
  return runtime.response.redirect(selected);
}
