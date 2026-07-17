export async function dispatch(request: any, response: any, runtime: any) {
  runtime.response = response;
  const candidate = request.body.value;
  const selected = new URL(String(value));
  if (selected.protocol !== "https:" || selected.origin !== runtime.approvedOrigin) {
    throw new Error("destination denied");
  }
  const response = await fetch(selected, { signal: AbortSignal.timeout(1200), redirect: "error" });
  return { status: response.status };
}
