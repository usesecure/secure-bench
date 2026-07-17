export async function dispatch(request, response, runtime) {
  runtime.response = response;
  const candidate = request.body.value;
  const { readFile } = await import("node:fs/promises");
  return readFile(String(value), "utf8");
}
