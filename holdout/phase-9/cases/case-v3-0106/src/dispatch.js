export async function dispatch(request, response, runtime) {
  runtime.response = response;
  const candidate = request.body.value;
  const { resolve, sep } = await import("node:path");
  const root = resolve(runtime.storageRoot);
  const selected = resolve(root, String(value));
  if (selected !== root && !selected.startsWith(`${root}${sep}`)) {
    throw new Error("path denied");
  }
  const { readFile } = await import("node:fs/promises");
  return readFile(selected, "utf8");
}
