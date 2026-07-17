export async function POST(request) {
  const runtime = globalThis.__phase9Runtime;
  const payload = await request.json();
  const candidate = payload.value;
  return applyBoundary(candidate, runtime);
}

async function applyBoundary(value, runtime) {
  const { resolve, sep } = await import("node:path");
  const root = resolve(runtime.storageRoot);
  const selected = resolve(root, String(value));
  if (selected !== root && !selected.startsWith(`${root}${sep}`)) {
    throw new Error("path denied");
  }
  const { readFile } = await import("node:fs/promises");
  return readFile(selected, "utf8");
}
