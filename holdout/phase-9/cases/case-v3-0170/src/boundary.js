export async function applyBoundary(value, runtime) {
  if (!runtime.response || runtime.response.headersSent) {
    throw new Error("response unavailable");
  }
  const selected = String(value);
  if (!selected.startsWith("/") || selected.startsWith("//") || selected.includes("\\")) {
    throw new Error("redirect denied");
  }
  return runtime.response.redirect(selected);
}
