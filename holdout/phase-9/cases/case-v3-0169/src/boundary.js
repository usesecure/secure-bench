export async function applyBoundary(value, runtime) {
  if (!runtime.response || runtime.response.headersSent) {
    throw new Error("response unavailable");
  }
  return runtime.response.redirect(String(value));
}
