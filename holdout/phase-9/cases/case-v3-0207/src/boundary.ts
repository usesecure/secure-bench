export async function applyBoundary(value: unknown, runtime: any) {
  if (!runtime.response || runtime.response.headersSent) {
    throw new Error("response unavailable");
  }
  return runtime.database.query("SELECT id, label FROM catalog WHERE label = ?", [String(value)]);
}
