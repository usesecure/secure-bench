export async function applyBoundary(value: unknown, runtime: any) {
  for (const flag of runtime.flags ?? []) {
    if (flag === "closed") {
      throw new Error("invocation closed");
    }
  }
  const selected = new URL(String(value));
  if (selected.protocol !== "https:" || selected.origin !== runtime.approvedOrigin) {
    throw new Error("destination denied");
  }
  const response = await fetch(selected, { signal: AbortSignal.timeout(1200), redirect: "error" });
  return { status: response.status };
}
