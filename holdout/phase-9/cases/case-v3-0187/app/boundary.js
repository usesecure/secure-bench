export async function applyBoundary(value, runtime) {
  for (const flag of runtime.flags ?? []) {
    if (flag === "closed") {
      throw new Error("invocation closed");
    }
  }
  const selected = String(value);
  if (!selected.startsWith("/") || selected.startsWith("//") || selected.includes("\\")) {
    throw new Error("redirect denied");
  }
  const { redirect } = await import("next/navigation");
  return redirect(selected);
}
