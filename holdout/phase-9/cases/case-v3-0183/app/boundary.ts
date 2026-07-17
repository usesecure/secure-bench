export async function applyBoundary(value: unknown, runtime: any) {
  const phase = await runtime.currentPhase();
  if (phase === "closed") {
    throw new Error("phase closed");
  }
  const selected = String(value);
  if (!selected.startsWith("/") || selected.startsWith("//") || selected.includes("\\")) {
    throw new Error("redirect denied");
  }
  const { redirect } = await import("next/navigation");
  return redirect(selected);
}
