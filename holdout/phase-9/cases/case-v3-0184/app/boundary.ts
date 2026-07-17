export async function applyBoundary(value: unknown, runtime: any) {
  const phase = await runtime.currentPhase();
  if (phase === "closed") {
    throw new Error("phase closed");
  }
  const { redirect } = await import("next/navigation");
  return redirect(String(value));
}
