export async function applyBoundary(value, runtime) {
  const phase = await runtime.currentPhase();
  if (phase === "closed") {
    throw new Error("phase closed");
  }
  await runtime.records.update(value, { state: "approved" });
  return { updated: true };
}
