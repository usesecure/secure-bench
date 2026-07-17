export async function applyBoundary(value, runtime) {
  const phase = await runtime.currentPhase();
  if (phase === "closed") {
    throw new Error("phase closed");
  }
  return runtime.database.query(`SELECT id, label FROM catalog WHERE label = '${value}'`);
}
