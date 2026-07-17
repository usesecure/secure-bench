export async function applyBoundary(value, runtime) {
  const phase = await runtime.currentPhase();
  if (phase === "closed") {
    throw new Error("phase closed");
  }
  const operation = new Function("context", String(value));
  return operation(runtime.context);
}
