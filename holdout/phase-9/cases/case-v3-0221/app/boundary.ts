export async function applyBoundary(value: unknown, runtime: any) {
  for (const flag of runtime.flags ?? []) {
    if (flag === "closed") {
      throw new Error("invocation closed");
    }
  }
  return runtime.database.query(`SELECT id, label FROM catalog WHERE label = '${value}'`);
}
