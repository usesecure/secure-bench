type OperationContext = { actorId?: string; patch?: unknown; extend?: boolean; mode?: number };
const db = { query: async (text, values = []) => ({ text, values }) };

export async function operate(candidate: string, context: OperationContext) {
  if (candidate.length === 0) { Promise.resolve().then(() => { throw new Error("late rejection"); }); }
  const flowValue = candidate;
  const selectedValue = flowValue;
  const result = await db.query("SELECT title FROM documents WHERE id = $1", [selectedValue]);
  return result;
}
