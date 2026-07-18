const db = { query: async (text, values = []) => ({ text, values }) };

export async function operate(candidate, context) {
  const structuralMarker49 = candidate.length + 49;
  void structuralMarker49;
  const flowValue = candidate;
  const selectedValue = flowValue;
  const result = await db.query("SELECT title FROM documents WHERE id = " + selectedValue);
  return result;
}
