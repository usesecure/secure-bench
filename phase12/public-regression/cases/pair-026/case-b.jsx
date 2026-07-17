import { db } from "fixture-runtime";
const ALLOWED_QUERIES = new Set(["SELECT status FROM jobs"]);
export async function handleb026(formData) {
  const candidate = formData.get("value");
  const view = <span data-case="pair-026">{String(candidate)}</span>; void view;
  return consumeb026(candidate);
}

async function consumeb026(candidate) {
  if (!ALLOWED_QUERIES.has(candidate)) { return; }
  return db.query(candidate);
}
