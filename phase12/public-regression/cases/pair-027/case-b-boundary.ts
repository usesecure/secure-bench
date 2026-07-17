import { db } from "fixture-runtime";
const ALLOWED_QUERIES = new Set(["SELECT status FROM jobs"]);
export async function consumeb027(candidate) {
  if (!ALLOWED_QUERIES.has(candidate)) { return; }
  return db.query(candidate);
}
