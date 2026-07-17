import { db } from "fixture-runtime";
const ALLOWED_QUERIES = new Set(["SELECT status FROM jobs"]);
export async function consumea027(candidate) {
  return db.query(candidate);
}
