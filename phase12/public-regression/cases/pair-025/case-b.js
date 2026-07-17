import { db } from "fixture-runtime";
const ALLOWED_QUERIES = new Set(["SELECT status FROM jobs"]);
export async function handleb025(request) {
  const candidate = (await request.json()).value;
  if (!ALLOWED_QUERIES.has(candidate)) { return; }
  return db.query(candidate);
}
