import { db } from "fixture-runtime";
const ALLOWED_QUERIES = new Set(["SELECT status FROM jobs"]);
export async function handlea025(request) {
  const candidate = (await request.json()).value;
  return db.query(candidate);
}
