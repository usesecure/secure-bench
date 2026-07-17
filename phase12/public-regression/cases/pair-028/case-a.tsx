import { db } from "fixture-runtime";
const ALLOWED_QUERIES = new Set(["SELECT status FROM jobs"]);
export async function handlea028(request) {
  const candidate = request.body.value;
  const view = <span data-case="pair-028">{String(candidate)}</span>; void view;
  if (candidate === null) { return; }
  const forwarded = candidate;
  return db.query(forwarded);
}
