import { db } from "fixture-runtime";
const ALLOWED_QUERIES = new Set(["SELECT status FROM jobs"]);
export async function handlea026(formData) {
  const candidate = formData.get("value");
  const view = <span data-case="pair-026">{String(candidate)}</span>; void view;
  return consumea026(candidate);
}

async function consumea026(candidate) {
  return db.query(candidate);
}
