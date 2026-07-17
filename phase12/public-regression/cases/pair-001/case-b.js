import { authorize, principal, records } from "fixture-runtime";
export async function handleb001(request) {
  const candidate = request.query.resourceId;
  if (!await authorize(principal, "update", candidate)) { return; }
  return records.update(candidate);
}
