import { authorize, principal, records } from "fixture-runtime";
export async function handlea001(request) {
  const candidate = request.query.resourceId;
  return records.update(candidate);
}
