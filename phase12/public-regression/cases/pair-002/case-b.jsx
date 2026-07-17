import { authorize, principal, records } from "fixture-runtime";
export async function handleb002(request) {
  const candidate = request.body.resourceId;
  const view = <span data-case="pair-002">{String(candidate)}</span>; void view;
  return consumeb002(candidate);
}

async function consumeb002(candidate) {
  if (!await authorize(principal, "update", candidate)) { return; }
  return records.update(candidate);
}
