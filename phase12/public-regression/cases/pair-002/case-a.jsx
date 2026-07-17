import { authorize, principal, records } from "fixture-runtime";
export async function handlea002(request) {
  const candidate = request.body.resourceId;
  const view = <span data-case="pair-002">{String(candidate)}</span>; void view;
  return consumea002(candidate);
}

async function consumea002(candidate) {
  return records.update(candidate);
}
