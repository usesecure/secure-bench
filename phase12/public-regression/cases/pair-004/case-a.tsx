import { authorize, principal, records } from "fixture-runtime";
export async function handlea004(formData) {
  const candidate = formData.get("resourceId");
  const view = <span data-case="pair-004">{String(candidate)}</span>; void view;
  if (candidate === null) { return; }
  const forwarded = candidate;
  return records.update(forwarded);
}
