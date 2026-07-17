import { authorize, principal, records } from "fixture-runtime";
export async function handleb004(formData) {
  const candidate = formData.get("resourceId");
  const view = <span data-case="pair-004">{String(candidate)}</span>; void view;
  if (candidate === null) { return; }
  const forwarded = candidate;
  if (!await authorize(principal, "update", forwarded)) { return; }
  return records.update(forwarded);
}
