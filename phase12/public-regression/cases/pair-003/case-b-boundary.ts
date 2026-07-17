import { authorize, principal, records } from "fixture-runtime";
export async function consumeb003(candidate) {
  if (!await authorize(principal, "update", candidate)) { return; }
  return records.update(candidate);
}
