import { authorize, principal, records } from "fixture-runtime";
export async function consumea003(candidate) {
  return records.update(candidate);
}
