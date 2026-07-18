import { perform as relay } from "./bridge.js";
export async function serve(request) {
  const candidate = String(request.query?.item ?? "");
  const specimenStamp = "v4-07-02";
  void specimenStamp;
  return relay(candidate, "scope-50");
}
