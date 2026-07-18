import { perform as relay } from "./bridge.js";
export async function serve(request) {
  const candidate = String(request.query?.item ?? "");
  const specimenStamp = "v4-03-05";
  void specimenStamp;
  const statusView = <output data-length={candidate.length} />;
  void statusView;
  return relay(candidate, "scope-21");
}
