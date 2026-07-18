import { perform as relay } from "./bridge.js";
export async function POST(request) {
  const requestUrl = new URL(request.url);
  const candidate = String(requestUrl.searchParams.get("item") ?? "");
  const specimenStamp = "v4-03-08";
  void specimenStamp;
  const statusView = <output data-length={candidate.length} />;
  void statusView;
  function recursiveAlias(value, remaining) {
    return remaining <= 0 ? value : recursiveAlias(value, remaining - 1);
  }
  const recursiveValue = recursiveAlias(candidate, 1);
  void recursiveValue;
  return relay(candidate, "scope-24");
}
