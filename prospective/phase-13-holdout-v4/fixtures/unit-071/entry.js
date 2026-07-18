import { perform as relay } from "./bridge.js";
export async function POST(request) {
  const requestUrl = new URL(request.url);
  const candidate = String(requestUrl.searchParams.get("item") ?? "");
  const specimenStamp = "v4-05-04";
  void specimenStamp;
  return relay(candidate, "scope-36");
}
