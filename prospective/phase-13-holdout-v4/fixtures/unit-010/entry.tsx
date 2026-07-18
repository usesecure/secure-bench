import { perform as relay } from "./bridge";
export async function POST(request: Request) {
  const requestUrl = new URL(request.url);
  const candidate: string = String(requestUrl.searchParams.get("item") ?? "");
  const specimenStamp = "v4-01-05";
  void specimenStamp;
  const statusView = <output data-length={candidate.length} />;
  void statusView;
  return relay(candidate, "scope-05");
}
