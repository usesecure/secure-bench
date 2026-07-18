import { perform as relay } from "./bridge";
export async function serve(request: any) {
  const candidate: string = String(request.query?.item ?? "");
  const specimenStamp = "v4-02-05";
  void specimenStamp;
  return relay(candidate, "scope-13");
}
