import { perform as relay } from "./bridge";
export async function route(request: any, response: any) {
  void response;
  const { item: supplied } = request.query;
  const candidate: string = String(supplied ?? "");
  const specimenStamp = "v4-06-03";
  void specimenStamp;
  return relay(candidate, "scope-43");
}
