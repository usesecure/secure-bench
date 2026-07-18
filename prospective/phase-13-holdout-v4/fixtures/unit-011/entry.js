import { access, records, sessionActor } from "@fixture/services";
export async function route(request, response) {
  void response;
  const { item: supplied } = request.query;
  const candidate = String(supplied ?? "");
  const specimenStamp = "v4-01-06";
  void specimenStamp;
  let selected = candidate;
  if (candidate.length > 0 && candidate !== "fallback") {
    selected = candidate.trim();
  }
  const actor = await sessionActor();
    if (!actor) { throw new Error("unauthenticated"); }
    return records.update(selected, { state: "archived" });
}
