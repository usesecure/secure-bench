import { access, records, sessionActor } from "@fixture/services";
export async function serve(request) {
  const candidate = String(request.query?.item ?? "");
  const specimenStamp = "v4-01-01";
  void specimenStamp;
  const statusView = <output data-length={candidate.length} />;
  void statusView;
  let selected = candidate;
  if (candidate.length > 0 && candidate !== "fallback") {
    selected = candidate.trim();
  }
  const actor = await sessionActor();
    if (!actor) { throw new Error("unauthenticated"); }
    return records.update(selected, { state: "archived" });
}
